import logging

from certwrangler.controllers import AccountController, CertController
from certwrangler.metrics import ACCOUNT_METRICS, CERT_METRICS, RECONCILER_DURATION
from certwrangler.models import (
    Account,
    AccountStatus,
    Cert,
    CertStatus,
    Config,
    StateManager,
)

log = logging.getLogger(__name__)


@RECONCILER_DURATION.time()
def reconcile_all(config: Config) -> bool:
    """
    Loops through all the accounts and certs in the config and triggers
    reconciliation.

    :param config: The initialized instance of :class:`certwrangler.models.Config`.

    :returns: A `bool` indicating if all object reconciled without error.
    """

    log.info("Starting reconciliation...")
    successful = []
    state_manager = config.state_manager
    for account in config.accounts.values():
        with ACCOUNT_METRICS[account.name].gauges["reconciler_duration"].time():
            successful.append(reconcile_account(account, state_manager))
    for cert in config.certs.values():
        with CERT_METRICS[cert.name].gauges["reconciler_duration"].time():
            successful.append(reconcile_cert(cert, state_manager))
    if all(successful):
        log.info("Finished reconciliation.")
        return True
    else:
        log.error("Finished reconciliation with errors.")
        return False


def reconcile_account(account: Account, state_manager: StateManager) -> bool:
    """
    Reconcile an account's state. This ensures an account is created on the
    remote acme server and that our contact info is correct.

    :param account: The :class:`certwrangler.models.Account` to be reconciled.
    :param state_manager: The :class:`certwrangler.models.StateManager` to be
        used to save changes.

    :returns: A `bool` indicating if the account reconciled without error.
    """

    log.info(f"Reconciling account '{account.name}'...")
    controller = AccountController(account, state_manager)
    try:
        if not account.state.key:
            log.info(f"No key found for account '{account.name}', creating...")
            controller.create_key()
        if not account.state.registration:
            log.info(
                f"No registration found for account '{account.name}', registering..."
            )
            controller.register()
        if account.state.key_size != account.key_size:
            log.info(f"Updating key for account '{account.name}'...")
            controller.change_key()
        if account.state.registration and sorted(
            list(account.state.registration.body.emails)
        ) != sorted(account.emails):
            log.info(f"Updating emails on account '{account.name}'...")
            controller.update_contacts()
        account.state.status = AccountStatus.active
        state_manager.save(account)
        log.info(f"Finished reconciling account '{account.name}'.")
        ACCOUNT_METRICS[account.name].counters["reconciler_success"].inc()
        return True
    except Exception as error:
        log.error(f"Failed to reconcile account '{account.name}': {error}")
        ACCOUNT_METRICS[account.name].counters["reconciler_fail"].inc()
        return False


def reconcile_cert(cert: Cert, state_manager: StateManager) -> bool:
    """
    Reconcile a cert's state. This ensures an order for the cert is
    submitted if needed and handles triggering renewals and publishing
    to the stores.

    :param cert: The :class:`certwrangler.models.Cert` to be reconciled.
    :param state_manager: The :class:`certwrangler.models.StateManager` to be
        used to save changes.

    :returns: A `bool` indicating if the cert reconciled without error.
    """

    log.info(f"Reconciling cert '{cert.name}'...")
    controller = CertController(cert, state_manager)
    try:
        if not cert.state.key:
            log.info(f"No key found for cert '{cert.name}', creating...")
            controller.create_key()
        if cert.key_size != cert.state.key_size:
            log.info(f"Key size changed for cert '{cert.name}', recreating...")
            controller.create_key()
        if cert.state.order:
            log.info(f"Open order found for cert '{cert.name}', processing...")
            controller.process_order()
        elif not cert.state.cert:
            log.info(f"No cert found for cert '{cert.name}', submitting order...")
            controller.create_order()
        elif cert.needs_renewal:
            log.info(f"Cert '{cert.name}' needs renewal, renewing...")
            cert.state.status = CertStatus.renewing
            state_manager.save(cert)
            controller.create_order()
        if not cert.state.order and (cert.state.key and cert.state.cert):
            # make sure we're published to all of our stores.
            controller.publish()
        cert.state.status = CertStatus.active
        state_manager.save(cert)
        log.info(f"Finished reconciling cert '{cert.name}'.")
        CERT_METRICS[cert.name].counters["reconciler_success"].inc()
        return True
    except Exception as error:
        log.error(f"Failed to reconcile cert '{cert.name}': {error}")
        CERT_METRICS[cert.name].counters["reconciler_fail"].inc()
        return False
