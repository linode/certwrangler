import hashlib
import json
import logging
import pathlib
import sys
from importlib.util import find_spec
from ipaddress import ip_address
from typing import Any, Dict, List, Tuple

import click
from cryptography.fernet import Fernet

from certwrangler.exceptions import CertwranglerError
from certwrangler.reconcilers import reconcile_all
from certwrangler.utils import XDG_CONFIG_HOME, CertwranglerState, LogLevels

log = logging.getLogger(__name__)


def _validate_nameservers(
    ctx: click.Context, params: Dict[str, Any], values: List[str]
) -> List[str]:
    for value in values:
        try:
            ip_address(value)
        except ValueError:
            raise click.BadParameter(f"Nameserver '{value}' is not a valid IP address.")
    return list(values)


@click.group()
@click.version_option()
@click.option(
    "--config",
    "-c",
    type=click.Path(dir_okay=False, path_type=pathlib.Path),
    default=f"{XDG_CONFIG_HOME}/certwrangler.yaml",
    envvar="CERTWRANGLER_CONFIG",
    help="Config file for certwrangler. Defaults to `${XDG_CONFIG_HOME}/certwrangler.yaml` "
    "or `~/.config/certwrangler.yaml` if `${XDG_CONFIG_HOME}` is not set.",
    show_default=True,
    show_envvar=True,
)
@click.option(
    "--log-level",
    "-l",
    type=click.Choice([log_level.name for log_level in LogLevels]),
    default=LogLevels.info.name,
    envvar="CERTWRANGLER_LOG_LEVEL",
    help="Logging level for certwrangler.",
    show_default=True,
    show_envvar=True,
    callback=lambda ctx, params, value: LogLevels[value],
)
@click.option(
    "nameservers",
    "--nameserver",
    "-n",
    multiple=True,
    envvar="CERTWRANGLER_NAMESERVERS",
    help="Nameservers that certwrangler should use.",
    show_envvar=True,
    callback=_validate_nameservers,
)
@click.pass_context
def cli(
    ctx: click.Context, config: str, log_level: str, nameservers: List[str]
) -> None:
    """The certwrangler management cli."""

    ctx.ensure_object(CertwranglerState)
    with ctx.obj.lock:
        ctx.obj.config_path = config
        ctx.obj.log_level = log_level
        if nameservers:
            ctx.obj.resolver.nameservers = nameservers


@cli.command()
@click.pass_context
def daemon(ctx: click.Context) -> None:
    """Run certwrangler in daemon mode."""

    try:
        ctx.obj.daemon.run()
    except CertwranglerError as error:
        log.fatal(error)
        sys.exit(1)


@cli.command()
@click.option(
    "--initialize",
    "-i",
    is_flag=True,
    default=False,
    help="Initialize state (may create resources, should not be ran while daemon is running).",
    show_default=True,
)
@click.pass_context
def check_config(ctx: click.Context, initialize: bool) -> None:
    """Check that the provided config is valid."""

    try:
        ctx.obj.load_config(initialize=initialize)
        click.secho(" ✅ - Config file loaded successfully.", fg="green")
    except CertwranglerError as error:
        click.secho(f" ❌ - {error}", fg="red")
        sys.exit(1)


@cli.command()
@click.pass_context
def run(ctx: click.Context) -> None:
    """Run a single reconcile loop of certwrangler."""

    try:
        ctx.obj.load_config(initialize=True)
    except CertwranglerError as error:
        log.fatal(error)
        sys.exit(1)
    successful = reconcile_all(ctx.obj.config)
    if not successful:
        sys.exit(1)


if find_spec("IPython"):
    # Add the super secret dev shell.

    @cli.command(context_settings={"ignore_unknown_options": True})
    @click.argument("ipython_args", nargs=-1, type=click.UNPROCESSED)
    @click.pass_context
    def dev_shell(ctx: click.Context, ipython_args: Tuple[Any]) -> None:
        """Open an IPython shell with a certwrangler context."""

        ctx.obj.load_config()

        import IPython
        from IPython.terminal.ipapp import load_default_config

        from certwrangler import controllers, dns, models, reconcilers

        user_ns = {
            "ctx": ctx,
            "config": ctx.obj.config,
            "controllers": controllers,
            "dns": dns,
            "models": models,
            "reconcilers": reconcilers,
        }
        avail_vars = "\n  ".join(user_ns.keys())
        ipython_config = load_default_config()
        ipython_config.TerminalInteractiveShell.banner1 = (
            f"Welcome to certwrangler's development shell!\n"
            f"  Python {sys.version} on {sys.platform}.\n"
            f"Loaded certwrangler variables: \n  {avail_vars}\n"
            f"Config loaded but not initialized, initialize with: \n"
            f"  config.initialize()\n"
        )

        IPython.start_ipython(
            argv=ipython_args,
            user_ns=user_ns,
            config=ipython_config,
        )


@cli.group()
def state() -> None:
    """
    Commands for management of Certwrangler's state.

    Certwrangler should not be running while making modifications to the
    state!
    """


@state.command("generate-key")
def state_generate_key() -> None:
    """
    Generate a new key used to encrypt the local state.

    The new key should be added to the top of the list of encryption keys to
    make it the active key, example:

    \b
    state:
      encryption_keys:
        - <new key goes here>
        - <old key to be rotated out>
    """
    key = Fernet.generate_key()
    fingerprint = hashlib.sha512(key).hexdigest()[:12]
    click.secho(f"        Key: {key.decode()}")
    click.secho(f"Fingerprint: {fingerprint}")


@state.command("fingerprint")
@click.pass_context
def state_fingerprint(ctx: click.Context) -> None:
    """
    Print the active (first) encryption key's fingerprint.
    """
    ctx.obj.load_config()
    config = ctx.obj.config
    state_manager = config.state_manager
    if not state_manager.encryptor:
        click.secho("No encryption keys defined.", fg="red")
        sys.exit(1)
    click.secho(f"Fingerprint: {state_manager.encryptor.fingerprint}")


@state.command("list")
@click.option(
    "--orphaned",
    "-o",
    is_flag=True,
    default=False,
    help="Only list orphaned states.",
    show_default=True,
)
@click.pass_context
def state_list(ctx: click.Context, orphaned: bool) -> None:
    """
    List entities in the state manager.

    This includes orphaned entities that are not in the config.
    """
    ctx.obj.load_config()
    config = ctx.obj.config
    state_manager = config.state_manager
    try:
        states = state_manager.list()
        if orphaned:
            states["accounts"] = {
                name: state
                for name, state in states["accounts"].items()
                if state["orphaned"]
            }
            states["certs"] = {
                name: state
                for name, state in states["certs"].items()
                if state["orphaned"]
            }
        click.secho(json.dumps(states, indent=4, sort_keys=True))
    except CertwranglerError as error:
        click.secho(error, fg="red")
        sys.exit(1)


@state.command("show")
@click.argument(
    "entity_class",
    type=click.Choice(["account", "cert"]),
)
@click.argument("entity_name")
@click.pass_context
def state_show(ctx: click.Context, entity_class: str, entity_name: str) -> None:
    """
    Show the specified entity's state.

    WARNING: This command will output sensitive information!
    """
    ctx.obj.load_config()
    config = ctx.obj.config
    config.initialize()
    try:
        entity = {"account": config.accounts, "cert": config.certs}[entity_class][
            entity_name
        ]
    except KeyError:
        click.secho(
            f"Unable to find state for {entity_class} named '{entity_name}'.",
            fg="red",
        )
        sys.exit(1)
    click.secho(entity.state.model_dump_json(indent=4))


@state.command("delete")
@click.argument(
    "entity_class",
    type=click.Choice(["account", "cert"]),
)
@click.argument("entity_name")
@click.option(
    "--yes",
    "-y",
    is_flag=True,
    default=False,
    help="Don't prompt for confirmation.",
    show_default=True,
)
@click.pass_context
def state_delete(
    ctx: click.Context, entity_class: str, entity_name: str, yes: bool
) -> None:
    """
    Delete the state for the given entity.
    """
    ctx.obj.load_config()
    config = ctx.obj.config
    state_manager = config.state_manager
    try:
        try:
            state = {entity_name: state_manager.list()[f"{entity_class}s"][entity_name]}
        except KeyError:
            click.secho(
                f"Unable to find state for {entity_class} named '{entity_name}'.",
                fg="red",
            )
            sys.exit(1)
        click.secho(f"Deleting the following {entity_class} from the state:")
        click.secho(json.dumps(state, indent=4, sort_keys=True))
        if not yes:
            answer = input("Continue? Only 'yes' will be accepted: ")
            if answer != "yes":
                click.secho("Aborted.", fg="red")
                sys.exit(1)
        state_manager.delete(entity_class, entity_name)
        click.secho(f"Deleted state for {entity_class} '{entity_name}'.")
    except CertwranglerError as error:
        click.secho(error, fg="red")
        sys.exit(1)


@state.command("encrypt")
@click.pass_context
def state_encrypt(ctx: click.Context) -> None:
    """
    Encrypt all managed state objects with the active (first) key.

    Already encrypted objects will be re-encrypted with the active key.
    """
    ctx.obj.load_config()
    config = ctx.obj.config
    state_manager = config.state_manager
    if not state_manager.encryptor:
        click.secho("No encryption keys defined.", fg="red")
        sys.exit(1)
    try:
        for account in config.accounts.values():
            click.secho(f"Encrypting account '{account.name}'...")
            state_manager.load(account)
            state_manager.save(account, encrypt=True)
        for cert in config.certs.values():
            click.secho(f"Encrypting cert '{cert.name}'...")
            state_manager.load(cert)
            state_manager.save(cert, encrypt=True)
    except CertwranglerError as error:
        click.secho(error, fg="red")
        sys.exit(1)


@state.command("decrypt")
@click.pass_context
def state_decrypt(ctx: click.Context) -> None:
    """
    Decrypt all managed state objects.
    """
    ctx.obj.load_config()
    config = ctx.obj.config
    state_manager = config.state_manager
    if not state_manager.encryptor:
        click.secho("No encryption keys defined.", fg="red")
        sys.exit(1)
    try:
        for account in config.accounts.values():
            click.secho(f"Decrypting account '{account.name}'...")
            state_manager.load(account)
            state_manager.save(account, encrypt=False)
        for cert in config.certs.values():
            click.secho(f"Decrypting cert '{cert.name}'...")
            state_manager.load(cert)
            state_manager.save(cert, encrypt=False)
    except CertwranglerError as error:
        click.secho(error, fg="red")
        sys.exit(1)


def main() -> None:
    cli()
