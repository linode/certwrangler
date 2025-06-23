import logging
import time
from datetime import datetime, timedelta
from typing import List, Tuple

import click
from dns.message import QueryMessage
from dns.rdatatype import RdataType
from dns.resolver import NXDOMAIN, NoAnswer

log = logging.getLogger(__name__)


@click.pass_context
def wait_for_challenges(
    ctx: click.Context,
    dns_records: List[Tuple[str, str]],
    wait_timeout: timedelta,
    sleep: int = 5,
) -> None:
    """
    Wait for our DNS challenges to propagate.

    .. todo:: this should probably be switched to async operations to clean up
        the code.

    :param ctx: The :class:`click.Context` of the application.
    :param dns_records: A list of tuples containing the domain and the expected
        TXT record value.
    :param wait_timeout: A :class:`datetime.timedelta` of how long to wait.
    :param sleep: How long to sleep between each loop.

    :raises TimeoutError: Raised if the ``wait_timeout`` expires before we get
        our expected results.
    """
    resolver = ctx.obj.resolver
    challenges = {
        name: {"passed": False, "token": token} for name, token in dns_records
    }
    stop_time = datetime.now() + wait_timeout
    while datetime.now() < stop_time:
        for name, info in challenges.items():
            if info["passed"]:
                continue
            try:
                answers = resolver.resolve(name, rdtype=RdataType.TXT)
            except (NXDOMAIN, NoAnswer):
                continue
            for answer in answers:
                if answer.rdtype == RdataType.TXT:
                    if answer.strings[0].decode() == info["token"]:
                        challenges[name]["passed"] = True
        if all([info["passed"] for info in challenges.values()]):
            return
        time.sleep(sleep)
    waiting_names = ", ".join(
        [name for name, info in challenges.items() if not info["passed"]]
    )
    raise TimeoutError(
        f"Timeout expired for DNS propagation of following records: {waiting_names}."
    )


@click.pass_context
def resolve_cname(ctx: click.Context, name: str) -> str:
    """
    Resolves ``name`` to its canonical name by recursively following any CNAME
    records until we fail to get a response. This can result in ``name`` just
    being returned if it doesn't resolve to a CNAME.

    :param ctx: The :class:`click.Context` of the application.
    :param name: The domain name to resolve.

    :returns: The canonical name that ``name`` resolves to.

    :raises ValueError: Raised if an infinite loop is detected in CNAME
        resolution.
    """
    resolver = ctx.obj.resolver
    current_name = name
    visited = [current_name]

    while True:
        try:
            answer = resolver.resolve(current_name, rdtype=RdataType.CNAME)
            current_name = str(answer[0].target)
            if current_name in visited:
                resolution_map = " -> ".join([*visited, current_name])
                raise ValueError(
                    f"Error, CNAME resolution for {current_name} ended in an infinite loop!\n"
                    f"{resolution_map}"
                )
            visited.append(current_name)
        except (NXDOMAIN, NoAnswer):
            # No more CNAME in the chain, we have the final canonical name
            return current_name.rstrip(".")


@click.pass_context
def resolve_zone(ctx: click.Context, name: str) -> str:
    """
    Climb through the domain tree until we find the SOA for the zone.

    :param ctx: The :class:`click.Context` of the application.
    :param name: The domain name to resolve.

    :returns: The zone ``name`` belongs to.

    :raises ValueError: Raised if we fail to find an SOA.
    """

    def _contains_cname(response: QueryMessage) -> bool:
        for answer in response.answer:
            if answer.rdtype == RdataType.CNAME:
                return True
        return False

    resolver = ctx.obj.resolver
    split_name = name.rstrip(".").split(".")
    for index, _ in enumerate(split_name):
        domain = ".".join(split_name[index:])
        try:
            response = resolver.resolve(domain, rdtype=RdataType.SOA).response
        except (NXDOMAIN, NoAnswer):
            # No SOA at this level, move up and try again
            continue
        # CNAMEs can't exist at the root of a zone, continue if we have one.
        if _contains_cname(response):
            continue
        for answer in response.answer:
            if answer.rdtype == RdataType.SOA:
                return answer.name.to_text().rstrip(".")
    raise ValueError(f"Unable to find SOA in DNS tree for '{name}'")
