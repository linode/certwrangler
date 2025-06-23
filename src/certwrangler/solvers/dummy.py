from __future__ import annotations

import logging
from typing import Literal

from certwrangler.models import Solver

log = logging.getLogger(__name__)


class DummySolver(Solver):
    """
    Dummy solver driver. Mostly used for testing.
    """

    driver: Literal["dummy"]

    def initialize(self) -> None:
        """
        No-op initialization, just log we were here.
        """
        log.info(f"initialize called on dummy solver '{self.name}'")

    def create(self, name: str, domain: str, content: str) -> None:
        """
        No-op create, just log we were here.
        """
        log.info(
            f"create called with name: '{name}', domain: '{domain}', content: '{content}'"
            f" on dummy solver '{self.name}'",
        )

    def delete(self, name: str, domain: str, content: str) -> None:
        """
        No-op delete, just log we were here.
        """
        log.info(
            f"delete called with name: '{name}', domain: '{domain}', content: '{content}'"
            f" on dummy solver '{self.name}'",
        )
