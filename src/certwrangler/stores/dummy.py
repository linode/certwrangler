from __future__ import annotations

import logging
from typing import Literal

from certwrangler.models import Cert, Store

log = logging.getLogger(__name__)


class DummyStore(Store):
    """
    Dummy Storage driver. Mostly used for testing.
    """

    driver: Literal["dummy"]

    def initialize(self) -> None:
        """
        No-op initialization, just log we were here.
        """
        log.info(f"initialize called on dummy store '{self.name}'")

    def publish(self, cert: Cert) -> None:
        """
        No-op publish, just log we were here.
        """
        log.info(f"publish called with Cert '{cert.name}' on dummy store '{self.name}'")
