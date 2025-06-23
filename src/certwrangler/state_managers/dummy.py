from __future__ import annotations

import logging
from typing import Any, Dict, Literal, Union

from certwrangler.models import Account, Cert, StateManager

log = logging.getLogger(__name__)


class DummyStateManager(StateManager):
    """
    Dummy state manager driver. Mostly used for testing.
    """

    driver: Literal["dummy"]

    def initialize(self) -> None:
        """
        No-op initialization, just log we were here.
        """
        log.info("initialize called on dummy state manager")

    def list(self) -> Dict[str, Dict[str, Any]]:
        """
        No-op list, just log we were here and return an empty dict.
        """
        log.info("list called on dummy state manager")
        return {}

    def save(self, entity: Union[Account, Cert], encrypt: bool = True) -> None:
        """
        No-op save, just log we were here.
        """
        entity_type = entity.__class__.__name__
        log.info(
            f"save called with {entity_type} '{entity.name}' encrypt={encrypt} on dummy state manager"
        )

    def load(self, entity: Union[Account, Cert]) -> None:
        """
        No-op load, just log we were here.
        """
        entity_type = entity.__class__.__name__
        log.info(
            f"load called with {entity_type} '{entity.name}' on dummy state manager"
        )

    def delete(
        self, entity_class: Union[Literal["account"], Literal["cert"]], entity_name: str
    ) -> None:
        """
        No-op delete, just log we were here.
        """
        log.info(
            f"delete called with {entity_class} '{entity_name}' on dummy state manager"
        )
