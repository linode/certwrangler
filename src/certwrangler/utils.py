from __future__ import annotations

import logging
import os
import sys
import threading
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path
from string import Template
from typing import List, Optional

import yaml
from dns.resolver import Resolver
from pydantic import ValidationError

from certwrangler.daemon import Daemon
from certwrangler.exceptions import CertwranglerError, ConfigError
from certwrangler.metrics import reconcile_dynamic_metrics
from certwrangler.models import Config

XDG_CONFIG_HOME = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
XDG_DATA_HOME = os.environ.get("XDG_DATA_HOME") or os.path.expanduser("~/.local/share")

log = logging.getLogger(__name__)


class LogLevels(IntEnum):
    """
    An Enum representing the supported log levels.
    """

    debug = logging.DEBUG
    info = logging.INFO
    warning = logging.WARNING
    error = logging.ERROR
    critical = logging.CRITICAL


@dataclass
class CertwranglerState:
    """
    The main state of the application. This class is responsible for loading
    the config from disk, setting up logging, and storing config passed in
    from CLI options.
    """

    config_path: Path = Path(f"{XDG_CONFIG_HOME}/certwrangler.yaml")
    """
    A :class:`pathlib.Path` object referencing the location of the config file.
    Defaults to '${XDG_CONFIG_HOME}/certwrangler.yaml' or '~/.config/certwrangler.yaml'
    if '${XDG_CONFIG_HOME}' is not set.
    """

    daemon: Daemon = field(init=False, default_factory=Daemon)
    """
    The instance of :class:`certwrangler.daemon.Daemon`.
    """

    config: Optional[Config] = None
    """
    The loaded instance of :class:`certwrangler.models.Config`, populated by :meth:`load_config`.
    """

    resolver: Resolver = field(init=False, default_factory=Resolver)
    """
    The instance of :class:`dns.resolver.Resolver` used for all DNS operations.
    """

    lock: threading.RLock = field(init=False, default_factory=threading.RLock)
    """
    Resource lock for making changes to the state.
    """

    _log_level: LogLevels = field(init=False, repr=False, default=LogLevels.info)
    _loggers: List[logging.Logger] = field(
        init=False,
        repr=False,
        default_factory=lambda: [
            logging.getLogger(x) for x in ["acme", "certwrangler", "uvicorn"]
        ],
    )

    def __post_init__(self) -> None:
        log_handler = logging.StreamHandler(sys.stdout)
        log_handler.setFormatter(
            logging.Formatter(
                "%(asctime)s: %(levelname)s [%(name)s, %(funcName)s(), line %(lineno)d, thread %(threadName)s] - %(message)s"
            )
        )
        for logger in self._loggers:
            logger.handlers.clear()
            logger.addHandler(log_handler)
            logger.setLevel(self.log_level)

    @property
    def log_level(self) -> LogLevels:
        return self._log_level

    @log_level.setter
    def log_level(self, value: LogLevels) -> None:
        """
        Setter for log_level, cascades the change to any loaded loggers.
        """
        if type(value) is property:
            value = CertwranglerState._log_level
        self._log_level = value
        if getattr(self, "_loggers", None):
            for logger in self._loggers:
                logger.setLevel(value)

    def load_config(self, initialize: bool = False) -> None:
        """
        Loads the config from `config_path` and optionally initializes it.
        This also cascades the change to the metrics system to reconcile
        the entities in the metrics registries.

        :param initialize: If ``True``, :meth:`certwrangler.models.Config.initialize`
            will be called on :attr:`CertwranglerState.config` after loading.

        :raises ConfigError: Raised on any issues with loading, parsing,
            or initializing the config.
        """
        with self.lock:
            if not self.config_path:
                raise ConfigError("No config_path defined to load from.")
            try:
                log.info(f"Loading config from {self.config_path}")
                with open(self.config_path, "r") as file_handler:
                    config_template = Template(file_handler.read())
                    self.config = Config(
                        **yaml.load(
                            config_template.substitute(os.environ),
                            Loader=yaml.FullLoader,
                        )
                    )
            except KeyError as error:
                raise ConfigError(
                    f"Failure loading config: Environment variable {error} not defined."
                ) from error
            except (FileNotFoundError, ValidationError) as error:
                raise ConfigError(f"Failure loading config: {error}") from error
            if initialize:
                try:
                    self.config.initialize()
                except CertwranglerError as error:
                    raise ConfigError(
                        f"Failure initializing Certwrangler: {error}"
                    ) from error
                reconcile_dynamic_metrics()
            log.info(f"Config loaded from '{self.config_path}'.")
