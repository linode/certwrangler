class CertwranglerError(Exception):
    """
    Base certwrangler error.
    """


class ConfigError(CertwranglerError):
    """
    Failure during cert controller operation.
    """


class ControllerError(CertwranglerError):
    """
    Failure during cert controller operation.
    """


class DaemonError(CertwranglerError):
    """
    Failure during daemon operation.
    """


class SolverError(CertwranglerError):
    """
    Failure during solver operation.
    """


class StateManagerError(CertwranglerError):
    """
    Failure during state manager operation.
    """


class StoreError(CertwranglerError):
    """
    Failure during store operation.
    """
