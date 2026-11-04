import pytest
from pydantic import BaseModel, ValidationError

from certwrangler.types import FileMode


class ModeModel(BaseModel):
    mode: FileMode


@pytest.mark.parametrize(
    "value,expected",
    [
        # yaml 1.1 resolves an unquoted 0600 to this
        (0o600, 0o600),
        ("0600", 0o600),
        ("600", 0o600),
        (0, 0),
        (0o777, 0o777),
    ],
)
def test_file_mode(value, expected):
    """
    Test that we accept octal ints and octal strings.
    """
    assert ModeModel(mode=value).mode == expected


@pytest.mark.parametrize(
    "value",
    [
        # unquoted decimal modes, the most likely misconfiguration
        600,
        644,
        755,
        -1,
        0o1777,
        "0888",
        "not a mode",
    ],
)
def test_file_mode_invalid(value):
    """
    Test that we reject anything outside of a plain octal permission mode.
    """
    with pytest.raises(ValidationError):
        ModeModel(mode=value)
