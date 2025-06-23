import pytest
from importlib_metadata import entry_points
from lexicon.exceptions import LexiconError
from pydantic import ValidationError
from requests.exceptions import RequestException

from certwrangler.exceptions import SolverError
from certwrangler.solvers.lexicon import LexiconSolver


class TestLexiconSolver:
    """
    Tests for the LexiconSolver.
    """

    @pytest.fixture(autouse=True)
    def _mock_lexicon(self, mocker, click_ctx):
        """
        Autouse fixture that patches our calls to lexicon and brings in the click_ctx fixture.
        """
        mocker.patch("certwrangler.solvers.lexicon.ConfigResolver")
        self._mock_client = mocker.MagicMock()
        mocker.patch(
            "certwrangler.solvers.lexicon.Client",
            mocker.MagicMock(return_value=self._mock_client),
        )

    def test_plugin(self):
        """
        Test we correctly see the LexiconSolver plugin.
        """
        (plugin,) = entry_points(group="certwrangler.solver", name="lexicon")
        assert plugin.load() == LexiconSolver

    @pytest.mark.parametrize(
        "missing",
        [
            "provider_name",
        ],
    )
    def test_config_missing(self, missing, solver_lexicon_config):
        """
        Test that missing required config keys throw a ValidationError.
        """
        bad_config = solver_lexicon_config.copy()
        bad_config.pop(missing)
        with pytest.raises(
            ValidationError,
            match=f"1 validation error for LexiconSolver\n{missing}\n  Field required",
        ):
            LexiconSolver(**bad_config)

    def test_create_success(self, solver_lexicon):
        """
        Test the create method for successful execution.
        """
        solver_lexicon.create("test_name", "example.com", "test_content")
        self._mock_client.execute.assert_called_once()

    def test_create_request_exception(self, solver_lexicon):
        """
        Test the create method when a RequestException is raised.
        """
        self._mock_client.execute.side_effect = RequestException("Request failed")
        with pytest.raises(SolverError):
            solver_lexicon.create("test_name", "test_domain", "test_content")

    def test_create_lexicon_error(self, solver_lexicon):
        """
        Test the create method when a LexiconError is raised
        """
        self._mock_client.execute.side_effect = LexiconError("Lexicon error")
        # Invoking the exception with side effect.
        with pytest.raises(SolverError):
            solver_lexicon.create("test_name", "test_domain", "test_content")

    def test_delete_success(self, solver_lexicon):
        """
        Test the delete method and ensure the successful execution.
        """
        solver_lexicon.delete("test_name", "test_domain", "test_content")
        self._mock_client.execute.assert_called_once()

    def test_delete_request_exception(self, solver_lexicon):
        """
        Test the delete method when a RequestException is raised.
        """
        self._mock_client.execute.side_effect = RequestException("Request failed")
        with pytest.raises(SolverError):
            solver_lexicon.delete("test_name", "test_domain", "test_content")

    def test_delete_lexicon_error(self, solver_lexicon):
        """
        Test the delete method when a Lexicon Error is raised.
        """
        self._mock_client.execute.side_effect = LexiconError("Lexicon error")
        with pytest.raises(SolverError):
            solver_lexicon.delete("test_name", "test_domain", "test_content")

    def test_build_config(self, solver_lexicon):
        """
        Test the _build_config method for the correct configuration construction.
        """
        config = solver_lexicon._build_config(
            "create", "test_name", "test_domain", "test_content"
        )
        expected_config = {
            "action": "create",
            "name": "test_name",
            "domain": "test_domain",
            "delegated": "test_domain",
            "type": "TXT",
            "content": "test_content",
            "provider_name": "test_provider",
            "test_provider": {"key": "value"},
        }
        assert config == expected_config
