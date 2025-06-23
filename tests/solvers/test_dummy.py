import logging

from importlib_metadata import entry_points

from certwrangler.solvers.dummy import DummySolver


class TestDummySolver:
    """
    Tests for the DummySolver.
    """

    def test_plugin(self):
        """
        Test we correctly see the DummySolver plugin.
        """
        (plugin,) = entry_points(group="certwrangler.solver", name="dummy")
        assert plugin.load() == DummySolver

    def test_initialize(self, click_ctx, caplog, solver_dummy):
        caplog.set_level(logging.INFO)
        solver_dummy.initialize()
        assert "initialize called on dummy solver 'test_solver'" in caplog.text

    def test_create(self, click_ctx, caplog, solver_dummy):
        caplog.set_level(logging.INFO)
        solver_dummy.create("test", "example.com", "123")
        assert (
            "create called with name: 'test', domain: 'example.com', content: '123'"
            " on dummy solver 'test_solver'" in caplog.text
        )

    def test_delete(self, click_ctx, caplog, solver_dummy):
        caplog.set_level(logging.INFO)
        solver_dummy.delete("test", "example.com", "123")
        assert (
            "delete called with name: 'test', domain: 'example.com', content: '123'"
            " on dummy solver 'test_solver'" in caplog.text
        )
