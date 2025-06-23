import logging

from importlib_metadata import entry_points

from certwrangler.state_managers.dummy import DummyStateManager


class TestDummyStateManager:
    """
    Tests for the DummyStateManager.
    """

    def test_plugin(self):
        """
        Test we correctly see the DummyStateManager plugin.
        """
        (plugin,) = entry_points(group="certwrangler.state_manager", name="dummy")
        assert plugin.load() == DummyStateManager

    def test_initialize(self, click_ctx, caplog, state_manager_dummy):
        caplog.set_level(logging.INFO)
        state_manager_dummy.initialize()
        assert "initialize called on dummy state manager" in caplog.text

    def test_list(self, click_ctx, caplog, state_manager_dummy):
        caplog.set_level(logging.INFO)
        state_manager_dummy.list()
        assert "list called on dummy state manager" in caplog.text

    def test_save_account(self, click_ctx, caplog, state_manager_dummy, account):
        caplog.set_level(logging.INFO)
        state_manager_dummy.save(account)
        assert (
            "save called with Account 'test_account' encrypt=True on dummy state manager"
            in caplog.text
        )
        state_manager_dummy.save(account, encrypt=False)
        assert (
            "save called with Account 'test_account' encrypt=False on dummy state manager"
            in caplog.text
        )

    def test_save_cert(self, click_ctx, caplog, state_manager_dummy, cert):
        caplog.set_level(logging.INFO)
        state_manager_dummy.save(cert)
        assert (
            "save called with Cert 'test_cert' encrypt=True on dummy state manager"
            in caplog.text
        )
        state_manager_dummy.save(cert, encrypt=False)
        assert (
            "save called with Cert 'test_cert' encrypt=False on dummy state manager"
            in caplog.text
        )

    def test_load_account(self, click_ctx, caplog, state_manager_dummy, account):
        caplog.set_level(logging.INFO)
        state_manager_dummy.load(account)
        assert (
            "load called with Account 'test_account' on dummy state manager"
            in caplog.text
        )

    def test_load_cert(self, click_ctx, caplog, state_manager_dummy, cert):
        caplog.set_level(logging.INFO)
        state_manager_dummy.load(cert)
        assert "load called with Cert 'test_cert' on dummy state manager" in caplog.text

    def test_delete(self, click_ctx, caplog, state_manager_dummy):
        caplog.set_level(logging.INFO)
        state_manager_dummy.delete("cert", "test_cert")
        assert (
            "delete called with cert 'test_cert' on dummy state manager" in caplog.text
        )
        state_manager_dummy.delete("account", "test_account")
        assert (
            "delete called with account 'test_account' on dummy state manager"
            in caplog.text
        )
