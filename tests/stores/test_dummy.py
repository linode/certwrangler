import logging

from importlib_metadata import entry_points

from certwrangler.stores.dummy import DummyStore


class TestDummyStore:
    """
    Tests for the DummyStore.
    """

    def test_dummy_plugin(self):
        """
        Test we correctly see the DummyStore plugin.
        """
        (plugin,) = entry_points(group="certwrangler.store", name="dummy")
        assert plugin.load() == DummyStore

    def test_dummy_initialize(self, click_ctx, caplog, store_dummy):
        caplog.set_level(logging.INFO)
        store_dummy.initialize()
        assert "initialize called on dummy store 'test_store'" in caplog.text

    def test_dummy_publish(self, click_ctx, caplog, store_dummy, cert):
        caplog.set_level(logging.INFO)
        store_dummy.publish(cert)
        assert (
            "publish called with Cert 'test_cert' on dummy store 'test_store'"
            in caplog.text
        )
