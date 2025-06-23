from certwrangler.schema_migrations import _cert_migration_00_add_chain


class TestCertStateSchemaMigrations:
    """
    Tests for cert state schema migrations.
    """

    def test__cert_migration_00_add_chain(self):
        """
        Test that we migrate to the chain field correctly.
        """
        # Test with none values for ca and intermediates, should result in chain being None.
        data = {"ca": None, "intermediates": None}
        assert _cert_migration_00_add_chain(data) == {"chain": None}
        # Add a ca, we should see that move to a list under the "chain" key.
        data = {"ca": "test ca", "intermediates": None}
        assert _cert_migration_00_add_chain(data) == {"chain": ["test ca"]}
        # Same with intermediates.
        data = {
            "ca": None,
            "intermediates": ["test intermediate 1", "test intermediate 2"],
        }
        assert _cert_migration_00_add_chain(data) == {
            "chain": ["test intermediate 1", "test intermediate 2"]
        }
        # Now test with both populated, we should see the ca tacked to the end of the chain.
        data = {
            "ca": "test ca",
            "intermediates": ["test intermediate 1", "test intermediate 2"],
        }
        assert _cert_migration_00_add_chain(data) == {
            "chain": ["test intermediate 1", "test intermediate 2", "test ca"]
        }
