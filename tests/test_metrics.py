import pytest
from prometheus_client import Counter, Gauge
from prometheus_client.core import REGISTRY

from certwrangler.metrics import DynamicInfo, MetricRegistry


@pytest.fixture(scope="function")
def cleanup_prom_registry():
    # quick and dirty reset of the prom client state between tests
    REGISTRY.__init__(auto_describe=True)


@pytest.mark.usefixtures("cleanup_prom_registry")
class TestDynamicInfo:
    """
    Tests for DynamicInfo.
    """

    def test_set_function(self):
        """
        Test that we can use set_function to set a callable to get the samples.
        """
        test_info = DynamicInfo("test_info", "Just test things, mind your business.")
        test_info.set_function(lambda: {"nope": "chuck testa"})
        assert test_info.collect()[0].samples[0].labels == {"nope": "chuck testa"}

    def test_set_function_ValueError_overlap(self):
        """
        Test that we raise a ValueError if we have overlapping labels.
        """
        test_info = DynamicInfo(
            "test_info", "Just test things, mind your business.", labelnames=["name"]
        )
        sub_test_info = test_info.labels(name="my_test")
        sub_test_info.set_function(lambda: {"name": "chuck testa"})
        with pytest.raises(
            ValueError,
            match=(
                "Overlapping labels for DynamicInfo metric, metric: "
                "\\('name',\\) child: {'name': 'chuck testa'}"
            ),
        ):
            test_info.collect()

    def test_set_function_ValueError_None_value(self):
        """
        Test that we raise a ValueError if we have a None value label.
        """
        test_info = DynamicInfo("test_info", "Just test things, mind your business.")
        test_info.set_function(lambda: {"nope": None})
        with pytest.raises(
            ValueError,
            match="Label value cannot be None",
        ):
            test_info.collect()


@pytest.mark.usefixtures("cleanup_prom_registry")
class TestMetricRegistry:
    """
    Tests for the MetricRegistry.
    """

    def test___init__(self):
        """
        Test that we can initialize the registry.
        """
        test_registry = MetricRegistry("test")
        assert test_registry.subsystem == "test"

    def test_add_counter(self):
        """
        Test that we're able to add a new counter to our registry.
        """
        test_registry = MetricRegistry("test")
        test_registry.add_counter("my_test_counter", "Fancy description")
        assert isinstance(test_registry._counters["my_test_counter"], Counter)
        assert test_registry._counters["my_test_counter"]._labelnames == ("name",)
        assert test_registry._counters["my_test_counter"]._unit == ""
        # Fancier test
        test_registry.add_counter(
            "my_fancy_test_counter",
            "Fancy description",
            unit="hunger",
        )
        assert isinstance(test_registry._counters["my_fancy_test_counter"], Counter)
        assert test_registry._counters["my_fancy_test_counter"]._labelnames == ("name",)
        assert test_registry._counters["my_fancy_test_counter"]._unit == "hunger"

    def test_add_counter_ValueError(self, click_ctx):
        """
        Test that we raise a ValueError if we try to add a duplicate counter.
        """
        test_registry = MetricRegistry("test")
        test_registry.add_counter("my_test_counter", "Fancy description")
        with pytest.raises(
            ValueError, match="A counter named 'my_test_counter' is already registered."
        ):
            test_registry.add_counter("my_test_counter", "Fancy description")
        test_registry.add_entity("test")
        with pytest.raises(
            ValueError, match="Cannot add new metrics after entities have been added."
        ):
            test_registry.add_counter("my_new_test_counter", "Fancy description")

    def test_add_gauge(self):
        """
        Test that we're able to add a new gauge to our registry.
        """
        test_registry = MetricRegistry("test")
        test_registry.add_gauge("my_test_gauge", "Fancy description")
        assert isinstance(test_registry._gauges["my_test_gauge"], Gauge)
        assert test_registry._gauges["my_test_gauge"]._labelnames == ("name",)
        assert test_registry._gauges["my_test_gauge"]._unit == ""
        assert test_registry._gauge_functions["my_test_gauge"] is None

        # Fancier test
        def test_function(ctx, x):
            return x

        test_registry.add_gauge(
            "my_fancy_test_gauge",
            "Fancy description",
            unit="hunger",
            function=test_function,
        )
        assert isinstance(test_registry._gauges["my_fancy_test_gauge"], Gauge)
        assert test_registry._gauges["my_fancy_test_gauge"]._labelnames == ("name",)
        assert test_registry._gauges["my_fancy_test_gauge"]._unit == "hunger"
        assert test_registry._gauge_functions["my_fancy_test_gauge"] == test_function

    def test_add_gauge_ValueError(self, click_ctx):
        """
        Test that we raise a ValueError if we try to add a duplicate gauge or
        add a gauge after entities have been populated.
        """
        test_registry = MetricRegistry("test")
        test_registry.add_gauge("my_test_gauge", "Fancy description")
        with pytest.raises(
            ValueError, match="A gauge named 'my_test_gauge' is already registered."
        ):
            test_registry.add_gauge("my_test_gauge", "Fancy description")
        test_registry.add_entity("test")
        with pytest.raises(
            ValueError, match="Cannot add new metrics after entities have been added."
        ):
            test_registry.add_gauge("my_new_test_gauge", "Fancy description")

    def test_add_info(self):
        """
        Test that we're able to add a new info to our registry.
        """
        test_registry = MetricRegistry("test")
        test_registry.add_info("my_test_info", "Fancy description")
        assert isinstance(test_registry._infos["my_test_info"], DynamicInfo)
        assert test_registry._infos["my_test_info"]._labelnames == ("name",)
        assert test_registry._info_functions["my_test_info"] is None

        # Fancier test
        def test_function(ctx, x):
            return {"blah": x}

        test_registry.add_info(
            "my_fancy_test_info",
            "Fancy description",
            function=test_function,
        )
        assert isinstance(test_registry._infos["my_fancy_test_info"], DynamicInfo)
        assert test_registry._infos["my_fancy_test_info"]._labelnames == ("name",)
        assert test_registry._info_functions["my_fancy_test_info"] == test_function

    def test_add_info_ValueError(self, click_ctx):
        """
        Test that we raise a ValueError if we try to add a duplicate info or
        add a info after entities have been populated.
        """
        test_registry = MetricRegistry("test")
        test_registry.add_info("my_test_info", "Fancy description")
        with pytest.raises(
            ValueError, match="An info named 'my_test_info' is already registered."
        ):
            test_registry.add_info("my_test_info", "Fancy description")
        test_registry.add_entity("test")
        with pytest.raises(
            ValueError, match="Cannot add new metrics after entities have been added."
        ):
            test_registry.add_info("my_new_test_info", "Fancy description")

    def test_reconcile_entities(self, click_ctx):
        """
        Test that we can reconcile changes to the monitored entities.
        """
        test_registry = MetricRegistry("test")
        test_registry.add_gauge("my_test_gauge", "Fancy description")
        test_registry.add_entity("test1")
        test_registry.add_entity("test2")
        test_registry.add_entity("test3")
        test_registry.add_entity("test4")
        assert list(test_registry.keys()) == ["test1", "test2", "test3", "test4"]
        test_registry.reconcile_entities(["test0", "test2", "test4"])
        # We cast both to set since ordering isn't really guaranteed with dicts
        assert set(test_registry.keys()) == set(["test0", "test2", "test4"])

    def test_add_entity(self, click_ctx):
        """
        Test that we can add a new entity to the registry.
        """
        test_registry = MetricRegistry("test")
        test_registry.add_counter("my_test_counter", "Fancy description")
        test_registry.add_gauge("my_test_gauge", "Fancy description")
        test_registry.add_gauge(
            "my_test_gauge_with_function",
            "Fancy description",
            function=lambda ctx, x: 1234.0,
        )
        test_registry.add_info("my_test_info", "Fancy description")
        test_registry.add_info(
            "my_test_info_with_function",
            "Fancy description",
            function=lambda ctx, x: {"soylent green": "still people"},
        )
        test_registry.add_entity("test")
        # make sure the prometheus metric objects have the label registered
        assert ("test",) in test_registry._counters["my_test_counter"]._metrics
        assert ("test",) in test_registry._gauges["my_test_gauge"]._metrics
        assert ("test",) in test_registry._gauges[
            "my_test_gauge_with_function"
        ]._metrics
        assert ("test",) in test_registry._infos["my_test_info"]._metrics
        assert ("test",) in test_registry._infos["my_test_info_with_function"]._metrics
        # make sure we make reference to the labeled objects in our entity dict
        assert isinstance(test_registry["test"].counters["my_test_counter"], Counter)
        assert test_registry["test"].counters["my_test_counter"]._labelvalues == (
            "test",
        )
        assert isinstance(test_registry["test"].gauges["my_test_gauge"], Gauge)
        assert test_registry["test"].gauges["my_test_gauge"]._labelvalues == ("test",)
        assert isinstance(
            test_registry["test"].gauges["my_test_gauge_with_function"], Gauge
        )
        assert test_registry["test"].gauges[
            "my_test_gauge_with_function"
        ]._labelvalues == ("test",)
        assert isinstance(test_registry["test"].infos["my_test_info"], DynamicInfo)
        assert test_registry["test"].infos["my_test_info"]._labelvalues == ("test",)
        assert isinstance(
            test_registry["test"].infos["my_test_info_with_function"], DynamicInfo
        )
        assert test_registry["test"].infos[
            "my_test_info_with_function"
        ]._labelvalues == ("test",)
        # this magic just executes the function that the prometheus client embedded
        assert (
            test_registry["test"]
            .gauges["my_test_gauge_with_function"]
            ._child_samples()[0]
            .value
            == 1234.0
        )
        assert (
            test_registry["test"]
            .infos["my_test_info_with_function"]
            ._child_samples()[0]
            .value
            == 1.0
        )
        assert test_registry["test"].infos[
            "my_test_info_with_function"
        ]._child_samples()[0].labels == {
            "soylent green": "still people",
        }

    def test_add_entity_ValueError(self, click_ctx):
        """
        Test that we raise a ValueError if we try to add a duplicate entity.
        """
        test_registry = MetricRegistry("test")
        test_registry.add_entity("test")
        with pytest.raises(
            ValueError, match="An entity named 'test' is already registered."
        ):
            test_registry.add_entity("test")

    def test_remove_entity(self, click_ctx):
        """
        Test that we can remove an entity from the registry.
        """
        test_registry = MetricRegistry("test")
        test_registry.add_counter("my_test_counter", "Fancy description")
        test_registry.add_gauge("my_test_gauge", "Fancy description")
        test_registry.add_info("my_test_info", "Fancy description")
        test_registry.add_entity("test")
        test_registry.add_entity("test1")
        # Ensure our metrics were added
        assert "test" in test_registry
        assert "test1" in test_registry
        assert len(test_registry._gauges["my_test_gauge"].collect()[0].samples) == 2
        for sample in test_registry._gauges["my_test_gauge"].collect()[0].samples:
            assert sample.labels["name"] in ["test", "test1"]
        assert len(test_registry._infos["my_test_info"].collect()[0].samples) == 2
        for sample in test_registry._infos["my_test_info"].collect()[0].samples:
            assert sample.labels["name"] in ["test", "test1"]
        # There are 4 samples because prometheus client automatically adds a second
        # one suffixed with "_created" to indicate when the collector started collecting
        # data.
        assert len(test_registry._counters["my_test_counter"].collect()[0].samples) == 4
        for sample in test_registry._counters["my_test_counter"].collect()[0].samples:
            assert sample.labels["name"] in ["test", "test1"]
        # Now remove the "test" entity and ensure we left "test1"
        test_registry.remove_entity("test")
        assert "test" not in test_registry
        assert "test1" in test_registry
        assert len(test_registry._gauges["my_test_gauge"].collect()[0].samples) == 1
        for sample in test_registry._gauges["my_test_gauge"].collect()[0].samples:
            assert sample.labels["name"] == "test1"
        assert len(test_registry._infos["my_test_info"].collect()[0].samples) == 1
        for sample in test_registry._infos["my_test_info"].collect()[0].samples:
            assert sample.labels["name"] == "test1"
        assert len(test_registry._counters["my_test_counter"].collect()[0].samples) == 2
        for sample in test_registry._counters["my_test_counter"].collect()[0].samples:
            assert sample.labels["name"] == "test1"
