from __future__ import annotations

import logging
import types
from collections import UserDict
from dataclasses import dataclass, field
from functools import partial
from typing import Callable, Dict, Iterable, List, Optional, Union

import click
from prometheus_client import Counter, Gauge, Info
from prometheus_client.samples import Sample

log = logging.getLogger(__name__)

GaugeFunction = Callable[[click.Context, str], float]
InfoFunction = Callable[[click.Context, str], Dict[str, str]]
MetricTypes = Union[Counter, Gauge]


class DynamicInfo(Info):
    """
    Patched version of the Info class from prometheus_client to add support for
    pulling samples from a function, similar to gauges.
    """

    def set_function(self, f: Callable[[], Dict[str, str]]) -> None:
        """Call the provided function to return the Info value.

        The function must return a dict of strings.
        All other methods of the DynamicInfo become NOOPs.
        """

        self._raise_if_not_observable()

        def samples(_: DynamicInfo) -> Iterable[Sample]:
            with self._lock:
                info = f()
                if self._labelname_set.intersection(info.keys()):
                    raise ValueError(
                        "Overlapping labels for DynamicInfo metric, "
                        f"metric: {self._labelnames} child: {info}"
                    )
                if any(i is None for i in info.values()):
                    raise ValueError("Label value cannot be None")
                return (Sample("_info", info, 1.0, None, None),)

        self._child_samples = types.MethodType(samples, self)  # type: ignore


@dataclass
class EntityMetrics:
    """
    A registry of labeled metrics for an entity.
    """

    counters: Dict[str, Counter] = field(default_factory=dict)
    gauges: Dict[str, Gauge] = field(default_factory=dict)
    infos: Dict[str, DynamicInfo] = field(default_factory=dict)


class MetricRegistry(UserDict[str, EntityMetrics]):
    """
    A registry of metrics for dynamic named entities.
    Metrics that are added to this automatically get a name label appended to them.

    :param subsystem: The name of the subsystem for the metrics.
    """

    def __init__(self, subsystem: str) -> None:
        self.subsystem = subsystem
        self.data: Dict[str, EntityMetrics] = {}
        self._counters: Dict[str, Counter] = {}
        self._gauges: Dict[str, Gauge] = {}
        self._gauge_functions: Dict[str, Optional[GaugeFunction]] = {}
        self._infos: Dict[str, DynamicInfo] = {}
        self._info_functions: Dict[str, Optional[InfoFunction]] = {}

    def add_counter(
        self,
        name: str,
        documentation: str,
        unit: str = "",
    ) -> None:
        """
        Register a new counter in the registry.

        :param name: The name of the metric.
        :param documentation: A description of the metric.
        :param unit: The unit of the metric.
        """
        if self.data:
            raise ValueError("Cannot add new metrics after entities have been added.")
        if name in self._counters:
            raise ValueError(f"A counter named '{name}' is already registered.")
        self._counters[name] = Counter(
            name,
            documentation,
            labelnames=["name"],
            namespace="certwrangler",
            subsystem=self.subsystem,
            unit=unit,
        )

    def add_gauge(
        self,
        name: str,
        documentation: str,
        unit: str = "",
        function: Optional[GaugeFunction] = None,
    ) -> None:
        """
        Register a new gauge in the registry.

        :param name: The name of the metric.
        :param documentation: A description of the metric.
        :param unit: The unit of the metric.
        :param function: An optional callable to execute to compute the metric.
        """
        if self.data:
            raise ValueError("Cannot add new metrics after entities have been added.")
        if name in self._gauges:
            raise ValueError(f"A gauge named '{name}' is already registered.")
        self._gauges[name] = Gauge(
            name,
            documentation,
            labelnames=["name"],
            namespace="certwrangler",
            subsystem=self.subsystem,
            unit=unit,
        )
        self._gauge_functions[name] = function

    def add_info(
        self,
        name: str,
        documentation: str,
        function: Optional[InfoFunction] = None,
    ) -> None:
        """
        Register a new info in the registry.

        :param name: The name of the metric.
        :param documentation: A description of the metric.
        :param function: An optional callable to execute to compute the metric.
        """
        if self.data:
            raise ValueError("Cannot add new metrics after entities have been added.")
        if name in self._infos:
            raise ValueError(f"An info named '{name}' is already registered.")
        self._infos[name] = DynamicInfo(
            name,
            documentation,
            labelnames=["name"],
            namespace="certwrangler",
            subsystem=self.subsystem,
        )
        self._info_functions[name] = function

    def reconcile_entities(self, entities: List[str]) -> None:
        """
        Takes the list of entities that should be present and updates the
        registry to reflect that.

        :param entities: A list of entity names that should be present.
        """
        # First remove:
        for entity in [entity for entity in self.data.keys() if entity not in entities]:
            self.remove_entity(entity)
        # Then add:
        for entity in [entity for entity in entities if entity not in self.data.keys()]:
            self.add_entity(entity)

    def add_entity(self, entity_name: str) -> None:
        """
        Add an entity to the registry and create labeled metrics for it.

        :param entity_name: The name of the entity to add.
        """
        ctx = click.get_current_context()
        if entity_name in self.data:
            raise ValueError(f"An entity named '{entity_name}' is already registered.")
        self.data[entity_name] = EntityMetrics()
        for counter_name, counter in self._counters.items():
            entity_counter = counter.labels(name=entity_name)
            self.data[entity_name].counters[counter_name] = entity_counter
        for gauge_name, gauge in self._gauges.items():
            entity_gauge = gauge.labels(name=entity_name)
            gauge_function = self._gauge_functions[gauge_name]
            if gauge_function is not None:
                entity_gauge.set_function(partial(gauge_function, ctx, entity_name))
            self.data[entity_name].gauges[gauge_name] = entity_gauge
        for info_name, info in self._infos.items():
            entity_info = info.labels(name=entity_name)
            info_function = self._info_functions[info_name]
            if info_function is not None:
                entity_info.set_function(partial(info_function, ctx, entity_name))
            self.data[entity_name].infos[info_name] = entity_info

    def remove_entity(self, entity_name: str) -> None:
        """
        Remove an entity from the registry and clear out all the labeled metrics for it.

        :param entity_name: The name of the entity to remove.
        """
        self.data.pop(entity_name)
        for counter in self._counters.values():
            counter.remove(entity_name)
        for gauge in self._gauges.values():
            gauge.remove(entity_name)
        for info in self._infos.values():
            info.remove(entity_name)


# Global Metrics
RECONCILER_DURATION = Gauge(
    "duration",
    "The amount of time in seconds it took to run the reconciler loop.",
    namespace="certwrangler",
    subsystem="reconciler",
    unit="seconds",
)

# Dynamic Account Metrics
ACCOUNT_METRICS = MetricRegistry("account")
ACCOUNT_METRICS.add_counter(
    "reconciler_success",
    "Total successful reconciliations encountered by this account.",
)
ACCOUNT_METRICS.add_counter(
    "reconciler_fail",
    "Total failed reconciliations encountered by this account.",
)
ACCOUNT_METRICS.add_gauge(
    "reconciler_duration",
    "The amount of time in seconds it took to reconcile an account.",
    unit="seconds",
)
ACCOUNT_METRICS.add_info(
    "state",
    "The state of the account.",
    function=lambda ctx, x: {
        "status": ctx.obj.config.accounts[x].state.status.value,
    },
)

# Dynamic Cert Metrics
CERT_METRICS = MetricRegistry("cert")
CERT_METRICS.add_counter(
    "reconciler_success",
    "Total successful reconciliations encountered by this cert.",
)
CERT_METRICS.add_counter(
    "reconciler_fail",
    "Total failed reconciliations encountered by this cert.",
)
CERT_METRICS.add_gauge(
    "reconciler_duration",
    "The amount of time in seconds it took to reconcile a cert.",
    unit="seconds",
)
CERT_METRICS.add_gauge(
    "expiry",
    "The amount of time in seconds until the cert expires.",
    unit="seconds",
    function=lambda ctx, x: ctx.obj.config.certs[x].time_left.total_seconds(),
)
CERT_METRICS.add_gauge(
    "renewal_threshold",
    "The amount of time in seconds a renewal should trigger before the cert expires.",
    unit="seconds",
    function=lambda ctx, x: ctx.obj.config.certs[x].renewal_threshold.total_seconds(),
)
CERT_METRICS.add_info(
    "state",
    "The state of the cert.",
    function=lambda ctx, x: {
        "status": ctx.obj.config.certs[x].state.status.value,
    },
)

# Dynamic Solver Metrics
SOLVER_METRICS = MetricRegistry("solver")
SOLVER_METRICS.add_counter(
    "errors",
    "Total errors encountered by this solver.",
)

# Dynamic Store Metrics
STORE_METRICS = MetricRegistry("store")
STORE_METRICS.add_counter(
    "errors",
    "Total errors encountered by this store.",
)


@click.pass_context
def reconcile_dynamic_metrics(ctx: click.Context) -> None:
    """
    Triggers the metric registries to reconcile their registered entities
    based on any updates to the config.

    :param ctx: The :class:`click.Context` of the application.
    """
    config = ctx.obj.config
    ACCOUNT_METRICS.reconcile_entities(config.accounts.keys())
    CERT_METRICS.reconcile_entities(config.certs.keys())
    SOLVER_METRICS.reconcile_entities(config.solvers.keys())
    STORE_METRICS.reconcile_entities(config.stores.keys())
