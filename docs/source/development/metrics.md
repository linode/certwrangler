# Metrics

Certwrangler metrics are available through an HTTP endpoint when running in [daemon mode](/usage/cli.md#certwrangler-daemon). Certwrangler maintains [metrics registries](#certwrangler.metrics.MetricRegistry) for the various models described in the config. When the config is reloaded through a SIGHUP a [reconciliation task](#certwrangler.metrics.reconcile_dynamic_metrics) on the metrics registries is performed to remove or add any entities in the registry that may have changed in the config. The metric registries are defined as global variables in `src/certwrangler/metrics.py`.

Under the hood the the metrics system makes use of the official [Prometheus python client](https://prometheus.github.io/client_python/), it is recommended to familiarize yourself with how that library works before adding new metrics.

Global scope metrics, as in metrics that aren't tied to a specific entity (like a cert or account object) and don't make use of the metric registry, are pretty straight forward to add. Taking the `RECONCILER_DURATION` gauge as an example, you'd just define it as a global variable:

```python
RECONCILER_DURATION = Gauge(
    "duration",
    "The amount of time in seconds it took to run the reconciler loop.",
    namespace="certwrangler",
    subsystem="reconciler",
    unit="seconds",
)
```

and use it as described in the upstream docs:

```python
from certwrangler.metrics import RECONCILER_DURATION

@RECONCILER_DURATION.time()
def reconcile_all(config: Config) -> bool:
    example_code()
```

Metrics for dynamic entities in the config require use of a [](#certwrangler.metrics.MetricRegistry) for that specific model. For example, to add a new metric for certs you would first need a metric registry for the certs (there is already one defined in `src/certwrangler/metrics.py` as `CERT_METRICS`), and metrics would be added using [](#certwrangler.metrics.MetricRegistry.add_counter) or [](#certwrangler.metrics.MetricRegistry.add_gauge), depending on the type of metric it is:

```python
CERT_METRICS = MetricRegistry("cert")
CERT_METRICS.add_counter(
    "reconciler_success",
    "Total successful reconciliations encountered by this cert.",
)
```

Gauge metrics added through [](#certwrangler.metrics.MetricRegistry.add_gauge) support the ability to provide a [](inv:python:std:term:callable#callable) at creation using the `function` argument, which is useful for reporting metrics dynamically at the time prometheus scrapes certwrangler. The callable should accept two arguments with the first being the click context and the second being the name of the entity. An example of defining a metric like this:

```python
CERT_METRICS.add_gauge(
    "expiry",
    "The amount of time in seconds until the cert expires.",
    unit="seconds",
    function=lambda ctx, x: ctx.obj.config.certs[x].time_left.total_seconds(),
)
```

In this example we read the [](#certwrangler.models.Cert.time_left) attribute on the cert object to export as our metric value.
