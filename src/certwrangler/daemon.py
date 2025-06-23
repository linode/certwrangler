import asyncio
import inspect
import logging
import signal
import sys
import threading
from types import FrameType
from typing import Any, Callable, Iterable, List, Mapping, Optional

import click

from certwrangler.exceptions import DaemonError
from certwrangler.http import create_http_server
from certwrangler.reconcilers import reconcile_all

log = logging.getLogger(__name__)


class ThreadWithContext(threading.Thread):
    """
    Base thread class for certwrangler. Takes the same args and works like
    :class:`threading.Thread`, but adds support for the click context and
    adds support to handle graceful stop events for normal threads and
    threads that are running a coroutine.

    Subclasses should define their thread logic under the ``_run()`` method
    instead of :meth:`run`. ``_run()`` can either be a normal method or a
    coroutine. For a normal method, the thread should support gracefully
    stopping when the ``self.graceful_stop_event`` :class:`threading.Event`
    is set. For coroutines the thread should support gracefully stopping when
    the ``self.async_graceful_stop_event`` :class:`asyncio.Event` is set.
    """

    def __init__(
        self,
        group: None = None,
        target: Optional[Callable[..., object]] = None,
        name: Optional[str] = None,
        args: Iterable[Any] = [],
        kwargs: Optional[Mapping[str, Any]] = None,
        *,
        daemon: Optional[bool] = None,
    ) -> None:
        self.ctx: click.Context = click.get_current_context()
        self.loop: Optional[asyncio.AbstractEventLoop] = None
        self.graceful_stop_event: threading.Event = threading.Event()
        self.async_graceful_stop_event: Optional[asyncio.Event] = None
        super().__init__(group, target, name, args, kwargs, daemon=daemon)

    def run(self) -> None:
        """
        Runs ``_run()`` within the click context. If ``_run()`` is a coroutine
        this also takes care of setting up an asyncio event loop to run it in.
        """
        with self.ctx:
            _run = getattr(self, "_run", None)
            if inspect.iscoroutinefunction(_run):
                self.loop = asyncio.new_event_loop()
                asyncio.set_event_loop(self.loop)
                self.async_graceful_stop_event = asyncio.Event()
                try:
                    self.loop.run_until_complete(_run())
                finally:
                    if not self.loop.is_closed():
                        self.loop.close()
            elif inspect.ismethod(_run):
                _run()
            else:
                super().run()

    def graceful_stop(self) -> None:
        """
        Sets ``self.graceful_stop_event`` and ``self.async_graceful_stop_event``
        to trigger a graceful stop.
        """
        self.graceful_stop_event.set()
        if (
            self.async_graceful_stop_event is not None
            and self.loop is not None
            and not self.loop.is_closed()
        ):
            self.loop.call_soon_threadsafe(self.async_graceful_stop_event.set)


class WebServerThread(ThreadWithContext):
    """
    Thread that runs the webserver.
    """

    async def _run(self) -> None:
        server = create_http_server()
        task = asyncio.create_task(server.serve())
        await self.async_graceful_stop_event.wait()  # type: ignore
        server.should_exit = True
        await task


class ReconcilerThread(ThreadWithContext):
    """
    Thread that runs the reconciler loop. This thread will run the reconciler
    by the interval defined under the reconciler configuration.
    """

    def _run(self) -> None:
        while not self.graceful_stop_event.is_set():
            with self.ctx.obj.lock:
                reconcile_all(self.ctx.obj.config)
            if self.graceful_stop_event.wait(
                timeout=self.ctx.obj.config.daemon.reconciler.interval
            ):
                break


class Daemon:
    """
    The thread manager class for certwrangler. It is responsible for the
    lifecycle of the threads, including starting, stopping, and handling
    reloads.
    """

    def __init__(self) -> None:
        self.ctx: click.Context = click.get_current_context()
        self.threads: List[ThreadWithContext] = []
        self.stopping: threading.Event = threading.Event()
        self.reloading: threading.Lock = threading.Lock()

    def _create_threads(self) -> None:
        """
        Creates the threads.

        :raises DaemonError: Raised if any threads already exist.
        """
        if self.threads:
            raise DaemonError(
                f"Threads already exist: {', '.join([x.name for x in self.threads])}"
            )
        self.threads = [
            WebServerThread(daemon=True, name="http_server"),
            ReconcilerThread(daemon=True, name="reconciler"),
        ]

    def _start_threads(self) -> None:
        """
        Starts the threads.
        """
        for thread in self.threads:
            log.info(f"Starting {thread.name} thread...")
            thread.start()

    def _stop_threads(self) -> None:
        """
        Stops the threads by issuing :meth:`ThreadWithContext.graceful_stop`
        to each thread. Does not return until all threads are stopped.
        """
        for thread in self.threads:
            thread.graceful_stop()
        for thread in self.threads:
            if thread.is_alive():
                thread.join()
            log.info(f"Thread {thread.name} stopped.")
        self.threads = [thread for thread in self.threads if thread.is_alive()]

    def _reload_handler(self, signal_number: int, _frame: Optional[FrameType]) -> None:
        """
        Handles processing a reload of the config on SIGHUP. This will gracefully
        stop the threads, reload and re-initialize the config, then start the
        threads back up.
        """
        if self.reloading.locked():
            # reload already in progress
            return
        with self.reloading:
            signal_name = signal.Signals(signal_number).name
            log.info(f"Caught {signal_name}, stopping threads to reload config.")
            self._stop_threads()
            self.ctx.obj.load_config(initialize=True)
            self._create_threads()
            self._start_threads()

    def _stop_handler(self, signal_number: int, _frame: Optional[FrameType]) -> None:
        """
        Handles processing stopping the threads on SIGTERM and SIGINT. This
        will first attempt to gracefully stop the threads, then forcefully
        exits if it catches a second SIGTERM or SIGINT.
        """
        signal_name = signal.Signals(signal_number).name
        if not self.stopping.is_set():
            log.info(f"Caught {signal_name}, gracefully stopping daemon...")
            self.stopping.set()
        else:
            log.info(f"Caught {signal_name} while stopping, forcefully quitting.")
            sys.exit()

    def run(self) -> None:
        """
        Runs the daemon. This loads and initializes the config, starts the
        threads, sets up the signal handlers for graceful stop and reload,
        and sets up a watchdog on the threads to raise an exception if one of
        the threads die unexpectedly.

        The watchdog interval can be set under the daemon section in the config.

        :raises DaemonError: Raised if any of the threads die unexpectedly.
        """
        self.ctx.obj.load_config(initialize=True)
        self._create_threads()
        self._start_threads()

        signal.signal(signal.SIGHUP, self._reload_handler)
        signal.signal(signal.SIGTERM, self._stop_handler)
        signal.signal(signal.SIGINT, self._stop_handler)

        while True:
            # Every loop we check the health of our threads and quit if they die unexpectedly.
            for thread in self.threads:
                if (
                    not (self.stopping.is_set() or self.reloading.locked())
                    and not thread.is_alive()
                ):
                    # Thread is dead, let's mourn its passing by raising an exception.
                    raise DaemonError(f"{thread.name} thread died")
            if self.stopping.wait(timeout=self.ctx.obj.config.daemon.watchdog_interval):
                # wait for threads to die then return
                self._stop_threads()
                return
