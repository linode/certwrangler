import asyncio
import logging
import signal
import threading
import time

import click
import pytest

from certwrangler.daemon import (
    Daemon,
    ReconcilerThread,
    ThreadWithContext,
    WebServerThread,
)
from certwrangler.exceptions import DaemonError


class TestThreadWithContext:
    """
    Tests for ThreadWithContext.
    """

    def test___init__(self, click_ctx):
        """
        Test that the extra attributes get properly set with ThreadWithContext.
        """
        thread = ThreadWithContext()
        assert thread.ctx == click_ctx
        assert thread.loop is None
        assert isinstance(thread.graceful_stop_event, threading.Event)
        assert thread.async_graceful_stop_event is None

    def test_run_function(self, click_ctx):
        """
        Test that ThreadWithContext runs target functions as expected.
        """

        def _thread_func():
            ctx = click.get_current_context()
            assert ctx == click_ctx
            raise ValueError("test123")

        thread = ThreadWithContext(target=_thread_func)
        with pytest.raises(ValueError, match="test123"):
            thread.run()

    def test_run_method(self, click_ctx):
        """
        Test that ThreadWithContext runs _run methods as expected.
        """

        class TestThread(ThreadWithContext):
            def _run(self):
                assert self.ctx == click_ctx
                raise ValueError("test123")

        thread = TestThread()
        with pytest.raises(ValueError, match="test123"):
            thread.run()

    def test_run_async_method(self, click_ctx):
        """
        Test that ThreadWithContext runs _run async methods as expected.
        """

        class TestThread(ThreadWithContext):
            async def _run(self):
                assert isinstance(self.loop, asyncio.AbstractEventLoop)
                assert isinstance(self.async_graceful_stop_event, asyncio.Event)
                assert self.ctx == click_ctx
                raise ValueError("test123")

        thread = TestThread()
        with pytest.raises(ValueError, match="test123"):
            thread.run()
        assert thread.loop.is_closed()

    def test_graceful_stop(self, click_ctx):
        """
        Test that graceful_stop issues the graceful_stop_event.
        """

        class TestThread(ThreadWithContext):
            def _run(self):
                self.graceful_stop_event.wait()

        thread = TestThread()
        thread.start()
        assert thread.is_alive()
        thread.graceful_stop()
        thread.join(1)
        assert not thread.is_alive()

    def test_graceful_stop_async(self, click_ctx):
        """
        Test that graceful_stop issues the async_graceful_stop_event.
        """

        class TestThread(ThreadWithContext):
            async def _run(self):
                await self.async_graceful_stop_event.wait()

        thread = TestThread()
        thread.start()
        assert thread.is_alive()
        while thread.loop is None or not thread.loop.is_running():
            # wait for the loop to start up before we try to kill it
            time.sleep(0.1)
        thread.graceful_stop()
        thread.join(1)
        assert not thread.is_alive()
        assert not thread.loop.is_running()
        assert thread.loop.is_closed()


class TestWebServerThread:
    """
    Tests for WebServerThread.
    """

    def test_run(self, click_ctx, mocker):
        """
        Test that the WebServerThread works as expected.
        """

        class FakeServer:
            def __init__(self):
                self.should_exit = False

            async def serve(self):
                while not self.should_exit:
                    await asyncio.sleep(0.1)

        fake_server = FakeServer()
        mocked_create_http_server = mocker.patch(
            "certwrangler.daemon.create_http_server", return_value=fake_server
        )
        thread = WebServerThread()
        thread.start()
        assert thread.is_alive()
        while thread.loop is None or not thread.loop.is_running():
            # wait for the loop to start up before we try to kill it
            time.sleep(0.1)
        mocked_create_http_server.assert_called_once()
        assert not fake_server.should_exit
        thread.graceful_stop()
        thread.join()
        assert fake_server.should_exit
        assert not thread.is_alive()
        assert not thread.loop.is_running()
        assert thread.loop.is_closed()


class TestReconcilerThread:
    """
    Tests for ReconcilerThread.
    """

    def test_run(self, click_ctx, mocker):
        """
        Test that the ReconcilerThread works as expected.
        """
        # load the config since we need it for this test
        click_ctx.obj.load_config(initialize=True)
        # set the loop interval to 0.1
        click_ctx.obj.config.daemon.reconciler.interval = 0.1
        # we replace reconcile_all with a stub lambda that just waits for an event.
        # this allows us to control each iteration of the loop.
        wait_event = threading.Event()
        mocked_reconcile_all = mocker.patch(
            "certwrangler.daemon.reconcile_all", side_effect=lambda x: wait_event.wait()
        )
        thread = ReconcilerThread()
        thread.start()
        assert thread.is_alive()
        mocked_reconcile_all.assert_called_once_with(click_ctx.obj.config)
        # now cycle the wait event a couple of times to ensure we're looping as expected
        wait_event.set()
        wait_event.clear()
        time.sleep(0.2)
        wait_event.set()
        wait_event.clear()
        time.sleep(0.2)
        assert mocked_reconcile_all.call_count == 3
        thread.graceful_stop()
        wait_event.set()
        thread.join()
        assert not thread.is_alive()


class TestDaemon:
    """
    Tests for Daemon.
    """

    def test___init__(self, click_ctx):
        """
        Check that the Daemon initializes as expected.
        """
        daemon = Daemon()
        assert daemon.ctx == click_ctx
        assert daemon.threads == []
        assert isinstance(daemon.stopping, threading.Event)
        assert isinstance(daemon.reloading, type(threading.Lock()))

    def test__create_threads(self, click_ctx):
        """
        Test that we properly create new threads when we don't have any
        and raise an exception if we already have threads.
        """
        daemon = Daemon()
        assert daemon.threads == []
        daemon._create_threads()
        assert len(daemon.threads) == 2
        assert any([isinstance(x, WebServerThread) for x in daemon.threads])
        assert any([isinstance(x, ReconcilerThread) for x in daemon.threads])
        # Make sure we throw an error if the threads already exist.
        with pytest.raises(DaemonError, match="Threads already exist"):
            daemon._create_threads()

    def test__start_threads(self, click_ctx, caplog):
        """
        Test that we're able to start managed threads.
        """
        caplog.set_level(logging.INFO)

        class TestThread(ThreadWithContext):
            def _run(self):
                self.graceful_stop_event.wait()

        daemon = Daemon()
        daemon.threads = [
            TestThread(daemon=True, name="test_thread_1"),
            TestThread(daemon=True, name="test_thread_2"),
        ]
        daemon._start_threads()
        assert "Starting test_thread_1 thread..." in caplog.text
        assert "Starting test_thread_2 thread..." in caplog.text
        for thread in daemon.threads:
            assert thread.is_alive()
            thread.graceful_stop()
            thread.join()

    def test__stop_threads(self, click_ctx, caplog):
        """
        Test that we're able to stop managed threads.
        """
        caplog.set_level(logging.INFO)

        class TestThread(ThreadWithContext):
            def _run(self):
                self.graceful_stop_event.wait()
                # sleep to simulate shutdown events
                time.sleep(0.5)

        daemon = Daemon()
        daemon.threads = [
            TestThread(daemon=True, name="test_thread_1"),
            TestThread(daemon=True, name="test_thread_2"),
        ]
        daemon._start_threads()
        for thread in daemon.threads:
            assert thread.is_alive()
        daemon._stop_threads()
        assert "Thread test_thread_1 stopped." in caplog.text
        assert "Thread test_thread_2 stopped." in caplog.text
        assert daemon.threads == []

    def test__reload_handler(self, click_ctx, caplog, mocker):
        """
        Test that the reload handler properly fires off the reload tasks.
        """
        caplog.set_level(logging.INFO)

        daemon = Daemon()
        # Mock everything out
        daemon._create_threads = mocker.MagicMock()
        daemon._start_threads = mocker.MagicMock()
        daemon._stop_threads = mocker.MagicMock()
        daemon.ctx.obj.load_config = mocker.MagicMock()
        # Now reload and ensure everything was called
        daemon._reload_handler(1, None)
        daemon._stop_threads.assert_called_once()
        daemon.ctx.obj.load_config.assert_called_once_with(initialize=True)
        daemon._create_threads.assert_called_once()
        daemon._start_threads.assert_called_once()
        assert "Caught SIGHUP, stopping threads to reload config." in caplog.text

    def test__reload_handler_reloading(self, click_ctx, caplog):
        """
        Test that we don't do anything if the reload lock is already held.
        """
        caplog.set_level(logging.INFO)
        daemon = Daemon()
        with daemon.reloading:
            daemon._reload_handler(1, None)
        assert not caplog.text
        assert daemon.threads == []

    def test__stop_handler(self, click_ctx, caplog):
        """
        Test that the stop handler sets the stop flag.
        """
        caplog.set_level(logging.INFO)
        daemon = Daemon()
        assert not daemon.stopping.is_set()
        daemon._stop_handler(15, None)
        assert "Caught SIGTERM, gracefully stopping daemon..." in caplog.text
        assert daemon.stopping.is_set()

    def test__stop_handler_stopping(self, click_ctx, caplog, mocker):
        """
        Test that issuing a stop while we're already stopping just quits.
        """
        caplog.set_level(logging.INFO)
        mocked_sys_exit = mocker.patch("certwrangler.daemon.sys.exit")
        daemon = Daemon()
        daemon.stopping.set()
        daemon._stop_handler(15, None)
        assert "Caught SIGTERM while stopping, forcefully quitting." in caplog.text
        mocked_sys_exit.assert_called_once()

    def test_run(self, click_ctx, caplog, mocker):
        """
        Test that running the daemon properly sets up all the threads and
        all the signal handlers.
        """
        caplog.set_level(logging.INFO)
        mocked_signal = mocker.patch("certwrangler.daemon.signal.signal")
        daemon = Daemon()
        # set to stopping so we don't get stuck in an endless loop
        daemon.stopping.set()
        daemon._create_threads = mocker.MagicMock()
        daemon._start_threads = mocker.MagicMock()
        daemon._stop_threads = mocker.MagicMock()

        mocked_thread = mocker.MagicMock()
        mocked_thread.name = "dummy"
        mocked_thread.is_alive = mocker.MagicMock(return_value=True)

        daemon.threads = [mocked_thread]

        daemon.run()

        daemon._create_threads.assert_called_once()
        daemon._start_threads.assert_called_once()
        daemon._stop_threads.assert_called_once()

        assert mocked_signal.call_args_list == [
            mocker.call(signal.SIGHUP, daemon._reload_handler),
            mocker.call(signal.SIGTERM, daemon._stop_handler),
            mocker.call(signal.SIGINT, daemon._stop_handler),
        ]

    def test_run_thread_died(self, click_ctx, caplog, mocker):
        """
        Test that we raise a DaemonError when a thread dies unexpectedly.
        """
        caplog.set_level(logging.INFO)
        mocker.patch("certwrangler.daemon.signal.signal")
        daemon = Daemon()
        daemon._create_threads = mocker.MagicMock()
        daemon._start_threads = mocker.MagicMock()
        daemon._stop_threads = mocker.MagicMock()

        mocked_thread = mocker.MagicMock()
        mocked_thread.name = "dummy"
        mocked_thread.is_alive = mocker.MagicMock(return_value=False)

        daemon.threads = [mocked_thread]

        with pytest.raises(DaemonError, match="dummy thread died"):
            daemon.run()
