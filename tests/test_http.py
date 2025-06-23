import pytest

from certwrangler.http import create_http_server, status


def test_create_http_server(config):
    server = create_http_server()
    assert server.config.host == str(config.daemon.http.host)
    assert server.config.app.routes[0].path == "/"
    assert server.config.app.routes[1].path == "/metrics"


@pytest.mark.asyncio
async def test_status(click_ctx, mocker):
    mock_request = mocker.MagicMock()
    mock_request.app.state.ctx_obj = click_ctx.obj
    mock_thread_1 = mocker.MagicMock()
    mock_thread_1.is_alive = mocker.MagicMock(return_value=True)
    mock_thread_1.name = "test_thread_1"
    mock_thread_2 = mocker.MagicMock()
    mock_thread_2.is_alive = mocker.MagicMock(return_value=True)
    mock_thread_2.name = "test_thread_2"
    click_ctx.obj.daemon.threads = [mock_thread_1, mock_thread_2]
    response = await status(mock_request)
    assert response.status_code == 200
    assert response.body == b'{"test_thread_1":true,"test_thread_2":true}'
