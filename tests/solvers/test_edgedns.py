import pytest
import requests
from akamai.edgegrid import EdgeGridAuth
from importlib_metadata import entry_points
from pydantic import ValidationError

from certwrangler.exceptions import SolverError
from certwrangler.solvers.edgedns import ENDPOINT_PATTERN, EdgeDNSSolver


class TestEdgeDNSSolver:
    """
    Tests for the EdgeDNSSolver.
    """

    def test_plugin(self):
        """
        Test we correctly see the EdgeDNSSolver plugin.
        """
        (plugin,) = entry_points(group="certwrangler.solver", name="edgedns")
        assert plugin.load() == EdgeDNSSolver

    def test_ENDPOINT_PATTERN(self):
        """
        Test that the endpoint pattern renders as expected.
        """
        assert (
            ENDPOINT_PATTERN.format(
                host="dummyapi.example.com",
                domain="example.com",
                name="_acme-challenge",
            )
            == "https://dummyapi.example.com/config-dns/v2/zones/example.com/names/_acme-challenge.example.com/types/TXT"
        )

    def test_config_invalid_host(self, click_ctx, solver_edgedns_config):
        """
        Test that a malformed host key throw a ValidationError.
        """
        bad_config = solver_edgedns_config.copy()
        bad_config["host"] = "123_not_a_domain!"
        with pytest.raises(
            ValidationError,
            match="1 validation error for EdgeDNSSolver\nhost\n  String should match pattern",
        ):
            EdgeDNSSolver(**bad_config)

    @pytest.mark.parametrize(
        "missing",
        [
            "host",
            "client_token",
            "client_secret",
            "access_token",
        ],
    )
    def test_config_missing(self, click_ctx, missing, solver_edgedns_config):
        """
        Test that missing required config keys throw a ValidationError.
        """
        bad_config = solver_edgedns_config.copy()
        bad_config.pop(missing)
        with pytest.raises(
            ValidationError,
            match=f"1 validation error for EdgeDNSSolver\n{missing}\n  Field required",
        ):
            EdgeDNSSolver(**bad_config)

    def test_initialize(self, click_ctx, solver_edgedns_config):
        """
        Test that we're able to initialize EdgeDNSSolver with good config.
        """
        solver = EdgeDNSSolver(**solver_edgedns_config)
        assert isinstance(solver._session, requests.Session)
        assert solver._session.auth is None
        solver.initialize()
        assert isinstance(solver._session.auth, EdgeGridAuth)

    def test_create_new(self, click_ctx, solver_edgedns, requests_mock):
        """
        Test that we can create a new record when no TXT record exists.
        """
        solver_edgedns.initialize()
        kwargs = {
            "domain": "example.com",
            "name": "_acme-challenge",
            "content": "test content",
        }
        endpoint = ENDPOINT_PATTERN.format(host=solver_edgedns.host, **kwargs)

        def _post_callback(request, context):
            assert request.json() == {
                "name": "{name}.{domain}".format(**kwargs),
                "type": "TXT",
                "ttl": 300,
                "rdata": [kwargs["content"]],
            }
            return {"test": True}

        requests_mock.get(endpoint, status_code=404)
        requests_mock.post(endpoint, status_code=201, json=_post_callback)
        solver_edgedns.create(**kwargs)
        assert len(requests_mock.request_history) == 2
        assert requests_mock.request_history[0].method == "GET"
        assert requests_mock.request_history[1].method == "POST"

    def test_create_update(self, click_ctx, solver_edgedns, requests_mock):
        """
        Test that we can update an existing TXT record when one already exists.
        """
        solver_edgedns.initialize()
        kwargs = {
            "domain": "example.com",
            "name": "_acme-challenge",
            "content": "test content",
        }
        endpoint = ENDPOINT_PATTERN.format(host=solver_edgedns.host, **kwargs)

        def _put_callback(request, context):
            assert request.json() == {
                "name": "{name}.{domain}".format(**kwargs),
                "type": "TXT",
                "ttl": 300,
                "rdata": ["legit record", kwargs["content"]],
            }
            return request.json()

        requests_mock.get(
            endpoint,
            status_code=200,
            json={
                "name": "{name}.{domain}".format(**kwargs),
                "type": "TXT",
                "ttl": 300,
                "rdata": ["legit record"],
            },
        )
        requests_mock.put(endpoint, status_code=200, json=_put_callback)
        solver_edgedns.create(**kwargs)
        assert len(requests_mock.request_history) == 2
        assert requests_mock.request_history[0].method == "GET"
        assert requests_mock.request_history[1].method == "PUT"

    def test_create_existing(self, click_ctx, solver_edgedns, requests_mock):
        """
        Test that we don't take action when a TXT record is already in place.
        """
        solver_edgedns.initialize()
        kwargs = {
            "domain": "example.com",
            "name": "_acme-challenge",
            "content": "test content",
        }
        endpoint = ENDPOINT_PATTERN.format(host=solver_edgedns.host, **kwargs)

        requests_mock.get(
            endpoint,
            status_code=200,
            json={
                "name": "{name}.{domain}".format(**kwargs),
                "type": "TXT",
                "ttl": 300,
                "rdata": ["other", kwargs["content"]],
            },
        )
        solver_edgedns.create(**kwargs)
        assert len(requests_mock.request_history) == 1
        assert requests_mock.request_history[0].method == "GET"

    def test_create_bad_response(self, click_ctx, solver_edgedns, requests_mock):
        """
        Test that we throw an exception if we get a bogus response on create.
        """
        solver_edgedns.initialize()
        kwargs = {
            "domain": "example.com",
            "name": "_acme-challenge",
            "content": "test content",
        }
        endpoint = ENDPOINT_PATTERN.format(host=solver_edgedns.host, **kwargs)

        requests_mock.get(
            endpoint,
            status_code=200,
            json={
                "name": "{name}.{domain}".format(**kwargs),
                "type": "TXT",
                "ttl": 300,
                "rdata": "bad data",
            },
        )
        with pytest.raises(
            SolverError, match="Expected 'rdata' in response to be a list, got str."
        ):
            solver_edgedns.create(**kwargs)

    def test_delete_last_item(self, click_ctx, solver_edgedns, requests_mock):
        """
        Test that we completely delete the TXT record if we remove the last entry.
        """
        solver_edgedns.initialize()
        kwargs = {
            "domain": "example.com",
            "name": "_acme-challenge",
            "content": "test content",
        }
        endpoint = ENDPOINT_PATTERN.format(host=solver_edgedns.host, **kwargs)

        requests_mock.get(
            endpoint,
            status_code=200,
            json={
                "name": "{name}.{domain}".format(**kwargs),
                "type": "TXT",
                "ttl": 300,
                "rdata": [kwargs["content"]],
            },
        )
        requests_mock.delete(endpoint, status_code=204)
        solver_edgedns.delete(**kwargs)
        assert len(requests_mock.request_history) == 2
        assert requests_mock.request_history[0].method == "GET"
        assert requests_mock.request_history[1].method == "DELETE"

    def test_delete_update(self, click_ctx, solver_edgedns, requests_mock):
        """
        Test that we only delete a single entry from a TXT record with multiple entries.
        """
        solver_edgedns.initialize()
        kwargs = {
            "domain": "example.com",
            "name": "_acme-challenge",
            "content": "test content",
        }
        endpoint = ENDPOINT_PATTERN.format(host=solver_edgedns.host, **kwargs)

        def _put_callback(request, context):
            assert request.json() == {
                "name": "{name}.{domain}".format(**kwargs),
                "type": "TXT",
                "ttl": 300,
                "rdata": ["legit record"],
            }
            return request.json()

        requests_mock.get(
            endpoint,
            status_code=200,
            json={
                "name": "{name}.{domain}".format(**kwargs),
                "type": "TXT",
                "ttl": 300,
                "rdata": ["legit record", kwargs["content"]],
            },
        )
        requests_mock.put(endpoint, status_code=200, json=_put_callback)
        solver_edgedns.delete(**kwargs)
        assert len(requests_mock.request_history) == 2
        assert requests_mock.request_history[0].method == "GET"
        assert requests_mock.request_history[1].method == "PUT"

    def test_delete_no_record(self, click_ctx, solver_edgedns, requests_mock):
        """
        Test that we don't take action when a TXT record is already deleted.
        """
        solver_edgedns.initialize()
        kwargs = {
            "domain": "example.com",
            "name": "_acme-challenge",
            "content": "test content",
        }
        endpoint = ENDPOINT_PATTERN.format(host=solver_edgedns.host, **kwargs)

        requests_mock.get(endpoint, status_code=404)
        solver_edgedns.delete(**kwargs)
        assert len(requests_mock.request_history) == 1
        assert requests_mock.request_history[0].method == "GET"

    def test_delete_no_content(self, click_ctx, solver_edgedns, requests_mock):
        """
        Test that we don't take action when a TXT doesn't have the content to be removed.
        """
        solver_edgedns.initialize()
        kwargs = {
            "domain": "example.com",
            "name": "_acme-challenge",
            "content": "test content",
        }
        endpoint = ENDPOINT_PATTERN.format(host=solver_edgedns.host, **kwargs)

        requests_mock.get(
            endpoint,
            status_code=200,
            json={
                "name": "{name}.{domain}".format(**kwargs),
                "type": "TXT",
                "ttl": 300,
                "rdata": ["legit record"],
            },
        )
        solver_edgedns.delete(**kwargs)
        assert len(requests_mock.request_history) == 1
        assert requests_mock.request_history[0].method == "GET"

    def test_delete_bad_response(self, click_ctx, solver_edgedns, requests_mock):
        """
        Test that we throw an exception if we get a bogus response on delete.
        """
        solver_edgedns.initialize()
        kwargs = {
            "domain": "example.com",
            "name": "_acme-challenge",
            "content": "test content",
        }
        endpoint = ENDPOINT_PATTERN.format(host=solver_edgedns.host, **kwargs)

        requests_mock.get(
            endpoint,
            status_code=200,
            json={
                "name": "{name}.{domain}".format(**kwargs),
                "type": "TXT",
                "ttl": 300,
                "rdata": "bad data",
            },
        )
        with pytest.raises(
            SolverError, match="Expected 'rdata' in response to be a list, got str."
        ):
            solver_edgedns.delete(**kwargs)

    def test__cleanup_response(self, click_ctx, solver_edgedns):
        """
        Test that we strip away extra double quotes in the response data.
        """
        response = {
            "name": "_acme-challenge.example.com",
            "type": "TXT",
            "ttl": 300,
            "rdata": ["test", '"test"', '"test', 'test"', '""test""'],
        }
        response = solver_edgedns._cleanup_response(response)
        assert response["rdata"][0] == "test"
        assert response["rdata"][1] == "test"
        assert response["rdata"][2] == '"test'
        assert response["rdata"][3] == 'test"'
        assert response["rdata"][4] == '"test"'

    def test__delete(self, click_ctx, solver_edgedns, requests_mock):
        """
        Test that we can issue a well-formed DELETE.
        """
        solver_edgedns.initialize()
        endpoint = ENDPOINT_PATTERN.format(
            host=solver_edgedns.host, domain="example.com", name="_acme-challenge"
        )

        # test that 404 and 403 raise exceptions
        requests_mock.delete(endpoint, status_code=404)
        with pytest.raises(SolverError):
            solver_edgedns._delete(endpoint)
        assert len(requests_mock.request_history) == 1
        requests_mock.reset_mock()

        requests_mock.delete(endpoint, status_code=403)
        with pytest.raises(SolverError):
            solver_edgedns._delete(endpoint)
        assert len(requests_mock.request_history) == 1
        requests_mock.reset_mock()

        # test that we can issue a delete to the endpoint
        def _delete_callback(request, context):
            assert request.url == endpoint
            assert request.method == "DELETE"
            assert "client_token=kinda_secret;" in request.headers["Authorization"]
            assert (
                "access_token=just a token trying to live its best life;"
                in request.headers["Authorization"]
            )
            return "ok"

        requests_mock.delete(endpoint, status_code=204, text=_delete_callback)
        assert solver_edgedns._delete(endpoint) == b"ok"
        assert len(requests_mock.request_history) == 1

    def test__get(self, click_ctx, solver_edgedns, requests_mock):
        """
        Test that we can issue a well-formed GET.
        """
        solver_edgedns.initialize()
        endpoint = ENDPOINT_PATTERN.format(
            host=solver_edgedns.host, domain="example.com", name="_acme-challenge"
        )

        # test that 404 returns None
        requests_mock.get(endpoint, status_code=404)
        assert solver_edgedns._get(endpoint) is None
        assert len(requests_mock.request_history) == 1
        requests_mock.reset_mock()

        # test that 403 raises an exception
        requests_mock.get(endpoint, status_code=403)
        with pytest.raises(SolverError):
            solver_edgedns._get(endpoint)
        assert len(requests_mock.request_history) == 1
        requests_mock.reset_mock()

        # test that the headers are set correctly and we return json as expected
        def _get_callback(request, context):
            assert request.url == endpoint
            assert request.method == "GET"
            assert "client_token=kinda_secret;" in request.headers["Authorization"]
            assert (
                "access_token=just a token trying to live its best life;"
                in request.headers["Authorization"]
            )
            assert request.headers["Accept"] == "application/json"
            assert request.headers["Content-Type"] == "application/json"
            return '{"test": true}'

        requests_mock.get(endpoint, status_code=200, text=_get_callback)
        assert solver_edgedns._get(endpoint) == {"test": True}
        assert len(requests_mock.request_history) == 1

    def test__post(self, click_ctx, solver_edgedns, requests_mock):
        """
        Test that we can issue a well-formed POST.
        """
        solver_edgedns.initialize()
        endpoint = ENDPOINT_PATTERN.format(
            host=solver_edgedns.host, domain="example.com", name="_acme-challenge"
        )

        # test that 403 raises an exception
        requests_mock.post(endpoint, status_code=403)
        with pytest.raises(SolverError):
            solver_edgedns._post(endpoint, {})
        assert len(requests_mock.request_history) == 1
        requests_mock.reset_mock()

        # test that the headers are set correctly and we return json as expected
        def _post_callback(request: requests.Request, context):
            assert request.url == endpoint
            assert request.method == "POST"
            assert "client_token=kinda_secret;" in request.headers["Authorization"]
            assert (
                "access_token=just a token trying to live its best life;"
                in request.headers["Authorization"]
            )
            assert request.headers["Accept"] == "application/json"
            assert request.headers["Content-Type"] == "application/json"
            assert request.json() == {"dns": "please make"}
            return '{"dns": "sure"}'

        requests_mock.post(endpoint, status_code=201, text=_post_callback)
        assert solver_edgedns._post(endpoint, {"dns": "please make"}) == {"dns": "sure"}
        assert len(requests_mock.request_history) == 1

    def test__put(self, click_ctx, solver_edgedns, requests_mock):
        """
        Test that we can issue a well-formed PUT.
        """
        solver_edgedns.initialize()
        endpoint = ENDPOINT_PATTERN.format(
            host=solver_edgedns.host, domain="example.com", name="_acme-challenge"
        )

        # test that 403 raises an exception
        requests_mock.put(endpoint, status_code=403)
        with pytest.raises(SolverError):
            solver_edgedns._put(endpoint, {})
        assert len(requests_mock.request_history) == 1
        requests_mock.reset_mock()

        # test that the headers are set correctly and we return json as expected
        def _put_callback(request: requests.Request, context):
            assert request.url == endpoint
            assert request.method == "PUT"
            assert "client_token=kinda_secret;" in request.headers["Authorization"]
            assert (
                "access_token=just a token trying to live its best life;"
                in request.headers["Authorization"]
            )
            assert request.headers["Accept"] == "application/json"
            assert request.headers["Content-Type"] == "application/json"
            assert request.json() == {"new_key": "done"}
            return '{"dns": "sure", "new_key": "done"}'

        requests_mock.put(endpoint, status_code=200, text=_put_callback)
        assert solver_edgedns._put(endpoint, {"new_key": "done"}) == {
            "dns": "sure",
            "new_key": "done",
        }
        assert len(requests_mock.request_history) == 1
