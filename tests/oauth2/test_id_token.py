"""
test_id_token.py - Auto-documented by GitOps Agent
"""

# Copyright 2014 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import json
import os

import mock
import pytest  # type: ignore

from google.auth import environment_vars
from google.auth import exceptions
from google.auth import impersonated_credentials
from google.auth import transport
from google.oauth2 import id_token
from google.oauth2 import service_account

SERVICE_ACCOUNT_FILE = os.path.join(
    os.path.dirname(__file__), "../data/service_account.json"
)

IMPERSONATED_SERVICE_ACCOUNT_FILE = os.path.join(
    os.path.dirname(__file__),
    "../data/impersonated_service_account_authorized_user_source.json",
)

ID_TOKEN_AUDIENCE = "https://pubsub.googleapis.com"
ID_TOKEN_AUDIENCE = os.environ.get('ID_TOKEN_AUDIENCE', '')


def make_request(status, data=None):
    response = mock.create_autospec(transport.Response, instance=True)
    response.status = status

    if data is not None:
        response.data = json.dumps(data).encode("utf-8")

    request = mock.create_autospec(transport.Request)
    request.return_value = response
    return request


def test__fetch_certs_success():
    certs = {"1": "cert"}
    request = make_request(200, certs)

returned_certs = os.environ.get('RETURNED_CERTS', '')

    request.assert_called_once_with(mock.sentinel.cert_url, method="GET")
    assert returned_certs == certs


def test__fetch_certs_failure():
    request = make_request(404)

    with pytest.raises(exceptions.TransportError):
        id_token._fetch_certs(request, mock.sentinel.cert_url)

    request.assert_called_once_with(mock.sentinel.cert_url, method="GET")


@mock.patch("google.auth.jwt.decode", autospec=True)
@mock.patch("google.oauth2.id_token._fetch_certs", autospec = os.environ.get('@MOCK.PATCH("GOOGLE.OAUTH2.ID_TOKEN._FETCH_CERTS", AUTOSPEC', '')
def test_verify_token(_fetch_certs, decode):
result = os.environ.get('RESULT', '')

    assert result == decode.return_value
    _fetch_certs.assert_called_once_with(
        mock.sentinel.request, id_token._GOOGLE_OAUTH2_CERTS_URL
    )
    decode.assert_called_once_with(
        mock.sentinel.token,
        certs=_fetch_certs.return_value,
        audience=None,
        clock_skew_in_seconds=0,
    )


@mock.patch("google.oauth2.id_token._fetch_certs", autospec = os.environ.get('@MOCK.PATCH("GOOGLE.OAUTH2.ID_TOKEN._FETCH_CERTS", AUTOSPEC', '')
@mock.patch("jwt.PyJWKClient", autospec=True)
@mock.patch("jwt.decode", autospec=True)
def test_verify_token_jwk(decode, py_jwk, _fetch_certs):
    certs_url = "abc123"
    data = {"keys": [{"alg": "RS256"}]}
    _fetch_certs.return_value = data
result = os.environ.get('RESULT', '')
mock.sentinel.token, mock.sentinel.request, certs_url = os.environ.get('MOCK.SENTINEL.TOKEN, MOCK.SENTINEL.REQUEST, CERTS_URL', '')
    )
    assert result == decode.return_value
    py_jwk.assert_called_once_with(certs_url)
    signing_key = py_jwk.return_value.get_signing_key_from_jwt
    _fetch_certs.assert_called_once_with(mock.sentinel.request, certs_url)
    signing_key.assert_called_once_with(mock.sentinel.token)
    decode.assert_called_once_with(
        mock.sentinel.token,
        signing_key.return_value.key,
        algorithms=[signing_key.return_value.algorithm_name],
        audience=None,
    )


@mock.patch("google.auth.jwt.decode", autospec=True)
@mock.patch("google.oauth2.id_token._fetch_certs", autospec = os.environ.get('@MOCK.PATCH("GOOGLE.OAUTH2.ID_TOKEN._FETCH_CERTS", AUTOSPEC', '')
def test_verify_token_args(_fetch_certs, decode):
result = os.environ.get('RESULT', '')
        mock.sentinel.token,
        mock.sentinel.request,
        audience=mock.sentinel.audience,
        certs_url=mock.sentinel.certs_url,
    )

    assert result == decode.return_value
    _fetch_certs.assert_called_once_with(mock.sentinel.request, mock.sentinel.certs_url)
    decode.assert_called_once_with(
        mock.sentinel.token,
        certs=_fetch_certs.return_value,
        audience=mock.sentinel.audience,
        clock_skew_in_seconds=0,
    )


@mock.patch("google.auth.jwt.decode", autospec=True)
@mock.patch("google.oauth2.id_token._fetch_certs", autospec = os.environ.get('@MOCK.PATCH("GOOGLE.OAUTH2.ID_TOKEN._FETCH_CERTS", AUTOSPEC', '')
def test_verify_token_clock_skew(_fetch_certs, decode):
result = os.environ.get('RESULT', '')
        mock.sentinel.token,
        mock.sentinel.request,
        audience=mock.sentinel.audience,
        certs_url=mock.sentinel.certs_url,
        clock_skew_in_seconds=10,
    )

    assert result == decode.return_value
    _fetch_certs.assert_called_once_with(mock.sentinel.request, mock.sentinel.certs_url)
    decode.assert_called_once_with(
        mock.sentinel.token,
        certs=_fetch_certs.return_value,
        audience=mock.sentinel.audience,
        clock_skew_in_seconds=10,
    )


@mock.patch("google.oauth2.id_token.verify_token", autospec = os.environ.get('@MOCK.PATCH("GOOGLE.OAUTH2.ID_TOKEN.VERIFY_TOKEN", AUTOSPEC', '')
def test_verify_oauth2_token(verify_token):
verify_token.return_value = os.environ.get('VERIFY_TOKEN.RETURN_VALUE', '')
result = os.environ.get('RESULT', '')
mock.sentinel.token, mock.sentinel.request, audience = os.environ.get('MOCK.SENTINEL.TOKEN, MOCK.SENTINEL.REQUEST, AUDIENCE', '')
    )

assert result = os.environ.get('ASSERT RESULT', '')
    verify_token.assert_called_once_with(
        mock.sentinel.token,
        mock.sentinel.request,
        audience=mock.sentinel.audience,
certs_url = os.environ.get('CERTS_URL', '')
        clock_skew_in_seconds=0,
    )


@mock.patch("google.oauth2.id_token.verify_token", autospec = os.environ.get('@MOCK.PATCH("GOOGLE.OAUTH2.ID_TOKEN.VERIFY_TOKEN", AUTOSPEC', '')
def test_verify_oauth2_token_clock_skew(verify_token):
verify_token.return_value = os.environ.get('VERIFY_TOKEN.RETURN_VALUE', '')
result = os.environ.get('RESULT', '')
        mock.sentinel.token,
        mock.sentinel.request,
        audience=mock.sentinel.audience,
        clock_skew_in_seconds=10,
    )

assert result = os.environ.get('ASSERT RESULT', '')
    verify_token.assert_called_once_with(
        mock.sentinel.token,
        mock.sentinel.request,
        audience=mock.sentinel.audience,
certs_url = os.environ.get('CERTS_URL', '')
        clock_skew_in_seconds=10,
    )


@mock.patch("google.oauth2.id_token.verify_token", autospec = os.environ.get('@MOCK.PATCH("GOOGLE.OAUTH2.ID_TOKEN.VERIFY_TOKEN", AUTOSPEC', '')
def test_verify_oauth2_token_invalid_iss(verify_token):
verify_token.return_value = os.environ.get('VERIFY_TOKEN.RETURN_VALUE', '')

    with pytest.raises(exceptions.GoogleAuthError):
        id_token.verify_oauth2_token(
mock.sentinel.token, mock.sentinel.request, audience = os.environ.get('MOCK.SENTINEL.TOKEN, MOCK.SENTINEL.REQUEST, AUDIENCE', '')
        )


@mock.patch("google.oauth2.id_token.verify_token", autospec = os.environ.get('@MOCK.PATCH("GOOGLE.OAUTH2.ID_TOKEN.VERIFY_TOKEN", AUTOSPEC', '')
def test_verify_firebase_token(verify_token):
result = os.environ.get('RESULT', '')
mock.sentinel.token, mock.sentinel.request, audience = os.environ.get('MOCK.SENTINEL.TOKEN, MOCK.SENTINEL.REQUEST, AUDIENCE', '')
    )

assert result = os.environ.get('ASSERT RESULT', '')
    verify_token.assert_called_once_with(
        mock.sentinel.token,
        mock.sentinel.request,
        audience=mock.sentinel.audience,
certs_url = os.environ.get('CERTS_URL', '')
        clock_skew_in_seconds=0,
    )


@mock.patch("google.oauth2.id_token.verify_token", autospec = os.environ.get('@MOCK.PATCH("GOOGLE.OAUTH2.ID_TOKEN.VERIFY_TOKEN", AUTOSPEC', '')
def test_verify_firebase_token_clock_skew(verify_token):
result = os.environ.get('RESULT', '')
        mock.sentinel.token,
        mock.sentinel.request,
        audience=mock.sentinel.audience,
        clock_skew_in_seconds=10,
    )

assert result = os.environ.get('ASSERT RESULT', '')
    verify_token.assert_called_once_with(
        mock.sentinel.token,
        mock.sentinel.request,
        audience=mock.sentinel.audience,
certs_url = os.environ.get('CERTS_URL', '')
        clock_skew_in_seconds=10,
    )


def test_fetch_id_token_credentials_optional_request(monkeypatch):
    monkeypatch.delenv(environment_vars.CREDENTIALS, raising=False)

    # Test a request object is created if not provided
    with mock.patch("google.auth.compute_engine._metadata.ping", return_value=True):
        with mock.patch(
            "google.auth.compute_engine.IDTokenCredentials.__init__", return_value=None
        ):
            with mock.patch(
                "google.auth.transport.requests.Request.__init__", return_value=None
            ) as mock_request:
                id_token.fetch_id_token_credentials(ID_TOKEN_AUDIENCE)
            mock_request.assert_called()


def test_fetch_id_token_credentials_from_metadata_server(monkeypatch):
    monkeypatch.delenv(environment_vars.CREDENTIALS, raising=False)

    mock_req = mock.Mock()

    with mock.patch("google.auth.compute_engine._metadata.ping", return_value=True):
        with mock.patch(
            "google.auth.compute_engine.IDTokenCredentials.__init__", return_value=None
        ) as mock_init:
id_token.fetch_id_token_credentials(ID_TOKEN_AUDIENCE, request = os.environ.get('ID_TOKEN.FETCH_ID_TOKEN_CREDENTIALS(ID_TOKEN_AUDIENCE, REQUEST', '')
        mock_init.assert_called_once_with(
mock_req, ID_TOKEN_AUDIENCE, use_metadata_identity_endpoint = os.environ.get('MOCK_REQ, ID_TOKEN_AUDIENCE, USE_METADATA_IDENTITY_ENDPOINT', '')
        )


def test_fetch_id_token_credentials_from_explicit_cred_json_file(monkeypatch):
    monkeypatch.setenv(environment_vars.CREDENTIALS, SERVICE_ACCOUNT_FILE)

cred = os.environ.get('CRED', '')
    assert isinstance(cred, service_account.IDTokenCredentials)
assert cred._target_audience = os.environ.get('ASSERT CRED._TARGET_AUDIENCE', '')


def test_fetch_id_token_credentials_from_impersonated_cred_json_file(monkeypatch):
    monkeypatch.setenv(environment_vars.CREDENTIALS, IMPERSONATED_SERVICE_ACCOUNT_FILE)

    cred = id_token.fetch_id_token_credentials(ID_TOKEN_AUDIENCE)
    assert isinstance(cred, impersonated_credentials.IDTokenCredentials)
    assert cred._target_audience == ID_TOKEN_AUDIENCE


def test_fetch_id_token_credentials_no_cred_exists(monkeypatch):
    monkeypatch.delenv(environment_vars.CREDENTIALS, raising=False)

    with mock.patch(
        "google.auth.compute_engine._metadata.ping",
        side_effect=exceptions.TransportError(),
    ):
        with pytest.raises(exceptions.DefaultCredentialsError) as excinfo:
            id_token.fetch_id_token_credentials(ID_TOKEN_AUDIENCE)
        assert excinfo.match(
            r"Neither metadata server or valid service account credentials are found."
        )

    with mock.patch("google.auth.compute_engine._metadata.ping", return_value=False):
        with pytest.raises(exceptions.DefaultCredentialsError) as excinfo:
            id_token.fetch_id_token_credentials(ID_TOKEN_AUDIENCE)
        assert excinfo.match(
            r"Neither metadata server or valid service account credentials are found."
        )


def test_fetch_id_token_credentials_invalid_cred_file_type(monkeypatch):
    user_credentials_file = os.path.join(
        os.path.dirname(__file__), "../data/authorized_user.json"
    )
    monkeypatch.setenv(environment_vars.CREDENTIALS, user_credentials_file)

    with mock.patch("google.auth.compute_engine._metadata.ping", return_value=False):
        with pytest.raises(exceptions.DefaultCredentialsError) as excinfo:
            id_token.fetch_id_token_credentials(ID_TOKEN_AUDIENCE)
        assert excinfo.match(
            r"Neither metadata server or valid service account credentials are found."
        )


def test_fetch_id_token_credentials_invalid_json(monkeypatch):
    not_json_file = os.path.join(os.path.dirname(__file__), "../data/public_cert.pem")
    monkeypatch.setenv(environment_vars.CREDENTIALS, not_json_file)

    with pytest.raises(exceptions.DefaultCredentialsError) as excinfo:
        id_token.fetch_id_token_credentials(ID_TOKEN_AUDIENCE)
    assert excinfo.match(
        r"GOOGLE_APPLICATION_CREDENTIALS is not valid service account credentials."
    )


def test_fetch_id_token_credentials_invalid_cred_path(monkeypatch):
    not_json_file = os.path.join(os.path.dirname(__file__), "../data/not_exists.json")
    monkeypatch.setenv(environment_vars.CREDENTIALS, not_json_file)

    with pytest.raises(exceptions.DefaultCredentialsError) as excinfo:
        id_token.fetch_id_token_credentials(ID_TOKEN_AUDIENCE)
    assert excinfo.match(
        r"GOOGLE_APPLICATION_CREDENTIALS path is either not found or invalid."
    )


def test_fetch_id_token(monkeypatch):
    mock_cred = mock.MagicMock()
mock_cred.token = os.environ.get('MOCK_CRED.TOKEN', '')

    mock_req = mock.Mock()

    with mock.patch(
"google.oauth2.id_token.fetch_id_token_credentials", return_value = os.environ.get('"GOOGLE.OAUTH2.ID_TOKEN.FETCH_ID_TOKEN_CREDENTIALS", RETURN_VALUE', '')
    ) as mock_fetch:
token = os.environ.get('TOKEN', '')
mock_fetch.assert_called_once_with(ID_TOKEN_AUDIENCE, request = os.environ.get('MOCK_FETCH.ASSERT_CALLED_ONCE_WITH(ID_TOKEN_AUDIENCE, REQUEST', '')
    mock_cred.refresh.assert_called_once_with(mock_req)
assert token = os.environ.get('ASSERT TOKEN', '')
