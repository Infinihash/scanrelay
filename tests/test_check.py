import httpx

from scanrelay.check import explain, run

ENV = {"SCANRELAY_TENANT_ID": "t", "SCANRELAY_CLIENT_ID": "c",
       "SCANRELAY_CLIENT_SECRET": "supersecret", "SCANRELAY_SENDER": "scans@contoso.com"}


def client(token_status=200, send_status=202, send_body=""):
    calls = []

    def h(req):
        calls.append(req)
        if req.url.path.endswith("/token"):
            if token_status != 200:
                return httpx.Response(token_status, text='{"error_description":"AADSTS7000215: Invalid client secret"}')
            return httpx.Response(200, json={"access_token": "T", "expires_in": 3600})
        return httpx.Response(send_status, text=send_body)
    return httpx.Client(transport=httpx.MockTransport(h)), calls


def test_missing_settings():
    lines = []
    assert run({}, out=lines.append) == 2 and "SCANRELAY_SENDER" in lines[0]


def test_token_only_sends_nothing():
    c, calls = client()
    lines = []
    assert run(ENV, client=c, out=lines.append) == 0
    assert len(calls) == 1 and "SKIP" in lines[-1]


def test_bad_secret_explained_and_not_printed():
    c, _ = client(token_status=401)
    lines = []
    assert run(ENV, client=c, out=lines.append) == 1
    text = "\n".join(lines)
    assert "Secret ID" in text and "supersecret" not in text


def test_send_access_denied_explained():
    c, calls = client(send_status=403, send_body='{"error":{"code":"ErrorAccessDenied"}}')
    lines = []
    assert run(ENV, send_to="me@contoso.com", client=c, out=lines.append) == 1
    assert "RBAC" in lines[-1]
    assert calls[-1].url.path == "/v1.0/users/scans@contoso.com/sendMail"


def test_send_ok():
    c, _ = client()
    lines = []
    assert run(ENV, send_to="me@contoso.com", client=c, out=lines.append) == 0
    assert lines[-1].startswith("OK")


def test_explain_unknown():
    assert "Unrecognised" in explain("weird")
