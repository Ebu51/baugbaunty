import json

from baugbaunty import mcp_server as mcp


def test_tool_scope_check():
    out = mcp.tool_scope_check({
        "include": ["*.acme.com"], "exclude": ["secret.acme.com"],
        "assets": ["www.acme.com", "secret.acme.com", "evil.org"],
    })
    assert "IN_SCOPE" in out and "www.acme.com" in out
    assert "OUT_OF_SCOPE" in out and "secret.acme.com" in out
    assert "NOT_LISTED" in out and "evil.org" in out


def test_tool_import_scope_list():
    out = json.loads(mcp.tool_import_scope({
        "platform": "list", "text": "*.foo.com\n!internal.foo.com\n",
    }))
    assert out["include"] == ["*.foo.com"]
    assert out["exclude"] == ["internal.foo.com"]


def test_tool_import_scope_writes_config(tmp_path):
    cfg_path = tmp_path / "p.json"
    out = json.loads(mcp.tool_import_scope({
        "platform": "list", "text": "*.bar.com\n", "name": "bar", "output": str(cfg_path),
    }))
    assert out["written_config"] == str(cfg_path)
    cfg = json.loads(cfg_path.read_text())
    assert cfg["scope"]["include"] == ["*.bar.com"]
    assert cfg["program"]["authorized"] is False


def test_tool_tools_status():
    out = json.loads(mcp.tool_tools_status({}))
    assert "nuclei" in out and isinstance(out["nuclei"], bool)


def test_tools_registry_complete():
    for name in ("scope_check", "import_scope", "tools_status", "summary",
                 "list_findings", "list_assets", "generate_report", "read_report",
                 "generate_submission", "run"):
        assert name in mcp.TOOLS
        assert "handler" in mcp.TOOLS[name]
        assert mcp.TOOLS[name]["schema"]["type"] == "object"


def test_handle_initialize_and_tools_list(monkeypatch):
    sent = []
    monkeypatch.setattr(mcp, "_send", lambda m: sent.append(m))

    mcp._handle({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    mcp._handle({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})

    assert sent[0]["result"]["serverInfo"]["name"] == "baugbaunty"
    names = {t["name"] for t in sent[1]["result"]["tools"]}
    assert "run" in names and "scope_check" in names


def test_handle_unknown_tool_is_tool_error(monkeypatch):
    sent = []
    monkeypatch.setattr(mcp, "_send", lambda m: sent.append(m))
    mcp._handle({"jsonrpc": "2.0", "id": 5, "method": "tools/call",
                 "params": {"name": "does_not_exist", "arguments": {}}})
    assert "error" in sent[0]  # unknown tool -> JSON-RPC error


def test_handle_notification_no_response(monkeypatch):
    sent = []
    monkeypatch.setattr(mcp, "_send", lambda m: sent.append(m))
    mcp._handle({"jsonrpc": "2.0", "method": "notifications/initialized"})
    assert sent == []  # notifications get no reply
