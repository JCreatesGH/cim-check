import json
from cimcheck.cli import main


def _events(tmp_path, evs):
    f = tmp_path / "events.json"
    f.write_text(json.dumps(evs))
    return str(f)


def test_cli_report_and_min_compliance(tmp_path, capsys):
    path = _events(tmp_path, [
        {"action": "success", "user": "a", "src": "1.1.1.1"},   # compliant
        {"action": "failure", "user": "b"},                      # missing src
    ])
    code = main(["Authentication", path, "--min-compliance", "75"])
    out = capsys.readouterr().out
    assert code == 1                              # 50% < 75%
    assert "compliance:" in out and "missing-required" in out


def test_cli_json(tmp_path, capsys):
    path = _events(tmp_path, [{"action": "success", "user": "a", "src": "1.1.1.1"}])
    assert main(["Authentication", path, "--json"]) == 0
    rep = json.loads(capsys.readouterr().out)
    assert rep["model"] == "Authentication" and rep["compliance_pct"] == 100.0


def test_cli_list_models(capsys):
    assert main(["--list-models"]) == 0
    out = capsys.readouterr().out
    assert "Authentication" in out and "Change" in out


def test_cli_unknown_model(tmp_path, capsys):
    path = _events(tmp_path, [])
    assert main(["Nope", path]) == 2
    assert "unknown model" in capsys.readouterr().err


def test_cli_accepts_result_wrapper(tmp_path, capsys):
    rows = [{"action": "success", "user": "a", "src": "1.1.1.1"}]
    f = tmp_path / "w.json"
    f.write_text(json.dumps({"result": rows}))
    assert main(["Authentication", str(f)]) == 0
