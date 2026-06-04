from cimcheck import get_model, check_event, check_events


AUTH = get_model("Authentication")
WEB = get_model("Web")


def rules(findings):
    return {f.rule for f in findings}


def test_compliant_auth_event():
    ev = {"action": "success", "user": "alice", "src": "10.0.0.1", "dest": "10.0.0.2", "app": "ssh", "signature": "login"}
    assert check_event(ev, AUTH) == []


def test_missing_required():
    ev = {"action": "failure", "user": "bob"}   # no src
    r = rules(check_event(ev, AUTH))
    assert "missing-required" in r


def test_wrong_type_ip_and_number():
    ev = {"action": "success", "user": "x", "src": "not-an-ip"}
    assert "wrong-type" in rules(check_event(ev, AUTH))
    web = {"action": "allowed", "src": "1.1.1.1", "dest": "2.2.2.2", "http_method": "GET", "status": "abc"}
    assert "wrong-type" in rules(check_event(web, WEB))


def test_invalid_value():
    ev = {"action": "maybe", "user": "x", "src": "1.1.1.1"}
    assert "invalid-value" in rules(check_event(ev, AUTH))


def test_missing_recommended_is_low():
    ev = {"action": "success", "user": "x", "src": "1.1.1.1"}   # no dest/app/signature
    findings = check_event(ev, AUTH)
    assert any(f.rule == "missing-recommended" and f.severity == "low" for f in findings)


def test_compliance_report():
    events = [
        {"action": "success", "user": "a", "src": "1.1.1.1"},   # compliant (no high)
        {"action": "failure", "user": "b"},                      # missing src -> non-compliant
    ]
    rep = check_events(events, AUTH)
    assert rep.total == 2 and rep.compliant == 1
    assert rep.compliance_pct == 50.0
    assert rep.findings_by_rule["missing-required"] >= 1
