from cimcheck import (
    get_model, check_event, check_events,
    find_alias, suggest_fieldaliases, render_props_conf,
)


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


def test_change_model():
    change = get_model("Change")
    assert change is not None
    ok = {"action": "updated", "dvc": "host01", "object": "firewall_rule", "status": "success"}
    # required + valid enums satisfied -> compliant (only LOW missing-recommended may remain)
    assert all(f.severity != "high" for f in check_event(ok, change))
    assert "invalid-value" not in rules(check_event(ok, change))
    bad = {"action": "modified", "dvc": "host01"}   # missing object + invalid action value
    r = rules(check_event(bad, change))
    assert "missing-required" in r and "invalid-value" in r


def test_alias_detected_for_missing_required():
    # `user` is missing under the CIM name, but `username` is present
    ev = {"action": "success", "username": "alice", "src": "1.1.1.1"}
    findings = check_event(ev, AUTH)
    aliased = [f for f in findings if f.rule == "field-aliased" and f.field == "user"]
    assert aliased and aliased[0].severity == "high"
    assert "username" in aliased[0].message and "FIELDALIAS" in aliased[0].message
    # the generic missing-required is *replaced* by the more actionable alias finding
    assert "missing-required" not in rules(findings)


def test_no_alias_falls_back_to_missing_required():
    ev = {"action": "success", "src": "1.1.1.1"}   # user absent, no alias either
    r = rules(check_event(ev, AUTH))
    assert "missing-required" in r and "field-aliased" not in r


def test_find_alias_returns_source_field():
    ev = {"src_ip": "1.1.1.1"}
    assert find_alias(ev, get_model("Web"), "src") == "src_ip"
    assert find_alias(ev, get_model("Web"), "dest") is None


def test_suggest_fieldaliases_votes_most_common():
    events = [
        {"action": "success", "username": "a", "src_ip": "1.1.1.1"},
        {"action": "success", "username": "b", "srcip": "2.2.2.2"},
        {"action": "success", "username": "c", "src_ip": "3.3.3.3"},
    ]
    sug = suggest_fieldaliases(events, AUTH)
    assert sug["user"] == "username"
    assert sug["src"] == "src_ip"          # 2 votes beats srcip's 1


def test_render_props_conf():
    conf = render_props_conf("my:sourcetype", {"user": "username", "src": "src_ip"})
    assert "[my:sourcetype]" in conf
    assert "FIELDALIAS-cim_user = username AS user" in conf
    assert "FIELDALIAS-cim_src = src_ip AS src" in conf


def test_render_props_conf_empty():
    conf = render_props_conf("clean:st", {})
    assert "[clean:st]" in conf and "No field aliases needed" in conf
