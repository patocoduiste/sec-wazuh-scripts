from src.log_parser import parse_auth_log


def test_parse_auth_log_sample():
    events = parse_auth_log("tests/samples/auth.log")
    assert len(events) == 2
    assert events[0]["ip"] == "192.168.56.10"
    assert "ts_event" in events[0]
