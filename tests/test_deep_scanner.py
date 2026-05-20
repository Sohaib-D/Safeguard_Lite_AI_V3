import pytest

from backend.network import deep_scanner


def test_compute_grade_values() -> None:
    assert deep_scanner.compute_grade(20) == "F"
    assert deep_scanner.compute_grade(95) == "A+"
    assert deep_scanner.compute_grade(89) == "A"
    assert deep_scanner.compute_grade(70) == "B"
    assert deep_scanner.compute_grade(60) == "C"
    assert deep_scanner.compute_grade(50) == "D"
    assert deep_scanner.compute_grade(40) == "E"


def test_module_error_does_not_expose_raw_exception() -> None:
    error = deep_scanner._module_error("http_headers", Exception("raw failure"))
    assert error["status"] == "error"
    assert error["module"] == "http_headers"
    assert error["reason"] == "Http Headers analysis could not be completed"
    assert error["findings"] == []


@pytest.mark.asyncio
async def test_dns_checks_skipped_for_ip_address() -> None:
    result = await deep_scanner.dns_scan("192.0.2.1", is_ip=True)
    assert result["status"] == "completed"
    assert result["spf"]["skipped"] is True
    assert result["dmarc"]["skipped"] is True
    assert result["findings"] == []


@pytest.mark.asyncio
async def test_spf_dmarc_missing_records_return_present_false(monkeypatch) -> None:
    def fake_resolve(domain: str, record_type: str):
        raise Exception("no answer")

    monkeypatch.setattr(deep_scanner.dns.resolver, "resolve", fake_resolve)

    spf = await deep_scanner.check_spf("example.com")
    dmarc = await deep_scanner.check_dmarc("example.com")

    assert spf["present"] is False
    assert spf.get("record") is None
    assert dmarc["present"] is False
    assert dmarc.get("record") is None
