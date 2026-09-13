"""The deployment gate must stop before uploads when Space settings are missing."""
import runpy
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "deploy_hf.py"


def run_check(monkeypatch, variables, secrets, *, check_only=True):
    api = SimpleNamespace(
        get_space_variables=lambda space: {k: SimpleNamespace(value=v) for k, v in variables.items()},
        get_space_secrets=lambda space: {k: SimpleNamespace(description="DO_NOT_LOG") for k in secrets},
    )
    monkeypatch.setitem(sys.modules, "huggingface_hub", SimpleNamespace(HfApi=lambda **kwargs: api))
    monkeypatch.setenv("HF_TOKEN", "TEST_TOKEN_DO_NOT_LOG")
    monkeypatch.delenv("JEP_REVISION", raising=False)
    monkeypatch.setattr(sys, "argv", [str(SCRIPT)] + (["--check-only"] if check_only else []))
    with pytest.raises(SystemExit) as result:
        runpy.run_path(str(SCRIPT), run_name="__main__")
    return result.value.code


@pytest.mark.parametrize("check_only", [True, False])
def test_production_flag_alone_does_not_allow_deployment(monkeypatch, capsys, check_only):
    result = run_check(monkeypatch, {"JEP_DEPLOYMENT_MODE": "production"}, [], check_only=check_only)
    assert all(name in result for name in ("JEP_DATABASE_URL", "JEP_SIGNING_TOKEN", "JEP_KEYRING_JSON"))
    assert "DO_NOT_LOG" not in capsys.readouterr().out


def test_keyring_check_is_read_only(monkeypatch, capsys):
    assert run_check(monkeypatch, {"JEP_DEPLOYMENT_MODE": "production"},
                     ["JEP_DATABASE_URL", "JEP_SIGNING_TOKEN", "JEP_KEYRING_JSON"]) == 0
    assert "DO_NOT_LOG" not in capsys.readouterr().out


def test_public_variables_do_not_substitute_for_secrets(monkeypatch):
    variables = {"JEP_DEPLOYMENT_MODE": "production", "JEP_DATABASE_URL": "DO_NOT_LOG"}
    result = run_check(monkeypatch, variables, ["JEP_SIGNING_TOKEN", "JEP_KEYRING_JSON"])
    assert "secret JEP_DATABASE_URL" in result
    assert "DO_NOT_LOG" not in result


def test_production_mode_is_required(monkeypatch):
    result = run_check(monkeypatch, {}, ["JEP_DATABASE_URL", "JEP_SIGNING_TOKEN", "JEP_KEYRING_JSON"])
    assert "JEP_DEPLOYMENT_MODE=production" in result


def test_incomplete_vault_configuration_is_rejected(monkeypatch):
    result = run_check(monkeypatch, {"JEP_DEPLOYMENT_MODE": "production", "JEP_VAULT_ADDR": "http://vault"},
                       ["JEP_DATABASE_URL", "JEP_SIGNING_TOKEN"])
    assert all(name in result for name in ("HTTPS", "JEP_VAULT_KEY", "JEP_VAULT_KID_PREFIX", "JEP_VAULT_TOKEN"))


def test_vault_check_is_read_only(monkeypatch):
    variables = {"JEP_DEPLOYMENT_MODE": "production", "JEP_VAULT_ADDR": "https://vault",
                 "JEP_VAULT_KEY": "jep", "JEP_VAULT_KID_PREFIX": "jep-key"}
    assert run_check(monkeypatch, variables, ["JEP_DATABASE_URL", "JEP_SIGNING_TOKEN", "JEP_VAULT_TOKEN"]) == 0
