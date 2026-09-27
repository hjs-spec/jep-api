"""Guard the explicit hosting decision without starting or authenticating a service."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_hosting_has_no_automatic_event_trigger():
    text = (ROOT / '.github/workflows/deploy.yml').read_text()
    events = text.split('on:\n', 1)[1].split('permissions:\n', 1)[0]
    assert '  workflow_dispatch:' in events
    assert 'workflow_run:' not in events
    assert '  push:' not in events
    assert '  schedule:' not in events


def test_hosting_requires_main_and_explicit_confirmation():
    text = (ROOT / '.github/workflows/deploy.yml').read_text()
    assert "if: github.ref == 'refs/heads/main' && inputs.confirmation == 'deploy-hosted-api'" in text
    assert 'required: true' in text
    assert 'JEP_REVISION: ${{ github.sha }}' in text
    assert 'python scripts/deploy_hf.py' in text


def test_software_release_remains_independent():
    text = (ROOT / '.github/workflows/release.yml').read_text()
    assert 'docker push' in text
    assert 'HF_TOKEN' not in text
    assert 'deploy_hf.py' not in text
