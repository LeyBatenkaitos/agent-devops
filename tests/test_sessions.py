"""Unit tests for sessions.py."""

from __future__ import annotations

from unittest.mock import patch

import pytest

import sessions


@pytest.fixture
def isolated_home(tmp_path, monkeypatch):
    """Redirect XDG_CONFIG_HOME to a temp dir so tests never touch $HOME."""

    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    monkeypatch.delenv("DEVOPS_SESSION_ID", raising=False)
    return tmp_path


def test_resolve_explicit_cli_wins(isolated_home) -> None:
    state = sessions.RegistryState()
    sid, is_new = sessions.resolve_session_id(
        cli_value="custom-name", force_new=False, state=state
    )
    assert sid == "custom-name"
    assert is_new is True


def test_resolve_env_fallback(isolated_home, monkeypatch) -> None:
    monkeypatch.setenv("DEVOPS_SESSION_ID", "env-session")
    state = sessions.RegistryState()
    sid, _ = sessions.resolve_session_id(cli_value=None, force_new=False, state=state)
    assert sid == "env-session"


def test_resolve_auto_resume_last_session(isolated_home) -> None:
    state = sessions.RegistryState(last_session_id="gabriel-proj-20260101")
    state.sessions["gabriel-proj-20260101"] = sessions.SessionMeta(
        id="gabriel-proj-20260101",
        created_at="2026-01-01T00:00:00+00:00",
        last_used_at="2026-01-01T00:00:00+00:00",
    )
    sid, is_new = sessions.resolve_session_id(
        cli_value=None, force_new=False, state=state
    )
    assert sid == "gabriel-proj-20260101"
    assert is_new is False


def test_resolve_force_new_generates_unique_suffix(isolated_home) -> None:
    state = sessions.RegistryState()
    state.sessions["alice-proj-20260417"] = sessions.SessionMeta(
        id="alice-proj-20260417",
        created_at="2026-04-17T00:00:00+00:00",
        last_used_at="2026-04-17T00:00:00+00:00",
    )
    with patch.object(
        sessions,
        "_semantic_base_id",
        return_value=("alice-proj-20260417", "alice@example.com", "proj"),
    ):
        sid, is_new = sessions.resolve_session_id(
            cli_value=None, force_new=True, state=state
        )
    assert sid == "alice-proj-20260417-2"
    assert is_new is True


def test_resolve_falls_back_to_uuid_when_gcloud_absent(isolated_home) -> None:
    state = sessions.RegistryState()
    with patch.object(sessions, "_gcloud_value", return_value=None):
        sid, is_new = sessions.resolve_session_id(
            cli_value=None, force_new=True, state=state
        )
    assert sid.startswith("devops-")
    assert is_new is True


def test_register_and_increment_persist(isolated_home) -> None:
    state = sessions.RegistryState()
    with patch.object(
        sessions,
        "_semantic_base_id",
        return_value=("alice-proj-20260417", "alice@example.com", "proj"),
    ):
        sessions.register_session(state, "alice-proj-20260417")
        sessions.increment_turn(state, "alice-proj-20260417")
        sessions.increment_turn(state, "alice-proj-20260417")

    reloaded = sessions.load_state()
    assert reloaded.last_session_id == "alice-proj-20260417"
    assert reloaded.sessions["alice-proj-20260417"].turn_count == 2
    assert reloaded.sessions["alice-proj-20260417"].gcp_user == "alice@example.com"


def test_format_session_list_marks_current(isolated_home) -> None:
    state = sessions.RegistryState(last_session_id="b")
    state.sessions["a"] = sessions.SessionMeta(
        id="a",
        created_at="2026-01-01T00:00:00+00:00",
        last_used_at="2026-01-01T00:00:00+00:00",
        turn_count=3,
    )
    state.sessions["b"] = sessions.SessionMeta(
        id="b",
        created_at="2026-04-16T00:00:00+00:00",
        last_used_at="2026-04-17T00:00:00+00:00",
        turn_count=7,
    )
    output = sessions.format_session_list(state)
    assert "* b" in output  # current marker
    assert "  a" in output
    assert "7 turns" in output


def test_format_session_list_empty(isolated_home) -> None:
    assert sessions.format_session_list(sessions.RegistryState()) == "(no sessions yet)"


def test_slug_normalizes_email_and_project() -> None:
    assert sessions._slug("Alice.Smith@Example.com") == "alice-smith-example-com"
    assert sessions._slug("my_cool-project!") == "my-cool-project"


def test_semantic_base_id_uses_gcloud_context() -> None:
    with patch.object(
        sessions,
        "_gcloud_value",
        side_effect=lambda key: {
            "account": "alice@example.com",
            "core/project": "my-project-dev",
        }.get(key),
    ):
        base, user, project = sessions._semantic_base_id()
    assert base.startswith("alice-my-project-dev-")
    assert user == "alice@example.com"
    assert project == "my-project-dev"
