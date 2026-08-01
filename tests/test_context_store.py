from datetime import datetime, timedelta, timezone

from threatlens.context.models import ContextScope, SavedContextAnswer
from threatlens.context.store import ContextStore


def test_upsert_and_get_scoped(tmp_path):
    store = ContextStore(tmp_path / "context.json")
    store.upsert(
        SavedContextAnswer(
            key="untrusted_users_reachable",
            value="Yes",
            scope=ContextScope.REPOSITORY,
            repository_id="github.com/acme/a",
        )
    )
    store.upsert(
        SavedContextAnswer(
            key="untrusted_users_reachable",
            value="No",
            scope=ContextScope.REPOSITORY,
            repository_id="github.com/acme/b",
        )
    )
    a = store.get("untrusted_users_reachable", repository_id="github.com/acme/a")
    b = store.get("untrusted_users_reachable", repository_id="github.com/acme/b")
    assert a is not None and a.value == "Yes"
    assert b is not None and b.value == "No"


def test_expired_ignored(tmp_path):
    store = ContextStore(tmp_path / "context.json")
    store.upsert(
        SavedContextAnswer(
            key="k",
            value="Yes",
            scope=ContextScope.REPOSITORY,
            repository_id="github.com/acme/a",
            expires_at=datetime.now(timezone.utc) - timedelta(hours=1),
        )
    )
    assert store.get("k", repository_id="github.com/acme/a") is None


def test_clear_repository(tmp_path):
    store = ContextStore(tmp_path / "context.json")
    store.upsert(
        SavedContextAnswer(
            key="k",
            value="Yes",
            scope=ContextScope.REPOSITORY,
            repository_id="github.com/acme/a",
        )
    )
    assert store.clear(repository_id="github.com/acme/a") == 1
    assert store.list_answers() == []


def test_malformed_file_fails_safe(tmp_path):
    path = tmp_path / "context.json"
    path.write_text("{not-json", encoding="utf-8")
    store = ContextStore(path)
    assert store.list_answers() == []
