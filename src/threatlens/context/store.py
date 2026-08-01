"""Persistent storage for scoped external-context answers."""

from __future__ import annotations

import json
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from pydantic import BaseModel, Field

from threatlens.context.models import ContextScope, SavedContextAnswer


def default_context_path() -> Path:
    if sys.platform == "win32":
        base = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
        return base / "threatlens" / "context.json"
    if sys.platform == "darwin":
        return (
            Path.home()
            / "Library"
            / "Application Support"
            / "threatlens"
            / "context.json"
        )
    xdg = os.environ.get("XDG_CONFIG_HOME", str(Path.home() / ".config"))
    return Path(xdg) / "threatlens" / "context.json"


class ContextFile(BaseModel):
    version: int = 1
    answers: list[SavedContextAnswer] = Field(default_factory=list)


class ContextStore:
    def __init__(self, path: Path | None = None) -> None:
        self.path = path or default_context_path()

    def load(self) -> ContextFile:
        if not self.path.is_file():
            return ContextFile()
        try:
            raw = self.path.read_text(encoding="utf-8")
            if not raw.strip():
                return ContextFile()
            return ContextFile.model_validate_json(raw)
        except (OSError, ValueError, json.JSONDecodeError):
            return ContextFile()

    def save(self, data: ContextFile) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = data.model_dump_json(indent=2)
        fd, tmp_name = tempfile.mkstemp(
            dir=str(self.path.parent), prefix=".context-", suffix=".tmp"
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                handle.write(payload)
                handle.write("\n")
            os.replace(tmp_name, self.path)
            try:
                os.chmod(self.path, 0o600)
            except OSError:
                pass
        finally:
            if os.path.exists(tmp_name):
                try:
                    os.remove(tmp_name)
                except OSError:
                    pass

    def list_answers(
        self,
        *,
        repository_id: str | None = None,
        include_expired: bool = False,
    ) -> list[SavedContextAnswer]:
        now = datetime.now(timezone.utc)
        out: list[SavedContextAnswer] = []
        for answer in self.load().answers:
            if not include_expired and answer.is_expired(now=now):
                continue
            if repository_id and answer.repository_id not in (None, repository_id):
                if answer.scope != ContextScope.ORGANIZATION:
                    continue
            out.append(answer)
        return out

    def get(
        self,
        key: str,
        *,
        repository_id: str | None = None,
        finding_fingerprint: str | None = None,
    ) -> SavedContextAnswer | None:
        candidates = [
            a
            for a in self.list_answers(repository_id=repository_id)
            if a.key == key
        ]
        # Prefer finding-scoped, then repository, then organization.
        def rank(a: SavedContextAnswer) -> int:
            if (
                a.scope == ContextScope.FINDING
                and finding_fingerprint
                and a.finding_fingerprint == finding_fingerprint
            ):
                return 0
            if a.scope == ContextScope.REPOSITORY and a.repository_id == repository_id:
                return 1
            if a.scope == ContextScope.SERVICE and a.repository_id == repository_id:
                return 2
            if a.scope == ContextScope.ORGANIZATION:
                return 3
            return 9

        ranked = sorted(candidates, key=rank)
        for answer in ranked:
            if answer.scope == ContextScope.FINDING:
                if answer.finding_fingerprint == finding_fingerprint:
                    return answer
                continue
            return answer
        return None

    def upsert(self, answer: SavedContextAnswer) -> SavedContextAnswer:
        data = self.load()
        now = datetime.now(timezone.utc)
        answer.updated_at = now
        replaced = False
        new_answers: list[SavedContextAnswer] = []
        for existing in data.answers:
            same = (
                existing.key == answer.key
                and existing.scope == answer.scope
                and existing.repository_id == answer.repository_id
                and existing.service_id == answer.service_id
                and existing.finding_fingerprint == answer.finding_fingerprint
            )
            if same:
                answer.created_at = existing.created_at
                new_answers.append(answer)
                replaced = True
            else:
                new_answers.append(existing)
        if not replaced:
            if answer.created_at is None:
                answer.created_at = now
            new_answers.append(answer)
        data.answers = new_answers
        self.save(data)
        return answer

    def clear(
        self,
        *,
        repository_id: str | None = None,
    ) -> int:
        data = self.load()
        before = len(data.answers)
        if repository_id is None:
            data.answers = []
        else:
            data.answers = [
                a
                for a in data.answers
                if a.repository_id != repository_id
                or a.scope == ContextScope.ORGANIZATION
            ]
        removed = before - len(data.answers)
        self.save(data)
        return removed
