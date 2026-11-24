"""KB maintenance tests: provenance repair, embedding integrity, source counts.

No live database is required — the store surface is faked. The goal is to lock
the non-destructive / reversible guarantees:
  * provenance keys are derived only from an existing external id, never
    fabricated, and complete rows are left alone;
  * embedding refresh backs up replaced vectors and only re-embeds rows whose
    stored vector hash no longer matches the current embedding body;
  * source record counts are recomputed from the actual rows.
"""


from agentsafe.knowledge.db import content_hash_of
from agentsafe.knowledge.importers import embedding_body
from agentsafe.knowledge.maintenance import (
    backfill_provenance,
    parse_external_id,
    refresh_embeddings,
    refresh_source_counts,
)


class TestParseExternalId:
    def test_code4rena(self):
        p = parse_external_id("code4rena:2022-01-behodler-findings:102")
        assert p == {"source_platform": "code4rena",
                     "contest": "2022-01-behodler-findings", "issue_id": "102"}

    def test_sherlock(self):
        p = parse_external_id("sherlock:sentiment-update:M-4")
        assert p == {"source_platform": "sherlock",
                     "contest": "sentiment-update", "issue_id": "M-4"}

    def test_chunk_suffix_stripped(self):
        p = parse_external_id("sherlock:sentiment-update:M-4#chunk2")
        assert p["issue_id"] == "M-4"

    def test_unrecognised_returns_none(self):
        assert parse_external_id("KB-A-1") is None
        assert parse_external_id("") is None
        assert parse_external_id(None) is None
        assert parse_external_id("other:foo:bar") is None


class TestEmbeddingBody:
    def test_includes_structured_fields(self):
        body = embedding_body({
            "title": "t", "description": "d", "root_cause": "rc",
            "preconditions": ["p1", "p2"], "impact": "i", "remediation": "r"})
        for part in ("t", "d", "rc", "p1", "p2", "i", "r"):
            assert part in body

    def test_skips_empty(self):
        assert embedding_body({"title": "t", "description": None}) == "t"

    def test_caps_oversized_body(self):
        from agentsafe.knowledge.importers import EMBED_BODY_CAP
        body = embedding_body({"title": "t", "description": "x" * 50_000})
        assert len(body) == EMBED_BODY_CAP


# --- fake store -------------------------------------------------------------
class _Cursor:
    def __init__(self, store):
        self.store = store
        self._rows = []
        self.rowcount = 0

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute(self, sql, params=None):
        s = " ".join(sql.split())
        self.store.sql.append(s)
        if s.startswith("SELECT") and "LEFT JOIN knowledge_embeddings" in s:
            self._rows = [dict(r) for r in self.store.embed_rows]
        elif s.startswith("SELECT") and "FROM knowledge_sources" in s:
            self._rows = [dict(r) for r in self.store.source_rows]
        elif s.startswith("SELECT") and "FROM vulnerability_knowledge" in s:
            self._rows = [dict(r) for r in self.store.prov_rows]
        elif s.startswith("INSERT INTO knowledge_embeddings_backup"):
            self.rowcount = len(self.store.backup_ids)
            self.store.backed_up = True
        elif s.startswith("UPDATE knowledge_embeddings"):
            self.rowcount = 1
            self.store.embed_updates.append(params)
        else:
            self.rowcount = 1

    def executemany(self, sql, seq_of_params):
        for params in seq_of_params:
            self.execute(sql, params)
        self.rowcount = len(seq_of_params)

    def fetchall(self):
        return list(self._rows)

    def fetchone(self):
        return self._rows[0] if self._rows else None


class _Conn:
    def __init__(self, store):
        self.store = store

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def cursor(self):
        return _Cursor(self.store)


class _Store:
    vector_dim = 8

    def __init__(self, *, prov_rows=None, embed_rows=None, source_rows=None,
                 backup_ids=None):
        self.prov_rows = prov_rows or []
        self.embed_rows = embed_rows or []
        self.source_rows = source_rows or []
        self.backup_ids = backup_ids or []
        self.sql = []
        self.backed_up = False
        self.embed_updates = []

    def _connect(self):
        return _Conn(self)


class TestBackfillProvenance:
    def test_fills_missing_keys_from_external_id(self):
        store = _Store(prov_rows=[
            {"id": 1, "external_record_id": "sherlock:sentiment-update:M-4",
             "metadata": {}},
            {"id": 2, "external_record_id": "code4rena:2022-01-x-findings:5",
             "metadata": {"contest": "2022-01-x-findings",
                          "source_platform": "code4rena"}},
            {"id": 3, "external_record_id": "KB-A-1", "metadata": {}},
        ])
        s = backfill_provenance(store, sources=["speca-sherlock"])
        assert s.scanned == 3 and s.updated == 2 and s.unrecognised == 1

    def test_complete_row_untouched(self):
        store = _Store(prov_rows=[
            {"id": 9, "external_record_id": "sherlock:c:M-1",
             "metadata": {"source_platform": "sherlock", "contest": "c",
                          "issue_id": "M-1"}}])
        s = backfill_provenance(store, sources=["speca-sherlock"])
        assert s.already_complete == 1 and s.updated == 0


class TestRefreshSourceCounts:
    def test_returns_mapping(self):
        store = _Store(source_rows=[{"name": "s", "record_counts": 5}])
        out = refresh_source_counts(store)
        assert out == {"s": 5}
        assert any("SET record_counts = 0" in s for s in store.sql)


class TestRefreshEmbeddings:
    def _row(self, bad_hash):
        base = {"id": 1, "title": "t", "description": "d", "root_cause": "rc",
                "preconditions": [], "impact": "i", "remediation": "r"}
        return dict(base, emb_hash=bad_hash)

    def test_only_stale_rows_reembedded_and_backed_up(self):
        good = self._row(None)
        good["emb_hash"] = content_hash_of(embedding_body(good))
        stale = self._row("old-hash")
        store = _Store(embed_rows=[good, dict(stale, id=2)],
                       backup_ids=[2])

        class _Emb:
            name = "fake"

            def embed(self, texts):
                return [[0.1] * 8 for _ in texts]

        s = refresh_embeddings(store, _Emb(), sources=["speca-x"])
        assert s.scanned == 2
        assert s.stale == 1
        assert s.reembedded == 1
        assert store.backed_up is True
        assert len(store.embed_updates) == 1

    def test_no_embedder_is_reported(self):
        s = refresh_embeddings(_Store(), None, sources=["speca-x"])
        assert s.errors and s.reembedded == 0
