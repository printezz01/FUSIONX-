-- ═══════════════════════════════════════════════════
-- Sentinel AI — Database Schema Migration
-- Run this against your Supabase PostgreSQL instance
-- ═══════════════════════════════════════════════════

-- Enable pgvector extension
CREATE EXTENSION IF NOT EXISTS vector;

-- ───────────────────────────────────────────────────
-- Table: scan_sessions
-- ───────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS scan_sessions (
    id           UUID PRIMARY KEY,
    target       TEXT NOT NULL,
    target_type  TEXT NOT NULL CHECK (target_type IN ('ip', 'subnet', 'url', 'github')),
    status       TEXT NOT NULL CHECK (status IN ('queued', 'running', 'complete', 'failed')) DEFAULT 'queued',
    current_tool TEXT DEFAULT NULL,
    created_at   TIMESTAMPTZ DEFAULT now(),
    completed_at TIMESTAMPTZ
);

-- ───────────────────────────────────────────────────
-- Table: findings
-- gives/requires are CRITICAL for attack chain building
-- ───────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS findings (
    id           UUID PRIMARY KEY,
    scan_id      UUID REFERENCES scan_sessions(id) ON DELETE CASCADE,
    layer        TEXT CHECK (layer IN ('network', 'code', 'web', 'iot')),
    severity     TEXT CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    title        TEXT NOT NULL,
    description  TEXT NOT NULL,
    cve_id       TEXT,
    gives        TEXT NOT NULL,
    requires     TEXT NOT NULL,
    raw_output   JSONB,
    embedding    VECTOR(1536),
    created_at   TIMESTAMPTZ DEFAULT now()
);

-- ───────────────────────────────────────────────────
-- Table: chain_edges
-- ───────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS chain_edges (
    id            UUID PRIMARY KEY,
    scan_id       UUID REFERENCES scan_sessions(id) ON DELETE CASCADE,
    from_finding  UUID REFERENCES findings(id) ON DELETE CASCADE,
    to_finding    UUID REFERENCES findings(id) ON DELETE CASCADE,
    reason        TEXT
);

-- ───────────────────────────────────────────────────
-- Table: risk_scores
-- ───────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS risk_scores (
    scan_id    UUID PRIMARY KEY REFERENCES scan_sessions(id) ON DELETE CASCADE,
    score      INT NOT NULL,
    breakdown  JSONB
);

-- ───────────────────────────────────────────────────
-- Table: owasp_mappings
-- ───────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS owasp_mappings (
    id             UUID PRIMARY KEY,
    finding_id     UUID REFERENCES findings(id) ON DELETE CASCADE,
    owasp_category TEXT NOT NULL
);

-- ───────────────────────────────────────────────────
-- Indexes for performance
-- ───────────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_chain_edges_scan_id ON chain_edges(scan_id);
CREATE INDEX IF NOT EXISTS idx_owasp_mappings_finding_id ON owasp_mappings(finding_id);

-- ───────────────────────────────────────────────────
-- pgvector index for fast RAG similarity search
-- ───────────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_findings_embedding
    ON findings USING ivfflat (embedding vector_cosine_ops)
    WITH (lists = 100);

-- ═══════════════════════════════════════════════════
-- RPC Function: match_findings
-- Called by engine.py search_rag() for RAG chat
-- Performs cosine similarity search over embeddings
-- ═══════════════════════════════════════════════════
CREATE OR REPLACE FUNCTION match_findings(
    query_embedding  VECTOR(1536),
    match_threshold  FLOAT,
    match_count      INT,
    p_scan_id        UUID
)
RETURNS TABLE (
    id          UUID,
    scan_id     UUID,
    layer       TEXT,
    severity    TEXT,
    title       TEXT,
    description TEXT,
    cve_id      TEXT,
    gives       TEXT,
    requires    TEXT,
    raw_output  JSONB,
    similarity  FLOAT
)
LANGUAGE plpgsql
AS $$
BEGIN
    RETURN QUERY
    SELECT
        f.id,
        f.scan_id,
        f.layer,
        f.severity,
        f.title,
        f.description,
        f.cve_id,
        f.gives,
        f.requires,
        f.raw_output,
        1 - (f.embedding <=> query_embedding) AS similarity
    FROM findings f
    WHERE
        f.scan_id = p_scan_id
        AND f.embedding IS NOT NULL
        AND 1 - (f.embedding <=> query_embedding) > match_threshold
    ORDER BY f.embedding <=> query_embedding
    LIMIT match_count;
END;
$$;
