-- ═══════════════════════════════════════════════════
-- Sentinel AI — Database Schema Migration
-- Run this against your Supabase PostgreSQL instance
-- Requires: pgvector extension enabled
-- ═══════════════════════════════════════════════════

-- Enable pgvector extension
CREATE EXTENSION IF NOT EXISTS vector;

-- ───────────────────────────────────────────────────
-- Table: scan_sessions
-- Tracks each scanning session lifecycle
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
-- Individual vulnerability findings across all layers
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
-- Attack chain graph edges connecting findings
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
-- Overall risk score per scan session
-- ───────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS risk_scores (
    scan_id    UUID PRIMARY KEY REFERENCES scan_sessions(id) ON DELETE CASCADE,
    score      INT NOT NULL,
    breakdown  JSONB
);

-- ───────────────────────────────────────────────────
-- Table: owasp_mappings
-- OWASP Top 10 (2021) mappings per finding
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
