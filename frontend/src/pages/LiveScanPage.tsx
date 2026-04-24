// ═══════════════════════════════════════════════════
// Sentinel AI — Live Scan Feed
// Real-time polling with terminal log and timer
// ═══════════════════════════════════════════════════

import { useEffect, useRef, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { getScanStatus } from '../api/client';
import type { Finding, Severity } from '../types/api';
import { CheckCircle, AlertTriangle, ArrowRight, Loader } from 'lucide-react';
import toast from 'react-hot-toast';

const SEVERITY_COLORS: Record<Severity, string> = {
  critical: '#c75050',
  high: '#d4784a',
  medium: '#c4a644',
  low: '#7a9c5e',
  info: '#8a8e7c',
};

const TOOL_DESCRIPTIONS: Record<string, string> = {
  nmap: 'Scanning ports and services',
  bandit: 'Analyzing Python source code',
  semgrep: 'Running pattern-based code analysis',
  trufflehog: 'Scanning for leaked secrets',
  nikto: 'Probing web vulnerabilities',
  'NVD lookup': 'Cross-referencing known CVEs',
  'CCTV check': 'Fingerprinting IoT cameras',
  'attack chain build': 'Building attack graph',
  embedding: 'Generating semantic embeddings',
};



export default function LiveScanPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const logRef = useRef<HTMLDivElement>(null);
  const [seenIds, setSeenIds] = useState<Set<string>>(new Set());
  const [logEntries, setLogEntries] = useState<Finding[]>([]);
  // ── Reliable 1-second timer ──────────────────────
  const [elapsedSeconds, setElapsedSeconds] = useState(0);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const { data: status } = useQuery({
    queryKey: ['scanStatus', id],
    queryFn: () => getScanStatus(id!),
    refetchInterval: (query) => {
      const s = query.state.data?.status;
      if (s === 'completed' || s === 'failed') return false;
      return 1500;
    },
    retry: 1,
    enabled: !!id,
  });

  // Start the timer on mount, stop when scan ends
  useEffect(() => {
    timerRef.current = setInterval(() => {
      setElapsedSeconds((prev) => prev + 1);
    }, 1000);

    return () => {
      if (timerRef.current) clearInterval(timerRef.current);
    };
  }, []);

  // Stop the timer when scan completes or fails
  useEffect(() => {
    if (status?.status === 'completed' || status?.status === 'failed') {
      if (timerRef.current) {
        clearInterval(timerRef.current);
        timerRef.current = null;
      }
    }
  }, [status?.status]);

  // Track new findings
  useEffect(() => {
    if (!status?.findings_so_far) return;
    const newFindings = status.findings_so_far.filter(
      (f) => !seenIds.has(f.id)
    );
    if (newFindings.length > 0) {
      setSeenIds((prev) => {
        const next = new Set(prev);
        newFindings.forEach((f) => next.add(f.id));
        return next;
      });
      setLogEntries((prev) => [...prev, ...newFindings]);
    }
  }, [status?.findings_so_far, seenIds]);

  // Auto-scroll terminal
  useEffect(() => {
    if (logRef.current) {
      logRef.current.scrollTop = logRef.current.scrollHeight;
    }
  }, [logEntries]);

  // Show toast on failure
  useEffect(() => {
    if (status?.status === 'failed') {
      toast.error('Scan failed. Partial results may be available.');
    }
  }, [status?.status]);

  const minutes = Math.floor(elapsedSeconds / 60).toString().padStart(2, '0');
  const seconds = (elapsedSeconds % 60).toString().padStart(2, '0');
  const isComplete = status?.status === 'completed';
  const isFailed = status?.status === 'failed';

  return (
    <div className="animate-fade-in h-full flex flex-col">
      {/* Header */}
      <div className="mb-6">
        <div className="text-[11px] tracking-[0.2em] uppercase text-sentinel-text-dim font-medium mb-3">
          Live Scan
        </div>
        <h1 className="text-3xl font-semibold text-[#2a2e24] mb-2">
          {isComplete ? 'Scan Complete' : isFailed ? 'Scan Failed' : 'Scanning target...'}
        </h1>
      </div>

      {/* Timer & Status */}
      <div className="flex items-center gap-8 mb-6">
        {/* Timer */}
        <div className="threat-panel px-8 py-6">
          <div className="text-[10px] tracking-[0.2em] uppercase text-sentinel-text-muted mb-2">
            Elapsed
          </div>
          <div className="text-5xl font-bold text-sentinel-text font-mono tabular-nums">
            {minutes}:{seconds}
          </div>
        </div>

        {/* Current tool */}
        <div className="flex-1">
          {!isComplete && !isFailed && status?.current_tool && (
            <div className="glass-panel p-5 animate-fade-in">
              <div className="flex items-center gap-3 mb-2">
                <Loader size={16} className="text-sentinel-accent animate-spin" />
                <span className="font-mono text-sm font-semibold text-[#2a2e24]">
                  {status.current_tool}
                </span>
              </div>
              <p className="text-[13px] text-[#6b6e60]">
                {TOOL_DESCRIPTIONS[status.current_tool] ?? 'Processing...'}
              </p>
            </div>
          )}

          {isComplete && (
            <div className="glass-panel p-5 animate-fade-in border-l-4 border-l-sev-low">
              <div className="flex items-center gap-3 mb-2">
                <CheckCircle size={20} className="text-sev-low" />
                <span className="font-semibold text-[#2a2e24]">Scan Complete</span>
              </div>
              <p className="text-[13px] text-[#6b6e60] mb-3">
                Found {logEntries.length} vulnerabilities in {minutes}:{seconds}
              </p>
              <button
                onClick={() => navigate(`/scan/${id}/dashboard`)}
                className="btn-primary"
              >
                View Dashboard
                <ArrowRight size={16} />
              </button>
            </div>
          )}

          {isFailed && (
            <div className="glass-panel p-5 animate-fade-in border-l-4 border-l-sev-critical">
              <div className="flex items-center gap-3 mb-2">
                <AlertTriangle size={20} className="text-sev-critical" />
                <span className="font-semibold text-[#2a2e24]">Scan Failed</span>
              </div>
              <p className="text-[13px] text-[#6b6e60] mb-3">
                Partial results may be available.
              </p>
              <button
                onClick={() => navigate(`/scan/${id}/dashboard`)}
                className="btn-primary"
              >
                View Partial Results
                <ArrowRight size={16} />
              </button>
            </div>
          )}
        </div>

        {/* Stats */}
        <div className="flex gap-4">
          <div className="stat-card text-center min-w-[100px]">
            <div className="text-[10px] tracking-[0.15em] uppercase text-[#8a8e7c] mb-1">
              Findings
            </div>
            <div className="text-3xl font-bold text-[#2a2e24]">
              {logEntries.length}
            </div>
          </div>
          <div className="stat-card text-center min-w-[100px]">
            <div className="text-[10px] tracking-[0.15em] uppercase text-[#8a8e7c] mb-1">
              Critical
            </div>
            <div className="text-3xl font-bold text-sev-critical">
              {logEntries.filter((f) => f.severity === 'critical').length}
            </div>
          </div>
        </div>
      </div>

      {/* Terminal Log */}
      <div className="flex-1 min-h-0">
        <div ref={logRef} className="terminal h-full max-h-[420px]">
          <div className="text-sentinel-accent mb-2">
            {'>'} Sentinel AI v1.0 — scan initiated for {id}
          </div>
          <div className="text-sentinel-text-dim mb-3">
            {'>'} Probing target across network, code, web, and IoT surfaces...
          </div>
          {logEntries.map((finding, i) => (
            <div key={finding.id} className="terminal-line flex items-start gap-2">
              <span className="text-sentinel-text-dim select-none shrink-0">
                [{new Date(Date.now() - (logEntries.length - i) * 2000).toLocaleTimeString()}]
              </span>
              <span
                className="font-semibold shrink-0 uppercase text-[11px] min-w-[64px]"
                style={{ color: SEVERITY_COLORS[finding.severity] }}
              >
                {finding.severity}
              </span>
              <span className="text-sentinel-text">
                {finding.title}
              </span>
              {finding.cve_id && (
                <span className="text-sentinel-accent font-mono text-[11px]">
                  {finding.cve_id}
                </span>
              )}
            </div>
          ))}
          {!isComplete && !isFailed && (
            <div className="terminal-line text-sentinel-accent animate-pulse mt-1">
              {'>'} scanning...
            </div>
          )}
          {isComplete && (
            <div className="terminal-line text-sev-low mt-2">
              {'>'} Scan completed. {logEntries.length} findings across all layers.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
