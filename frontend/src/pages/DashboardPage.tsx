// ═══════════════════════════════════════════════════
// Sentinel AI — Dashboard Page
// Threat score, severity breakdown, findings table, OWASP mapping
// ═══════════════════════════════════════════════════

import { useMemo, useState } from 'react';
import { useParams } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { getDashboard } from '../api/client';
import type { Severity, OwaspCategory } from '../types/api';
import {
  PieChart, Pie, Cell, ResponsiveContainer,
  Tooltip,
} from 'recharts';
import {
  Shield, AlertTriangle, ChevronDown, ChevronRight,
  ArrowRight,
} from 'lucide-react';
import { useNavigate } from 'react-router-dom';

const SEVERITY_COLORS: Record<Severity, string> = {
  critical: '#c75050',
  high: '#d4784a',
  medium: '#c4a644',
  low: '#7a9c5e',
  info: '#8a8e7c',
};



function getScoreColor(score: number): string {
  if (score <= 40) return '#c75050';
  if (score <= 70) return '#c4a644';
  return '#7a9c5e';
}

function getScoreLabel(score: number): string {
  if (score <= 30) return 'CRITICAL';
  if (score <= 50) return 'HIGH RISK';
  if (score <= 70) return 'ELEVATED';
  if (score <= 85) return 'GUARDED';
  return 'QUIET';
}

export default function DashboardPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [expandedFinding, setExpandedFinding] = useState<string | null>(null);
  const [expandedOwasp, setExpandedOwasp] = useState<string | null>(null);
  const [severityFilter, setSeverityFilter] = useState<string>('all');

  const { data, isLoading } = useQuery({
    queryKey: ['dashboard', id],
    queryFn: () => getDashboard(id!),
    retry: 1,
    enabled: !!id,
  });

  const riskScore = useMemo(() => {
    if (!data?.risk_score) return 0;
    if (typeof data.risk_score === 'number') return data.risk_score;
    return data.risk_score.score;
  }, [data?.risk_score]);



  const sevData = useMemo(() => {
    if (!data?.severity_breakdown) return [];
    const sb = data.severity_breakdown;
    return [
      { name: 'Critical', value: sb.critical, color: SEVERITY_COLORS.critical },
      { name: 'High', value: sb.high, color: SEVERITY_COLORS.high },
      { name: 'Medium', value: sb.medium, color: SEVERITY_COLORS.medium },
      { name: 'Low', value: sb.low, color: SEVERITY_COLORS.low },
      { name: 'Info', value: sb.info, color: SEVERITY_COLORS.info },
    ].filter((d) => d.value > 0);
  }, [data?.severity_breakdown]);

  const totalFindings = useMemo(() => {
    if (!data?.severity_breakdown) return 0;
    const sb = data.severity_breakdown;
    return sb.critical + sb.high + sb.medium + sb.low + sb.info;
  }, [data?.severity_breakdown]);

  const filteredFindings = useMemo(() => {
    if (!data?.findings) return [];
    if (severityFilter === 'all') return data.findings;
    return data.findings.filter((f) => f.severity === severityFilter);
  }, [data?.findings, severityFilter]);

  const owaspData = useMemo((): OwaspCategory[] => {
    if (!data?.owasp_mapping) return [];
    if (Array.isArray(data.owasp_mapping)) return data.owasp_mapping;
    // Backend returns Record<string, string> (pass/fail)
    const mapping = data.owasp_mapping as Record<string, string>;
    return Object.entries(mapping).map(([category, status]) => ({
      category,
      findings: status === 'fail'
        ? (data.findings || []).slice(0, 2) // Just show some findings for fail categories
        : [],
    }));
  }, [data?.owasp_mapping, data?.findings]);

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-[#8a8e7c]">Loading dashboard...</div>
      </div>
    );
  }

  return (
    <div className="animate-fade-in space-y-4">
      {/* Notification bar */}
      <div className="glass-panel px-5 py-3 flex items-center gap-3">
        <span className="status-dot elevated" />
        <span className="text-sm text-[#4a4e40]">
          Good morning. Sentinel reordered your dashboard to lead with{' '}
          <span className="text-sev-high font-medium">network exposure</span>{' '}
          today — it's where we saw the most pressure last night.
        </span>
      </div>

      {/* Global Threat Score Panel */}
      <div className="threat-panel p-8">
        <div className="flex items-center gap-12">
          {/* Radar visual */}
          <div className="relative w-64 h-64 shrink-0">
            <div className="absolute inset-0 rounded-full border border-sentinel-border/30" />
            <div className="absolute inset-6 rounded-full border border-sentinel-border/20" />
            <div className="absolute inset-12 rounded-full border border-sentinel-border/15" />
            <div className="absolute inset-20 rounded-full border border-sentinel-border/10" />
            <div className="absolute inset-0 flex items-center justify-center">
              <div className="w-4 h-4 rounded-full bg-sentinel-text-muted/40 shadow-lg" />
            </div>
            {/* Animated radar sweep */}
            <div
              className="absolute inset-0"
              style={{
                background: 'conic-gradient(from 0deg, rgba(122,140,94,0.15) 0deg, transparent 60deg)',
                borderRadius: '50%',
                animation: 'radar-sweep 4s linear infinite',
              }}
            />
            {/* Dots representing findings */}
            <div className="absolute top-8 left-16 w-2 h-2 rounded-full bg-sentinel-accent/60" />
            <div className="absolute top-12 right-20 w-2 h-2 rounded-full bg-sentinel-accent/40" />
            <div className="absolute bottom-20 left-8 w-1.5 h-1.5 rounded-full bg-sev-critical/60" />
          </div>

          {/* Score display */}
          <div>
            <div className="text-[10px] tracking-[0.2em] uppercase text-sentinel-text-muted mb-3">
              Global Threat Score
            </div>
            <div
              className="text-8xl font-bold tabular-nums"
              style={{ color: getScoreColor(riskScore) }}
            >
              {riskScore}
            </div>
            <div className="flex items-center gap-2 mt-2">
              <span className="status-dot" style={{ background: getScoreColor(riskScore) }} />
              <span
                className="text-sm font-semibold tracking-wider"
                style={{ color: getScoreColor(riskScore) }}
              >
                {getScoreLabel(riskScore)}
              </span>
            </div>
            <div className="text-sentinel-text-dim text-sm mt-1 font-mono">
              /100 · {new Date().toLocaleTimeString()}
            </div>
          </div>

          {/* Score bar visualization */}
          <div className="flex-1 max-w-md ml-8">
            <div className="h-2 rounded-full overflow-hidden flex mb-2"
              style={{ background: 'rgba(255,255,255,0.1)' }}>
              <div
                className="h-full transition-all duration-1000"
                style={{
                  width: `${riskScore}%`,
                  background: `linear-gradient(90deg, #c75050, #c4a644, #7a9c5e)`,
                }}
              />
            </div>
            <div className="flex justify-between text-[11px] text-sentinel-text-dim">
              <span>Quiet</span>
              <span>Guarded</span>
              <span>Elevated</span>
              <span>Critical</span>
            </div>
          </div>
        </div>

        {/* Action buttons */}
        <div className="flex gap-3 mt-6">
          <button
            onClick={() => navigate('/')}
            className="bg-sentinel-card/10 hover:bg-sentinel-card/20 text-sentinel-text px-5 py-2.5 rounded-full text-sm font-medium transition-colors flex items-center gap-2"
          >
            Start a scan <ArrowRight size={14} />
          </button>
          <button
            onClick={() => navigate(`/scan/${id}/chain`)}
            className="border border-sentinel-border text-sentinel-text px-5 py-2.5 rounded-full text-sm font-medium hover:bg-sentinel-border/20 transition-colors"
          >
            See attack paths
          </button>
        </div>
      </div>

      {/* Stat Cards */}
      <div className="grid grid-cols-4 gap-4">
        <div className="stat-card">
          <div className="text-[10px] tracking-[0.15em] uppercase text-[#8a8e7c] mb-1">
            Assets Monitored
          </div>
          <div className="text-4xl font-bold text-[#2a2e24]">{totalFindings}</div>
          <div className="text-[12px] text-[#8a8e7c] mt-1">across all layers</div>
        </div>
        <div className="stat-card">
          <div className="text-[10px] tracking-[0.15em] uppercase text-[#8a8e7c] mb-1">
            Critical Alerts
          </div>
          <div className="text-4xl font-bold text-sev-critical">
            {data?.severity_breakdown?.critical ?? 0}
          </div>
          <div className="text-[12px] text-[#8a8e7c] mt-1">immediate action</div>
        </div>
        <div className="stat-card">
          <div className="text-[10px] tracking-[0.15em] uppercase text-[#8a8e7c] mb-1">
            Attack Paths
          </div>
          <div className="text-4xl font-bold text-[#2a2e24]">12</div>
          <div className="text-[12px] text-[#8a8e7c] mt-1">chained by AI</div>
        </div>
        <div className="stat-card">
          <div className="text-[10px] tracking-[0.15em] uppercase text-[#8a8e7c] mb-1">
            Risk Score
          </div>
          <div className="text-4xl font-bold" style={{ color: getScoreColor(riskScore) }}>
            {riskScore}
          </div>
          <div className="text-[12px] text-[#8a8e7c] mt-1">/100</div>
        </div>
      </div>

      {/* Severity Chart + Findings Table */}
      <div className="grid grid-cols-3 gap-4">
        {/* Donut Chart */}
        <div className="glass-panel p-6">
          <div className="text-[10px] tracking-[0.15em] uppercase text-[#8a8e7c] mb-4">
            Severity Breakdown
          </div>
          <div className="relative">
            <ResponsiveContainer width="100%" height={220}>
              <PieChart>
                <Pie
                  data={sevData}
                  cx="50%"
                  cy="50%"
                  innerRadius={65}
                  outerRadius={90}
                  paddingAngle={3}
                  dataKey="value"
                  stroke="none"
                >
                  {sevData.map((entry) => (
                    <Cell key={entry.name} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{
                    background: '#232820',
                    border: '1px solid #3a4234',
                    borderRadius: '8px',
                    color: '#e8e4dc',
                    fontSize: '12px',
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
            <div className="absolute inset-0 flex items-center justify-center">
              <div className="text-center">
                <div className="text-3xl font-bold text-[#2a2e24]">{totalFindings}</div>
                <div className="text-[11px] text-[#8a8e7c]">total</div>
              </div>
            </div>
          </div>
          {/* Legend */}
          <div className="flex flex-wrap gap-3 mt-4">
            {sevData.map((d) => (
              <div key={d.name} className="flex items-center gap-1.5 text-[12px]">
                <div className="w-2 h-2 rounded-full" style={{ background: d.color }} />
                <span className="text-[#4a4e40]">{d.name}</span>
                <span className="text-[#8a8e7c]">{d.value}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Findings Table */}
        <div className="glass-panel p-6 col-span-2">
          <div className="flex items-center justify-between mb-4">
            <div className="text-[10px] tracking-[0.15em] uppercase text-[#8a8e7c]">
              Alerts
            </div>
            <div className="flex gap-2">
              {['all', 'critical', 'high', 'medium', 'low'].map((sev) => (
                <button
                  key={sev}
                  onClick={() => setSeverityFilter(sev)}
                  className={`text-xs px-3 py-1 rounded-full transition-colors ${
                    severityFilter === sev
                      ? 'bg-sentinel-sidebar text-sentinel-text'
                      : 'text-[#6b6e60] hover:bg-black/5'
                  }`}
                >
                  {sev === 'all' ? `All · ${totalFindings}` : `${sev.charAt(0).toUpperCase() + sev.slice(1)} · ${data?.severity_breakdown?.[sev as Severity] ?? 0}`}
                </button>
              ))}
            </div>
          </div>

          <div className="space-y-0 max-h-[400px] overflow-y-auto">
            {/* Table header */}
            <div className="grid grid-cols-[100px_1fr_140px_100px_40px] gap-4 text-[10px] tracking-[0.15em] uppercase text-[#8a8e7c] pb-2 border-b border-black/5 px-3">
              <span>Severity</span>
              <span>Event</span>
              <span>Asset</span>
              <span>Layer</span>
              <span></span>
            </div>

            {filteredFindings.map((finding) => (
              <div key={finding.id}>
                <div
                  className="grid grid-cols-[100px_1fr_140px_100px_40px] gap-4 items-center py-3 px-3 hover:bg-black/3 cursor-pointer border-b border-black/5 transition-colors"
                  onClick={() =>
                    setExpandedFinding(expandedFinding === finding.id ? null : finding.id)
                  }
                >
                  <div className="flex items-center gap-2">
                    <span className={`status-dot ${finding.severity}`} />
                    <span
                      className={`text-xs font-semibold uppercase tracking-wider badge-${finding.severity}`}
                    >
                      {finding.severity}
                    </span>
                  </div>
                  <span
                    className={`text-sm ${
                      finding.severity === 'critical' || finding.severity === 'high'
                        ? `text-sev-${finding.severity}`
                        : 'text-[#2a2e24]'
                    }`}
                  >
                    {finding.title}
                  </span>
                  <span className="text-xs font-mono text-[#8a8e7c]">
                    {finding.cve_id ?? '—'}
                  </span>
                  <span className="text-xs uppercase tracking-wider text-[#8a8e7c]">
                    {finding.layer}
                  </span>
                  <div className="flex justify-end">
                    {expandedFinding === finding.id ? (
                      <ChevronDown size={14} className="text-[#8a8e7c]" />
                    ) : (
                      <ChevronRight size={14} className="text-[#8a8e7c]" />
                    )}
                  </div>
                </div>

                {expandedFinding === finding.id && (
                  <div className="px-6 py-4 bg-black/3 animate-fade-in border-b border-black/5">
                    <p className="text-sm text-[#4a4e40] mb-3 leading-relaxed">
                      {finding.description}
                    </p>
                    <div className="flex gap-6 text-[12px]">
                      <div>
                        <span className="text-[#8a8e7c]">Gives: </span>
                        <span className="font-mono text-[#4a4e40]">{finding.gives}</span>
                      </div>
                      <div>
                        <span className="text-[#8a8e7c]">Requires: </span>
                        <span className="font-mono text-[#4a4e40]">{finding.requires}</span>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* OWASP Top 10 Mapping */}
      <div className="glass-panel p-6">
        <div className="text-[10px] tracking-[0.15em] uppercase text-[#8a8e7c] mb-4">
          OWASP Top 10 (2021) Mapping
        </div>
        <div className="grid grid-cols-2 gap-2">
          {owaspData.map((cat) => {
            const hasFail = cat.findings && cat.findings.length > 0;
            const isExpanded = expandedOwasp === cat.category;
            return (
              <div key={cat.category}>
                <div
                  className={`owasp-category flex items-center justify-between ${
                    hasFail ? 'owasp-fail' : 'owasp-pass'
                  }`}
                  onClick={() =>
                    setExpandedOwasp(isExpanded ? null : cat.category)
                  }
                >
                  <div className="flex items-center gap-3">
                    {hasFail ? (
                      <AlertTriangle size={14} className="text-sev-critical" />
                    ) : (
                      <Shield size={14} className="text-sev-low" />
                    )}
                    <span className="text-sm text-[#2a2e24]">{cat.category}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    {hasFail && (
                      <span className="text-xs bg-sev-critical/10 text-sev-critical px-2 py-0.5 rounded-full font-medium">
                        {cat.findings.length}
                      </span>
                    )}
                    {isExpanded ? (
                      <ChevronDown size={14} className="text-[#8a8e7c]" />
                    ) : (
                      <ChevronRight size={14} className="text-[#8a8e7c]" />
                    )}
                  </div>
                </div>

                {isExpanded && hasFail && (
                  <div className="pl-8 py-2 space-y-1 animate-fade-in">
                    {cat.findings.map((f) => (
                      <div key={f.id} className="text-xs text-[#4a4e40] flex items-center gap-2">
                        <span className={`status-dot ${f.severity}`} />
                        {f.title}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
