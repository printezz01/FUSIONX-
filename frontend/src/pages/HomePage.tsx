// ═══════════════════════════════════════════════════
// Sentinel AI — Home / Scan Page
// "Scan anything. Sentinel will figure out what it is."
// ═══════════════════════════════════════════════════

import { useState, useRef, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Search, ArrowRight, Download } from 'lucide-react';
import { startScan, downloadReport } from '../api/client';
import type { TargetType } from '../types/api';
import toast from 'react-hot-toast';

// Quick-select target examples
const QUICK_TARGETS = [
  { value: '10.42.1.0/24', label: 'Network subnet', type: 'subnet' as TargetType },
  { value: 'https://portal.internal', label: 'Web app', type: 'url' as TargetType },
  { value: 'github.com/OWASP/PyGoat', label: 'Source repo', type: 'github' as TargetType },
  { value: '127.0.0.1', label: 'Localhost', type: 'ip' as TargetType },
];

// Validation patterns
const PATTERNS: Record<TargetType, RegExp> = {
  ip: /^(\d{1,3}\.){3}\d{1,3}$/,
  subnet: /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/,
  url: /^https?:\/\/.+/i,
  github: /^(https?:\/\/)?(www\.)?github\.com\/.+\/.+/i,
};

function detectTargetType(input: string): TargetType {
  if (PATTERNS.github.test(input)) return 'github';
  if (PATTERNS.url.test(input)) return 'url';
  if (PATTERNS.subnet.test(input)) return 'subnet';
  return 'ip';
}

export default function HomePage() {
  const navigate = useNavigate();
  const [target, setTarget] = useState('');
  const [scanning, setScanning] = useState(false);
  const [lastScanId, setLastScanId] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  // Auto-focus the scan input on mount
  useEffect(() => {
    inputRef.current?.focus();
  }, []);

  const detectedType = target ? detectTargetType(target) : null;

  const typeLabels: Record<TargetType, string> = {
    ip: 'Network',
    subnet: 'Network',
    url: 'Web app',
    github: 'Source repo',
  };

  const handleScan = async () => {
    if (!target.trim()) {
      toast.error('Enter a target to scan');
      return;
    }

    const type = detectTargetType(target);
    if (!PATTERNS[type].test(target)) {
      toast.error(`Invalid ${type} format`);
      return;
    }

    setScanning(true);
    try {
      const res = await startScan({ target, target_type: type });
      setLastScanId(res.scan_id);
      // Navigate to the live scan page
      navigate(`/scan/${res.scan_id}/live`);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Scan failed');
    } finally {
      setScanning(false);
    }
  };

  const handleQuickTarget = (qt: typeof QUICK_TARGETS[0]) => {
    setTarget(qt.value);
  };

  const handleDownloadPdf = async () => {
    if (!lastScanId) return;
    try {
      await downloadReport(lastScanId);
      toast.success('Report downloaded');
    } catch {
      toast.error('Failed to download report');
    }
  };

  return (
    <div className="animate-fade-in">
      {/* Header */}
      <div className="mb-2">
        <div className="text-[11px] tracking-[0.2em] uppercase text-sentinel-text-dim font-medium mb-3">
          Unified Scan
        </div>
        <h1 className="text-4xl md:text-5xl font-semibold leading-tight text-[#2a2e24] mb-4 max-w-2xl">
          Scan anything. Sentinel will figure out what it is.
        </h1>
        <p className="text-base text-[#6b6e60] max-w-2xl leading-relaxed">
          One input for every surface. Paste an IP, a subnet, a URL, a repository link,
          or an RTSP camera stream — our AI engine detects the target type and runs the right probes.
        </p>
      </div>

      {/* Search bar */}
      <div className="flex items-center gap-3 mt-8 mb-4">
        <div className="flex-1 relative">
          <Search size={18} className="absolute left-4 top-1/2 -translate-y-1/2 text-[#8a8e7c]" />
          <input
            ref={inputRef}
            type="text"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleScan()}
            placeholder="Type or paste a target here…  e.g. 127.0.0.1  ·  github.com/OWASP/PyGoat"
            className="search-input text-base py-4"
            id="scan-target-input"
            autoFocus
          />
        </div>

        <button
          onClick={handleScan}
          disabled={scanning || !target.trim()}
          className="btn-primary"
          id="scan-start-button"
        >
          {scanning ? 'Scanning...' : 'Scan'}
          <ArrowRight size={16} />
        </button>

        {lastScanId && (
          <button
            onClick={handleDownloadPdf}
            className="btn-outline"
          >
            <Download size={14} />
            Download PDF
          </button>
        )}
      </div>

      {/* Quick target chips */}
      <div className="flex flex-wrap gap-2 mb-8">
        {QUICK_TARGETS.map((qt) => (
          <button
            key={qt.value}
            onClick={() => handleQuickTarget(qt)}
            className="target-chip"
          >
            <span className="font-mono text-[13px]">{qt.value}</span>
            <span className="chip-label">· {qt.label}</span>
          </button>
        ))}
      </div>

      {/* Detected type indicator (shown when user types) */}
      {detectedType && target.trim() && (
        <div className="flex gap-4 animate-fade-in">
          {/* Detection card */}
          <div className="glass-panel p-6 flex-1 max-w-md">
            <div className="text-[10px] tracking-[0.2em] uppercase text-sentinel-text-dim mb-2">
              Detected As
            </div>
            <div className="text-2xl font-semibold text-[#2a2e24] mb-3">
              {typeLabels[detectedType]}
            </div>
            <p className="text-[13px] text-[#6b6e60] mb-4">
              {detectedType === 'ip' && 'IP / CIDR — port map + service fingerprint'}
              {detectedType === 'subnet' && 'Subnet — host discovery + port scan'}
              {detectedType === 'url' && 'Web application — vulnerability scan + header analysis'}
              {detectedType === 'github' && 'Source code — static analysis + secret detection'}
            </p>
            <div className="space-y-2 text-[13px] text-[#4a4e40]">
              <div className="flex justify-between">
                <span>target</span>
                <span className="font-mono">{target}</span>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Demo disclaimer */}
      <div className="mt-8 text-xs text-[#8a8e7c] max-w-xl">
        Demo build. Only localhost targets and whitelisted public vulnerable repos are accepted.
      </div>
    </div>
  );
}
