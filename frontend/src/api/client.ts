// ═══════════════════════════════════════════════════
// Sentinel AI — API Client
// Handles both real API calls and mock mode
// ═══════════════════════════════════════════════════

import type {
  ScanRequest, ScanResponse, ScanStatusResponse,
  DashboardResponse, ChainResponse, ChatResponse,
} from '../types/api';
import {
  getMockScanStatus, getMockDashboard, getMockChain,
  getMockChat, resetMockState,
} from '../mocks/fixtures';

const BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';
const USE_MOCKS = import.meta.env.VITE_USE_MOCKS === 'true';

async function apiFetch<T>(
  path: string,
  options?: RequestInit,
): Promise<T> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 30000);

  try {
    const res = await fetch(`${BASE_URL}${path}`, {
      ...options,
      signal: controller.signal,
      headers: {
        'Content-Type': 'application/json',
        ...options?.headers,
      },
    });

    if (!res.ok) {
      const body = await res.json().catch(() => ({ detail: res.statusText }));
      throw new Error(body.detail || `HTTP ${res.status}`);
    }

    return await res.json() as T;
  } finally {
    clearTimeout(timeout);
  }
}

export async function startScan(req: ScanRequest): Promise<ScanResponse> {
  if (USE_MOCKS) {
    resetMockState();
    return { scan_id: `mock-${Date.now().toString(36)}` };
  }
  return apiFetch<ScanResponse>('/scan', {
    method: 'POST',
    body: JSON.stringify(req),
  });
}

export async function getScanStatus(scanId: string): Promise<ScanStatusResponse> {
  if (USE_MOCKS) {
    return getMockScanStatus(scanId);
  }
  return apiFetch<ScanStatusResponse>(`/scan/${scanId}/status`);
}

export async function getDashboard(scanId: string): Promise<DashboardResponse> {
  if (USE_MOCKS) {
    return getMockDashboard();
  }
  return apiFetch<DashboardResponse>(`/scan/${scanId}/dashboard`);
}

export async function getChain(scanId: string): Promise<ChainResponse> {
  if (USE_MOCKS) {
    return getMockChain();
  }
  return apiFetch<ChainResponse>(`/scan/${scanId}/chain`);
}

export async function sendChat(
  scanId: string,
  question: string,
): Promise<ChatResponse> {
  if (USE_MOCKS) {
    await new Promise((r) => setTimeout(r, 1200));
    return getMockChat(question);
  }
  return apiFetch<ChatResponse>(`/scan/${scanId}/chat`, {
    method: 'POST',
    body: JSON.stringify({ question }),
  });
}

export async function downloadReport(scanId: string): Promise<void> {
  if (USE_MOCKS) {
    const blob = new Blob(['Mock PDF Report'], { type: 'application/pdf' });
    triggerDownload(blob, `sentinel-report-${scanId}.pdf`);
    return;
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 30000);

  try {
    const res = await fetch(`${BASE_URL}/scan/${scanId}/report`, {
      signal: controller.signal,
    });
    if (!res.ok) throw new Error('Failed to download report');
    const blob = await res.blob();
    triggerDownload(blob, `sentinel-report-${scanId}.pdf`);
  } finally {
    clearTimeout(timeout);
  }
}

function triggerDownload(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

export async function checkBackendHealth(): Promise<boolean> {
  if (USE_MOCKS) return true;
  try {
    const res = await fetch(`${BASE_URL}/health`, {
      signal: AbortSignal.timeout(5000),
    });
    return res.ok;
  } catch {
    return false;
  }
}
