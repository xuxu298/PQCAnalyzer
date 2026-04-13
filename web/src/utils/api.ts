const BASE = '/api';

async function request<T>(path: string, options?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    headers: { 'Content-Type': 'application/json' },
    ...options,
  });
  if (!res.ok) {
    const detail = await res.text().catch(() => res.statusText);
    throw new Error(`API ${res.status}: ${detail}`);
  }
  return res.json();
}

export const api = {
  // Health
  health: () => request<{ status: string }>('/health'),

  // Scanner
  scanConfig: (body: object) => request('/scan/config', { method: 'POST', body: JSON.stringify(body) }),
  scanSSH: (body: object) => request('/scan/ssh', { method: 'POST', body: JSON.stringify(body) }),
  scanVPN: (body: object) => request('/scan/vpn', { method: 'POST', body: JSON.stringify(body) }),
  scanCode: (body: object) => request('/scan/code', { method: 'POST', body: JSON.stringify(body) }),

  // Benchmark
  getHardware: () => request('/benchmark/hardware'),
  benchKEM: (body: object) => request('/benchmark/kem', { method: 'POST', body: JSON.stringify(body) }),
  benchSign: (body: object) => request('/benchmark/sign', { method: 'POST', body: JSON.stringify(body) }),

  // Roadmap
  generateRoadmap: (body: object) => request('/roadmap/generate', { method: 'POST', body: JSON.stringify(body) }),

  // Reports
  generateReport: (body: object) => request('/report/generate', { method: 'POST', body: JSON.stringify(body) }),
  generateHTML: (body: object) => request('/report/html', { method: 'POST', body: JSON.stringify(body) }),
  getFormats: () => request('/report/formats'),
};
