import { useState } from 'react';
import { Scan, FileCode, Server, Shield, Network } from 'lucide-react';
import { api } from '../utils/api';
import FindingsTable from '../components/FindingsTable';

interface Props {
  t: (key: string) => string;
  lang: string;
}

type ScanType = 'config' | 'ssh' | 'vpn' | 'code';

interface ScanResult {
  findings: any[];
  summary?: any;
}

export default function Scanner({ t }: Props) {
  const [scanType, setScanType] = useState<ScanType>('config');
  const [target, setTarget] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [result, setResult] = useState<ScanResult | null>(null);

  const scanTypes: { type: ScanType; icon: any; label: string }[] = [
    { type: 'config', icon: FileCode, label: t('scan_type_config') },
    { type: 'ssh', icon: Server, label: t('scan_type_ssh') },
    { type: 'vpn', icon: Shield, label: t('scan_type_vpn') },
    { type: 'code', icon: Network, label: t('scan_type_code') },
  ];

  const handleScan = async () => {
    if (!target.trim()) return;
    setLoading(true);
    setError('');
    setResult(null);

    try {
      let res: any;
      const body = scanType === 'code'
        ? { directory: target }
        : { config_path: target };

      switch (scanType) {
        case 'config':
          res = await api.scanConfig(body);
          break;
        case 'ssh':
          res = await api.scanSSH(body);
          break;
        case 'vpn':
          res = await api.scanVPN(body);
          break;
        case 'code':
          res = await api.scanCode(body);
          break;
      }

      setResult(res);

      // Save to dashboard
      if (res?.findings) {
        const counts = { critical: 0, high: 0, medium: 0, low: 0, safe: 0 };
        let qv = 0;
        for (const f of res.findings) {
          const key = f.risk_level?.toLowerCase();
          if (key in counts) counts[key as keyof typeof counts]++;
          if (f.quantum_vulnerable) qv++;
        }
        const dashData = {
          total_findings: res.findings.length,
          ...counts,
          quantum_vulnerable: qv,
          overall_risk: counts.critical > 0 ? 'CRITICAL' : counts.high > 0 ? 'HIGH' : 'MEDIUM',
          findings: res.findings.slice(0, 20),
        };
        localStorage.setItem('pqc-dashboard', JSON.stringify(dashData));
      }
    } catch (err: any) {
      setError(err.message || 'Scan failed');
    } finally {
      setLoading(false);
    }
  };

  const placeholders: Record<ScanType, string> = {
    config: '/etc/nginx/nginx.conf',
    ssh: '/etc/ssh/sshd_config',
    vpn: '/etc/openvpn/server.conf',
    code: '/path/to/project/src',
  };

  return (
    <div>
      <div className="page-header">
        <h2><Scan size={24} style={{ verticalAlign: 'middle', marginRight: 8 }} />{t('scanner_title')}</h2>
      </div>

      <div className="card" style={{ marginBottom: 24 }}>
        {/* Scan type selector */}
        <div className="btn-group" style={{ marginBottom: 20 }}>
          {scanTypes.map(({ type, icon: Icon, label }) => (
            <button
              key={type}
              className={`btn ${scanType === type ? 'btn-primary' : 'btn-secondary'}`}
              onClick={() => { setScanType(type); setResult(null); }}
            >
              <Icon size={16} /> {label}
            </button>
          ))}
        </div>

        {/* Target input */}
        <div className="form-group">
          <label>{t('target_label')}</label>
          <input
            type="text"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder={placeholders[scanType]}
            onKeyDown={(e) => e.key === 'Enter' && handleScan()}
          />
        </div>

        <button
          className="btn btn-primary"
          onClick={handleScan}
          disabled={loading || !target.trim()}
        >
          {loading ? (
            <><span className="spinner" /> {t('scanning')}</>
          ) : (
            <><Scan size={16} /> {t('start_scan')}</>
          )}
        </button>
      </div>

      {error && <div className="alert error">{error}</div>}

      {result && (
        <div className="card">
          <div className="card-header">
            {t('results')} ({result.findings?.length || 0} findings)
          </div>
          <FindingsTable findings={result.findings || []} t={t} />
        </div>
      )}
    </div>
  );
}
