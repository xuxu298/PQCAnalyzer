import { useState, useEffect } from 'react';
import { Gauge, Cpu, Play } from 'lucide-react';
import { api } from '../utils/api';
import BenchmarkChart from '../components/BenchmarkChart';

interface Props {
  t: (key: string) => string;
  lang: string;
}

export default function Benchmark({ t }: Props) {
  const [hardware, setHardware] = useState<any>(null);
  const [kemResults, setKemResults] = useState<any[]>([]);
  const [signResults, setSignResults] = useState<any[]>([]);
  const [loading, setLoading] = useState<string>('');
  const [error, setError] = useState('');
  const [iterations, setIterations] = useState(100);

  useEffect(() => {
    api.getHardware()
      .then(setHardware)
      .catch(() => { /* API not available */ });
  }, []);

  const runKEM = async () => {
    setLoading('kem');
    setError('');
    try {
      const res: any = await api.benchKEM({ iterations });
      const chartData = (res.comparisons || []).map((c: any) => ({
        name: `${c.classical_name} vs ${c.pqc_name}`,
        classical: c.classical_keygen_ms || 0,
        pqc: c.pqc_keygen_ms || 0,
      }));
      setKemResults(chartData);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading('');
    }
  };

  const runSign = async () => {
    setLoading('sign');
    setError('');
    try {
      const res: any = await api.benchSign({ iterations });
      const chartData = (res.comparisons || []).map((c: any) => ({
        name: `${c.classical_name} vs ${c.pqc_name}`,
        classical: c.classical_sign_ms || 0,
        pqc: c.pqc_sign_ms || 0,
      }));
      setSignResults(chartData);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading('');
    }
  };

  return (
    <div>
      <div className="page-header">
        <h2><Gauge size={24} style={{ verticalAlign: 'middle', marginRight: 8 }} />{t('benchmark_title')}</h2>
      </div>

      {/* Hardware info */}
      {hardware && (
        <div className="card" style={{ marginBottom: 24 }}>
          <div className="card-header"><Cpu size={14} style={{ verticalAlign: 'middle', marginRight: 6 }} />{t('benchmark_hardware')}</div>
          <div className="grid-3">
            <div>
              <strong>CPU:</strong> {hardware.cpu_model || 'Unknown'}
            </div>
            <div>
              <strong>Cores:</strong> {hardware.cpu_cores || '-'}
            </div>
            <div>
              <strong>RAM:</strong> {hardware.ram_gb ? `${hardware.ram_gb} GB` : '-'}
            </div>
          </div>
          {hardware.cpu_flags && (
            <div style={{ marginTop: 8, fontSize: 12, color: 'var(--text-secondary)' }}>
              <strong>Crypto flags:</strong>{' '}
              {hardware.cpu_flags.filter((f: string) => ['aes', 'avx2', 'avx512f', 'sha_ni'].includes(f.toLowerCase())).join(', ') || 'none detected'}
            </div>
          )}
        </div>
      )}

      {/* Controls */}
      <div className="card" style={{ marginBottom: 24 }}>
        <div className="form-group">
          <label>{t('iterations')}</label>
          <input
            type="number"
            value={iterations}
            onChange={(e) => setIterations(Number(e.target.value))}
            min={10}
            max={10000}
            style={{ width: 200 }}
          />
        </div>

        <div className="btn-group">
          <button className="btn btn-primary" onClick={runKEM} disabled={!!loading}>
            {loading === 'kem' ? <><span className="spinner" /> Running...</> : <><Play size={16} /> {t('benchmark_kem')}</>}
          </button>
          <button className="btn btn-primary" onClick={runSign} disabled={!!loading}>
            {loading === 'sign' ? <><span className="spinner" /> Running...</> : <><Play size={16} /> {t('benchmark_sign')}</>}
          </button>
        </div>
      </div>

      {error && <div className="alert error">{error}</div>}

      {/* Results */}
      <div className="grid-2">
        {kemResults.length > 0 && (
          <BenchmarkChart data={kemResults} title="KEM Key Generation" unit="ms" />
        )}
        {signResults.length > 0 && (
          <BenchmarkChart data={signResults} title="Signature Performance" unit="ms" />
        )}
      </div>

      {kemResults.length === 0 && signResults.length === 0 && !loading && (
        <div className="empty-state">
          <Gauge size={48} />
          <p style={{ marginTop: 16 }}>Run a benchmark to see performance comparison between classical and PQC algorithms.</p>
        </div>
      )}
    </div>
  );
}
