import { useState } from 'react';
import { FileText, Download, FileJson, Code, FileBarChart } from 'lucide-react';
import { api } from '../utils/api';

interface Props {
  t: (key: string) => string;
  lang: string;
}

type Format = 'html' | 'json' | 'sarif' | 'summary';

export default function Report({ t, lang }: Props) {
  const [format, setFormat] = useState<Format>('html');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [result, setResult] = useState<string>('');
  const [organization, setOrganization] = useState('');

  const formats: { type: Format; icon: any; label: string }[] = [
    { type: 'html', icon: FileText, label: t('format_html') },
    { type: 'json', icon: FileJson, label: t('format_json') },
    { type: 'sarif', icon: Code, label: t('format_sarif') },
    { type: 'summary', icon: FileBarChart, label: t('format_summary') },
  ];

  const handleGenerate = async () => {
    const dashData = localStorage.getItem('pqc-dashboard');
    if (!dashData) {
      setError(t('no_data'));
      return;
    }

    setLoading(true);
    setError('');
    setResult('');

    try {
      const dash = JSON.parse(dashData);
      const res: any = await api.generateReport({
        format,
        organization: organization || 'Organization',
        findings: dash.findings,
        language: lang,
      });
      setResult(typeof res === 'string' ? res : JSON.stringify(res, null, 2));
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const downloadResult = () => {
    if (!result) return;
    const ext = format === 'html' ? 'html' : format === 'sarif' ? 'sarif.json' : 'json';
    const mime = format === 'html' ? 'text/html' : 'application/json';
    const blob = new Blob([result], { type: mime });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `pqc-report.${ext}`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div>
      <div className="page-header">
        <h2><FileText size={24} style={{ verticalAlign: 'middle', marginRight: 8 }} />{t('report_title')}</h2>
      </div>

      <div className="card" style={{ marginBottom: 24 }}>
        {/* Format selector */}
        <div className="btn-group" style={{ marginBottom: 20 }}>
          {formats.map(({ type, icon: Icon, label }) => (
            <button
              key={type}
              className={`btn ${format === type ? 'btn-primary' : 'btn-secondary'}`}
              onClick={() => { setFormat(type); setResult(''); }}
            >
              <Icon size={16} /> {label}
            </button>
          ))}
        </div>

        <div className="form-group">
          <label>{lang === 'vi' ? 'Ten to chuc' : 'Organization'}</label>
          <input
            type="text"
            value={organization}
            onChange={(e) => setOrganization(e.target.value)}
            placeholder="e.g., VNPT, Viettel..."
          />
        </div>

        <div className="btn-group">
          <button className="btn btn-primary" onClick={handleGenerate} disabled={loading}>
            {loading ? <><span className="spinner" /> Generating...</> : <><FileText size={16} /> {t('generate_report')}</>}
          </button>
          {result && (
            <button className="btn btn-secondary" onClick={downloadResult}>
              <Download size={16} /> {t('download')}
            </button>
          )}
        </div>
      </div>

      {error && <div className="alert error">{error}</div>}

      {result && (
        <div className="card">
          <div className="card-header">{t('results')}</div>
          {format === 'html' ? (
            <iframe
              srcDoc={result}
              style={{
                width: '100%',
                height: 600,
                border: '1px solid var(--border)',
                borderRadius: 6,
                background: '#fff',
              }}
              title="Report preview"
            />
          ) : (
            <pre style={{
              background: 'var(--bg-primary)',
              padding: 16,
              borderRadius: 6,
              overflow: 'auto',
              maxHeight: 500,
              fontSize: 12,
              lineHeight: 1.5,
            }}>
              {result}
            </pre>
          )}
        </div>
      )}
    </div>
  );
}
