import { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  PieChart, Pie, Cell, ResponsiveContainer, Tooltip,
} from 'recharts';
import { Scan, Gauge, FileText, ShieldAlert, Shield } from 'lucide-react';
import RiskBadge from '../components/RiskBadge';

interface Props {
  t: (key: string) => string;
  lang: string;
}

interface DashboardData {
  total_findings: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  safe: number;
  quantum_vulnerable: number;
  overall_risk: string;
  findings: {
    risk_level: string;
    component: string;
    algorithm: string;
    location: string;
  }[];
}

const RISK_COLORS = ['#E53E3E', '#ED8936', '#ECC94B', '#48BB78', '#38B2AC'];

export default function Dashboard({ t }: Props) {
  const navigate = useNavigate();
  const [data, setData] = useState<DashboardData | null>(null);

  // Load data from localStorage (saved after scans)
  useEffect(() => {
    const saved = localStorage.getItem('pqc-dashboard');
    if (saved) {
      try { setData(JSON.parse(saved)); } catch { /* ignore */ }
    }
  }, []);

  const pieData = data ? [
    { name: 'Critical', value: data.critical },
    { name: 'High', value: data.high },
    { name: 'Medium', value: data.medium },
    { name: 'Low', value: data.low },
    { name: 'Safe', value: data.safe },
  ].filter(d => d.value > 0) : [];

  const readinessScore = data
    ? Math.max(0, Math.round(100 - (data.critical * 15 + data.high * 8 + data.medium * 3) / Math.max(data.total_findings, 1) * 10))
    : 0;

  const topFindings = data?.findings
    ?.filter(f => f.risk_level === 'CRITICAL' || f.risk_level === 'HIGH')
    .slice(0, 5) || [];

  if (!data) {
    return (
      <div>
        <div className="page-header">
          <h2>{t('dashboard_title')}</h2>
        </div>
        <div className="empty-state">
          <ShieldAlert size={48} />
          <p style={{ marginTop: 16, fontSize: 16 }}>{t('no_data')}</p>
          <div className="btn-group" style={{ justifyContent: 'center', marginTop: 24 }}>
            <button className="btn btn-primary" onClick={() => navigate('/scanner')}>
              <Scan size={16} /> {t('run_scan')}
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div>
      <div className="page-header">
        <h2>{t('dashboard_title')}</h2>
      </div>

      {/* Stats */}
      <div className="stats-grid">
        <div className="stat-card">
          <span className="stat-label">{t('overall_score')}</span>
          <span className="stat-value" style={{ color: readinessScore < 40 ? '#E53E3E' : readinessScore < 70 ? '#ECC94B' : '#48BB78' }}>
            {readinessScore}/100
          </span>
        </div>
        <div className="stat-card critical">
          <span className="stat-label">{t('critical_findings')}</span>
          <span className="stat-value">{data.critical}</span>
        </div>
        <div className="stat-card high">
          <span className="stat-label">{t('quantum_vulnerable')}</span>
          <span className="stat-value">{data.quantum_vulnerable}</span>
        </div>
        <div className="stat-card">
          <span className="stat-label">{t('total_findings')}</span>
          <span className="stat-value">{data.total_findings}</span>
        </div>
        <div className="stat-card safe">
          <span className="stat-label">{t('safe_algorithms')}</span>
          <span className="stat-value">{data.safe}</span>
        </div>
      </div>

      <div className="grid-2">
        {/* Pie chart */}
        <div className="card">
          <div className="card-header">{t('risk_distribution')}</div>
          <ResponsiveContainer width="100%" height={260}>
            <PieChart>
              <Pie
                data={pieData}
                cx="50%"
                cy="50%"
                innerRadius={60}
                outerRadius={100}
                paddingAngle={2}
                dataKey="value"
                label={({ name, value }) => `${name}: ${value}`}
              >
                {pieData.map((_, idx) => (
                  <Cell key={idx} fill={RISK_COLORS[['Critical', 'High', 'Medium', 'Low', 'Safe'].indexOf(pieData[idx].name)]} />
                ))}
              </Pie>
              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
        </div>

        {/* Top urgent */}
        <div className="card">
          <div className="card-header">{t('top_urgent')}</div>
          {topFindings.length === 0 ? (
            <div className="empty-state" style={{ padding: 20 }}>
              <Shield size={32} />
              <p style={{ marginTop: 8 }}>No critical findings</p>
            </div>
          ) : (
            <ul className="task-list">
              {topFindings.map((f, i) => (
                <li key={i}>
                  <span>
                    <RiskBadge level={f.risk_level} />{' '}
                    <strong>{f.algorithm}</strong> — {f.component}
                  </span>
                  <span style={{ fontSize: 11, color: 'var(--text-secondary)' }}>{f.location}</span>
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>

      {/* Quick actions */}
      <div className="card">
        <div className="card-header">{t('quick_actions')}</div>
        <div className="btn-group">
          <button className="btn btn-primary" onClick={() => navigate('/scanner')}>
            <Scan size={16} /> {t('run_scan')}
          </button>
          <button className="btn btn-secondary" onClick={() => navigate('/benchmark')}>
            <Gauge size={16} /> {t('run_benchmark')}
          </button>
          <button className="btn btn-secondary" onClick={() => navigate('/report')}>
            <FileText size={16} /> {t('generate_report')}
          </button>
        </div>
      </div>
    </div>
  );
}
