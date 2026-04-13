import { useState } from 'react';
import { Map, Play } from 'lucide-react';
import { api } from '../utils/api';
import RiskBadge from '../components/RiskBadge';
import ComplianceBadge from '../components/ComplianceBadge';

interface Props {
  t: (key: string) => string;
  lang: string;
}

export default function Roadmap({ t, lang }: Props) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [roadmap, setRoadmap] = useState<any>(null);
  const [organization, setOrganization] = useState('');

  const handleGenerate = async () => {
    // Use findings from localStorage
    const dashData = localStorage.getItem('pqc-dashboard');
    if (!dashData) {
      setError(t('no_data'));
      return;
    }
    const dash = JSON.parse(dashData);

    setLoading(true);
    setError('');
    try {
      const res = await api.generateRoadmap({
        organization: organization || 'Organization',
        findings: dash.findings,
        language: lang,
      });
      setRoadmap(res);
    } catch (err: any) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  const PHASE_NAMES = [
    'Assessment & Planning',
    'Quick Wins',
    'Core Migration',
    'Full PQC Transition',
  ];

  const PHASE_COLORS = ['#14A3C7', '#48BB78', '#ED8936', '#E53E3E'];

  return (
    <div>
      <div className="page-header">
        <h2><Map size={24} style={{ verticalAlign: 'middle', marginRight: 8 }} />{t('roadmap_title')}</h2>
      </div>

      <div className="card" style={{ marginBottom: 24 }}>
        <div className="form-group">
          <label>{lang === 'vi' ? 'Ten to chuc' : 'Organization Name'}</label>
          <input
            type="text"
            value={organization}
            onChange={(e) => setOrganization(e.target.value)}
            placeholder="e.g., VNPT, Viettel, FPT..."
          />
        </div>
        <button className="btn btn-primary" onClick={handleGenerate} disabled={loading}>
          {loading ? <><span className="spinner" /> Generating...</> : <><Play size={16} /> {t('generate_roadmap')}</>}
        </button>
      </div>

      {error && <div className="alert error">{error}</div>}

      {roadmap && (
        <>
          {/* Summary */}
          <div className="stats-grid">
            <div className="stat-card">
              <span className="stat-label">Overall Risk</span>
              <span className="stat-value"><RiskBadge level={roadmap.overall_risk || 'MEDIUM'} /></span>
            </div>
            <div className="stat-card">
              <span className="stat-label">{t('total_findings')}</span>
              <span className="stat-value">{roadmap.total_findings || 0}</span>
            </div>
            <div className="stat-card critical">
              <span className="stat-label">{t('critical_findings')}</span>
              <span className="stat-value">{roadmap.critical_findings || 0}</span>
            </div>
            <div className="stat-card high">
              <span className="stat-label">{t('quantum_vulnerable')}</span>
              <span className="stat-value">{roadmap.quantum_vulnerable_count || 0}</span>
            </div>
          </div>

          {/* Phases */}
          {(roadmap.phases || []).map((phase: any, idx: number) => (
            <div className="phase-card" key={idx}>
              <div className="phase-header">
                <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                  <div className="phase-number" style={{ background: PHASE_COLORS[idx] || '#14A3C7' }}>
                    {phase.phase_number}
                  </div>
                  <div>
                    <div className="phase-name">{phase.name || PHASE_NAMES[idx]}</div>
                    <div className="phase-timeline">{phase.timeline}</div>
                  </div>
                </div>
                <div style={{ textAlign: 'right', fontSize: 13, color: 'var(--text-secondary)' }}>
                  {phase.total_effort_hours || 0}h {t('effort')}
                </div>
              </div>
              {phase.tasks && phase.tasks.length > 0 && (
                <ul className="task-list">
                  {phase.tasks.map((task: any, ti: number) => (
                    <li key={ti}>
                      <span>
                        <RiskBadge level={task.risk_level || 'MEDIUM'} />
                        {' '}{task.title}
                      </span>
                      <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
                        {task.effort_hours || 0}h
                      </span>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          ))}

          {/* Cost */}
          {roadmap.cost_estimate && (
            <div className="card" style={{ marginBottom: 16 }}>
              <div className="card-header">{t('cost_estimate')}</div>
              <div className="grid-3">
                <div>
                  <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>Total Hours</div>
                  <div style={{ fontSize: 24, fontWeight: 700 }}>{roadmap.cost_estimate.total_person_hours}h</div>
                </div>
                <div>
                  <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>Timeline</div>
                  <div style={{ fontSize: 24, fontWeight: 700 }}>{roadmap.cost_estimate.timeline_months} months</div>
                </div>
                <div>
                  <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>Cost (VND)</div>
                  <div style={{ fontSize: 18, fontWeight: 700, color: 'var(--accent)' }}>
                    {roadmap.cost_estimate.total_cost_vnd?.toLocaleString('vi-VN')} VND
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Compliance */}
          {roadmap.compliance && roadmap.compliance.length > 0 && (
            <div className="card">
              <div className="card-header">{t('compliance_status')}</div>
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Standard</th>
                    <th>Requirement</th>
                    <th>Status</th>
                    <th>Details</th>
                  </tr>
                </thead>
                <tbody>
                  {roadmap.compliance.map((c: any, i: number) => (
                    <tr key={i}>
                      <td><strong>{c.standard}</strong></td>
                      <td>{c.requirement}</td>
                      <td><ComplianceBadge status={c.status} /></td>
                      <td style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{c.details}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </>
      )}
    </div>
  );
}
