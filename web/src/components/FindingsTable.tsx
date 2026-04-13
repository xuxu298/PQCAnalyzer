import RiskBadge from './RiskBadge';

interface Finding {
  risk_level: string;
  component: string;
  algorithm: string;
  quantum_vulnerable: boolean;
  location: string;
  replacement?: string[];
}

interface Props {
  findings: Finding[];
  t: (key: string) => string;
}

export default function FindingsTable({ findings, t }: Props) {
  if (findings.length === 0) {
    return <div className="empty-state"><p>{t('no_data')}</p></div>;
  }

  return (
    <table className="data-table">
      <thead>
        <tr>
          <th>Risk</th>
          <th>Component</th>
          <th>Algorithm</th>
          <th>QV</th>
          <th>Location</th>
          <th>Replacement</th>
        </tr>
      </thead>
      <tbody>
        {findings.map((f, i) => (
          <tr key={i}>
            <td><RiskBadge level={f.risk_level} /></td>
            <td>{f.component}</td>
            <td><code>{f.algorithm}</code></td>
            <td>{f.quantum_vulnerable ? '!!!' : '-'}</td>
            <td style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>{f.location}</td>
            <td style={{ fontSize: '12px' }}>{f.replacement?.join(', ') || '-'}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
