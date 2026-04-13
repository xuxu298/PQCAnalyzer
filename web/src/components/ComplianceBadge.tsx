interface Props {
  status: string;
}

export default function ComplianceBadge({ status }: Props) {
  const map: Record<string, string> = {
    compliant: 'pass',
    non_compliant: 'fail',
    partial: 'partial',
  };
  const cls = map[status] || 'fail';
  const label = status === 'compliant' ? 'PASS' : status === 'partial' ? 'PARTIAL' : 'FAIL';
  return <span className={`compliance-badge ${cls}`}>{label}</span>;
}
