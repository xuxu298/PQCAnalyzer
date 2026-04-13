interface Props {
  level: string;
}

export default function RiskBadge({ level }: Props) {
  const cls = level.toLowerCase();
  return <span className={`risk-badge ${cls}`}>{level}</span>;
}
