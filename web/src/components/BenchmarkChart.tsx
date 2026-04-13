import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer,
} from 'recharts';

interface Props {
  data: { name: string; classical: number; pqc: number }[];
  title: string;
  unit?: string;
}

export default function BenchmarkChart({ data, title, unit = 'ms' }: Props) {
  if (data.length === 0) return null;

  return (
    <div className="card">
      <div className="card-header">{title}</div>
      <ResponsiveContainer width="100%" height={300}>
        <BarChart data={data} margin={{ top: 5, right: 20, bottom: 5, left: 0 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="#2D3748" />
          <XAxis dataKey="name" tick={{ fill: '#A0AEC0', fontSize: 12 }} />
          <YAxis tick={{ fill: '#A0AEC0', fontSize: 12 }} unit={` ${unit}`} />
          <Tooltip
            contentStyle={{
              background: '#1A2332',
              border: '1px solid #2D3748',
              borderRadius: '6px',
              color: '#E2E8F0',
            }}
          />
          <Legend />
          <Bar dataKey="classical" fill="#ED8936" name="Classical" radius={[4, 4, 0, 0]} />
          <Bar dataKey="pqc" fill="#14A3C7" name="PQC" radius={[4, 4, 0, 0]} />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
