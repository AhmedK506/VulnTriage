import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import {
  PieChart, Pie, Cell, Tooltip, Legend, ResponsiveContainer,
  BarChart, Bar, XAxis, YAxis, CartesianGrid,
} from 'recharts'
import {
  BugAntIcon, ShieldCheckIcon, ExclamationTriangleIcon,
  ArrowUpTrayIcon, ChartBarIcon, TrashIcon,
} from '@heroicons/react/24/outline'
import { getDashboardSummary, getTopFindings, clearScanData } from '../services/dashboard'
import StatCard from '../components/common/StatCard'
import { SeverityBadge, ClassificationBadge, CLASSIFICATION_LABELS } from '../components/common/Badge'
import { PageLoader } from '../components/common/Loading'
import EmptyState from '../components/common/EmptyState'

const SEVERITY_COLORS = {
  Critical: '#dc2626', High: '#ea580c', Medium: '#d97706',
  Low: '#16a34a', Informational: '#6b7280', Unknown: '#9ca3af',
}
// Keyed by the display labels (classData names are mapped through CLASSIFICATION_LABELS).
const CLASS_COLORS = {
  'Vulnerability Confirmed': '#16a34a', 'Needs Manual Verification': '#d97706',
  'Vulnerability Not Confirmed': '#dc2626', Unclassified: '#9ca3af',
}

export default function Dashboard() {
  const [summary, setSummary]   = useState(null)
  const [topFindings, setTopFindings] = useState([])
  const [loading, setLoading]   = useState(true)
  const [clearing, setClearing] = useState(false)

  function load() {
    return Promise.all([getDashboardSummary(), getTopFindings()])
      .then(([s, t]) => {
        setSummary(s.data)
        setTopFindings(t.data.top_findings)
      })
      .finally(() => setLoading(false))
  }

  useEffect(() => { load() }, [])

  async function handleClear() {
    if (!confirm(
      'Clear ALL scan data (uploads, findings, and reports) for a fresh session?\n\n' +
      'This cannot be undone. Your account and the CWE reference data are kept.'
    )) return
    setClearing(true)
    try {
      const { data } = await clearScanData()
      alert(`Cleared ${data.uploads_deleted} upload(s) and ${data.reports_deleted} report(s).`)
      await load()
    } catch {
      alert('Failed to clear data.')
    } finally {
      setClearing(false)
    }
  }

  if (loading) return <PageLoader />

  const severityData = summary
    ? Object.entries(summary.severity_breakdown).map(([name, value]) => ({ name, value }))
    : []

  const classData = summary
    ? Object.entries(summary.classification_breakdown)
        .map(([name, value]) => ({ name: CLASSIFICATION_LABELS[name] ?? name, value }))
    : []

  const scannerData = summary
    ? Object.entries(summary.scanner_breakdown).map(([name, value]) => ({ name, value }))
    : []

  const confirmed    = summary?.classification_breakdown?.['Confirmed'] ?? 0
  const needsReview  = summary?.classification_breakdown?.['Needs Manual Verification'] ?? 0
  const notConfirmed = summary?.classification_breakdown?.['Not Confirmed'] ?? 0

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold text-gray-900">Dashboard</h1>
        <button
          onClick={handleClear}
          disabled={clearing || (summary?.total_findings ?? 0) === 0}
          className="btn-secondary text-xs disabled:opacity-40"
          title="Delete all uploads, findings and reports to start a fresh session"
        >
          <TrashIcon className="h-4 w-4" />
          {clearing ? 'Clearing…' : 'Clear Data'}
        </button>
      </div>

      {/* Stats row */}
      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
        <StatCard
          label="Total Findings"
          value={summary?.total_findings ?? 0}
          icon={BugAntIcon}
          color="blue"
        />
        <StatCard
          label="Confirmed"
          value={confirmed}
          sub="High-confidence vulnerabilities"
          icon={ShieldCheckIcon}
          color="green"
        />
        <StatCard
          label="Needs Review"
          value={needsReview}
          sub="Require manual analysis"
          icon={ExclamationTriangleIcon}
          color="amber"
        />
        <StatCard
          label="Total Uploads"
          value={summary?.upload_count ?? 0}
          icon={ArrowUpTrayIcon}
          color="purple"
        />
      </div>

      {/* Charts row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Severity breakdown */}
        <div className="card p-5">
          <h2 className="text-sm font-semibold text-gray-700 mb-4">Severity Breakdown</h2>
          {severityData.length === 0 ? (
            <EmptyState title="No findings yet" />
          ) : (
            <ResponsiveContainer width="100%" height={220}>
              <PieChart>
                <Pie data={severityData} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={80} label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`} labelLine={false}>
                  {severityData.map((entry) => (
                    <Cell key={entry.name} fill={SEVERITY_COLORS[entry.name] ?? '#9ca3af'} />
                  ))}
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          )}
        </div>

        {/* Classification breakdown */}
        <div className="card p-5">
          <h2 className="text-sm font-semibold text-gray-700 mb-4">Classification Results</h2>
          {classData.length === 0 ? (
            <EmptyState title="No classifications yet" message="Upload and run the pipeline to classify findings." />
          ) : (
            <ResponsiveContainer width="100%" height={220}>
              <PieChart>
                <Pie data={classData} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={80}>
                  {classData.map((entry) => (
                    <Cell key={entry.name} fill={CLASS_COLORS[entry.name] ?? '#9ca3af'} />
                  ))}
                </Pie>
                <Tooltip />
                <Legend iconSize={10} />
              </PieChart>
            </ResponsiveContainer>
          )}
        </div>

        {/* Scanner breakdown */}
        <div className="card p-5">
          <h2 className="text-sm font-semibold text-gray-700 mb-4">Scans by Tool</h2>
          {scannerData.length === 0 ? (
            <EmptyState title="No uploads yet" />
          ) : (
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={scannerData} margin={{ top: 5, right: 10, left: -20, bottom: 5 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#f0f0f0" />
                <XAxis dataKey="name" tick={{ fontSize: 12 }} />
                <YAxis tick={{ fontSize: 12 }} />
                <Tooltip />
                <Bar dataKey="value" name="Uploads" fill="#3b82f6" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          )}
        </div>
      </div>

      {/* Top findings table */}
      <div className="card">
        <div className="flex items-center justify-between px-5 py-4 border-b border-gray-100">
          <h2 className="text-sm font-semibold text-gray-700 flex items-center gap-2">
            <ChartBarIcon className="h-4 w-4 text-gray-400" />
            Top 10 Findings by CVSS Score
          </h2>
          <Link to="/findings" className="text-xs text-primary-600 hover:underline">View all →</Link>
        </div>

        {topFindings.length === 0 ? (
          <EmptyState
            title="No findings yet"
            message="Upload scanner results and run the pipeline to see findings here."
            action={
              <Link to="/upload" className="btn-primary">Upload Scans</Link>
            }
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="bg-gray-50 border-b border-gray-100">
                <tr>
                  {['Vulnerability', 'Severity', 'CVSS', 'Classification', 'Scanner', 'CWE'].map((h) => (
                    <th key={h} className="text-left px-4 py-3 text-xs font-semibold text-gray-500 uppercase tracking-wide">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-50">
                {topFindings.map((f) => (
                  <tr key={f.id} className="hover:bg-gray-50 transition-colors">
                    <td className="px-4 py-3">
                      <Link to={`/findings/${f.id}`} className="font-medium text-gray-900 hover:text-primary-600 line-clamp-1 block max-w-xs">
                        {f.title}
                      </Link>
                      {f.url && <span className="text-xs text-gray-400 truncate block max-w-xs">{f.url}</span>}
                    </td>
                    <td className="px-4 py-3"><SeverityBadge severity={f.severity} /></td>
                    <td className="px-4 py-3 font-mono text-gray-700">{f.cvss_score?.toFixed(1) ?? '—'}</td>
                    <td className="px-4 py-3"><ClassificationBadge classification={f.classification} /></td>
                    <td className="px-4 py-3 text-gray-500 capitalize">{f.scanner_sources?.join(', ') ?? '—'}</td>
                    <td className="px-4 py-3 text-gray-500 font-mono text-xs">{f.cwe_id ?? '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}
