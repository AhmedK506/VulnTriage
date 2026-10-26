import { useEffect, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { MagnifyingGlassIcon, FunnelIcon } from '@heroicons/react/24/outline'
import { listFindings } from '../services/vulnerabilities'
import { SeverityBadge, ClassificationBadge, PriorityBadge, CLASSIFICATION_LABELS } from '../components/common/Badge'
import { PageLoader } from '../components/common/Loading'
import EmptyState from '../components/common/EmptyState'

const SEVERITIES       = ['Critical', 'High', 'Medium', 'Low', 'Informational']
const CLASSIFICATIONS  = ['Confirmed', 'Needs Manual Verification', 'Not Confirmed', 'Informational']

export default function Findings() {
  const [searchParams, setSearchParams] = useSearchParams()
  const [findings, setFindings] = useState([])
  const [total, setTotal]       = useState(0)
  const [pages, setPages]       = useState(1)
  const [loading, setLoading]   = useState(true)

  const page           = Number(searchParams.get('page') || 1)
  const severity       = searchParams.get('severity') || ''
  const classification = searchParams.get('classification') || ''

  useEffect(() => {
    setLoading(true)
    const params = { page, per_page: 50 }
    if (severity)       params.severity       = severity
    if (classification) params.classification = classification

    listFindings(params)
      .then(({ data }) => {
        setFindings(data.findings)
        setTotal(data.total)
        setPages(data.pages)
      })
      .finally(() => setLoading(false))
  }, [page, severity, classification])

  function setFilter(key, value) {
    const next = new URLSearchParams(searchParams)
    if (value) next.set(key, value)
    else next.delete(key)
    next.delete('page')
    setSearchParams(next)
  }

  function setPage(p) {
    const next = new URLSearchParams(searchParams)
    next.set('page', p)
    setSearchParams(next)
  }

  return (
    <div className="space-y-4">
      {/* Filters */}
      <div className="card p-4 flex flex-wrap gap-3 items-center">
        <FunnelIcon className="h-4 w-4 text-gray-400 shrink-0" />

        <select
          value={severity}
          onChange={(e) => setFilter('severity', e.target.value)}
          className="input w-auto text-sm"
        >
          <option value="">All Severities</option>
          {SEVERITIES.map((s) => <option key={s}>{s}</option>)}
        </select>

        <select
          value={classification}
          onChange={(e) => setFilter('classification', e.target.value)}
          className="input w-auto text-sm"
        >
          <option value="">All Classifications</option>
          {CLASSIFICATIONS.map((c) => <option key={c} value={c}>{CLASSIFICATION_LABELS[c] ?? c}</option>)}
        </select>

        <span className="ml-auto text-sm text-gray-500">
          {total.toLocaleString()} finding{total !== 1 ? 's' : ''}
        </span>
      </div>

      {/* Table */}
      <div className="card">
        {loading ? (
          <PageLoader />
        ) : findings.length === 0 ? (
          <EmptyState
            title="No findings match your filters"
            message="Try adjusting the filters or upload and run the pipeline on a scanner file."
            action={<Link to="/upload" className="btn-primary">Upload Scans</Link>}
          />
        ) : (
          <>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="bg-gray-50 border-b border-gray-100">
                  <tr>
                    {['Vulnerability', 'Severity', 'CVSS', 'Priority (ML)', 'Confidence', 'Classification', 'Scanners'].map((h) => (
                      <th key={h} className="text-left px-4 py-3 text-xs font-semibold text-gray-500 uppercase tracking-wide whitespace-nowrap">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-50">
                  {findings.map((f) => (
                    <tr key={f.id} className="hover:bg-gray-50 transition-colors">
                      <td className="px-4 py-3 max-w-xs">
                        <Link
                          to={`/findings/${f.id}`}
                          className="font-medium text-gray-900 hover:text-primary-600 block truncate"
                        >
                          {f.title}
                        </Link>
                        {f.url && (
                          <span className="text-xs text-gray-400 block truncate">{f.url}</span>
                        )}
                        {f.cwe_id && (
                          <span className="text-xs font-mono text-gray-400">{f.cwe_id}</span>
                        )}
                      </td>
                      <td className="px-4 py-3 whitespace-nowrap"><SeverityBadge severity={f.severity} /></td>
                      <td className="px-4 py-3 font-mono text-gray-700 whitespace-nowrap">
                        {f.cvss_score != null ? f.cvss_score.toFixed(1) : '—'}
                      </td>
                      <td className="px-4 py-3 whitespace-nowrap">
                        <PriorityBadge priority={f.ml_prediction?.predicted_priority} />
                      </td>
                      <td className="px-4 py-3 whitespace-nowrap">
                        {f.confidence_score ? (
                          <ConfidenceMeter score={f.confidence_score.score} />
                        ) : '—'}
                      </td>
                      <td className="px-4 py-3 whitespace-nowrap">
                        <ClassificationBadge classification={f.classification} />
                      </td>
                      <td className="px-4 py-3 text-gray-500 capitalize text-xs">
                        {f.scanner_sources?.join(', ') ?? '—'}
                        {f.scanner_count > 1 && (
                          <span className="ml-1 badge bg-blue-100 text-blue-700">{f.scanner_count}</span>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Pagination */}
            {pages > 1 && (
              <div className="flex items-center justify-between px-4 py-3 border-t border-gray-100">
                <button
                  onClick={() => setPage(page - 1)}
                  disabled={page <= 1}
                  className="btn-secondary text-xs disabled:opacity-40"
                >
                  Previous
                </button>
                <span className="text-sm text-gray-500">Page {page} of {pages}</span>
                <button
                  onClick={() => setPage(page + 1)}
                  disabled={page >= pages}
                  className="btn-secondary text-xs disabled:opacity-40"
                >
                  Next
                </button>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  )
}

function ConfidenceMeter({ score }) {
  const color =
    score >= 70 ? 'bg-green-500' :
    score >= 40 ? 'bg-amber-500' :
                  'bg-red-500'
  return (
    <div className="flex items-center gap-2">
      <div className="w-16 bg-gray-200 rounded-full h-1.5">
        <div className={`${color} h-1.5 rounded-full`} style={{ width: `${score}%` }} />
      </div>
      <span className="text-xs text-gray-600 tabular-nums">{score.toFixed(0)}</span>
    </div>
  )
}
