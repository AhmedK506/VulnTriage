import { useEffect, useState, useCallback } from 'react'
import {
  DocumentArrowDownIcon,
  DocumentChartBarIcon,
  PlusIcon,
  XMarkIcon,
  ArrowPathIcon,
} from '@heroicons/react/24/outline'
import { listReports, downloadReport, generateReport } from '../services/reports'
import { listUploads } from '../services/upload'
import { StatusBadge } from '../components/common/Badge'
import { PageLoader, Spinner } from '../components/common/Loading'
import EmptyState from '../components/common/EmptyState'

export default function Reports() {
  const [reports,    setReports]    = useState([])
  const [loading,    setLoading]    = useState(true)
  const [showModal,  setShowModal]  = useState(false)
  const [generating, setGenerating] = useState(false)
  const [genError,   setGenError]   = useState('')

  const load = useCallback(() =>
    listReports().then(({ data }) => setReports(data.reports)).finally(() => setLoading(false)),
  [])

  useEffect(() => { load() }, [load])

  async function handleDownload(id, type) {
    try {
      const { data } = await downloadReport(id)
      const url  = URL.createObjectURL(new Blob([data], { type: 'application/pdf' }))
      const link = document.createElement('a')
      link.href     = url
      link.download = `vuln_report_${id}.${type}`
      link.click()
      URL.revokeObjectURL(url)
    } catch {
      alert('Download failed — report may not be ready yet.')
    }
  }

  async function handleGenerate(uploadIds, title) {
    setGenerating(true)
    setGenError('')
    try {
      await generateReport(uploadIds, title)
      setShowModal(false)
      setLoading(true)
      await load()
    } catch (e) {
      setGenError(e.response?.data?.error || 'Report generation failed')
    } finally {
      setGenerating(false)
    }
  }

  if (loading) return <PageLoader />

  return (
    <div className="max-w-5xl space-y-4">
      {/* Header row */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-gray-900">Reports</h1>
          <p className="text-sm text-gray-500 mt-0.5">
            Generate and download PDF vulnerability triage reports.
          </p>
        </div>
        <button onClick={() => setShowModal(true)} className="btn-primary flex items-center gap-2">
          <PlusIcon className="h-4 w-4" />
          Generate Report
        </button>
      </div>

      {/* Info banner */}
      <div className="card p-4 bg-blue-50 border-blue-200 flex items-start gap-3">
        <DocumentChartBarIcon className="h-5 w-5 text-blue-600 mt-0.5 shrink-0" />
        <p className="text-sm text-blue-700">
          Reports are generated as PDF documents containing an executive summary,
          severity and classification breakdowns, detailed findings, ML analysis,
          and CWE-based remediation recommendations.
          Reports are also auto-generated after each pipeline run.
        </p>
      </div>

      {/* Reports table */}
      <div className="card">
        <div className="px-5 py-4 border-b border-gray-100 flex items-center justify-between">
          <h2 className="text-sm font-semibold text-gray-700">Generated Reports</h2>
          <button
            onClick={() => { setLoading(true); load() }}
            className="text-gray-400 hover:text-gray-600"
            title="Refresh"
          >
            <ArrowPathIcon className="h-4 w-4" />
          </button>
        </div>

        {reports.length === 0 ? (
          <EmptyState
            title="No reports yet"
            message="Generate a report above, or run the triage pipeline on an uploaded scan."
            action={
              <button onClick={() => setShowModal(true)} className="btn-primary">
                Generate Report
              </button>
            }
          />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="bg-gray-50 border-b border-gray-100">
                <tr>
                  {['Title', 'Type', 'Findings', 'Status', 'Generated', 'Download'].map((h) => (
                    <th key={h} className="text-left px-4 py-3 text-xs font-semibold text-gray-500 uppercase tracking-wide">
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-50">
                {reports.map((r) => (
                  <tr key={r.id} className="hover:bg-gray-50 transition-colors">
                    <td className="px-4 py-3 font-medium text-gray-900 max-w-xs truncate">{r.title}</td>
                    <td className="px-4 py-3 uppercase text-gray-500 text-xs font-mono">{r.report_type}</td>
                    <td className="px-4 py-3">
                      <div className="text-xs space-y-0.5 text-gray-600">
                        <p>Total: <span className="font-semibold">{r.total_findings}</span></p>
                        <p className="text-green-700">Confirmed: {r.confirmed_count}</p>
                        <p className="text-red-600">Not Confirmed: {r.not_confirmed_count}</p>
                      </div>
                    </td>
                    <td className="px-4 py-3"><StatusBadge status={r.status} /></td>
                    <td className="px-4 py-3 text-gray-500 text-xs whitespace-nowrap">
                      {r.generated_at ? new Date(r.generated_at).toLocaleString() : '—'}
                    </td>
                    <td className="px-4 py-3">
                      {r.status === 'completed' ? (
                        <button
                          onClick={() => handleDownload(r.id, r.report_type)}
                          className="flex items-center gap-1.5 text-primary-600 hover:text-primary-800 text-sm font-medium"
                        >
                          <DocumentArrowDownIcon className="h-4 w-4" />
                          Download PDF
                        </button>
                      ) : (
                        <span className="text-gray-400 text-xs">
                          {r.status === 'generating' ? 'Generating…' : '—'}
                        </span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Generate Report Modal */}
      {showModal && (
        <GenerateModal
          onClose={() => { setShowModal(false); setGenError('') }}
          onGenerate={handleGenerate}
          generating={generating}
          error={genError}
        />
      )}
    </div>
  )
}

// ── Generate Report Modal ───────────────────────────────────────────────────

function GenerateModal({ onClose, onGenerate, generating, error }) {
  const [uploads,    setUploads]    = useState([])
  const [selected,   setSelected]   = useState([])    // upload IDs
  const [title,      setTitle]      = useState('')
  const [loadingUpl, setLoadingUpl] = useState(true)

  useEffect(() => {
    listUploads()
      .then(({ data }) => {
        const completed = data.uploads.filter((u) => u.status === 'completed')
        setUploads(completed)
      })
      .finally(() => setLoadingUpl(false))
  }, [])

  function toggleUpload(id) {
    setSelected((s) => s.includes(id) ? s.filter((x) => x !== id) : [...s, id])
  }

  function submit() {
    const finalTitle =
      title.trim() ||
      `Vulnerability Triage Report — ${new Date().toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' })}`
    onGenerate(selected, finalTitle)
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-sm">
      <div className="bg-white rounded-2xl shadow-2xl w-full max-w-lg mx-4 overflow-hidden">
        {/* Modal header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-gray-100">
          <h3 className="text-base font-semibold text-gray-900">Generate PDF Report</h3>
          <button onClick={onClose} className="text-gray-400 hover:text-gray-700">
            <XMarkIcon className="h-5 w-5" />
          </button>
        </div>

        {/* Body */}
        <div className="px-6 py-5 space-y-4">
          {/* Title input */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">Report Title</label>
            <input
              type="text"
              placeholder="Leave blank to auto-generate"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              className="input w-full"
            />
          </div>

          {/* Upload scope */}
          <div>
            <label className="block text-sm font-medium text-gray-700 mb-1">
              Scope (uploads to include)
            </label>
            <p className="text-xs text-gray-400 mb-2">
              Leave all unchecked to include every finding for your account.
            </p>

            {loadingUpl ? (
              <div className="flex justify-center py-4"><Spinner size="md" /></div>
            ) : uploads.length === 0 ? (
              <p className="text-sm text-gray-500">No completed uploads found.</p>
            ) : (
              <div className="max-h-48 overflow-y-auto border border-gray-200 rounded-lg divide-y divide-gray-100">
                {uploads.map((u) => (
                  <label key={u.id} className="flex items-center gap-3 px-4 py-2.5 hover:bg-gray-50 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={selected.includes(u.id)}
                      onChange={() => toggleUpload(u.id)}
                      className="h-4 w-4 rounded border-gray-300 text-primary-600"
                    />
                    <div className="min-w-0">
                      <p className="text-sm font-medium text-gray-800 truncate">{u.filename}</p>
                      <p className="text-xs text-gray-400 capitalize">{u.scanner_type} · {u.vulnerability_count} vulns</p>
                    </div>
                  </label>
                ))}
              </div>
            )}
          </div>

          {error && (
            <p className="text-sm text-red-600 bg-red-50 rounded-lg px-3 py-2">{error}</p>
          )}
        </div>

        {/* Footer */}
        <div className="flex items-center justify-end gap-3 px-6 py-4 border-t border-gray-100">
          <button onClick={onClose} className="btn-secondary" disabled={generating}>Cancel</button>
          <button
            onClick={submit}
            disabled={generating}
            className="btn-primary flex items-center gap-2 min-w-[140px] justify-center"
          >
            {generating ? (
              <><Spinner size="sm" /><span>Generating…</span></>
            ) : (
              <><DocumentChartBarIcon className="h-4 w-4" /><span>Generate PDF</span></>
            )}
          </button>
        </div>
      </div>
    </div>
  )
}
