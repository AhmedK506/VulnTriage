import { useCallback, useState } from 'react'
import { useDropzone } from 'react-dropzone'
import { CloudArrowUpIcon, CheckCircleIcon, XCircleIcon, ClockIcon, TrashIcon, PlayIcon } from '@heroicons/react/24/outline'
import { uploadFile, listUploads, deleteUpload, runPipeline } from '../services/upload'
import { StatusBadge } from '../components/common/Badge'
import { Spinner } from '../components/common/Loading'
import EmptyState from '../components/common/EmptyState'
import clsx from 'clsx'
import { useEffect } from 'react'

const SCANNERS = [
  { value: 'zap',    label: 'OWASP ZAP',  ext: '.xml' },
  { value: 'nuclei', label: 'Nuclei',      ext: '.json, .jsonl' },
  { value: 'nessus', label: 'Nessus',      ext: '.nessus' },
]

export default function Upload() {
  const [scanner, setScanner]   = useState('zap')
  const [uploads, setUploads]   = useState([])
  const [uploading, setUploading] = useState(false)
  const [progress, setProgress] = useState(0)
  const [error, setError]       = useState('')
  const [success, setSuccess]   = useState('')
  const [pipeline, setPipeline] = useState({})   // { [id]: 'running'|'done'|'error' }
  const [runPoc,   setRunPoc]   = useState(false)
  const [pocScope, setPocScope] = useState('')
  const [searchExploits, setSearchExploits] = useState(false)

  useEffect(() => { loadUploads() }, [])

  async function loadUploads() {
    try {
      const { data } = await listUploads()
      setUploads(data.uploads)
    } catch { /* ignore */ }
  }

  const onDrop = useCallback(async (accepted) => {
    const file = accepted[0]
    if (!file) return
    setError('')
    setSuccess('')
    setUploading(true)
    setProgress(0)
    try {
      await uploadFile(file, scanner, setProgress)
      setSuccess(`${file.name} uploaded and parsed successfully.`)
      await loadUploads()
    } catch (e) {
      setError(e.response?.data?.error || 'Upload failed')
    } finally {
      setUploading(false)
      setProgress(0)
    }
  }, [scanner])

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    multiple: false,
    accept: { 'text/xml': ['.xml'], 'application/json': ['.json', '.jsonl'], 'application/octet-stream': ['.nessus'] },
  })

  async function handleDelete(id) {
    if (!confirm('Delete this upload and all its findings?')) return
    await deleteUpload(id)
    await loadUploads()
  }

  async function handlePipeline(id) {
    setPipeline((p) => ({ ...p, [id]: 'running' }))
    try {
      const { data } = await runPipeline(id, { runPoc, pocScope, searchExploits })
      const r = data.pipeline_results
      const ex = r.exploit_search
      setSuccess(
        `Pipeline complete — ${r.normalised ?? 0} findings normalised, ` +
        `${r.confidence_scored ?? 0} scored` +
        (ex?.available ? `, ${ex.total_exploits} exploit(s) found for ${ex.findings_with_exploits} finding(s)` : '') +
        (r.poc_validated != null ? `, ${r.poc_validated} PoC checks run` : '') +
        (r.report_id ? `, report #${r.report_id} generated` : '') + '.'
      )
      setPipeline((p) => ({ ...p, [id]: 'done' }))
      await loadUploads()
    } catch (e) {
      setPipeline((p) => ({ ...p, [id]: 'error' }))
      setError(e.response?.data?.error || 'Pipeline failed')
    }
  }

  return (
    <div className="max-w-4xl space-y-6">
      {/* Upload card */}
      <div className="card p-6">
        <h2 className="text-base font-semibold text-gray-800 mb-4">Upload Scanner Output</h2>

        {/* Scanner selector */}
        <div className="flex gap-2 mb-5">
          {SCANNERS.map((s) => (
            <button
              key={s.value}
              onClick={() => setScanner(s.value)}
              className={clsx(
                'px-4 py-2 rounded-lg text-sm font-medium border transition-all',
                scanner === s.value
                  ? 'bg-primary-600 text-white border-primary-600'
                  : 'bg-white text-gray-600 border-gray-300 hover:bg-gray-50'
              )}
            >
              {s.label}
              <span className="ml-1.5 text-xs opacity-60">{s.ext}</span>
            </button>
          ))}
        </div>

        {/* Drop zone */}
        <div
          {...getRootProps()}
          className={clsx(
            'border-2 border-dashed rounded-xl p-10 text-center cursor-pointer transition-colors',
            isDragActive ? 'border-primary-400 bg-primary-50' : 'border-gray-300 hover:border-primary-400 hover:bg-gray-50'
          )}
        >
          <input {...getInputProps()} />
          <CloudArrowUpIcon className="h-10 w-10 mx-auto text-gray-400 mb-3" />
          {isDragActive ? (
            <p className="text-primary-600 font-medium">Drop the file here</p>
          ) : (
            <>
              <p className="text-gray-600 font-medium">Drag & drop your scanner file here</p>
              <p className="text-gray-400 text-sm mt-1">or click to browse</p>
            </>
          )}
        </div>

        {/* Upload progress */}
        {uploading && (
          <div className="mt-4">
            <div className="flex items-center justify-between text-sm text-gray-600 mb-1">
              <span>Uploading & parsing…</span>
              <span>{progress}%</span>
            </div>
            <div className="w-full bg-gray-200 rounded-full h-2">
              <div className="bg-primary-600 h-2 rounded-full transition-all" style={{ width: `${progress}%` }} />
            </div>
          </div>
        )}

        {/* Alerts */}
        {error && (
          <div className="mt-4 flex items-center gap-2 p-3 rounded-lg bg-red-50 border border-red-200 text-red-700 text-sm">
            <XCircleIcon className="h-4 w-4 shrink-0" />
            {error}
          </div>
        )}
        {success && (
          <div className="mt-4 flex items-center gap-2 p-3 rounded-lg bg-green-50 border border-green-200 text-green-700 text-sm">
            <CheckCircleIcon className="h-4 w-4 shrink-0" />
            {success}
          </div>
        )}
      </div>

      {/* Analysis options */}
      <div className="card p-5 space-y-5">
        <h2 className="text-sm font-semibold text-gray-700">Pipeline Options</h2>

        {/* Exploit search toggle */}
        <div className="flex items-center justify-between">
          <div className="pr-4">
            <p className="text-sm font-semibold text-gray-800">Exploit Lookup (Exploit-DB)</p>
            <p className="text-xs text-gray-400 mt-0.5">
              Searches your local Exploit-DB (via <code>searchsploit</code>) for public exploits
              matching each finding, by CVE or title. Raises confidence and attaches EDB references.
            </p>
          </div>
          <Toggle on={searchExploits} onClick={() => setSearchExploits((v) => !v)} />
        </div>

        {/* PoC validation toggle */}
        <div className="flex items-center justify-between border-t border-gray-100 pt-5">
          <div className="pr-4">
            <p className="text-sm font-semibold text-gray-800">PoC Validation (live HTTP)</p>
            <p className="text-xs text-gray-400 mt-0.5">
              Makes live, non-destructive requests to target URLs to confirm vulnerabilities
              (XSS, SQLi, open redirect, LFI, headers, CORS). A confirmed PoC forces a "Confirmed"
              classification. Only enable if the target is accessible and you are authorised to test it.
            </p>
          </div>
          <Toggle on={runPoc} onClick={() => setRunPoc((v) => !v)} />
        </div>

        {/* Optional PoC scope */}
        {runPoc && (
          <div className="border-t border-gray-100 pt-4">
            <label className="text-xs font-semibold text-gray-600">
              Authorised scope (optional)
            </label>
            <input
              type="text"
              value={pocScope}
              onChange={(e) => setPocScope(e.target.value)}
              placeholder="e.g. juice-shop.local, 10.0.0.5  (leave blank = unrestricted)"
              className="input mt-1 w-full text-sm"
            />
            <p className="text-xs text-gray-400 mt-1">
              When set, PoC probes only fire at these hosts (or their subdomains); out-of-scope
              targets are skipped. Leave blank to probe whatever the findings point at.
            </p>
          </div>
        )}
      </div>

      {/* Upload history */}
      <div className="card">
        <div className="px-5 py-4 border-b border-gray-100">
          <h2 className="text-sm font-semibold text-gray-700">Upload History</h2>
          <p className="text-xs text-gray-400 mt-0.5">
            "Run Pipeline" applies the options selected above.
          </p>
        </div>

        {uploads.length === 0 ? (
          <EmptyState title="No uploads yet" message="Upload your first scanner file above." />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="bg-gray-50 border-b border-gray-100">
                <tr>
                  {['File', 'Scanner', 'Status', 'Findings', 'Uploaded', 'Actions'].map((h) => (
                    <th key={h} className="text-left px-4 py-3 text-xs font-semibold text-gray-500 uppercase tracking-wide">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-50">
                {uploads.map((u) => (
                  <tr key={u.id} className="hover:bg-gray-50 transition-colors">
                    <td className="px-4 py-3">
                      <p className="font-medium text-gray-900 truncate max-w-[200px]">{u.filename}</p>
                      <p className="text-xs text-gray-400">{(u.file_size / 1024).toFixed(1)} KB</p>
                    </td>
                    <td className="px-4 py-3 capitalize text-gray-600">{u.scanner_type}</td>
                    <td className="px-4 py-3"><StatusBadge status={u.status} /></td>
                    <td className="px-4 py-3 text-gray-700 font-mono">{u.vulnerability_count}</td>
                    <td className="px-4 py-3 text-gray-500 text-xs">{new Date(u.uploaded_at).toLocaleString()}</td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        {u.status === 'completed' && (
                          <button
                            onClick={() => handlePipeline(u.id)}
                            disabled={pipeline[u.id] === 'running'}
                            className="flex items-center gap-1 text-xs text-primary-600 hover:text-primary-800 disabled:opacity-50"
                            title="Run triage pipeline"
                          >
                            {pipeline[u.id] === 'running' ? <Spinner size="sm" /> : <PlayIcon className="h-4 w-4" />}
                            {pipeline[u.id] === 'running' ? 'Running…' : 'Run Pipeline'}
                          </button>
                        )}
                        <button
                          onClick={() => handleDelete(u.id)}
                          className="text-gray-400 hover:text-red-600 transition-colors"
                          title="Delete upload"
                        >
                          <TrashIcon className="h-4 w-4" />
                        </button>
                      </div>
                    </td>
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

function Toggle({ on, onClick }) {
  return (
    <button
      onClick={onClick}
      className={`relative inline-flex h-6 w-11 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 focus:outline-none ${on ? 'bg-primary-600' : 'bg-gray-200'}`}
    >
      <span className={`inline-block h-5 w-5 rounded-full bg-white shadow transform transition-transform duration-200 ${on ? 'translate-x-5' : 'translate-x-0'}`} />
    </button>
  )
}
