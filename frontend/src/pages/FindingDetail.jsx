import { useEffect, useState } from 'react'
import { useParams, useNavigate, Link } from 'react-router-dom'
import { ArrowLeftIcon, PencilIcon, CheckIcon } from '@heroicons/react/24/outline'
import { getFinding, updateClassification } from '../services/vulnerabilities'
import { SeverityBadge, ClassificationBadge, PriorityBadge, CLASSIFICATION_LABELS } from '../components/common/Badge'
import { PageLoader } from '../components/common/Loading'

const CLASSIFICATIONS = ['Confirmed', 'Needs Manual Verification', 'Not Confirmed', 'Informational']

const FACTOR_LABELS = {
  scanner_agreement:    'Scanner Agreement',
  severity_consistency: 'Severity Consistency',
  cve_availability:     'CVE Available',
  cwe_mapping:          'CWE Mapped',
  ml_priority:          'ML Priority',          // legacy records
  exploit_availability: 'Exploit Available',
  poc_validation:       'PoC Validation',
}

export default function FindingDetail() {
  const { id }      = useParams()
  const navigate    = useNavigate()
  const [finding, setFinding] = useState(null)
  const [loading, setLoading] = useState(true)
  const [editing, setEditing] = useState(false)
  const [newClass, setNewClass] = useState('')
  const [saving, setSaving]   = useState(false)

  useEffect(() => {
    getFinding(id)
      .then(({ data }) => { setFinding(data); setNewClass(data.classification ?? '') })
      .finally(() => setLoading(false))
  }, [id])

  async function saveClassification() {
    setSaving(true)
    try {
      await updateClassification(id, newClass)
      setFinding((f) => ({ ...f, classification: newClass }))
      setEditing(false)
    } finally {
      setSaving(false)
    }
  }

  if (loading) return <PageLoader />
  if (!finding) return <p className="text-gray-500">Finding not found.</p>

  const cs = finding.confidence_score
  const ml = finding.ml_prediction
  const rawBreakdown = cs?.factor_breakdown ?? {}
  // v2 breakdowns nest factors under `.factors` + add a `.rationale`; older
  // records stored factors at the top level. Support both.
  const breakdown = rawBreakdown.factors ?? rawBreakdown
  const rationale = rawBreakdown.rationale ?? null

  return (
    <div className="max-w-4xl space-y-6">
      {/* Back + title */}
      <div className="flex items-start gap-3">
        <button onClick={() => navigate(-1)} className="mt-0.5 text-gray-400 hover:text-gray-700">
          <ArrowLeftIcon className="h-5 w-5" />
        </button>
        <div className="flex-1 min-w-0">
          <h1 className="text-xl font-bold text-gray-900 leading-tight">{finding.title}</h1>
          {finding.url && <p className="text-sm text-gray-400 mt-0.5 truncate">{finding.url}</p>}
        </div>
      </div>

      {/* Overview badges */}
      <div className="card p-5 flex flex-wrap gap-4">
        <Detail label="Severity">   <SeverityBadge severity={finding.severity} /></Detail>
        <Detail label="CVSS Score"> <span className="font-mono font-bold text-gray-800">{finding.cvss_score?.toFixed(1) ?? '—'}</span></Detail>
        <Detail label="CWE">        <span className="font-mono text-gray-700">{finding.cwe_id ?? '—'}</span></Detail>
        <Detail label="CVE">        <span className="font-mono text-gray-700">{finding.cve_id ?? '—'}</span></Detail>
        <Detail label="Method">     <span className="font-mono text-gray-700">{finding.method ?? '—'}</span></Detail>
        <Detail label="Scanners">   <span className="capitalize text-gray-700">{finding.scanner_sources?.join(', ') ?? '—'} ({finding.scanner_count})</span></Detail>
      </div>

      {/* Classification control */}
      <div className="card p-5">
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-sm font-semibold text-gray-700">Classification</h2>
          {!editing && (
            <button onClick={() => setEditing(true)} className="flex items-center gap-1 text-xs text-primary-600 hover:text-primary-800">
              <PencilIcon className="h-3.5 w-3.5" />Override
            </button>
          )}
        </div>
        {editing ? (
          <div className="flex items-center gap-3">
            <select value={newClass} onChange={(e) => setNewClass(e.target.value)} className="input w-auto text-sm">
              {CLASSIFICATIONS.map((c) => <option key={c} value={c}>{CLASSIFICATION_LABELS[c] ?? c}</option>)}
            </select>
            <button onClick={saveClassification} disabled={saving} className="btn-primary text-xs">
              <CheckIcon className="h-4 w-4" />Save
            </button>
            <button onClick={() => setEditing(false)} className="btn-secondary text-xs">Cancel</button>
          </div>
        ) : (
          <ClassificationBadge classification={finding.classification} />
        )}
      </div>

      {/* Confidence score */}
      {cs && (
        <div className="card p-5">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-sm font-semibold text-gray-700">Confidence Score</h2>
            <span className="text-2xl font-bold text-gray-900">{cs.score.toFixed(1)}<span className="text-sm text-gray-400">/100</span></span>
          </div>
          <div className="w-full bg-gray-200 rounded-full h-3 mb-4">
            <div
              className={`h-3 rounded-full ${cs.score >= 70 ? 'bg-green-500' : cs.score >= 40 ? 'bg-amber-500' : 'bg-red-500'}`}
              style={{ width: `${cs.score}%` }}
            />
          </div>
          {rationale && (
            <p className="text-sm text-gray-600 bg-gray-50 border border-gray-100 rounded-lg p-3 mb-5 leading-relaxed">
              {rationale}
            </p>
          )}
          <div className="space-y-3">
            {Object.entries(breakdown).map(([key, info]) => (
              <div key={key} className="text-sm">
                <div className="flex items-center gap-3">
                  <span className="w-40 text-gray-500 shrink-0">{FACTOR_LABELS[key] ?? key}</span>
                  <div className="flex-1 bg-gray-100 rounded-full h-2">
                    <div
                      className="bg-primary-500 h-2 rounded-full"
                      style={{ width: `${info.raw_score ?? 0}%` }}
                    />
                  </div>
                  <span className="w-12 text-right font-mono text-xs text-gray-600">
                    +{(info.contribution ?? 0).toFixed(1)}
                  </span>
                  <span className="text-xs text-gray-400 w-14">wt {info.weight}%</span>
                </div>
                {info.reason && (
                  <p className="ml-40 pl-3 mt-1 text-xs text-gray-400">{info.reason}</p>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ML Prediction */}
      {ml && (
        <div className="card p-5">
          <h2 className="text-sm font-semibold text-gray-700 mb-3">ML Priority Prediction</h2>
          <div className="flex items-center gap-4 mb-4">
            <PriorityBadge priority={ml.predicted_priority} />
            <span className="text-xs text-gray-400">model v{ml.model_version}</span>
          </div>
          <div className="grid grid-cols-4 gap-2">
            {[
              { label: 'Critical', val: ml.prob_critical },
              { label: 'High',     val: ml.prob_high },
              { label: 'Medium',   val: ml.prob_medium },
              { label: 'Low',      val: ml.prob_low },
            ].map(({ label, val }) => (
              <div key={label} className="text-center">
                <div className="text-xs text-gray-500 mb-1">{label}</div>
                <div className="text-sm font-bold text-gray-800">{((val ?? 0) * 100).toFixed(0)}%</div>
                <div className="w-full bg-gray-100 rounded h-1.5 mt-1">
                  <div className="bg-primary-500 h-1.5 rounded" style={{ width: `${(val ?? 0) * 100}%` }} />
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* CVSS Metrics */}
      {finding.attack_vector && (
        <div className="card p-5">
          <h2 className="text-sm font-semibold text-gray-700 mb-3">CVSS v3 Metrics</h2>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            {[
              ['Attack Vector',      finding.attack_vector],
              ['Attack Complexity',  finding.attack_complexity],
              ['Privileges Req.',    finding.privileges_required],
              ['User Interaction',   finding.user_interaction],
              ['Scope',              finding.scope],
              ['Confidentiality',    finding.confidentiality_impact],
              ['Integrity',          finding.integrity_impact],
              ['Availability',       finding.availability_impact],
            ].map(([label, val]) => (
              <div key={label} className="bg-gray-50 rounded-lg p-3 text-center">
                <p className="text-xs text-gray-400 mb-1">{label}</p>
                <p className="text-sm font-semibold text-gray-800 capitalize">{val?.toLowerCase() ?? '—'}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Description & Solution */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="card p-5">
          <h2 className="text-sm font-semibold text-gray-700 mb-2">Description</h2>
          <p className="text-sm text-gray-600 leading-relaxed whitespace-pre-line">{finding.description || 'No description available.'}</p>
        </div>
        <div className="card p-5">
          <h2 className="text-sm font-semibold text-gray-700 mb-2">Recommended Solution</h2>
          <p className="text-sm text-gray-600 leading-relaxed whitespace-pre-line">{finding.solution || 'No solution provided.'}</p>
        </div>
      </div>

      {/* PoC Validations */}
      {finding.poc_validations?.length > 0 && (
        <div className="card p-5">
          <h2 className="text-sm font-semibold text-gray-700 mb-3">PoC Validation Results</h2>
          <div className="space-y-3">
            {finding.poc_validations.map((v) => (
              <div key={v.id} className="border border-gray-100 rounded-lg p-4">
                <div className="flex items-center gap-3 mb-2">
                  <span className={`badge ${v.result === 'confirmed' ? 'bg-green-100 text-green-800' : v.result === 'not_confirmed' ? 'bg-gray-100 text-gray-600' : 'bg-red-100 text-red-700'}`}>
                    {v.result}
                  </span>
                  <span className="text-xs text-gray-500 font-mono">{v.validation_type}</span>
                  <span className="text-xs text-gray-400">{v.http_method} {v.target_url}</span>
                </div>
                {v.evidence && <p className="text-xs text-gray-600 font-mono bg-gray-50 rounded p-2 mt-1">{v.evidence}</p>}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

function Detail({ label, children }) {
  return (
    <div>
      <p className="text-xs text-gray-400 mb-0.5">{label}</p>
      {children}
    </div>
  )
}
