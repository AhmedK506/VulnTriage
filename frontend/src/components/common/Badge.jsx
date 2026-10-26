import clsx from 'clsx'

const SEVERITY_STYLES = {
  Critical:      'bg-red-100 text-red-800',
  High:          'bg-orange-100 text-orange-800',
  Medium:        'bg-amber-100 text-amber-800',
  Low:           'bg-green-100 text-green-800',
  Informational: 'bg-gray-100 text-gray-700',
  Unknown:       'bg-gray-100 text-gray-500',
}

const CLASSIFICATION_STYLES = {
  'Confirmed':               'bg-green-100 text-green-800',
  'Needs Manual Verification':'bg-amber-100 text-amber-800',
  'Not Confirmed':           'bg-red-100 text-red-800',
  'Informational':           'bg-blue-100 text-blue-700',
  'Unclassified':            'bg-gray-100 text-gray-500',
}

// Tester-friendly display labels. The internal/stored values stay unchanged
// (used for DB, report counts, thresholds); only the shown text differs.
export const CLASSIFICATION_LABELS = {
  'Confirmed':                'Vulnerability Confirmed',
  'Needs Manual Verification':'Needs Manual Verification',
  'Not Confirmed':            'Vulnerability Not Confirmed',
  'Informational':            'Informational',
  'Unclassified':             'Unclassified',
}

const PRIORITY_STYLES = {
  Critical: 'bg-red-100 text-red-800',
  High:     'bg-orange-100 text-orange-800',
  Medium:   'bg-amber-100 text-amber-800',
  Low:      'bg-green-100 text-green-800',
}

const STATUS_STYLES = {
  completed:  'bg-green-100 text-green-800',
  processing: 'bg-blue-100 text-blue-800',
  pending:    'bg-gray-100 text-gray-600',
  failed:     'bg-red-100 text-red-800',
}

export function SeverityBadge({ severity }) {
  return (
    <span className={clsx('badge', SEVERITY_STYLES[severity] ?? SEVERITY_STYLES.Unknown)}>
      {severity ?? 'Unknown'}
    </span>
  )
}

export function ClassificationBadge({ classification }) {
  const key = classification ?? 'Unclassified'
  return (
    <span className={clsx('badge', CLASSIFICATION_STYLES[key] ?? CLASSIFICATION_STYLES.Unclassified)}>
      {CLASSIFICATION_LABELS[key] ?? key}
    </span>
  )
}

export function PriorityBadge({ priority }) {
  return (
    <span className={clsx('badge', PRIORITY_STYLES[priority] ?? 'bg-gray-100 text-gray-500')}>
      {priority ?? '—'}
    </span>
  )
}

export function StatusBadge({ status }) {
  return (
    <span className={clsx('badge', STATUS_STYLES[status] ?? 'bg-gray-100 text-gray-500')}>
      {status}
    </span>
  )
}
