import { InboxIcon } from '@heroicons/react/24/outline'

export default function EmptyState({ title = 'No data', message, action }) {
  return (
    <div className="flex flex-col items-center justify-center py-16 text-center">
      <InboxIcon className="h-12 w-12 text-gray-300 mb-4" />
      <h3 className="text-sm font-semibold text-gray-700">{title}</h3>
      {message && <p className="mt-1 text-sm text-gray-400 max-w-xs">{message}</p>}
      {action && <div className="mt-4">{action}</div>}
    </div>
  )
}
