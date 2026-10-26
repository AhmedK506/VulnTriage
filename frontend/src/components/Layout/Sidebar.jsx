import { NavLink } from 'react-router-dom'
import {
  HomeIcon,
  ArrowUpTrayIcon,
  BoltIcon,
  BugAntIcon,
  DocumentChartBarIcon,
  ShieldCheckIcon,
} from '@heroicons/react/24/outline'
import clsx from 'clsx'

const NAV = [
  { to: '/dashboard', icon: HomeIcon,              label: 'Dashboard' },
  { to: '/upload',    icon: ArrowUpTrayIcon,        label: 'Upload Scans' },
  { to: '/autoscan',  icon: BoltIcon,               label: 'Auto Scan' },
  { to: '/findings',  icon: BugAntIcon,             label: 'Findings' },
  { to: '/reports',   icon: DocumentChartBarIcon,   label: 'Reports' },
]

export default function Sidebar() {
  return (
    <aside className="hidden lg:flex flex-col w-60 bg-gray-900 min-h-screen">
      {/* Brand */}
      <div className="flex items-center gap-3 px-6 py-5 border-b border-gray-800">
        <ShieldCheckIcon className="h-8 w-8 text-primary-400 shrink-0" />
        <div>
          <p className="text-white font-bold text-sm leading-tight">VulnTriage</p>
          <p className="text-gray-500 text-xs">AI Vulnerability Analysis</p>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 px-3 py-4 space-y-1">
        {NAV.map(({ to, icon: Icon, label }) => (
          <NavLink
            key={to}
            to={to}
            className={({ isActive }) =>
              clsx(
                'flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-colors',
                isActive
                  ? 'bg-primary-600 text-white'
                  : 'text-gray-400 hover:text-white hover:bg-gray-800'
              )
            }
          >
            <Icon className="h-5 w-5 shrink-0" />
            {label}
          </NavLink>
        ))}
      </nav>

      {/* Version */}
      <div className="px-6 py-4 border-t border-gray-800">
        <p className="text-gray-600 text-xs">v1.0.0 — FYP 2026</p>
      </div>
    </aside>
  )
}
