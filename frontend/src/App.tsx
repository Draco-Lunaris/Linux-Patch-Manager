import { Routes, Route, Navigate } from 'react-router-dom'
import { CssBaseline, ThemeProvider } from '@mui/material'
import { darkTheme } from './theme/theme'
import { useAuthStore } from './store/authStore'
import AppLayout from './components/AppLayout'
import LoginPage from './pages/LoginPage'
import MfaSetupPage from './pages/MfaSetupPage'
import HostsPage from './pages/HostsPage'
import HostDetailPage from './pages/HostDetailPage'
import GroupsPage from './pages/GroupsPage'
import UsersPage from './pages/UsersPage'
import DashboardPage from './pages/DashboardPage'
import PatchDeploymentPage from './pages/PatchDeploymentPage'
import JobsPage from './pages/JobsPage'
import MaintenanceWindowsPage from './pages/MaintenanceWindowsPage'
import CertificatesPage from './pages/CertificatesPage'
import ReportsPage from './pages/ReportsPage'
import SettingsPage from './pages/SettingsPage'

function RequireAuth({ children }: { children: React.ReactNode }) {
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated)
  return isAuthenticated ? <>{children}</> : <Navigate to="/login" replace />
}

function App() {
  return (
    <ThemeProvider theme={darkTheme}>
      <CssBaseline />
      <Routes>
        {/* Public */}
        <Route path="/login" element={<LoginPage />} />

        {/* Protected — wrapped in AppLayout with sidebar navigation */}
        <Route element={<RequireAuth><AppLayout /></RequireAuth>}>
          <Route path="/" element={<Navigate to="/dashboard" replace />} />
          <Route path="/mfa/setup" element={<MfaSetupPage />} />
          <Route path="/dashboard" element={<DashboardPage />} />
          <Route path="/hosts" element={<HostsPage />} />
          <Route path="/hosts/:id" element={<HostDetailPage />} />
          <Route path="/groups" element={<GroupsPage />} />
          <Route path="/users" element={<UsersPage />} />
          <Route path="/jobs" element={<JobsPage />} />
          <Route path="/deployment" element={<PatchDeploymentPage />} />
          <Route path="/maintenance" element={<MaintenanceWindowsPage />} />
          <Route path="/reports" element={<ReportsPage />} />
          <Route path="/certificates" element={<CertificatesPage />} />
          <Route path="/settings" element={<SettingsPage />} />
        </Route>

        <Route path="*" element={<Navigate to="/dashboard" replace />} />
      </Routes>
    </ThemeProvider>
  )
}

export default App
