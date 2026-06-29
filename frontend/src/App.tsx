import { useEffect } from 'react'
import { Routes, Route, Navigate } from 'react-router-dom'
import { CssBaseline, ThemeProvider, CircularProgress, Box } from '@mui/material'
import { darkTheme } from './theme/theme'
import { useAuthStore } from './store/authStore'
import AppLayout from './components/AppLayout'
import LoginPage from './pages/LoginPage'
import SsoCallbackPage from './pages/SsoCallbackPage'
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
import ProfilePage from './pages/ProfilePage'
import RepoManagementPage from './pages/RepoManagementPage'

function RequireAuth({ children }: { children: React.ReactNode }) {
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated)
  const isRestoring = useAuthStore((s) => s.isRestoring)

  if (isRestoring) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100vh' }}>
        <CircularProgress />
      </Box>
    )
  }

  return isAuthenticated ? <>{children}</> : <Navigate to="/login" replace />
}

/**
 * Waits for Zustand persist to finish rehydrating from localStorage,
 * then calls restoreSession() so it can see the persisted refreshToken.
 * Includes a safety timeout in case anything hangs.
 */
function AuthRestorer({ children }: { children: React.ReactNode }) {
  const restoreSession = useAuthStore((s) => s.restoreSession)

  useEffect(() => {
    let cancelled = false

    // Safety timeout: force isRestoring=false if restoration doesn't complete in 15s
    const timeout = setTimeout(() => {
      if (!cancelled) {
        console.warn('[auth] Restoration timeout — forcing isRestoring=false')
        useAuthStore.setState({ isRestoring: false })
      }
    }, 15_000)

    const doRestore = () => {
      if (!cancelled) restoreSession()
    }

    let unsub: (() => void) | undefined

    // Only call restoreSession AFTER Zustand has rehydrated the persisted state
    if (useAuthStore.persist.hasHydrated()) {
      console.warn('[auth] Store already hydrated, restoring session')
      doRestore()
    } else {
      console.warn('[auth] Waiting for Zustand hydration...')
      unsub = useAuthStore.persist.onFinishHydration(() => {
        console.warn('[auth] Hydration complete, restoring session')
        doRestore()
      })
    }

    return () => {
      cancelled = true
      clearTimeout(timeout)
      unsub?.()
    }
  }, [restoreSession])

  return <>{children}</>
}

function App() {
  return (
    <ThemeProvider theme={darkTheme}>
      <CssBaseline />
      <AuthRestorer>
        <Routes>
          {/* Public */}
          <Route path="/login" element={<LoginPage />} />
          <Route path="/auth/sso/callback" element={<SsoCallbackPage />} />

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
            <Route path="/repo" element={<RepoManagementPage />} />
            <Route path="/settings" element={<SettingsPage />} />
            <Route path="/profile" element={<ProfilePage />} />
          </Route>

          <Route path="*" element={<Navigate to="/dashboard" replace />} />
        </Routes>
      </AuthRestorer>
    </ThemeProvider>
  )
}

export default App
