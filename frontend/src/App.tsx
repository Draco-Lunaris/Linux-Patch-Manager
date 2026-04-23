import { Routes, Route, Navigate } from 'react-router-dom'
import { CssBaseline, ThemeProvider } from '@mui/material'
import { lightTheme } from './theme/theme'
import { useAuthStore } from './store/authStore'
import LoginPage from './pages/LoginPage'
import MfaSetupPage from './pages/MfaSetupPage'
import HostsPage from './pages/HostsPage'
import HostDetailPage from './pages/HostDetailPage'
import GroupsPage from './pages/GroupsPage'
import UsersPage from './pages/UsersPage'
import DashboardPage from './pages/DashboardPage'
import PatchDeploymentPage from './pages/PatchDeploymentPage'
import JobsPage from './pages/JobsPage'

// Placeholder pages — implemented in later milestones
const PlaceholderPage = ({ title }: { title: string }) => (
  <div style={{ padding: 32 }}>
    <h2>{title}</h2>
    <p>Coming soon in a future milestone.</p>
  </div>
)

function RequireAuth({ children }: { children: React.ReactNode }) {
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated)
  return isAuthenticated ? <>{children}</> : <Navigate to="/login" replace />
}

function App() {
  return (
    <ThemeProvider theme={lightTheme}>
      <CssBaseline />
      <Routes>
        {/* Public */}
        <Route path="/login" element={<LoginPage />} />

        {/* Protected — M2 */}
        <Route path="/" element={<RequireAuth><Navigate to="/dashboard" replace /></RequireAuth>} />
        <Route path="/mfa/setup" element={<RequireAuth><MfaSetupPage /></RequireAuth>} />

        {/* Protected — M3 */}
        <Route path="/dashboard" element={<RequireAuth><DashboardPage /></RequireAuth>} />
        <Route path="/hosts" element={<RequireAuth><HostsPage /></RequireAuth>} />
        <Route path="/hosts/:id" element={<RequireAuth><HostDetailPage /></RequireAuth>} />
        <Route path="/groups" element={<RequireAuth><GroupsPage /></RequireAuth>} />
        <Route path="/users" element={<RequireAuth><UsersPage /></RequireAuth>} />

        {/* Protected — later milestones */}
        <Route path="/jobs" element={<RequireAuth><JobsPage /></RequireAuth>} />
        <Route path="/deployment" element={<RequireAuth><PatchDeploymentPage /></RequireAuth>} />
        <Route path="/maintenance" element={<RequireAuth><PlaceholderPage title="Maintenance Windows" /></RequireAuth>} />
        <Route path="/reports" element={<RequireAuth><PlaceholderPage title="Reports" /></RequireAuth>} />
        <Route path="/certificates" element={<RequireAuth><PlaceholderPage title="Certificates" /></RequireAuth>} />
        <Route path="/settings" element={<RequireAuth><PlaceholderPage title="Settings" /></RequireAuth>} />

        <Route path="*" element={<PlaceholderPage title="404 Not Found" />} />
      </Routes>
    </ThemeProvider>
  )
}

export default App
