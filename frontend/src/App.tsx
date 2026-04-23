import { Routes, Route, Navigate } from 'react-router-dom'
import { CssBaseline, ThemeProvider } from '@mui/material'
import { lightTheme } from './theme/theme'
import { useAuthStore } from './store/authStore'
import LoginPage from './pages/LoginPage'
import MfaSetupPage from './pages/MfaSetupPage'

// Placeholder pages — implemented in M3+
const PlaceholderPage = ({ title }: { title: string }) => (
  <div style={{ padding: 32 }}>
    <h2>{title}</h2>
    <p>Coming soon in a future milestone.</p>
  </div>
)

// Guard component: redirects to /login if not authenticated
function RequireAuth({ children }: { children: React.ReactNode }) {
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated)
  return isAuthenticated ? <>{children}</> : <Navigate to="/login" replace />
}

function App() {
  return (
    <ThemeProvider theme={lightTheme}>
      <CssBaseline />
      <Routes>
        {/* Public routes */}
        <Route path="/login" element={<LoginPage />} />

        {/* Protected routes */}
        <Route path="/" element={<RequireAuth><Navigate to="/dashboard" replace /></RequireAuth>} />
        <Route path="/dashboard" element={<RequireAuth><PlaceholderPage title="Dashboard" /></RequireAuth>} />
        <Route path="/hosts" element={<RequireAuth><PlaceholderPage title="Hosts" /></RequireAuth>} />
        <Route path="/hosts/:id" element={<RequireAuth><PlaceholderPage title="Host Detail" /></RequireAuth>} />
        <Route path="/jobs" element={<RequireAuth><PlaceholderPage title="Jobs" /></RequireAuth>} />
        <Route path="/deployment" element={<RequireAuth><PlaceholderPage title="Patch Deployment" /></RequireAuth>} />
        <Route path="/maintenance" element={<RequireAuth><PlaceholderPage title="Maintenance Windows" /></RequireAuth>} />
        <Route path="/groups" element={<RequireAuth><PlaceholderPage title="Groups" /></RequireAuth>} />
        <Route path="/reports" element={<RequireAuth><PlaceholderPage title="Reports" /></RequireAuth>} />
        <Route path="/users" element={<RequireAuth><PlaceholderPage title="Users" /></RequireAuth>} />
        <Route path="/certificates" element={<RequireAuth><PlaceholderPage title="Certificates" /></RequireAuth>} />
        <Route path="/settings" element={<RequireAuth><PlaceholderPage title="Settings" /></RequireAuth>} />
        <Route path="/mfa/setup" element={<RequireAuth><MfaSetupPage /></RequireAuth>} />

        {/* 404 */}
        <Route path="*" element={<PlaceholderPage title="404 Not Found" />} />
      </Routes>
    </ThemeProvider>
  )
}

export default App
