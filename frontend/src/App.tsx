import { Routes, Route, Navigate } from 'react-router-dom'
import { CssBaseline, ThemeProvider } from '@mui/material'
import { lightTheme } from './theme/theme'

// Placeholder pages — implemented in M2+
const PlaceholderPage = ({ title }: { title: string }) => (
  <div style={{ padding: 32 }}>
    <h2>{title}</h2>
    <p>Coming soon in a future milestone.</p>
  </div>
)

function App() {
  return (
    <ThemeProvider theme={lightTheme}>
      <CssBaseline />
      <Routes>
        <Route path="/" element={<Navigate to="/dashboard" replace />} />
        <Route path="/dashboard" element={<PlaceholderPage title="Dashboard" />} />
        <Route path="/hosts" element={<PlaceholderPage title="Hosts" />} />
        <Route path="/hosts/:id" element={<PlaceholderPage title="Host Detail" />} />
        <Route path="/jobs" element={<PlaceholderPage title="Jobs" />} />
        <Route path="/deployment" element={<PlaceholderPage title="Patch Deployment" />} />
        <Route path="/maintenance" element={<PlaceholderPage title="Maintenance Windows" />} />
        <Route path="/groups" element={<PlaceholderPage title="Groups" />} />
        <Route path="/reports" element={<PlaceholderPage title="Reports" />} />
        <Route path="/users" element={<PlaceholderPage title="Users" />} />
        <Route path="/certificates" element={<PlaceholderPage title="Certificates" />} />
        <Route path="/settings" element={<PlaceholderPage title="Settings" />} />
        <Route path="/login" element={<PlaceholderPage title="Login" />} />
        <Route path="*" element={<PlaceholderPage title="404 Not Found" />} />
      </Routes>
    </ThemeProvider>
  )
}

export default App
