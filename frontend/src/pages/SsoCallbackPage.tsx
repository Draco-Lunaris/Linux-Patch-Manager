import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Box, Container, Paper, Typography, Alert, Button, CircularProgress,
} from '@mui/material'
import { useAuthStore } from '../store/authStore'
import type { User } from '../types'

export default function SsoCallbackPage() {
  const navigate = useNavigate()
  const { setTokens, setUser } = useAuthStore()
  const [error, setError] = useState<string | null>(null)
  const [processing, setProcessing] = useState(true)

  useEffect(() => {
    const params = new URLSearchParams(window.location.search)

    // Check for error from backend
    const errorCode = params.get('error')
    const errorDescription = params.get('error_description')
    if (errorCode) {
      setError(errorDescription || `SSO authentication failed: ${errorCode}`)
      setProcessing(false)
      return
    }

    // Extract tokens
    const accessToken = params.get('access_token')
    const refreshToken = params.get('refresh_token')

    if (!accessToken || !refreshToken) {
      setError('Missing authentication tokens. Please try logging in again.')
      setProcessing(false)
      return
    }

    // Parse user JSON from query param
    const userParam = params.get('user')
    if (!userParam) {
      setError('Missing user information. Please try logging in again.')
      setProcessing(false)
      return
    }

    let parsedUser: Record<string, unknown>
    try {
      parsedUser = JSON.parse(userParam)
    } catch {
      setError('Malformed user data received. Please try logging in again.')
      setProcessing(false)
      return
    }

    // Build a full User object from the SSO subset, filling in sensible defaults
    // auth_provider comes from the backend based on the OIDC provider type
    const authProvider = (parsedUser.auth_provider as string) || 'azure_sso'
    const user: User = {
      id: (parsedUser.id as string) || '',
      username: (parsedUser.username as string) || '',
      display_name: (parsedUser.display_name as string) || '',
      email: (parsedUser.email as string) || '',
      role: (parsedUser.role as User['role']) || 'operator',
      auth_provider: authProvider as User['auth_provider'],
      mfa_enabled: (parsedUser.mfa_enabled as boolean) ?? false,
      is_active: true,
      force_password_reset: false,
    }

    // Store tokens and user, then navigate
    setTokens(accessToken, refreshToken)
    setUser(user)
    navigate('/dashboard', { replace: true })
  }, [setTokens, setUser, navigate])

  return (
    <Container maxWidth="xs" sx={{ mt: 12 }}>
      <Paper elevation={4} sx={{ p: 4 }}>
        <Typography variant="h5" fontWeight={700} mb={3} align="center">
          🐉 Linux Patch Manager
        </Typography>

        {processing ? (
          <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'center', py: 4 }}>
            <CircularProgress size={48} sx={{ mb: 2 }} />
            <Typography variant="body1" color="text.secondary">
              Completing sign-in…
            </Typography>
          </Box>
        ) : (
          <Box>
            <Alert severity="error" sx={{ mb: 2 }}>
              {error}
            </Alert>
            <Button
              fullWidth
              variant="contained"
              size="large"
              onClick={() => navigate('/login', { replace: true })}
            >
              Back to Login
            </Button>
          </Box>
        )}
      </Paper>
    </Container>
  )
}
