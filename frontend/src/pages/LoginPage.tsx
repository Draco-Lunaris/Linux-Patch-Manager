import React, { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Box, Button, Container, TextField, Typography,
  Alert, CircularProgress, Paper, InputAdornment, IconButton,
} from '@mui/material'
import { Visibility, VisibilityOff } from '@mui/icons-material'
import { authApi } from '../api/client'
import { useAuthStore } from '../store/authStore'
import type { User } from '../types'

/** Extract a human-readable error message from an Axios error. */
function getErrorMessage(err: unknown): string {
  // Network error — no response at all (server unreachable, CORS, DNS failure)
  if (err instanceof Error && err.message === 'Network Error') {
    return 'Unable to connect to the server. Please check your network connection and try again.'
  }

  // Axios-style error with a response body
  const axiosErr = err as { response?: { status?: number; data?: { error?: { code?: string; message?: string } } } }
  const status = axiosErr.response?.status
  const code = axiosErr.response?.data?.error?.code
  const msg = axiosErr.response?.data?.error?.message

  // Rate limited
  if (status === 429) {
    return 'Too many login attempts. Please wait a moment and try again.'
  }

  // MFA required
  if (code === 'mfa_required') {
    return 'MFA_REQUIRED'  // sentinel — caller checks this
  }

  // Account disabled
  if (code === 'account_disabled') {
    return 'This account has been disabled. Contact your administrator.'
  }

  // Server-provided message
  if (msg) {
    return msg
  }

  // Generic status-based messages
  if (status === 401) {
    return 'Invalid username or password.'
  }
  if (status === 403) {
    return 'Access denied.'
  }
  if (status && status >= 500) {
    return 'A server error occurred. Please try again later.'
  }

  return 'Login failed. Please try again.'
}

export default function LoginPage() {
  const navigate = useNavigate()
  const { setTokens, setUser } = useAuthStore()

  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [totpCode, setTotpCode] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [needsMfa, setNeedsMfa] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    setError(null)

    try {
      const res = await authApi.login(username, password, needsMfa ? totpCode : undefined)
      const { access_token, refresh_token, user } = res.data
      setTokens(access_token, refresh_token)
      setUser(user as User)
      navigate('/dashboard', { replace: true })
    } catch (err: unknown) {
      const message = getErrorMessage(err)
      if (message === 'MFA_REQUIRED') {
        setNeedsMfa(true)
        setError('Please enter your MFA code.')
      } else {
        setError(message)
      }
    } finally {
      setLoading(false)
    }
  }

  return (
    <Container maxWidth="xs" sx={{ mt: 12 }}>
      <Paper elevation={4} sx={{ p: 4 }}>
        <Typography variant="h5" fontWeight={700} mb={3} align="center">
          🐉 Linux Patch Manager
        </Typography>

        {error && (
          <Alert
            severity={needsMfa ? 'info' : 'error'}
            sx={{ mb: 2 }}
            onClose={() => setError(null)}
          >
            {error}
          </Alert>
        )}

        <Box component="form" onSubmit={handleSubmit} noValidate>
          <TextField
            fullWidth margin="normal" label="Username" autoComplete="username"
            value={username} onChange={(e) => setUsername(e.target.value)}
            disabled={loading} required autoFocus
          />
          <TextField
            fullWidth margin="normal" label="Password" type={showPassword ? 'text' : 'password'}
            autoComplete="current-password" value={password}
            onChange={(e) => setPassword(e.target.value)} disabled={loading} required
            InputProps={{
              endAdornment: (
                <InputAdornment position="end">
                  <IconButton onClick={() => setShowPassword(!showPassword)} edge="end">
                    {showPassword ? <VisibilityOff /> : <Visibility />}
                  </IconButton>
                </InputAdornment>
              ),
            }}
          />
          {needsMfa && (
            <TextField
              fullWidth margin="normal" label="MFA Code" inputMode="numeric"
              inputProps={{ maxLength: 6, pattern: '[0-9]*' }}
              value={totpCode} onChange={(e) => setTotpCode(e.target.value)}
              disabled={loading} required autoFocus
              helperText="Enter the 6-digit code from your authenticator app"
            />
          )}
          <Button
            type="submit" fullWidth variant="contained" size="large"
            sx={{ mt: 3 }} disabled={loading}
          >
            {loading ? <CircularProgress size={24} /> : 'Sign In'}
          </Button>
        </Box>
      </Paper>
    </Container>
  )
}
