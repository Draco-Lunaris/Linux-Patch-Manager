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
      const e = err as { response?: { data?: { error?: { code?: string; message?: string } } } }
      const code = e.response?.data?.error?.code
      if (code === 'mfa_required') {
        setNeedsMfa(true)
        setError('Please enter your MFA code.')
      } else {
        setError(e.response?.data?.error?.message || 'Login failed')
      }
    } finally {
      setLoading(false)
    }
  }

  return (
    <Container maxWidth="xs" sx={{ mt: 12 }}>
      <Paper elevation={4} sx={{ p: 4 }}>
        <Typography variant="h5" fontWeight={700} mb={3} align="center">
          Linux Patch Manager
        </Typography>

        {error && <Alert severity={needsMfa && error.startsWith('Please') ? 'info' : 'error'} sx={{ mb: 2 }}>{error}</Alert>}

        <Box component="form" onSubmit={handleSubmit} noValidate>
          <TextField
            fullWidth margin="normal" label="Username" autoComplete="username"
            value={username} onChange={(e) => setUsername(e.target.value)}
            disabled={loading} required
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
