import React, { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Box, Button, Container, TextField, Typography,
  Alert, CircularProgress, Paper, InputAdornment, IconButton,
  List, ListItem, ListItemIcon, ListItemText,
} from '@mui/material'
import {
  Visibility, VisibilityOff,
  Check as CheckIcon, Close as CloseIcon,
} from '@mui/icons-material'
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

  // Password reset required
  if (code === 'password_reset_required') {
    return 'PASSWORD_RESET_REQUIRED'
  }

  // Account locked
  if (code === 'account_locked') {
    return 'ACCOUNT_LOCKED'
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

/** Password strength checker */
function checkPasswordStrength(password: string) {
  return {
    length: password.length >= 8,
    uppercase: /[A-Z]/.test(password),
    lowercase: /[a-z]/.test(password),
    digit: /[0-9]/.test(password),
    special: /[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]/.test(password),
  }
}

function isPasswordValid(checks: ReturnType<typeof checkPasswordStrength>) {
  return checks.length && checks.uppercase && checks.lowercase && checks.digit && checks.special
}

export default function LoginPage() {
  const navigate = useNavigate()
  const { setTokens, setUser } = useAuthStore()

  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [totpCode, setTotpCode] = useState('')
  const [showPassword, setShowPassword] = useState(false)
  const [needsMfa, setNeedsMfa] = useState(false)
  const [forcePasswordReset, setForcePasswordReset] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  // Force change password state
  const [newPassword, setNewPassword] = useState('')
  const [confirmNewPassword, setConfirmNewPassword] = useState('')
  const [showNewPassword, setShowNewPassword] = useState(false)
  const [passwordChanged, setPasswordChanged] = useState(false)

  const pwChecks = checkPasswordStrength(newPassword)
  const pwValid = isPasswordValid(pwChecks)
  const pwMismatch = !!(confirmNewPassword && newPassword !== confirmNewPassword)

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
      } else if (message === 'PASSWORD_RESET_REQUIRED') {
        setForcePasswordReset(true)
        setError('You must change your password before logging in.')
      } else if (message === 'ACCOUNT_LOCKED') {
        setError('Account locked due to too many failed login attempts. Please try again in 30 minutes.')
      } else {
        setError(message)
      }
    } finally {
      setLoading(false)
    }
  }

  const handleForceChangePassword = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!pwValid || pwMismatch) return
    setLoading(true)
    setError(null)

    try {
      await authApi.forceChangePassword(username, password, newPassword)
      setPasswordChanged(true)
      setForcePasswordReset(false)
      setNewPassword('')
      setConfirmNewPassword('')
      setPassword('')
    } catch (err: unknown) {
      const axiosErr = err as { response?: { data?: { error?: { code?: string; message?: string } } } }
      const code = axiosErr.response?.data?.error?.code
      const msg = axiosErr.response?.data?.error?.message
      if (code === 'weak_password') {
        setError(msg || 'Password does not meet strength requirements.')
      } else if (code === 'invalid_credentials') {
        setError('Invalid username or password.')
      } else {
        setError(msg || 'Failed to change password. Please try again.')
      }
    } finally {
      setLoading(false)
    }
  }

  const handleBackToLogin = () => {
    setForcePasswordReset(false)
    setPasswordChanged(false)
    setError(null)
    setPassword('')
    setNewPassword('')
    setConfirmNewPassword('')
  }

  return (
    <Container maxWidth="xs" sx={{ mt: 12 }}>
      <Paper elevation={4} sx={{ p: 4 }}>
        <Typography variant="h5" fontWeight={700} mb={3} align="center">
          🐉 Linux Patch Manager
        </Typography>

        {error && (
          <Alert
            severity={forcePasswordReset ? 'warning' : 'error'}
            sx={{ mb: 2 }}
            onClose={() => setError(null)}
          >
            {error}
          </Alert>
        )}

        {passwordChanged ? (
          <Box>
            <Alert severity="success" sx={{ mb: 2 }}>
              Password changed successfully! Please log in with your new password.
            </Alert>
            <Button
              fullWidth variant="contained" size="large"
              onClick={handleBackToLogin}
            >
              Back to Login
            </Button>
          </Box>
        ) : forcePasswordReset ? (
          <Box component="form" onSubmit={handleForceChangePassword} noValidate>
            <Typography variant="h6" fontWeight={600} mb={2}>
              Change Your Password
            </Typography>
            <Typography variant="body2" color="text.secondary" mb={2}>
              Your password has expired and must be changed before you can log in.
            </Typography>
            <TextField
              fullWidth margin="normal" label="Username"
              value={username} InputProps={{ readOnly: true }}
            />
            <TextField
              fullWidth margin="normal" label="Current Password" type="password"
              value={password} InputProps={{ readOnly: true }}
            />
            <TextField
              fullWidth margin="normal" label="New Password"
              type={showNewPassword ? 'text' : 'password'}
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              disabled={loading} required
              InputProps={{
                endAdornment: (
                  <InputAdornment position="end">
                    <IconButton onClick={() => setShowNewPassword(!showNewPassword)} edge="end">
                      {showNewPassword ? <VisibilityOff /> : <Visibility />}
                    </IconButton>
                  </InputAdornment>
                ),
              }}
            />
            {newPassword && (
              <Box sx={{ mt: 1, mb: 1 }}>
                <List dense disablePadding>
                  <ListItem disableGutters sx={{ py: 0 }}>
                    <ListItemIcon sx={{ minWidth: 28 }}>
                      {pwChecks.length ? <CheckIcon color="success" fontSize="small" /> : <CloseIcon color="error" fontSize="small" />}
                    </ListItemIcon>
                    <ListItemText primary="At least 8 characters" primaryTypographyProps={{ variant: 'caption' }} />
                  </ListItem>
                  <ListItem disableGutters sx={{ py: 0 }}>
                    <ListItemIcon sx={{ minWidth: 28 }}>
                      {pwChecks.uppercase ? <CheckIcon color="success" fontSize="small" /> : <CloseIcon color="error" fontSize="small" />}
                    </ListItemIcon>
                    <ListItemText primary="At least one uppercase letter" primaryTypographyProps={{ variant: 'caption' }} />
                  </ListItem>
                  <ListItem disableGutters sx={{ py: 0 }}>
                    <ListItemIcon sx={{ minWidth: 28 }}>
                      {pwChecks.lowercase ? <CheckIcon color="success" fontSize="small" /> : <CloseIcon color="error" fontSize="small" />}
                    </ListItemIcon>
                    <ListItemText primary="At least one lowercase letter" primaryTypographyProps={{ variant: 'caption' }} />
                  </ListItem>
                  <ListItem disableGutters sx={{ py: 0 }}>
                    <ListItemIcon sx={{ minWidth: 28 }}>
                      {pwChecks.digit ? <CheckIcon color="success" fontSize="small" /> : <CloseIcon color="error" fontSize="small" />}
                    </ListItemIcon>
                    <ListItemText primary="At least one digit" primaryTypographyProps={{ variant: 'caption' }} />
                  </ListItem>
                  <ListItem disableGutters sx={{ py: 0 }}>
                    <ListItemIcon sx={{ minWidth: 28 }}>
                      {pwChecks.special ? <CheckIcon color="success" fontSize="small" /> : <CloseIcon color="error" fontSize="small" />}
                    </ListItemIcon>
                    <ListItemText primary="At least one special character" primaryTypographyProps={{ variant: 'caption' }} />
                  </ListItem>
                </List>
              </Box>
            )}
            <TextField
              fullWidth margin="normal" label="Confirm New Password" type="password"
              value={confirmNewPassword}
              onChange={(e) => setConfirmNewPassword(e.target.value)}
              disabled={loading} required
              error={pwMismatch}
              helperText={pwMismatch ? 'Passwords do not match' : ''}
            />
            <Button
              type="submit" fullWidth variant="contained" size="large"
              sx={{ mt: 3 }} disabled={loading || !pwValid || pwMismatch}
            >
              {loading ? <CircularProgress size={24} /> : 'Change Password'}
            </Button>
          </Box>
        ) : (
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
        )}
      </Paper>
    </Container>
  )
}
