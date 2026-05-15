import React, { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Box, Button, Container, TextField, Typography,
  Alert, CircularProgress, Paper, InputAdornment, IconButton,
  List, ListItem, ListItemIcon, ListItemText,
  Divider,
} from '@mui/material'
import {
  Visibility, VisibilityOff,
  Check as CheckIcon, Close as CloseIcon,
  Cloud as CloudIcon, VpnKey as KeyIcon,
} from '@mui/icons-material'
import { authApi, ssoConfigApi } from '../api/client'
import { useAuthStore } from '../store/authStore'
import type { User } from '../types'

// ── WebAuthn utility functions ──────────────────────────────────────────────

function arrayBufferToBase64url(buffer: ArrayBuffer): string {
  return btoa(String.fromCharCode(...new Uint8Array(buffer)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '')
}

function base64urlToArrayBuffer(base64url: string): ArrayBuffer {
  const base64 = base64url.replace(/-/g, '+').replace(/_/g, '/')
  const padding = '='.repeat((4 - (base64.length % 4)) % 4)
  const binary = atob(base64 + padding)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i)
  }
  return bytes.buffer
}

function getErrorMessage(err: unknown): string {
  if (err instanceof Error && err.message === 'Network Error') {
    return 'Unable to connect to the server. Please check your network connection and try again.'
  }
  const axiosErr = err as { response?: { status?: number; data?: { error?: { code?: string; message?: string } } } }
  const status = axiosErr.response?.status
  const code = axiosErr.response?.data?.error?.code
  const msg = axiosErr.response?.data?.error?.message
  if (status === 429) return 'Too many login attempts. Please wait a moment and try again.'
  if (code === 'mfa_required') return 'MFA_REQUIRED'
  if (code === 'mfa_required_webauthn') return 'MFA_REQUIRED_WEBAUTHN'
  if (code === 'password_reset_required') return 'PASSWORD_RESET_REQUIRED'
  if (code === 'account_locked') return 'ACCOUNT_LOCKED'
  if (code === 'account_disabled') return 'This account has been disabled. Contact your administrator.'
  if (msg) return msg
  if (status === 401) return 'Invalid username or password.'
  if (status === 403) return 'Access denied.'
  if (status && status >= 500) return 'A server error occurred. Please try again later.'
  return 'Login failed. Please try again.'
}

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
  const [needsWebAuthn, setNeedsWebAuthn] = useState(false)
  const [webAuthnLoading, setWebAuthnLoading] = useState(false)
  const [forcePasswordReset, setForcePasswordReset] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const [ssoEnabled, setSsoEnabled] = useState(false)
  const [ssoDisplayName, setSsoDisplayName] = useState('SSO')
  const [ssoAuthUrl, setSsoAuthUrl] = useState('/api/v1/auth/sso/login')

  const [newPassword, setNewPassword] = useState('')
  const [confirmNewPassword, setConfirmNewPassword] = useState('')
  const [showNewPassword, setShowNewPassword] = useState(false)
  const [passwordChanged, setPasswordChanged] = useState(false)

  const pwChecks = checkPasswordStrength(newPassword)
  const pwValid = isPasswordValid(pwChecks)
  const pwMismatch = !!(confirmNewPassword && newPassword !== confirmNewPassword)

  useEffect(() => {
    ssoConfigApi.get().then(({ data }) => {
      setSsoEnabled(data.enabled)
      setSsoDisplayName(data.display_name || 'SSO')
      if (data.auth_url) setSsoAuthUrl(data.auth_url)
    }).catch(() => { /* SSO settings unavailable */ })
  }, [])

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
      } else if (message === 'MFA_REQUIRED_WEBAUTHN') {
        setNeedsWebAuthn(true)
        setError('Please authenticate with your security key.')
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

  const handleWebAuthnLogin = async () => {
    setWebAuthnLoading(true)
    setError(null)
    try {
      const startRes = await authApi.webauthnAuthenticateStart()
      const { challenge_key, assertion_options } = startRes.data

      const publicKey = assertion_options.publicKey
      const publicKeyCredentialRequestOptions: PublicKeyCredentialRequestOptions = {
        ...publicKey,
        challenge: base64urlToArrayBuffer(publicKey.challenge),
        allowCredentials: publicKey.allowCredentials?.map((c: { type: string; id: string }) => ({
          ...c,
          id: base64urlToArrayBuffer(c.id),
        })),
      }

      const assertion = await navigator.credentials.get({
        publicKey: publicKeyCredentialRequestOptions,
      }) as PublicKeyCredential | null

      if (!assertion) {
        setError('Security key authentication was cancelled.')
        return
      }

      const response = assertion.response as AuthenticatorAssertionResponse
      const serializedAssertion = {
        id: assertion.id,
        rawId: arrayBufferToBase64url(assertion.rawId),
        type: assertion.type,
        response: {
          authenticatorData: arrayBufferToBase64url(response.authenticatorData),
          clientDataJSON: arrayBufferToBase64url(response.clientDataJSON),
          signature: arrayBufferToBase64url(response.signature),
          userHandle: response.userHandle ? arrayBufferToBase64url(response.userHandle) : null,
        },
      }

      const completeRes = await authApi.webauthnAuthenticateComplete(challenge_key, serializedAssertion)
      if (completeRes.data.access_token && completeRes.data.refresh_token) {
        const { access_token, refresh_token, user } = completeRes.data
        setTokens(access_token, refresh_token)
        setUser(user as User)
        navigate('/dashboard', { replace: true })
      } else {
        setError('WebAuthn authentication succeeded. Please try logging in again.')
        setNeedsWebAuthn(false)
      }
    } catch (err: unknown) {
      const error = err as { name?: string; response?: { data?: { error?: { message?: string } } }; message?: string };
      if (error.name === 'NotAllowedError') {
        setError('Security key authentication was cancelled or timed out.');
      } else {
        const msg = error.response?.data?.error?.message || error.message || 'Authentication failed.';
        setError(`Security key authentication failed: ${msg}`);
      }
    } finally {
      setWebAuthnLoading(false)
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

  const ssoIcon = ssoDisplayName.toLowerCase().includes('keycloak') ? <KeyIcon /> : <CloudIcon />

  return (
    <Container maxWidth="xs" sx={{ mt: 12 }}>
      <Paper elevation={4} sx={{ p: 4 }}>
        <Typography variant="h5" fontWeight={700} mb={3} align="center">
          🐉 Linux Patch Manager
        </Typography>

        {error && (
          <Alert severity={forcePasswordReset ? 'warning' : 'error'} sx={{ mb: 2 }} onClose={() => setError(null)}>
            {error}
          </Alert>
        )}

        {passwordChanged ? (
          <Box>
            <Alert severity="success" sx={{ mb: 2 }}>Password changed successfully! Please log in with your new password.</Alert>
            <Button fullWidth variant="contained" size="large" onClick={handleBackToLogin}>Back to Login</Button>
          </Box>
        ) : forcePasswordReset ? (
          <Box component="form" onSubmit={handleForceChangePassword} noValidate>
            <Typography variant="h6" fontWeight={600} mb={2}>Change Your Password</Typography>
            <Typography variant="body2" color="text.secondary" mb={2}>Your password has expired and must be changed before you can log in.</Typography>
            <TextField fullWidth margin="normal" label="Username" value={username} InputProps={{ readOnly: true }} />
            <TextField fullWidth margin="normal" label="Current Password" type="password" value={password} InputProps={{ readOnly: true }} />
            <TextField fullWidth margin="normal" label="New Password" type={showNewPassword ? 'text' : 'password'} value={newPassword} onChange={(e) => setNewPassword(e.target.value)} disabled={loading} required InputProps={{ endAdornment: <InputAdornment position="end"><IconButton onClick={() => setShowNewPassword(!showNewPassword)} edge="end">{showNewPassword ? <VisibilityOff /> : <Visibility />}</IconButton></InputAdornment> }} />
            {newPassword && (
              <Box sx={{ mt: 1, mb: 1 }}>
                <List dense disablePadding>
                  <ListItem disableGutters sx={{ py: 0 }}><ListItemIcon sx={{ minWidth: 28 }}>{pwChecks.length ? <CheckIcon color="success" fontSize="small" /> : <CloseIcon color="error" fontSize="small" />}</ListItemIcon><ListItemText primary="At least 8 characters" primaryTypographyProps={{ variant: 'caption' }} /></ListItem>
                  <ListItem disableGutters sx={{ py: 0 }}><ListItemIcon sx={{ minWidth: 28 }}>{pwChecks.uppercase ? <CheckIcon color="success" fontSize="small" /> : <CloseIcon color="error" fontSize="small" />}</ListItemIcon><ListItemText primary="At least one uppercase letter" primaryTypographyProps={{ variant: 'caption' }} /></ListItem>
                  <ListItem disableGutters sx={{ py: 0 }}><ListItemIcon sx={{ minWidth: 28 }}>{pwChecks.lowercase ? <CheckIcon color="success" fontSize="small" /> : <CloseIcon color="error" fontSize="small" />}</ListItemIcon><ListItemText primary="At least one lowercase letter" primaryTypographyProps={{ variant: 'caption' }} /></ListItem>
                  <ListItem disableGutters sx={{ py: 0 }}><ListItemIcon sx={{ minWidth: 28 }}>{pwChecks.digit ? <CheckIcon color="success" fontSize="small" /> : <CloseIcon color="error" fontSize="small" />}</ListItemIcon><ListItemText primary="At least one digit" primaryTypographyProps={{ variant: 'caption' }} /></ListItem>
                  <ListItem disableGutters sx={{ py: 0 }}><ListItemIcon sx={{ minWidth: 28 }}>{pwChecks.special ? <CheckIcon color="success" fontSize="small" /> : <CloseIcon color="error" fontSize="small" />}</ListItemIcon><ListItemText primary="At least one special character" primaryTypographyProps={{ variant: 'caption' }} /></ListItem>
                </List>
              </Box>
            )}
            <TextField fullWidth margin="normal" label="Confirm New Password" type="password" value={confirmNewPassword} onChange={(e) => setConfirmNewPassword(e.target.value)} disabled={loading} required error={pwMismatch} helperText={pwMismatch ? 'Passwords do not match' : ''} />
            <Button type="submit" fullWidth variant="contained" size="large" sx={{ mt: 3 }} disabled={loading || !pwValid || pwMismatch}>{loading ? <CircularProgress size={24} /> : 'Change Password'}</Button>
          </Box>
        ) : (
          <Box component="form" onSubmit={handleSubmit} noValidate>
            <TextField fullWidth margin="normal" label="Username" autoComplete="username" value={username} onChange={(e) => setUsername(e.target.value)} disabled={loading} required autoFocus />
            <TextField fullWidth margin="normal" label="Password" type={showPassword ? 'text' : 'password'} autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} disabled={loading} required InputProps={{ endAdornment: <InputAdornment position="end"><IconButton onClick={() => setShowPassword(!showPassword)} edge="end">{showPassword ? <VisibilityOff /> : <Visibility />}</IconButton></InputAdornment> }} />
            {needsMfa && (
              <TextField fullWidth margin="normal" label="MFA Code" inputMode="numeric" inputProps={{ maxLength: 6, pattern: '[0-9]*' }} value={totpCode} onChange={(e) => setTotpCode(e.target.value)} disabled={loading} required autoFocus helperText="Enter the 6-digit code from your authenticator app" />
            )}
            {needsWebAuthn && (
              <Box sx={{ mt: 2, mb: 2 }}>
                <Button
                  fullWidth
                  variant="contained"
                  size="large"
                  startIcon={<KeyIcon />}
                  onClick={handleWebAuthnLogin}
                  disabled={webAuthnLoading}
                  sx={{ mb: 1 }}
                >
                  {webAuthnLoading ? <CircularProgress size={24} /> : 'Use Security Key'}
                </Button>
                <Typography variant="caption" color="text.secondary" display="block" textAlign="center">
                  Touch your security key or use your device biometrics to authenticate.
                </Typography>
              </Box>
            )}
            <Button type="submit" fullWidth variant="contained" size="large" sx={{ mt: 3 }} disabled={loading}>{loading ? <CircularProgress size={24} /> : 'Sign In'}</Button>
            {ssoEnabled && (
              <>
                <Divider sx={{ my: 3 }}>or</Divider>
                <Button fullWidth variant="outlined" size="large" startIcon={ssoIcon} onClick={() => { const state = Array.from(crypto.getRandomValues(new Uint8Array(16))).map(b => b.toString(16).padStart(2, '0')).join(''); sessionStorage.setItem('sso_csrf_state', state); window.location.href = ssoAuthUrl }} disabled={loading}>Sign in with {ssoDisplayName}</Button>
              </>
            )}
          </Box>
        )}
      </Paper>
    </Container>
  )
}
