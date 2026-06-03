import { useEffect, useState } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import {
  Box, Container, Paper, Typography, Alert, Button, CircularProgress,
} from '@mui/material'
import { useAuthStore } from '../store/authStore'
import type { User } from '../types'

/**
 * SSO callback page.
 *
 * Flow (per `tasks/sso-token-handoff-spec.md`):
 *  1. The OIDC provider redirects the browser here with `?handoff=<code>`
 *     in the URL. The actual JWT access/refresh tokens are NOT in the URL
 *     (that would leak them through browser history, proxy access logs,
 *     and the Referer header — see issue #4).
 *  2. On mount, we POST the handoff code to
 *     `POST /api/v1/auth/sso/handoff`. The backend atomically removes
 *     the entry (single-use) and returns the tokens in the JSON
 *     response.
 *  3. On success, we call `setTokens` + `setUser` on the auth store,
 *     replace the URL (removing the handoff code from history), and
 *     navigate to `/dashboard`.
 *  4. On failure, we show an error and let the user go back to `/login`.
 */
export default function SsoCallbackPage() {
  const navigate = useNavigate()
  const [searchParams] = useSearchParams()
  const { setTokens, setUser } = useAuthStore()
  const [error, setError] = useState<string | null>(null)
  const [processing, setProcessing] = useState(true)

  useEffect(() => {
    // Surface upstream OIDC errors (e.g. user denied consent) unchanged.
    const errorCode = searchParams.get('error')
    const errorDescription = searchParams.get('error_description')
    if (errorCode) {
      setError(errorDescription || `SSO authentication failed: ${errorCode}`)
      setProcessing(false)
      return
    }

    const handoffCode = searchParams.get('handoff')
    if (!handoffCode) {
      setError('Missing handoff code. Please try logging in again.')
      setProcessing(false)
      return
    }

    // Exchange the handoff code for tokens. The code is single-use and
    // 60-second TTL on the backend; the SPA must POST promptly.
    (async () => {
      try {
        const resp = await fetch('/api/v1/auth/sso/handoff', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ handoff_code: handoffCode }),
        })
        if (!resp.ok) {
          // Try to extract a structured error from the backend
          let message = `Failed to complete sign-in (HTTP ${resp.status})`
          try {
            const errBody = await resp.json()
            if (errBody?.error?.message) {
              message = errBody.error.message
            }
          } catch {
            // Body wasn't JSON; keep the default message
          }
          setError(message)
          setProcessing(false)
          return
        }

        const data = await resp.json()
        const user = buildUser(data.user)

        setTokens(data.access_token, data.refresh_token)
        setUser(user)

        // Clear the handoff code from the URL so it doesn't end up in
        // browser history or get shared via the address bar. The code
        // is already consumed (single-use) but defense-in-depth.
        window.history.replaceState({}, '', '/auth/sso/callback')

        navigate('/dashboard', { replace: true })
      } catch (err) {
        setError(
          err instanceof Error ? err.message : 'Failed to complete sign-in. Please try again.',
        )
        setProcessing(false)
      }
    })()
  }, [setTokens, setUser, navigate, searchParams])

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

/**
 * Map the SSO user JSON payload from the backend to the SPA's `User`
 * type. Fills in sensible defaults for any missing fields.
 */
function buildUser(parsed: Record<string, unknown>): User {
  const authProvider = (parsed.auth_provider as string) || 'azure_sso'
  return {
    id: (parsed.id as string) || '',
    username: (parsed.username as string) || '',
    display_name: (parsed.display_name as string) || '',
    email: (parsed.email as string) || '',
    role: (parsed.role as User['role']) || 'operator',
    auth_provider: authProvider as User['auth_provider'],
    mfa_enabled: (parsed.mfa_enabled as boolean) ?? false,
    is_active: true,
    force_password_reset: false,
  }
}
