import React, { useEffect, useState, useCallback } from 'react'
import {
  Box, Button, Container, TextField, Typography,
  Alert, CircularProgress, Paper, Stepper, Step, StepLabel,
  IconButton, Tooltip, Snackbar, Tabs, Tab, List, ListItem,
  ListItemText, ListItemSecondaryAction, Dialog, DialogTitle,
  DialogContent, DialogActions,
} from '@mui/material'
import {
  ContentCopy as CopyIcon,
  Delete as DeleteIcon,
  VpnKey as KeyIcon,
  Add as AddIcon,
} from '@mui/icons-material'
import QRCode from 'qrcode'
import { authApi } from '../api/client'

const STEPS = ['Get your QR code', 'Verify code', 'Done']

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

// ── TOTP Setup Component ────────────────────────────────────────────────────

function TotpSetup() {
  const [step, setStep] = useState(0)
  const [setup, setSetup] = useState<{ secret_base32: string; otp_uri: string } | null>(null)
  const [code, setCode] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [qrDataUrl, setQrDataUrl] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)

  useEffect(() => {
    authApi.getMfaSetup()
      .then((res) => {
        setSetup(res.data)
        if (res.data.otp_uri) {
          QRCode.toDataURL(res.data.otp_uri, {
            width: 256,
            margin: 2,
            color: { dark: '#000000', light: '#ffffff' },
          })
            .then((url) => setQrDataUrl(url))
            .catch(() => setError('Failed to generate QR code.'))
        } else {
          setError('MFA setup returned invalid data. No OTP URI found.')
        }
      })
      .catch((err) => {
        const status = err?.response?.status
        const message = err?.message
        if (status === 401) {
          setError('Authentication required. Please log in again.')
        } else if (status === 403) {
          setError('You do not have permission to set up MFA.')
        } else if (message === 'Network Error') {
          setError('Network error. Please check your connection and try again.')
        } else {
          setError(`Failed to load MFA setup: ${message || 'Unknown error'} (Status: ${status || 'N/A'})`)
        }
      })
  }, [])

  const handleCopySecret = () => {
    if (setup?.secret_base32) {
      navigator.clipboard.writeText(setup.secret_base32)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    }
  }

  const handleVerify = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!setup) return
    setLoading(true)
    setError(null)
    try {
      await authApi.verifyMfa(setup.secret_base32, code)
      setStep(2)
    } catch {
      setError('Invalid code. Please try again.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <Box>
      <Stepper activeStep={step} sx={{ mb: 4 }}>
        {STEPS.map((label) => <Step key={label}><StepLabel>{label}</StepLabel></Step>)}
      </Stepper>

      {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}

      {step === 0 && setup && (
        <Box>
          <Typography mb={2}>Scan this QR code in your authenticator app:</Typography>
          {qrDataUrl ? (
            <Box sx={{ display: 'flex', justifyContent: 'center', mb: 2 }}>
              <img src={qrDataUrl} alt="MFA QR Code" width={256} height={256} style={{ imageRendering: 'pixelated' }} />
            </Box>
          ) : (
            <Box sx={{ display: 'flex', justifyContent: 'center', mb: 2 }}>
              <CircularProgress />
            </Box>
          )}
          <Typography variant="caption" color="text.secondary" display="block" mb={1}>
            If you can't scan the QR code, enter the secret manually:
          </Typography>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 3 }}>
            <Typography
              variant="body2"
              sx={{ fontFamily: 'monospace', wordBreak: 'break-all', p: 1, bgcolor: 'grey.100', borderRadius: 1, flexGrow: 1 }}
            >
              {setup.secret_base32}
            </Typography>
            <Tooltip title={copied ? 'Copied!' : 'Copy Secret'}>
              <IconButton onClick={handleCopySecret} color={copied ? 'success' : 'default'}>
                <CopyIcon />
              </IconButton>
            </Tooltip>
          </Box>
          <Button variant="contained" onClick={() => setStep(1)}>Continue</Button>
        </Box>
      )}

      {step === 1 && (
        <Box component="form" onSubmit={handleVerify}>
          <Typography mb={2}>Enter the 6-digit code from your authenticator app to confirm setup:</Typography>
          <TextField
            fullWidth label="Verification Code" inputMode="numeric"
            inputProps={{ maxLength: 6, pattern: '[0-9]*' }}
            value={code} onChange={(e) => setCode(e.target.value)}
            disabled={loading} required autoFocus
          />
          <Button type="submit" variant="contained" sx={{ mt: 2 }} disabled={loading}>
            {loading ? <CircularProgress size={24} /> : 'Verify & Enable MFA'}
          </Button>
        </Box>
      )}

      {step === 2 && (
        <Alert severity="success">
          MFA has been enabled for your account. You will need your authenticator app at each login.
        </Alert>
      )}

      <Snackbar
        open={copied}
        autoHideDuration={2000}
        onClose={() => setCopied(false)}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'center' }}
      >
        <Alert severity="success" variant="filled">Secret copied to clipboard</Alert>
      </Snackbar>
    </Box>
  )
}

// ── WebAuthn Setup Component ────────────────────────────────────────────────

interface WebAuthnCredential {
  id: string
  name: string
  created_at: string
}

function WebAuthnSetup() {
  const [credentials, setCredentials] = useState<WebAuthnCredential[]>([])
  const [loading, setLoading] = useState(false)
  const [registering, setRegistering] = useState(false)
  const [keyName, setKeyName] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)
  const [deleteConfirm, setDeleteConfirm] = useState<string | null>(null)

  const loadCredentials = useCallback(() => {
    authApi.webauthnListCredentials()
      .then((res) => {
        setCredentials(res.data.credentials || [])
      })
      .catch((err) => {
        console.error('[WebAuthn] Failed to load credentials:', err)
        setError('Failed to load security keys.')
      })
  }, [])

  useEffect(() => {
    loadCredentials()
  }, [loadCredentials])

  const handleRegister = async () => {
    setRegistering(true)
    setError(null)
    setSuccess(null)
    try {
      // Step 1: Start registration ceremony
      const startRes = await authApi.webauthnRegisterStart(keyName || undefined)
      const { challenge_key, creation_options } = startRes.data

      // Step 2: Convert base64url strings to ArrayBuffers for navigator.credentials.create
      const publicKey = creation_options.publicKey
      const publicKeyCredentialCreationOptions: PublicKeyCredentialCreationOptions = {
        ...publicKey,
        challenge: base64urlToArrayBuffer(publicKey.challenge),
        user: {
          ...publicKey.user,
          id: base64urlToArrayBuffer(publicKey.user.id),
        },
        excludeCredentials: publicKey.excludeCredentials?.map((c: { type: string; id: string }) => ({
          ...c,
          id: base64urlToArrayBuffer(c.id),
        })),
      }

      // Step 3: Create credential via browser WebAuthn API
      const credential = await navigator.credentials.create({
        publicKey: publicKeyCredentialCreationOptions,
      }) as PublicKeyCredential | null

      if (!credential) {
        setError('Security key registration was cancelled.')
        return
      }

      // Step 4: Serialize credential for server
      const response = credential.response as AuthenticatorAttestationResponse
      const serializedCredential = {
        id: credential.id,
        rawId: arrayBufferToBase64url(credential.rawId),
        type: credential.type,
        response: {
          attestationObject: arrayBufferToBase64url(response.attestationObject),
          clientDataJSON: arrayBufferToBase64url(response.clientDataJSON),
        },
      }

      // Step 5: Complete registration
      await authApi.webauthnRegisterComplete(challenge_key, serializedCredential, keyName || undefined)
      setSuccess('Security key registered successfully!')
      setKeyName('')
      loadCredentials()
    } catch (err: unknown) {
      const errorObj = err as { name?: string; response?: { data?: { error?: { message?: string } } }; message?: string }
      if (errorObj.name === 'NotAllowedError') {
        setError('Security key registration was cancelled or timed out.')
      } else {
        const msg = errorObj.response?.data?.error?.message || errorObj.message || 'Registration failed.'
        setError(`Failed to register security key: ${msg}`)
      }
    } finally {
      setRegistering(false)
    }
  }

  const handleDelete = async (id: string) => {
    setDeleteConfirm(null)
    setLoading(true)
    setError(null)
    try {
      await authApi.webauthnDeleteCredential(id)
      setSuccess('Security key removed successfully.')
      loadCredentials()
    } catch (err: unknown) {
      const errorObj = err as { response?: { data?: { error?: { message?: string } } }; message?: string }
      const msg = errorObj.response?.data?.error?.message || errorObj.message || 'Failed to delete key.'
      setError(`Failed to remove security key: ${msg}`)
    } finally {
      setLoading(false)
    }
  }

  return (
    <Box>
      {error && <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError(null)}>{error}</Alert>}
      {success && <Alert severity="success" sx={{ mb: 2 }} onClose={() => setSuccess(null)}>{success}</Alert>}

      <Typography variant="h6" fontWeight={600} mb={2}>
        Register a Security Key
      </Typography>
      <Typography variant="body2" color="text.secondary" mb={2}>
        Add a FIDO2/WebAuthn security key (e.g., YubiKey) for passwordless authentication.
        You can register multiple keys as backups.
      </Typography>

      <Box sx={{ display: 'flex', gap: 1, mb: 3, alignItems: 'flex-start' }}>
        <TextField
          size="small"
          label="Key Name (optional)"
          placeholder="e.g., My YubiKey"
          value={keyName}
          onChange={(e) => setKeyName(e.target.value)}
          disabled={registering}
          sx={{ flexGrow: 1 }}
        />
        <Button
          variant="contained"
          startIcon={<AddIcon />}
          onClick={handleRegister}
          disabled={registering}
        >
          {registering ? <CircularProgress size={24} /> : 'Register Security Key'}
        </Button>
      </Box>

      <Typography variant="h6" fontWeight={600} mb={1}>
        Registered Security Keys
      </Typography>

      {credentials.length === 0 ? (
        <Typography variant="body2" color="text.secondary" sx={{ py: 2, textAlign: 'center' }}>
          No security keys registered yet.
        </Typography>
      ) : (
        <List>
          {credentials.map((cred) => (
            <ListItem key={cred.id} sx={{ bgcolor: 'grey.50', borderRadius: 1, mb: 1 }}>
              <KeyIcon sx={{ mr: 2, color: 'action.active' }} />
              <ListItemText
                primary={cred.name || 'Unnamed Key'}
                secondary={`Added ${new Date(cred.created_at).toLocaleDateString()}`}
              />
              <ListItemSecondaryAction>
                <Tooltip title="Remove Key">
                  <IconButton
                    edge="end"
                    color="error"
                    onClick={() => setDeleteConfirm(cred.id)}
                    disabled={loading}
                  >
                    <DeleteIcon />
                  </IconButton>
                </Tooltip>
              </ListItemSecondaryAction>
            </ListItem>
          ))}
        </List>
      )}

      {/* Delete confirmation dialog */}
      <Dialog open={!!deleteConfirm} onClose={() => setDeleteConfirm(null)}>
        <DialogTitle>Remove Security Key?</DialogTitle>
        <DialogContent>
          <Typography>
            Are you sure you want to remove this security key? You will no longer be able to use it to sign in.
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDeleteConfirm(null)}>Cancel</Button>
          <Button
            color="error"
            variant="contained"
            onClick={() => deleteConfirm && handleDelete(deleteConfirm)}
          >
            Remove
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  )
}

// ── Main MFA Setup Page ─────────────────────────────────────────────────────

export default function MfaSetupPage() {
  const [activeTab, setActiveTab] = useState(0)

  return (
    <Container maxWidth="sm" sx={{ mt: 6 }}>
      <Paper elevation={3} sx={{ p: 4 }}>
        <Typography variant="h5" fontWeight={700} mb={3}>Set Up MFA</Typography>

        <Tabs value={activeTab} onChange={(_, v) => setActiveTab(v)} sx={{ mb: 3 }}>
          <Tab label="Authenticator App" icon={<CopyIcon />} iconPosition="start" />
          <Tab label="Security Key" icon={<KeyIcon />} iconPosition="start" />
        </Tabs>

        {activeTab === 0 && <TotpSetup />}
        {activeTab === 1 && <WebAuthnSetup />}
      </Paper>
    </Container>
  )
}
