import React, { useEffect, useState } from 'react'
import {
  Box, Button, Container, TextField, Typography,
  Alert, CircularProgress, Paper, Stepper, Step, StepLabel,
  IconButton, Tooltip, Snackbar,
} from '@mui/material'
import { ContentCopy as CopyIcon } from '@mui/icons-material'
import QRCode from 'qrcode'
import { authApi } from '../api/client'
import { useAuthStore } from '../store/authStore'

const STEPS = ['Get your QR code', 'Verify code', 'Done']

export default function MfaSetupPage() {
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
        console.warn('[MFA Setup] Success:', res.status, res.data)
        // Generate QR code from otpauth URI
        if (res.data.otp_uri) {
          QRCode.toDataURL(res.data.otp_uri, {
            width: 256,
            margin: 2,
            color: { dark: '#000000', light: '#ffffff' },
          })
            .then((url) => setQrDataUrl(url))
            .catch((qrErr) => {
              console.error('[MFA Setup] QR generation failed:', qrErr)
              setError('Failed to generate QR code.')
            })
        } else {
          console.error('[MFA Setup] No otp_uri in response:', res.data)
          setError('MFA setup returned invalid data. No OTP URI found.')
        }
      })
      .catch((err) => {
        const status = err?.response?.status
        const data = err?.response?.data
        const message = err?.message
        const token = useAuthStore.getState().accessToken
        console.error('[MFA Setup] Failed:', { status, data, message, hasToken: !!token })
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
    <Container maxWidth="sm" sx={{ mt: 6 }}>
      <Paper elevation={3} sx={{ p: 4 }}>
        <Typography variant="h5" fontWeight={700} mb={3}>Set Up MFA</Typography>
        <Stepper activeStep={step} sx={{ mb: 4 }}>
          {STEPS.map((label) => <Step key={label}><StepLabel>{label}</StepLabel></Step>)}
        </Stepper>

        {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}

        {step === 0 && setup && (
          <Box>
            <Typography mb={2}>
              Scan this QR code in your authenticator app:
            </Typography>
            {qrDataUrl ? (
              <Box sx={{ display: 'flex', justifyContent: 'center', mb: 2 }}>
                <img
                  src={qrDataUrl}
                  alt="MFA QR Code"
                  width={256}
                  height={256}
                  style={{ imageRendering: 'pixelated' }}
                />
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
                sx={{
                  fontFamily: 'monospace',
                  wordBreak: 'break-all',
                  p: 1,
                  bgcolor: 'grey.100',
                  borderRadius: 1,
                  flexGrow: 1,
                }}
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
      </Paper>

      <Snackbar
        open={copied}
        autoHideDuration={2000}
        onClose={() => setCopied(false)}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'center' }}
      >
        <Alert severity="success" variant="filled">Secret copied to clipboard</Alert>
      </Snackbar>
    </Container>
  )
}
