import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Box, Button, Card, CardContent, Chip, Container, Dialog,
  DialogActions, DialogContent, DialogTitle, Snackbar,
  Alert, TextField, Typography, InputAdornment, IconButton,
  List, ListItem, ListItemIcon, ListItemText,
} from '@mui/material'
import {
  Person as PersonIcon,
  Lock as LockIcon,
  Visibility, VisibilityOff,
  VpnKey as MfaIcon,
  Save as SaveIcon,
  Check as CheckIcon, Close as CloseIcon,
} from '@mui/icons-material'
import { useAuthStore } from '../store/authStore'
import { usersApi } from '../api/client'
import type { User } from '../types'

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

export default function ProfilePage() {
  const navigate = useNavigate()
  const { user, setUser } = useAuthStore()

  // ── Profile state ────────────────────────────────────────────────────────
  const [me, setMe] = useState<User | null>(null)
  const [displayName, setDisplayName] = useState('')
  const [email, setEmail] = useState('')
  const [loadingProfile, setLoadingProfile] = useState(true)
  const [savingProfile, setSavingProfile] = useState(false)

  // ── Password state ──────────────────────────────────────────────────────
  const [currentPw, setCurrentPw] = useState('')
  const [newPw, setNewPw] = useState('')
  const [confirmPw, setConfirmPw] = useState('')
  const [showCurrentPw, setShowCurrentPw] = useState(false)
  const [showNewPw, setShowNewPw] = useState(false)
  const [showConfirmPw, setShowConfirmPw] = useState(false)
  const [changingPw, setChangingPw] = useState(false)

  // ── MFA state ────────────────────────────────────────────────────────────
  const [mfaDisableOpen, setMfaDisableOpen] = useState(false)
  const [mfaDisablePw, setMfaDisablePw] = useState('')
  const [disablingMfa, setDisablingMfa] = useState(false)

  // ── Snackbar state ──────────────────────────────────────────────────────
  const [snack, setSnack] = useState<{ open: boolean; severity: 'success' | 'error'; message: string }>({
    open: false, severity: 'success', message: '',
  })

  const showSnack = (severity: 'success' | 'error', message: string) =>
    setSnack({ open: true, severity, message })

  const pwChecks = checkPasswordStrength(newPw)
  const pwValid = isPasswordValid(pwChecks)
  const pwMismatch = !!(newPw && confirmPw && newPw !== confirmPw)

  // ── Load current user on mount ──────────────────────────────────────────
  useEffect(() => {
    ;(async () => {
      try {
        const { data } = await usersApi.getMe()
        setMe(data)
        setDisplayName(data.display_name || '')
        setEmail(data.email || '')
      } catch {
        showSnack('error', 'Failed to load profile')
      } finally {
        setLoadingProfile(false)
      }
    })()
  }, [])

  // ── Save profile ────────────────────────────────────────────────────────
  const handleSaveProfile = async () => {
    if (!me) return
    setSavingProfile(true)
    try {
      const { data } = await usersApi.update(me.id, { display_name: displayName, email })
      setMe(data)
      setUser(data)
      showSnack('success', 'Profile updated')
    } catch {
      showSnack('error', 'Failed to update profile')
    } finally {
      setSavingProfile(false)
    }
  }

  // ── Change password ────────────────────────────────────────────────────
  const handleChangePassword = async () => {
    if (newPw !== confirmPw) {
      showSnack('error', 'New passwords do not match')
      return
    }
    if (!pwValid) {
      showSnack('error', 'Password does not meet strength requirements')
      return
    }
    setChangingPw(true)
    try {
      await usersApi.changePassword({ current_password: currentPw, new_password: newPw })
      setCurrentPw('')
      setNewPw('')
      setConfirmPw('')
      showSnack('success', 'Password changed successfully')
    } catch {
      showSnack('error', 'Failed to change password')
    } finally {
      setChangingPw(false)
    }
  }

  // ── Disable MFA ─────────────────────────────────────────────────────────
  const handleDisableMfa = async () => {
    setDisablingMfa(true)
    try {
      await usersApi.disableMfa(mfaDisablePw)
      if (me) setMe({ ...me, mfa_enabled: false })
      // Also update authStore user
      if (user) setUser({ ...user, mfa_enabled: false })
      setMfaDisablePw('')
      setMfaDisableOpen(false)
      showSnack('success', 'MFA disabled')
    } catch {
      showSnack('error', 'Failed to disable MFA')
    } finally {
      setDisablingMfa(false)
    }
  }

  if (loadingProfile) {
    return (
      <Container maxWidth="md" sx={{ mt: 3 }}>
        <Box display="flex" justifyContent="center" mt={4}>Loading profile…</Box>
      </Container>
    )
  }

  return (
    <Container maxWidth="md" sx={{ mt: 3 }}>
      <Typography variant="h5" fontWeight={700} sx={{ mb: 3 }}>My Profile</Typography>

      {/* ── Profile Section ──────────────────────────────────────────────── */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Typography variant="h6" fontWeight={600} sx={{ mb: 2, display: 'flex', alignItems: 'center', gap: 1 }}>
            <PersonIcon fontSize="small" /> Profile Information
          </Typography>
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
            <TextField
              label="Username"
              value={me?.username || ''}
              InputProps={{ readOnly: true }}
              sx={{ '& .MuiInputBase-input.Mui-readOnly': { color: 'text.disabled' } }}
            />
            <TextField
              label="Display Name"
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
            />
            <TextField
              label="Email"
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
            />
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
              <Typography variant="body2" color="text.secondary">Role:</Typography>
              <Chip
                size="small"
                label={me?.role || 'unknown'}
                color={me?.role === 'admin' ? 'primary' : 'default'}
              />
            </Box>
          </Box>
          <Box sx={{ mt: 2, display: 'flex', justifyContent: 'flex-end' }}>
            <Button
              variant="contained"
              startIcon={<SaveIcon />}
              onClick={handleSaveProfile}
              disabled={savingProfile}
            >
              {savingProfile ? 'Saving…' : 'Save Profile'}
            </Button>
          </Box>
        </CardContent>
      </Card>

      {/* ── Password Section ─────────────────────────────────────────────── */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Typography variant="h6" fontWeight={600} sx={{ mb: 2, display: 'flex', alignItems: 'center', gap: 1 }}>
            <LockIcon fontSize="small" /> Change Password
          </Typography>
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
            <TextField
              label="Current Password"
              type={showCurrentPw ? 'text' : 'password'}
              value={currentPw}
              onChange={(e) => setCurrentPw(e.target.value)}
              InputProps={{
                endAdornment: (
                  <InputAdornment position="end">
                    <IconButton size="small" onClick={() => setShowCurrentPw(!showCurrentPw)} edge="end">
                      {showCurrentPw ? <VisibilityOff fontSize="small" /> : <Visibility fontSize="small" />}
                    </IconButton>
                  </InputAdornment>
                ),
              }}
            />
            <TextField
              label="New Password"
              type={showNewPw ? 'text' : 'password'}
              value={newPw}
              onChange={(e) => setNewPw(e.target.value)}
              error={pwMismatch}
              InputProps={{
                endAdornment: (
                  <InputAdornment position="end">
                    <IconButton size="small" onClick={() => setShowNewPw(!showNewPw)} edge="end">
                      {showNewPw ? <VisibilityOff fontSize="small" /> : <Visibility fontSize="small" />}
                    </IconButton>
                  </InputAdornment>
                ),
              }}
            />
            {newPw && (
              <Box sx={{ mt: -1, mb: 0 }}>
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
              label="Confirm New Password"
              type={showConfirmPw ? 'text' : 'password'}
              value={confirmPw}
              onChange={(e) => setConfirmPw(e.target.value)}
              error={pwMismatch}
              helperText={pwMismatch ? 'Passwords do not match' : ''}
              InputProps={{
                endAdornment: (
                  <InputAdornment position="end">
                    <IconButton size="small" onClick={() => setShowConfirmPw(!showConfirmPw)} edge="end">
                      {showConfirmPw ? <VisibilityOff fontSize="small" /> : <Visibility fontSize="small" />}
                    </IconButton>
                  </InputAdornment>
                ),
              }}
            />
          </Box>
          <Box sx={{ mt: 2, display: 'flex', justifyContent: 'flex-end' }}>
            <Button
              variant="contained"
              onClick={handleChangePassword}
              disabled={changingPw || !currentPw || !newPw || !confirmPw || !!pwMismatch || !pwValid}
            >
              {changingPw ? 'Changing…' : 'Change Password'}
            </Button>
          </Box>
        </CardContent>
      </Card>

      {/* ── MFA Section ──────────────────────────────────────────────────── */}
      <Card sx={{ mb: 3 }}>
        <CardContent>
          <Typography variant="h6" fontWeight={600} sx={{ mb: 2, display: 'flex', alignItems: 'center', gap: 1 }}>
            <MfaIcon fontSize="small" /> Multi-Factor Authentication
          </Typography>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 2 }}>
            <Typography variant="body2" color="text.secondary">Status:</Typography>
            <Chip
              size="small"
              label={me?.mfa_enabled ? 'Enabled' : 'Disabled'}
              color={me?.mfa_enabled ? 'success' : 'warning'}
            />
          </Box>
          {me?.mfa_enabled ? (
            <Button
              variant="outlined"
              color="warning"
              onClick={() => setMfaDisableOpen(true)}
            >
              Disable MFA
            </Button>
          ) : (
            <Button
              variant="contained"
              color="primary"
              onClick={() => navigate('/mfa/setup')}
            >
              Enable MFA
            </Button>
          )}
        </CardContent>
      </Card>

      {/* ── Disable MFA Confirmation Dialog ─────────────────────────────── */}
      <Dialog open={mfaDisableOpen} onClose={() => setMfaDisableOpen(false)} maxWidth="xs" fullWidth>
        <DialogTitle>Disable MFA</DialogTitle>
        <DialogContent>
          <Typography variant="body2" sx={{ mb: 2 }}>
            Are you sure you want to disable multi-factor authentication? This will make your account less secure.
          </Typography>
          <TextField
            fullWidth
            label="Enter your password to confirm"
            type="password"
            value={mfaDisablePw}
            onChange={(e) => setMfaDisablePw(e.target.value)}
            autoFocus
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setMfaDisableOpen(false)}>Cancel</Button>
          <Button
            variant="contained"
            color="warning"
            onClick={handleDisableMfa}
            disabled={disablingMfa || !mfaDisablePw}
          >
            {disablingMfa ? 'Disabling…' : 'Disable MFA'}
          </Button>
        </DialogActions>
      </Dialog>

      {/* ── Snackbar ─────────────────────────────────────────────────────── */}
      <Snackbar
        open={snack.open}
        autoHideDuration={4000}
        onClose={() => setSnack((s) => ({ ...s, open: false }))}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'center' }}
      >
        <Alert
          severity={snack.severity}
          onClose={() => setSnack((s) => ({ ...s, open: false }))}
          variant="filled"
        >
          {snack.message}
        </Alert>
      </Snackbar>
    </Container>
  )
}
