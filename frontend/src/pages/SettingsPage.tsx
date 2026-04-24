import { useState, useEffect, useCallback } from 'react'
import {
  Accordion, AccordionDetails, AccordionSummary, Alert, Box, Button,
  CircularProgress, Container, FormControl, FormControlLabel, Grid,
  IconButton, InputLabel, MenuItem, Select, Snackbar, Switch, TextField,
  Toolbar, Typography,
} from '@mui/material'
import ExpandMoreIcon from '@mui/icons-material/ExpandMore'
import SaveIcon from '@mui/icons-material/Save'
import DeleteIcon from '@mui/icons-material/Delete'
import AddIcon from '@mui/icons-material/Add'
import CloudIcon from '@mui/icons-material/Cloud'
import EmailIcon from '@mui/icons-material/Email'
import VerifiedUserIcon from '@mui/icons-material/VerifiedUser'
import { settingsApi } from '../api/client'
import type { AzureSsoConfig, SmtpConfig, PollingConfig, NotificationConfig } from '../types'

type AzureSsoForm = AzureSsoConfig & { client_secret?: string }
type SmtpForm = SmtpConfig & { password?: string }

export default function SettingsPage() {
  const [azureSso, setAzureSso] = useState<AzureSsoForm>({
    enabled: false, tenant_id: '', client_id: '', client_secret: '', redirect_uri: '', scopes: 'openid email profile',
  })
  const [smtp, setSmtp] = useState<SmtpForm>({
    enabled: false, host: '', port: 587, username: '', password: '', from: '', tls_mode: 'starttls',
  })
  const [polling, setPolling] = useState<PollingConfig>({
    health_poll_interval_secs: 300, patch_poll_interval_secs: 1800,
  })
  const [ipWhitelist, setIpWhitelist] = useState<string[]>([])
  const [webTlsStrategy, setWebTlsStrategy] = useState('internal_ca')
  const [notification, setNotification] = useState<NotificationConfig>({
    email_enabled: false, email_from: 'patch-manager@localhost', recipients: [],
  })

  const [saving, setSaving] = useState(false)
  const [testingAzure, setTestingAzure] = useState(false)
  const [testingSmtp, setTestingSmtp] = useState(false)
  const [testingIntegrity, setTestingIntegrity] = useState(false)
  const [integrityResult, setIntegrityResult] = useState<{ intact: boolean; rows_checked: number; errors: Array<{ row_id: number; expected_hash: string; actual_hash: string }> } | null>(null)
  const [azureSsoTestResult, setAzureSsoTestResult] = useState<{ success: boolean; message: string } | null>(null)
  const [smtpTestResult, setSmtpTestResult] = useState<{ success: boolean; message: string } | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)

  const loadSettings = useCallback(async () => {
    try {
      setLoading(true)
      const { data } = await settingsApi.get()
      setAzureSso({ ...data.azure_sso, client_secret: '' })
      setSmtp({ ...data.smtp, password: '' })
      setPolling(data.polling)
      setIpWhitelist(data.ip_whitelist)
      setWebTlsStrategy(data.web_tls_strategy)
      setNotification(data.notification)
    } catch {
      setError('Failed to load settings')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { loadSettings() }, [loadSettings])

  const handleSave = async () => {
    setSaving(true)
    setError(null)
    setSuccess(null)
    try {
      await settingsApi.update({
        azure_sso: { ...azureSso },
        smtp: { ...smtp },
        polling,
        ip_whitelist: ipWhitelist,
        web_tls_strategy: webTlsStrategy,
        notification,
      })
      setSuccess('Settings saved successfully')
    } catch {
      setError('Failed to save settings')
    } finally {
      setSaving(false)
    }
  }

  const handleAuditIntegrity = async () => {
    setTestingIntegrity(true)
    setIntegrityResult(null)
    try {
      const { data } = await settingsApi.auditIntegrity()
      setIntegrityResult(data)
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Verification failed'
      setIntegrityResult({ intact: false, rows_checked: 0, errors: [{ row_id: 0, expected_hash: '', actual_hash: msg }] })
    } finally {
      setTestingIntegrity(false)
    }
  }

  const handleTestAzureSso = async () => {
    setTestingAzure(true)
    setAzureSsoTestResult(null)
    try {
      const { data } = await settingsApi.testAzureSso()
      setAzureSsoTestResult(data)
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Test failed'
      setAzureSsoTestResult({ success: false, message: msg })
    } finally {
      setTestingAzure(false)
    }
  }

  const handleTestSmtp = async () => {
    setTestingSmtp(true)
    setSmtpTestResult(null)
    try {
      const { data } = await settingsApi.testSmtp()
      setSmtpTestResult(data)
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Test failed'
      setSmtpTestResult({ success: false, message: msg })
    } finally {
      setTestingSmtp(false)
    }
  }

  const addWhitelistEntry = () => setIpWhitelist([...ipWhitelist, ''])
  const removeWhitelistEntry = (idx: number) => setIpWhitelist(ipWhitelist.filter((_, i) => i !== idx))
  const updateWhitelistEntry = (idx: number, value: string) => {
    const updated = [...ipWhitelist]
    updated[idx] = value
    setIpWhitelist(updated)
  }

  if (loading) {
    return (
      <Container maxWidth="lg" sx={{ mt: 3, textAlign: 'center' }}>
        <CircularProgress />
      </Container>
    )
  }

  return (
    <Container maxWidth="lg" sx={{ mt: 3 }}>
      <Toolbar disableGutters sx={{ mb: 3, justifyContent: 'space-between' }}>
        <Typography variant="h5" fontWeight={700}>Settings</Typography>
        <Button variant="contained" onClick={handleSave} disabled={saving} startIcon={saving ? <CircularProgress size={20} /> : <SaveIcon />}>
          Save Settings
        </Button>
      </Toolbar>

      {error && <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError(null)}>{error}</Alert>}

      {/* Section 1: Azure SSO Configuration */}
      <Accordion defaultExpanded>
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          <Typography fontWeight={600}>Azure SSO Configuration</Typography>
        </AccordionSummary>
        <AccordionDetails>
          <Grid container spacing={2}>
            <Grid size={12}>
              <FormControlLabel
                control={<Switch checked={azureSso.enabled} onChange={(e) => setAzureSso({ ...azureSso, enabled: e.target.checked })} />}
                label="Enable Azure SSO"
              />
            </Grid>
            <Grid size={6}>
              <TextField fullWidth label="Tenant ID" value={azureSso.tenant_id} onChange={(e) => setAzureSso({ ...azureSso, tenant_id: e.target.value })} />
            </Grid>
            <Grid size={6}>
              <TextField fullWidth label="Client ID" value={azureSso.client_id} onChange={(e) => setAzureSso({ ...azureSso, client_id: e.target.value })} />
            </Grid>
            <Grid size={6}>
              <TextField fullWidth label="Client Secret" type="password" value={azureSso.client_secret ?? ''} onChange={(e) => setAzureSso({ ...azureSso, client_secret: e.target.value })} placeholder="Enter new secret or leave masked" />
            </Grid>
            <Grid size={6}>
              <TextField fullWidth label="Redirect URI" value={azureSso.redirect_uri} onChange={(e) => setAzureSso({ ...azureSso, redirect_uri: e.target.value })} helperText="e.g. https://patch-manager.example.com/api/v1/auth/azure/callback" />
            </Grid>
            <Grid size={6}>
              <TextField fullWidth label="Scopes" value={azureSso.scopes} onChange={(e) => setAzureSso({ ...azureSso, scopes: e.target.value })} />
            </Grid>
            <Grid size={6}>
              <Button variant="outlined" onClick={handleTestAzureSso} disabled={testingAzure || !azureSso.tenant_id} startIcon={testingAzure ? <CircularProgress size={20} /> : <CloudIcon />}>
                Test Connection
              </Button>
              {azureSsoTestResult && (
                <Alert severity={azureSsoTestResult.success ? 'success' : 'error'} sx={{ mt: 1 }}>{azureSsoTestResult.message}</Alert>
              )}
            </Grid>
          </Grid>
        </AccordionDetails>
      </Accordion>

      {/* Section 2: SMTP Configuration */}
      <Accordion>
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          <Typography fontWeight={600}>SMTP Configuration</Typography>
        </AccordionSummary>
        <AccordionDetails>
          <Grid container spacing={2}>
            <Grid size={12}>
              <FormControlLabel
                control={<Switch checked={smtp.enabled} onChange={(e) => setSmtp({ ...smtp, enabled: e.target.checked })} />}
                label="Enable Email Notifications"
              />
            </Grid>
            <Grid size={6}>
              <TextField fullWidth label="SMTP Host" value={smtp.host} onChange={(e) => setSmtp({ ...smtp, host: e.target.value })} />
            </Grid>
            <Grid size={3}>
              <TextField fullWidth label="Port" type="number" value={smtp.port} onChange={(e) => setSmtp({ ...smtp, port: Number(e.target.value) })} />
            </Grid>
            <Grid size={3}>
              <FormControl fullWidth>
                <InputLabel>TLS Mode</InputLabel>
                <Select value={smtp.tls_mode} label="TLS Mode" onChange={(e) => setSmtp({ ...smtp, tls_mode: e.target.value })}>
                  <MenuItem value="none">None</MenuItem>
                  <MenuItem value="starttls">STARTTLS</MenuItem>
                  <MenuItem value="tls">TLS (Implicit)</MenuItem>
                </Select>
              </FormControl>
            </Grid>
            <Grid size={6}>
              <TextField fullWidth label="Username" value={smtp.username} onChange={(e) => setSmtp({ ...smtp, username: e.target.value })} />
            </Grid>
            <Grid size={6}>
              <TextField fullWidth label="Password" type="password" value={smtp.password ?? ''} onChange={(e) => setSmtp({ ...smtp, password: e.target.value })} placeholder="Enter new password or leave masked" />
            </Grid>
            <Grid size={6}>
              <TextField fullWidth label="From Address" value={smtp.from} onChange={(e) => setSmtp({ ...smtp, from: e.target.value })} helperText="noreply@example.com" />
            </Grid>
            <Grid size={6}>
              <Button variant="outlined" onClick={handleTestSmtp} disabled={testingSmtp || !smtp.enabled} startIcon={testingSmtp ? <CircularProgress size={20} /> : <EmailIcon />}>
                Send Test Email
              </Button>
              {smtpTestResult && (
                <Alert severity={smtpTestResult.success ? 'success' : 'error'} sx={{ mt: 1 }}>{smtpTestResult.message}</Alert>
              )}
            </Grid>
          </Grid>
        </AccordionDetails>
      </Accordion>

      {/* Section 3: Polling Intervals */}
      <Accordion>
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          <Typography fontWeight={600}>Polling Intervals</Typography>
        </AccordionSummary>
        <AccordionDetails>
          <Grid container spacing={2}>
            <Grid size={6}>
              <TextField fullWidth label="Health Poll Interval (seconds)" type="number" value={polling.health_poll_interval_secs} onChange={(e) => setPolling({ ...polling, health_poll_interval_secs: Number(e.target.value) })} helperText="How often to check agent health (default: 300)" />
            </Grid>
            <Grid size={6}>
              <TextField fullWidth label="Patch Data Poll Interval (seconds)" type="number" value={polling.patch_poll_interval_secs} onChange={(e) => setPolling({ ...polling, patch_poll_interval_secs: Number(e.target.value) })} helperText="How often to check for patch updates (default: 1800)" />
            </Grid>
          </Grid>
        </AccordionDetails>
      </Accordion>

      {/* Section 4: IP Whitelist */}
      <Accordion>
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          <Typography fontWeight={600}>IP Whitelist</Typography>
        </AccordionSummary>
        <AccordionDetails>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            Restrict access to specific IP addresses or CIDR ranges. Leave empty to allow all.
          </Typography>
          {ipWhitelist.map((entry, idx) => (
            <Box key={idx} sx={{ display: 'flex', gap: 1, mb: 1 }}>
              <TextField size="small" value={entry} onChange={(e) => updateWhitelistEntry(idx, e.target.value)} placeholder="10.0.0.0/8 or 192.168.1.100" sx={{ flexGrow: 1 }} />
              <IconButton onClick={() => removeWhitelistEntry(idx)}><DeleteIcon /></IconButton>
            </Box>
          ))}
          <Button variant="outlined" startIcon={<AddIcon />} onClick={addWhitelistEntry}>Add Entry</Button>
        </AccordionDetails>
      </Accordion>

      {/* Section 5: Web UI TLS Certificate Strategy */}
      <Accordion>
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          <Typography fontWeight={600}>Web UI TLS Certificate</Typography>
        </AccordionSummary>
        <AccordionDetails>
          <FormControl fullWidth>
            <InputLabel>TLS Certificate Strategy</InputLabel>
            <Select value={webTlsStrategy} label="TLS Certificate Strategy" onChange={(e) => setWebTlsStrategy(e.target.value)}>
              <MenuItem value="internal_ca">Internal CA (auto-generated)</MenuItem>
              <MenuItem value="operator_supplied">Operator-Supplied Certificate</MenuItem>
            </Select>
          </FormControl>
          <Typography variant="body2" color="text.secondary" sx={{ mt: 1 }}>
            {webTlsStrategy === 'internal_ca'
              ? 'The internal CA will automatically generate and renew the web UI TLS certificate.'
              : 'You must provide your own TLS certificate and key files at the configured paths.'}
          </Typography>
        </AccordionDetails>
      </Accordion>

      {/* Section 6: Email Notification Settings */}
      <Accordion>
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          <Typography fontWeight={600}>Email Notifications</Typography>
        </AccordionSummary>
        <AccordionDetails>
          <Grid container spacing={2}>
            <Grid size={12}>
              <FormControlLabel
                control={<Switch checked={notification.email_enabled} onChange={(e) => setNotification({ ...notification, email_enabled: e.target.checked })} />}
                label="Enable Email Notifications"
              />
            </Grid>
            <Grid size={6}>
              <TextField fullWidth label="From Address" value={notification.email_from} onChange={(e) => setNotification({ ...notification, email_from: e.target.value })} helperText="Sender address for notifications" />
            </Grid>
            <Grid size={12}>
              <Typography variant="subtitle2" sx={{ mt: 1, mb: 1 }}>Recipients</Typography>
              {notification.recipients.map((email, idx) => (
                <Box key={idx} sx={{ display: 'flex', gap: 1, mb: 1 }}>
                  <TextField size="small" value={email} onChange={(e) => {
                    const updated = [...notification.recipients]
                    updated[idx] = e.target.value
                    setNotification({ ...notification, recipients: updated })
                  }} placeholder="admin@example.com" sx={{ flexGrow: 1 }} />
                  <IconButton onClick={() => {
                    setNotification({ ...notification, recipients: notification.recipients.filter((_, i) => i !== idx) })
                  }}><DeleteIcon /></IconButton>
                </Box>
              ))}
              <Button variant="outlined" startIcon={<AddIcon />} onClick={() => {
                setNotification({ ...notification, recipients: [...notification.recipients, ''] })
              }}>Add Recipient</Button>
            </Grid>
          </Grid>
        </AccordionDetails>
      </Accordion>

      {/* Section 7: Audit Integrity Verification */}
      <Accordion>
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          <Typography fontWeight={600}>Audit Integrity Verification</Typography>
        </AccordionSummary>
        <AccordionDetails>
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
            Verify the integrity of the audit log hash chain. This checks that all audit entries are properly linked and have not been tampered with.
          </Typography>
          <Button variant="outlined" onClick={handleAuditIntegrity} disabled={testingIntegrity} startIcon={testingIntegrity ? <CircularProgress size={20} /> : <VerifiedUserIcon />}>
            Verify Audit Integrity
          </Button>
          {integrityResult && (
            <Alert severity={integrityResult.intact ? 'success' : 'error'} sx={{ mt: 2 }}>
              {integrityResult.intact
                ? `Audit chain intact — ${integrityResult.rows_checked} rows verified`
                : `Audit chain compromised! ${integrityResult.errors.length} error(s) found across ${integrityResult.rows_checked} rows checked`}
              {integrityResult.errors.length > 0 && (
                <Box sx={{ mt: 1 }}>
                  {integrityResult.errors.slice(0, 5).map((e, i) => (
                    <Typography key={i} variant="body2">
                      Row {e.row_id}: expected {e.expected_hash.substring(0, 16)}... got {e.actual_hash.substring(0, 16)}...
                    </Typography>
                  ))}
                  {integrityResult.errors.length > 5 && (
                    <Typography variant="body2">...and {integrityResult.errors.length - 5} more errors</Typography>
                  )}
                </Box>
              )}
            </Alert>
          )}
        </AccordionDetails>
      </Accordion>
      <Snackbar
        open={!!success}
        autoHideDuration={4000}
        onClose={() => setSuccess(null)}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'center' }}
      >
        <Alert severity="success" onClose={() => setSuccess(null)}>{success}</Alert>
      </Snackbar>
    </Container>
  )
}
