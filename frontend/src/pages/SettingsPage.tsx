import { useState, useEffect, useCallback } from 'react'
import {
  Accordion, AccordionDetails, AccordionSummary, Alert, Box, Button,
  CircularProgress, Container, Dialog, DialogActions, DialogContent, DialogTitle,
  FormControl, FormControlLabel, Grid, IconButton, InputLabel, MenuItem, Select,
  Chip, Snackbar, Switch, Table, TableBody, TableCell, TableHead, TableRow, TextField,
  Toolbar, Typography,
} from '@mui/material'
import type { AxiosError } from 'axios'
import ExpandMoreIcon from '@mui/icons-material/ExpandMore'
import SaveIcon from '@mui/icons-material/Save'
import DeleteIcon from '@mui/icons-material/Delete'
import AddIcon from '@mui/icons-material/Add'
import CloudIcon from '@mui/icons-material/Cloud'
import EmailIcon from '@mui/icons-material/Email'
import VpnKeyIcon from '@mui/icons-material/VpnKey'
import ExploreIcon from '@mui/icons-material/Explore'
import EditIcon from '@mui/icons-material/Edit'
import RefreshIcon from '@mui/icons-material/Refresh'
import { settingsApi, osPackageMappingsApi, upgradesApi } from '../api/client'
import { useAuthStore } from '../store/authStore'
import type { OidcConfigResponse, OidcDiscoveryResult, SmtpConfig, PollingConfig, NotificationConfig, OsPackageMapping, AvailableVersion } from '../types'

type OidcForm = OidcConfigResponse & { client_secret?: string }
type SmtpForm = SmtpConfig & { password?: string }

const KEYCLOAK_DISCOVERY_URL = 'https://keycloak.moon-dragon.us/realms/moon-dragon.us/.well-known/openid-configuration'

export default function SettingsPage() {
  const user = useAuthStore(state => state.user)
  const canWrite = user?.role === 'admin' || user?.role === 'operator'
  const [oidc, setOidc] = useState<OidcForm>({
    enabled: false, provider_type: 'azure', display_name: 'Azure AD',
    discovery_url: '', client_id: '', client_secret: '', redirect_uri: '', scopes: 'openid profile email',
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
  const [testingOidc, setTestingOidc] = useState(false)
  const [discoveringOidc, setDiscoveringOidc] = useState(false)
  const [testingSmtp, setTestingSmtp] = useState(false)
  const [oidcTestResult, setOidcTestResult] = useState<{ success: boolean; message: string } | null>(null)
  const [discoveryResult, setDiscoveryResult] = useState<OidcDiscoveryResult | null>(null)
  const [smtpTestResult, setSmtpTestResult] = useState<{ success: boolean; message: string } | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)

  // OS Package Mappings state
  const [osMappings, setOsMappings] = useState<OsPackageMapping[]>([])
  const [mappingDialogOpen, setMappingDialogOpen] = useState(false)
  const [editingMapping, setEditingMapping] = useState<OsPackageMapping | null>(null)
  const [mappingForm, setMappingForm] = useState({
    os_name: '', os_version: '', package_pattern: '', display_name: '',
  })
  const [mappingSaving, setMappingSaving] = useState(false)

  // Agent Upgrade Versions state
  const [availableVersions, setAvailableVersions] = useState<AvailableVersion[]>([])
  const [refreshingVersions, setRefreshingVersions] = useState(false)
  const [versionsSnackbar, setVersionsSnackbar] = useState<{ message: string; severity: 'success' | 'error' } | null>(null)

  const loadSettings = useCallback(async () => {
    try {
      setLoading(true)
      const { data } = await settingsApi.get()
      setOidc({ ...data.oidc, client_secret: '' })
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

  const loadMappings = useCallback(async () => {
    try {
      const { data } = await osPackageMappingsApi.list()
      setOsMappings(data)
    } catch {
      // ignore — admin-only endpoint may 403 for non-admins
    }
  }, [])

  useEffect(() => { loadMappings() }, [loadMappings])

  const loadAvailableVersions = useCallback(async () => {
    try {
      const { data } = await upgradesApi.listAvailableVersions()
      setAvailableVersions(data)
    } catch {
      // ignore — admin-only endpoint may 403 for non-admins
    }
  }, [])

  useEffect(() => { loadAvailableVersions() }, [loadAvailableVersions])

  const handleRefreshVersions = async () => {
    setRefreshingVersions(true)
    try {
      const { data } = await upgradesApi.refreshVersions()
      const upserted = (data as { upserted?: number })?.upserted ?? 0
      await loadAvailableVersions()
      setVersionsSnackbar({ message: `Refreshed versions (${upserted} upserted)`, severity: 'success' })
    } catch (err: unknown) {
      const axiosErr = err as AxiosError<{ error?: { message?: string } }>
      const msg = axiosErr.response?.data?.error?.message ?? 'Failed to refresh versions'
      setVersionsSnackbar({ message: msg, severity: 'error' })
    } finally {
      setRefreshingVersions(false)
    }
  }

  const handleOpenCreateMapping = () => {
    setEditingMapping(null)
    setMappingForm({ os_name: '', os_version: '', package_pattern: '', display_name: '' })
    setMappingDialogOpen(true)
  }

  const handleOpenEditMapping = (m: OsPackageMapping) => {
    setEditingMapping(m)
    setMappingForm({ os_name: m.os_name, os_version: m.os_version, package_pattern: m.package_pattern, display_name: m.display_name })
    setMappingDialogOpen(true)
  }

  const handleSaveMapping = async () => {
    setMappingSaving(true)
    try {
      if (editingMapping) {
        await osPackageMappingsApi.update(editingMapping.id, {
          package_pattern: mappingForm.package_pattern,
          display_name: mappingForm.display_name,
        })
      } else {
        await osPackageMappingsApi.create({
          os_name: mappingForm.os_name,
          os_version: mappingForm.os_version,
          package_pattern: mappingForm.package_pattern,
          display_name: mappingForm.display_name,
        })
      }
      setMappingDialogOpen(false)
      await loadMappings()
      setSuccess(editingMapping ? 'Mapping updated' : 'Mapping created')
    } catch (err: unknown) {
      const axiosErr = err as AxiosError<{ error?: { message?: string } }>
      setError(axiosErr.response?.data?.error?.message ?? 'Failed to save mapping')
    } finally {
      setMappingSaving(false)
    }
  }

  const handleDeleteMapping = async (id: string) => {
    try {
      await osPackageMappingsApi.delete(id)
      await loadMappings()
      setSuccess('Mapping deleted')
    } catch (err: unknown) {
      const axiosErr = err as AxiosError<{ error?: { message?: string } }>
      setError(axiosErr.response?.data?.error?.message ?? 'Failed to delete mapping')
    }
  }

  const handleProviderTypeChange = (providerType: string) => {
    let discoveryUrl = oidc.discovery_url
    let displayName = oidc.display_name

    if (providerType === 'keycloak') {
      discoveryUrl = KEYCLOAK_DISCOVERY_URL
      displayName = 'Keycloak'
    } else if (providerType === 'azure') {
      // Clear discovery URL for Azure — user must enter tenant ID pattern
      discoveryUrl = ''
      displayName = 'Azure AD'
    } else {
      // Custom — leave discovery URL as-is for user to enter
      displayName = 'OIDC Provider'
    }

    setOidc({ ...oidc, provider_type: providerType as OidcConfigResponse['provider_type'], display_name: displayName, discovery_url: discoveryUrl })
  }

  const handleDiscoverOidc = async () => {
    if (!oidc.discovery_url) return
    setDiscoveringOidc(true)
    setDiscoveryResult(null)
    try {
      const { data } = await settingsApi.discoverOidc(oidc.discovery_url)
      setDiscoveryResult(data)
    } catch (err: unknown) {
      const axiosErr = err as AxiosError
      if (axiosErr.response?.status === 403) {
        setDiscoveryResult({ success: false, issuer: '', authorization_endpoint: '', token_endpoint: '', jwks_uri: '', message: 'Only Admins can modify authentication configuration. Contact an Admin to make this change.' })
        return
      }
      const msg = err instanceof Error ? err.message : 'Discovery failed'
      setDiscoveryResult({ success: false, issuer: '', authorization_endpoint: '', token_endpoint: '', jwks_uri: '', message: msg })
    } finally {
      setDiscoveringOidc(false)
    }
  }

  const handleTestOidc = async () => {
    setTestingOidc(true)
    setOidcTestResult(null)
    try {
      // Save settings first so the test uses current form values
      await settingsApi.update({
        oidc: { ...oidc },
        smtp: { ...smtp },
        polling,
        ip_whitelist: ipWhitelist,
        web_tls_strategy: webTlsStrategy,
        notification: {
          ...notification,
          email_from: smtp.from,
        },
      })
      const { data } = await settingsApi.testOidc()
      setOidcTestResult(data)
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Test failed'
      setOidcTestResult({ success: false, message: msg })
    } finally {
      setTestingOidc(false)
    }
  }

  const handleSave = async () => {
    setSaving(true)
    setError(null)
    setSuccess(null)
    try {
      await settingsApi.update({
        oidc: { ...oidc },
        smtp: { ...smtp },
        polling,
        ip_whitelist: ipWhitelist,
        web_tls_strategy: webTlsStrategy,
        notification: {
          ...notification,
          email_from: smtp.from,
        },
      })
      setSuccess('Settings saved successfully')
    } catch (err: unknown) {
      const axiosErr = err as AxiosError<{ error?: { message?: string } }>
      if (axiosErr.response?.status === 403) {
        setError('Only Admins can modify authentication configuration. Contact an Admin to make this change.')
        return
      }
      const msg =
        axiosErr.response?.data?.error?.message ??
        (err instanceof Error ? err.message : 'Failed to save settings')
      setError(msg)
    } finally {
      setSaving(false)
    }
  }

  const handleTestSmtp = async () => {
    setTestingSmtp(true)
    setSmtpTestResult(null)
    try {
      await settingsApi.update({
        oidc: { ...oidc },
        smtp: { ...smtp },
        polling,
        ip_whitelist: ipWhitelist,
        web_tls_strategy: webTlsStrategy,
        notification: {
          ...notification,
          email_from: smtp.from,
        },
      })
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
        {canWrite && <Button variant="contained" onClick={handleSave} disabled={saving} startIcon={saving ? <CircularProgress size={20} /> : <SaveIcon />}>
          Save Settings
        </Button>}
      </Toolbar>

      {error && <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError(null)}>{error}</Alert>}

      {/* Section 1: OIDC Provider Configuration */}
      <Accordion defaultExpanded>
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          <Typography fontWeight={600}>OIDC Provider Configuration</Typography>
        </AccordionSummary>
        <AccordionDetails>
          <Grid container spacing={2}>
            <Grid size={12}>
              <FormControlLabel
                control={<Switch checked={oidc.enabled} onChange={(e) => setOidc({ ...oidc, enabled: e.target.checked })} />}
                label="Enable SSO / OIDC Authentication"
              />
            </Grid>
            <Grid size={4}>
              <FormControl fullWidth>
                <InputLabel>Provider Type</InputLabel>
                <Select
                  value={oidc.provider_type}
                  label="Provider Type"
                  onChange={(e) => handleProviderTypeChange(e.target.value)}
                  disabled={!oidc.enabled}
                >
                  <MenuItem value="keycloak">Keycloak</MenuItem>
                  <MenuItem value="azure">Azure AD</MenuItem>
                  <MenuItem value="custom">Custom OIDC</MenuItem>
                </Select>
              </FormControl>
            </Grid>
            <Grid size={4}>
              <TextField
                fullWidth
                label="Display Name"
                value={oidc.display_name}
                onChange={(e) => setOidc({ ...oidc, display_name: e.target.value })}
                helperText="Shown on the login button"
                disabled={!oidc.enabled}
              />
            </Grid>
            <Grid size={12}>
              <TextField
                fullWidth
                label="Discovery URL"
                value={oidc.discovery_url}
                onChange={(e) => setOidc({ ...oidc, discovery_url: e.target.value })}
                placeholder={oidc.provider_type === 'azure' ? 'https://login.microsoftonline.com/<tenant_id>/v2.0/.well-known/openid-configuration' : 'https://sso.example.com/.well-known/openid-configuration'}
                helperText={oidc.provider_type === 'keycloak' ? 'Auto-filled for Keycloak' : 'OIDC well-known endpoint URL'}
                disabled={!oidc.enabled}
              />
            </Grid>
            <Grid size={6}>
              <Button
                variant="outlined"
                onClick={handleDiscoverOidc}
                disabled={discoveringOidc || !oidc.discovery_url}
                startIcon={discoveringOidc ? <CircularProgress size={20} /> : <ExploreIcon />}
              >
                Discover Endpoints
              </Button>
              {discoveryResult && (
                <Alert severity={discoveryResult.success ? 'success' : 'error'} sx={{ mt: 1 }}>
                  {discoveryResult.success
                    ? `Discovered: ${discoveryResult.issuer}`
                    : discoveryResult.message || 'Discovery failed'}
                </Alert>
              )}
            </Grid>
            <Grid size={6}>
              <TextField
                fullWidth
                label="Client ID"
                value={oidc.client_id}
                onChange={(e) => setOidc({ ...oidc, client_id: e.target.value })}
                required
                disabled={!oidc.enabled}
              />
            </Grid>
            <Grid size={6}>
              <TextField
                fullWidth
                label="Client Secret"
                type="password"
                value={oidc.client_secret ?? ''}
                onChange={(e) => setOidc({ ...oidc, client_secret: e.target.value })}
                placeholder="Enter new secret or leave masked"
                helperText="Leave empty for public clients (e.g. Keycloak)"
                disabled={!oidc.enabled}
              />
            </Grid>
            <Grid size={6}>
              <TextField
                fullWidth
                label="Redirect URI"
                value={oidc.redirect_uri}
                onChange={(e) => setOidc({ ...oidc, redirect_uri: e.target.value })}
                helperText="e.g. https://patch-manager.example.com/api/v1/auth/sso/callback"
                disabled={!oidc.enabled}
              />
            </Grid>
            <Grid size={6}>
              <TextField
                fullWidth
                label="Scopes"
                value={oidc.scopes}
                onChange={(e) => setOidc({ ...oidc, scopes: e.target.value })}
                disabled={!oidc.enabled}
              />
            </Grid>
            <Grid size={6}>
              <Button
                variant="outlined"
                onClick={handleTestOidc}
                disabled={testingOidc || !oidc.discovery_url}
                startIcon={testingOidc ? <CircularProgress size={20} /> : (oidc.provider_type === 'keycloak' ? <VpnKeyIcon /> : <CloudIcon />)}
              >
                Test Connection
              </Button>
              {oidcTestResult && (
                <Alert severity={oidcTestResult.success ? 'success' : 'error'} sx={{ mt: 1 }}>{oidcTestResult.message}</Alert>
              )}
            </Grid>
          </Grid>
        </AccordionDetails>
      </Accordion>

      {/* Section 2: SMTP Configuration & Email Notifications */}
      <Accordion>
        <AccordionSummary expandIcon={<ExpandMoreIcon />}>
          <Typography fontWeight={600}>SMTP Configuration & Email Notifications</Typography>
        </AccordionSummary>
        <AccordionDetails>
          <Grid container spacing={2}>
            <Grid size={12}>
              <FormControlLabel
                control={<Switch checked={smtp.enabled} onChange={(e) => setSmtp({ ...smtp, enabled: e.target.checked })} />}
                label="Enable SMTP Server"
              />
              <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
                Enable the SMTP server connection for sending emails
              </Typography>
            </Grid>
            <Grid size={6}>
              <TextField fullWidth label="SMTP Host" value={smtp.host} onChange={(e) => setSmtp({ ...smtp, host: e.target.value })} disabled={!smtp.enabled} />
            </Grid>
            <Grid size={3}>
              <TextField fullWidth label="Port" type="number" value={smtp.port} onChange={(e) => setSmtp({ ...smtp, port: Number(e.target.value) })} disabled={!smtp.enabled} />
            </Grid>
            <Grid size={3}>
              <FormControl fullWidth>
                <InputLabel>TLS Mode</InputLabel>
                <Select value={smtp.tls_mode} label="TLS Mode" onChange={(e) => setSmtp({ ...smtp, tls_mode: e.target.value })} disabled={!smtp.enabled}>
                  <MenuItem value="none">None</MenuItem>
                  <MenuItem value="starttls">STARTTLS</MenuItem>
                  <MenuItem value="tls">TLS (Implicit)</MenuItem>
                </Select>
              </FormControl>
            </Grid>
            <Grid size={6}>
              <TextField fullWidth label="Username" value={smtp.username} onChange={(e) => setSmtp({ ...smtp, username: e.target.value })} disabled={!smtp.enabled} />
            </Grid>
            <Grid size={6}>
              <TextField fullWidth label="Password" type="password" value={smtp.password ?? ''} onChange={(e) => setSmtp({ ...smtp, password: e.target.value })} placeholder="Enter new password or leave masked" disabled={!smtp.enabled} />
            </Grid>
            <Grid size={6}>
              <TextField fullWidth label="From Address" value={smtp.from} onChange={(e) => setSmtp({ ...smtp, from: e.target.value })} helperText="Sender address for both SMTP and notifications (e.g. noreply@example.com)" disabled={!smtp.enabled} />
                       </Grid>
            <Grid size={12}>
              <FormControlLabel
                control={<Switch checked={notification.email_enabled} onChange={(e) => setNotification({ ...notification, email_enabled: e.target.checked })} />}
                label="Enable Email Notifications"
                disabled={!smtp.enabled}
              />
              <Typography variant="body2" color="text.secondary">
                Requires SMTP server to be enabled
              </Typography>
            </Grid>
            <Grid size={12}>
              <Typography variant="subtitle2" sx={{ mt: 1, mb: 1 }}>Notification Recipients</Typography>
              {notification.recipients.map((email, idx) => (
                <Box key={idx} sx={{ display: 'flex', gap: 1, mb: 1 }}>
                  <TextField size="small" value={email} onChange={(e) => {
                    const updated = [...notification.recipients]
                    updated[idx] = e.target.value
                    setNotification({ ...notification, recipients: updated })
                  }} placeholder="admin@example.com" sx={{ flexGrow: 1 }} disabled={!smtp.enabled || !notification.email_enabled} />
                  <IconButton onClick={() => {
                    setNotification({ ...notification, recipients: notification.recipients.filter((_, i) => i !== idx) })
                  }}><DeleteIcon /></IconButton>
                </Box>
              ))}
              <Button variant="outlined" startIcon={<AddIcon />} onClick={() => {
                setNotification({ ...notification, recipients: [...notification.recipients, ''] })
              }} disabled={!smtp.enabled || !notification.email_enabled}>Add Recipient</Button>
            </Grid>
            <Grid size={6}>
              <Button variant="outlined" onClick={handleTestSmtp} disabled={testingSmtp || !smtp.host} startIcon={testingSmtp ? <CircularProgress size={20} /> : <EmailIcon />}>
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

      {/* Section 6: OS Package Mappings (admin only) */}
      {user?.role === 'admin' && (
        <Accordion>
          <AccordionSummary expandIcon={<ExpandMoreIcon />}>
            <Typography fontWeight={600}>OS Package Mappings</Typography>
          </AccordionSummary>
          <AccordionDetails>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
              Maps OS name/version to package file patterns for filtering available upgrade versions by host OS.
            </Typography>
            {osMappings.length > 0 && (
              <Table size="small" sx={{ mb: 2 }}>
                <TableHead>
                  <TableRow>
                    <TableCell>OS Name</TableCell>
                    <TableCell>OS Version</TableCell>
                    <TableCell>Package Pattern</TableCell>
                    <TableCell>Display Name</TableCell>
                    <TableCell>Default</TableCell>
                    <TableCell>Actions</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {osMappings.map((m) => (
                    <TableRow key={m.id}>
                      <TableCell>{m.os_name}</TableCell>
                      <TableCell>{m.os_version}</TableCell>
                      <TableCell sx={{ fontFamily: 'monospace', fontSize: '0.85em' }}>{m.package_pattern}</TableCell>
                      <TableCell>{m.display_name}</TableCell>
                      <TableCell>{m.is_default ? 'Yes' : 'No'}</TableCell>
                      <TableCell>
                        <IconButton size="small" onClick={() => handleOpenEditMapping(m)} disabled={m.is_default}>
                          <EditIcon fontSize="small" />
                        </IconButton>
                        <IconButton size="small" onClick={() => handleDeleteMapping(m.id)} disabled={m.is_default}>
                          <DeleteIcon fontSize="small" />
                        </IconButton>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
            <Button variant="outlined" startIcon={<AddIcon />} onClick={handleOpenCreateMapping}>
              Add Mapping
            </Button>
          </AccordionDetails>
        </Accordion>
      )}

      {/* Section 7: Agent Upgrade Versions (admin only) */}
      {user?.role === 'admin' && (
        <Accordion>
          <AccordionSummary expandIcon={<ExpandMoreIcon />}>
            <Typography fontWeight={600}>Agent Upgrade Versions</Typography>
          </AccordionSummary>
          <AccordionDetails>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
              Available agent versions cached from GitHub releases. Click refresh to fetch the latest releases from the Linux-Patch-Api repository.
            </Typography>
            <Button
              variant="outlined"
              onClick={handleRefreshVersions}
              disabled={refreshingVersions}
              startIcon={refreshingVersions ? <CircularProgress size={20} /> : <RefreshIcon />}
              sx={{ mb: 2 }}
            >
              Refresh Versions
            </Button>
            {(() => {
              // Deduplicate by version — backend stores one row per package type (deb, rpm, etc.)
              const unique = availableVersions.filter((v, i, arr) =>
                arr.findIndex(x => x.version === v.version) === i
              )
              return unique.length > 0 ? (
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell>Version</TableCell>
                      <TableCell>Prerelease</TableCell>
                      <TableCell>Published At</TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {unique.map((v) => (
                      <TableRow key={v.id}>
                        <TableCell sx={{ fontFamily: 'monospace', fontSize: '0.85em' }}>{v.version}</TableCell>
                        <TableCell>
                          <Chip
                            label={v.prerelease ? 'Yes' : 'No'}
                            size="small"
                            color={v.prerelease ? 'warning' : 'success'}
                            variant={v.prerelease ? 'filled' : 'outlined'}
                          />
                        </TableCell>
                        <TableCell>{v.published_at ? new Date(v.published_at).toLocaleString() : '—'}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              ) : null
            })()}
          </AccordionDetails>
        </Accordion>
      )}

      {/* OS Package Mapping Create/Edit Dialog */}
      <Dialog open={mappingDialogOpen} onClose={() => setMappingDialogOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>{editingMapping ? 'Edit OS Package Mapping' : 'New OS Package Mapping'}</DialogTitle>
        <DialogContent>
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2, mt: 1 }}>
            <TextField
              fullWidth
              label="OS Name"
              value={mappingForm.os_name}
              onChange={(e) => setMappingForm({ ...mappingForm, os_name: e.target.value })}
              placeholder="e.g. Ubuntu"
              disabled={!!editingMapping}
              helperText={editingMapping ? 'Cannot be changed after creation' : 'OS family name'}
            />
            <TextField
              fullWidth
              label="OS Version"
              value={mappingForm.os_version}
              onChange={(e) => setMappingForm({ ...mappingForm, os_version: e.target.value })}
              placeholder="e.g. 24.04 or *"
              disabled={!!editingMapping}
              helperText={editingMapping ? 'Cannot be changed after creation' : 'Specific version or * for wildcard'}
            />
            <TextField
              fullWidth
              label="Package Pattern"
              value={mappingForm.package_pattern}
              onChange={(e) => setMappingForm({ ...mappingForm, package_pattern: e.target.value })}
              placeholder="e.g. .*ubuntu.*24\.04.*\.deb"
              helperText="Regex pattern to match package file names"
            />
            <TextField
              fullWidth
              label="Display Name"
              value={mappingForm.display_name}
              onChange={(e) => setMappingForm({ ...mappingForm, display_name: e.target.value })}
              placeholder="e.g. Ubuntu 24.04 (DEB)"
              helperText="Human-readable label"
            />
          </Box>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setMappingDialogOpen(false)}>Cancel</Button>
          <Button
            variant="contained"
            onClick={handleSaveMapping}
            disabled={mappingSaving || !mappingForm.os_name || !mappingForm.os_version || !mappingForm.package_pattern || !mappingForm.display_name}
            startIcon={mappingSaving ? <CircularProgress size={20} /> : <SaveIcon />}
          >
            {editingMapping ? 'Update' : 'Create'}
          </Button>
        </DialogActions>
      </Dialog>

      <Snackbar
        open={!!success}
        autoHideDuration={4000}
        onClose={() => setSuccess(null)}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'center' }}
      >
        <Alert severity="success" onClose={() => setSuccess(null)}>
          {success}
        </Alert>
      </Snackbar>

      <Snackbar
        open={!!versionsSnackbar}
        autoHideDuration={4000}
        onClose={() => setVersionsSnackbar(null)}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'center' }}
      >
        <Alert severity={versionsSnackbar?.severity} onClose={() => setVersionsSnackbar(null)}>
          {versionsSnackbar?.message}
        </Alert>
      </Snackbar>
    </Container>
  )
}
