import { useEffect, useState, useCallback } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import {
  Alert,
  Box,
  Button,
  Chip,
  CircularProgress,
  Container,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  Divider,
  FormControl,
  FormControlLabel,
  Grid,
  IconButton,
  InputLabel,
  MenuItem,
  Paper,
  Select,
  Snackbar,
  Switch,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableRow,
  TextField,
  Tooltip,
  Typography,
} from '@mui/material'
import {
  Add as AddIcon,
  ArrowBack,
  Cancel as CancelIcon,
  CheckCircle as CheckCircleIcon,
  Delete as DeleteIcon,
  Edit as EditIcon,
  MonitorHeart as MonitorHeartIcon,
  PlayArrow as PlayArrowIcon,
  Remove as RemoveIcon,
  Schedule as ScheduleIcon,
  VpnKey as VpnKeyIcon,
  ContentCopy as CopyIcon,
} from '@mui/icons-material'
import { apiClient, hostsApi, maintenanceWindowsApi, healthChecksApi, certsApi } from '../api/client'
import type {
  CreateHostRequest,
  IssuedCert,
  MaintenanceWindow,
  WindowRecurrence,
  HealthCheckType,
  HealthCheckWithResult,
  CreateHealthCheckRequest,
  UpdateHealthCheckRequest,
} from '../types'

// ── Helpers ───────────────────────────────────────────────────────────────────

const DAY_NAMES = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday']

function recurrenceLabel(r: WindowRecurrence): string {
  const map: Record<WindowRecurrence, string> = {
    once: 'One-Time', daily: 'Daily', weekly: 'Weekly', monthly: 'Monthly',
  }
  return map[r]
}

function scheduleDescription(w: MaintenanceWindow): string {
  const dur = `${w.duration_minutes} min`
  const time = new Date(w.start_at).toLocaleTimeString([], {
    hour: '2-digit', minute: '2-digit', timeZoneName: 'short',
  })
  switch (w.recurrence) {
    case 'once':
      return `Once at ${new Date(w.start_at).toLocaleString()} for ${dur}`
    case 'daily':
      return `Every day at ${time} for ${dur}`
    case 'weekly': {
      const day = w.recurrence_day != null ? DAY_NAMES[w.recurrence_day] ?? `Day ${w.recurrence_day}` : '?' // eslint-disable-line eqeqeq
      return `Every ${day} at ${time} for ${dur}`
    }
    case 'monthly': {
      const day = w.recurrence_day != null ? w.recurrence_day : '?' // eslint-disable-line eqeqeq
      return `Monthly on day ${day} at ${time} for ${dur}`
    }
  }
}

// ── Window form value type ────────────────────────────────────────────────────

interface FormValues {
  label: string
  recurrence: WindowRecurrence
  start_at: string
  duration_minutes: number
  recurrence_day: number | ''
  enabled: boolean
}

function defaultForm(): FormValues {
  return {
    label: '',
    recurrence: 'once',
    start_at: new Date().toISOString().slice(0, 16),
    duration_minutes: 60,
    recurrence_day: '',
    enabled: true,
  }
}

// ── Window form dialog ────────────────────────────────────────────────────────

interface WindowFormDialogProps {
  open: boolean
  title: string
  initial: FormValues
  onClose: () => void
  onSubmit: (values: FormValues) => Promise<void>
}

function WindowFormDialog({ open, title, initial, onClose, onSubmit }: WindowFormDialogProps) {
  const [form, setForm] = useState<FormValues>(initial)
  const [saving, setSaving] = useState(false)
  const [err, setErr] = useState<string | null>(null)

  useEffect(() => { setForm(initial); setErr(null) }, [open, initial])

  const set = (field: keyof FormValues, value: FormValues[keyof FormValues]) =>
    setForm(prev => ({ ...prev, [field]: value }))

  const needsDay = form.recurrence === 'weekly' || form.recurrence === 'monthly'

  const handleSubmit = async () => {
    if (!form.label.trim()) { setErr('Label is required'); return }
    if (needsDay && form.recurrence_day === '') { setErr('Recurrence day is required'); return }
    setSaving(true); setErr(null)
    try { await onSubmit(form) }
    catch (e: unknown) {
      const msg = (e as { response?: { data?: { error?: { message?: string } } } })
        ?.response?.data?.error?.message ?? 'Failed to save'
      setErr(msg)
    } finally { setSaving(false) }
  }

  return (
    <Dialog open={open} onClose={onClose} maxWidth="sm" fullWidth>
      <DialogTitle>{title}</DialogTitle>
      <DialogContent sx={{ display: 'flex', flexDirection: 'column', gap: 2, pt: 2 }}>
        {err && <Alert severity="error">{err}</Alert>}
        <TextField label="Label" value={form.label} onChange={e => set('label', e.target.value)} required fullWidth />
        <FormControl fullWidth>
          <InputLabel>Recurrence</InputLabel>
          <Select label="Recurrence" value={form.recurrence} onChange={e => set('recurrence', e.target.value as WindowRecurrence)}>
            <MenuItem value="once">One-Time</MenuItem>
            <MenuItem value="daily">Daily</MenuItem>
            <MenuItem value="weekly">Weekly</MenuItem>
            <MenuItem value="monthly">Monthly</MenuItem>
          </Select>
        </FormControl>
        <TextField
          label={form.recurrence === 'once' ? 'Start Date & Time (UTC)' : 'Reference Time (UTC)'}
          type="datetime-local" value={form.start_at}
          onChange={e => set('start_at', e.target.value)} fullWidth
          slotProps={{ inputLabel: { shrink: true } }}
        />
        <TextField label="Duration (minutes)" type="number" value={form.duration_minutes}
          onChange={e => set('duration_minutes', parseInt(e.target.value, 10) || 60)} fullWidth
          slotProps={{ htmlInput: { min: 1, max: 1440 } }}
        />
        {form.recurrence === 'weekly' && (
          <FormControl fullWidth>
            <InputLabel>Day of Week</InputLabel>
            <Select label="Day of Week" value={form.recurrence_day}
              onChange={e => set('recurrence_day', Number(e.target.value))}>
              {DAY_NAMES.map((name, i) => <MenuItem key={i} value={i}>{name}</MenuItem>)}
            </Select>
          </FormControl>
        )}
        {form.recurrence === 'monthly' && (
          <TextField label="Day of Month (1-31)" type="number" value={form.recurrence_day}
            onChange={e => set('recurrence_day', parseInt(e.target.value, 10) || 1)} fullWidth
            slotProps={{ htmlInput: { min: 1, max: 31 } }}
          />
        )}
        <FormControlLabel
          control={<Switch checked={form.enabled} onChange={e => set('enabled', e.target.checked)} />}
          label="Enabled"
        />
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose} disabled={saving}>Cancel</Button>
        <Button variant="contained" onClick={handleSubmit} disabled={saving}>
          {saving ? <CircularProgress size={20} /> : 'Save'}
        </Button>
      </DialogActions>
    </Dialog>
  )
}

// ── Health Check form value type ─────────────────────────────────────────────

interface HealthCheckFormValues {
  name: string
  check_type: HealthCheckType
  service_name: string
  url: string
  expected_body: string
  ignore_cert_errors: boolean
  basic_auth_user: string
  basic_auth_pass: string
  enabled: boolean
}

function defaultHealthCheckForm(): HealthCheckFormValues {
  return {
    name: '',
    check_type: 'service',
    service_name: '',
    url: '',
    expected_body: '',
    ignore_cert_errors: false,
    basic_auth_user: '',
    basic_auth_pass: '',
    enabled: true,
  }
}

// ── Health Check form dialog ──────────────────────────────────────────────────

interface HealthCheckFormDialogProps {
  open: boolean
  title: string
  initial: HealthCheckFormValues
  onClose: () => void
  onSubmit: (values: HealthCheckFormValues) => Promise<void>
}

function HealthCheckFormDialog({ open, title, initial, onClose, onSubmit }: HealthCheckFormDialogProps) {
  const [form, setForm] = useState<HealthCheckFormValues>(initial)
  const [saving, setSaving] = useState(false)
  const [err, setErr] = useState<string | null>(null)

  useEffect(() => { setForm(initial); setErr(null) }, [open, initial])

  const set = (field: keyof HealthCheckFormValues, value: HealthCheckFormValues[keyof HealthCheckFormValues]) =>
    setForm(prev => ({ ...prev, [field]: value }))

  const handleSubmit = async () => {
    if (!form.name.trim()) { setErr('Name is required'); return }
    if (form.check_type === 'service' && !form.service_name.trim()) { setErr('Service name is required'); return }
    if (form.check_type === 'http' && !form.url.trim()) { setErr('URL is required'); return }
    setSaving(true); setErr(null)
    try { await onSubmit(form) }
    catch (e: unknown) {
      const msg = (e as { response?: { data?: { error?: { message?: string } } } })
        ?.response?.data?.error?.message ?? 'Failed to save'
      setErr(msg)
    } finally { setSaving(false) }
  }

  return (
    <Dialog open={open} onClose={onClose} maxWidth="sm" fullWidth>
      <DialogTitle>{title}</DialogTitle>
      <DialogContent sx={{ display: 'flex', flexDirection: 'column', gap: 2, pt: 2 }}>
        {err && <Alert severity="error">{err}</Alert>}
        <TextField label="Name" value={form.name} onChange={e => set('name', e.target.value)} required fullWidth />
        <FormControl fullWidth>
          <InputLabel>Check Type</InputLabel>
          <Select label="Check Type" value={form.check_type} onChange={e => set('check_type', e.target.value as HealthCheckType)}>
            <MenuItem value="service">Service</MenuItem>
            <MenuItem value="http">HTTP</MenuItem>
          </Select>
        </FormControl>
        {form.check_type === 'service' && (
          <TextField label="Service Name" value={form.service_name} onChange={e => set('service_name', e.target.value)} required fullWidth
            helperText="Systemd service unit name to check" />
        )}
        {form.check_type === 'http' && (
          <>
            <TextField label="URL" value={form.url} onChange={e => set('url', e.target.value)} required fullWidth
              helperText="Full URL to check (e.g. https://example.com/health)" />
            <TextField label="Expected Body (optional)" value={form.expected_body} onChange={e => set('expected_body', e.target.value)} fullWidth
              helperText="Substring expected in response body" />
            <FormControlLabel
              control={<Switch checked={form.ignore_cert_errors} onChange={e => set('ignore_cert_errors', e.target.checked)} />}
              label="Ignore Certificate Errors"
            />
            <TextField label="Basic Auth User (optional)" value={form.basic_auth_user} onChange={e => set('basic_auth_user', e.target.value)} fullWidth />
            <TextField label="Basic Auth Password (optional)" type="password" value={form.basic_auth_pass} onChange={e => set('basic_auth_pass', e.target.value)} fullWidth
              helperText="Leave blank to keep existing password" />
          </>
        )}
        <FormControlLabel
          control={<Switch checked={form.enabled} onChange={e => set('enabled', e.target.checked)} />}
          label="Enabled"
        />
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose} disabled={saving}>Cancel</Button>
        <Button variant="contained" onClick={handleSubmit} disabled={saving}>
          {saving ? <CircularProgress size={20} /> : 'Save'}
        </Button>
      </DialogActions>
    </Dialog>
  )
}

// ── Create Host Form ──────────────────────────────────────────────────────────
// ── One-Time Key Display Dialog ───────────────────────────────────────────────

interface KeyDisplayDialogProps {
  open: boolean
  cert: IssuedCert | null
  onClose: () => void
}

function KeyDisplayDialog({ open, cert, onClose }: KeyDisplayDialogProps) {
  const [copiedField, setCopiedField] = useState<'cert' | 'key' | null>(null)

  const handleCopy = async (text: string, field: 'cert' | 'key') => {
    await navigator.clipboard.writeText(text)
    setCopiedField(field)
    setTimeout(() => setCopiedField(null), 2000)
  }

  return (
    <Dialog open={open} onClose={onClose} maxWidth="md" fullWidth>
      <DialogTitle>Certificate Issued — Save Your Private Key</DialogTitle>
      <DialogContent sx={{ display: 'flex', flexDirection: 'column', gap: 2, pt: 2 }}>
        <Alert severity="warning">
          <strong>This private key will NOT be shown again.</strong> Copy and store it securely
          before closing this dialog.
        </Alert>
        {cert && (
          <>
            <Typography variant="caption" color="text.secondary">
              Serial: {cert.serial_number} &nbsp;|&nbsp; Expires: {new Date(cert.expires_at).toLocaleDateString()}
            </Typography>
            <Box>
              <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 0.5 }}>
                <Typography variant="subtitle2">Certificate (cert.pem)</Typography>
                <Tooltip title={copiedField === 'cert' ? 'Copied!' : 'Copy certificate to clipboard'}>
                  <Button
                    size="small"
                    startIcon={<CopyIcon />}
                    onClick={() => handleCopy(cert.cert_pem, 'cert')}
                    variant="outlined"
                  >
                    {copiedField === 'cert' ? 'Copied!' : 'Copy Cert'}
                  </Button>
                </Tooltip>
              </Box>
              <Box
                component="pre"
                sx={{
                  p: 2,
                  bgcolor: 'grey.100',
                  borderRadius: 1,
                  fontSize: 12,
                  overflow: 'auto',
                  maxHeight: 200,
                  fontFamily: 'monospace',
                  whiteSpace: 'pre-wrap',
                  wordBreak: 'break-all',
                }}
              >
                {cert.cert_pem}
              </Box>
            </Box>
            <Box>
              <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 0.5 }}>
                <Typography variant="subtitle2" color="error">Private Key (key.pem)</Typography>
                <Tooltip title={copiedField === 'key' ? 'Copied!' : 'Copy private key to clipboard'}>
                  <Button
                    size="small"
                    startIcon={<CopyIcon />}
                    onClick={() => handleCopy(cert.key_pem, 'key')}
                    variant="outlined"
                    color="error"
                  >
                    {copiedField === 'key' ? 'Copied!' : 'Copy Key'}
                  </Button>
                </Tooltip>
              </Box>
              <Box
                component="pre"
                sx={{
                  p: 2,
                  bgcolor: 'grey.100',
                  borderRadius: 1,
                  fontSize: 12,
                  overflow: 'auto',
                  maxHeight: 200,
                  fontFamily: 'monospace',
                  whiteSpace: 'pre-wrap',
                  wordBreak: 'break-all',
                }}
              >
                {cert.key_pem}
              </Box>
            </Box>
          </>
        )}
      </DialogContent>
      <DialogActions>
        <Button variant="contained" onClick={onClose}>I Have Saved the Key</Button>
      </DialogActions>
    </Dialog>
  )
}

// ── Create Host Form ──────────────────────────────────────────────────────────

function CreateHostForm() {
  const navigate = useNavigate()
  const [form, setForm] = useState<CreateHostRequest>({
    fqdn: '',
    display_name: '',
    agent_port: 12443,
    notes: '',
  })
  const [saving, setSaving] = useState(false)
  const [err, setErr] = useState<string | null>(null)

  const set = (field: keyof CreateHostRequest, value: CreateHostRequest[keyof CreateHostRequest]) =>
    setForm(prev => ({ ...prev, [field]: value }))

  const handleSubmit = async () => {
    if (!form.fqdn.trim()) { setErr('FQDN is required'); return }
    setSaving(true); setErr(null)
    try {
      const body: CreateHostRequest = {
        fqdn: form.fqdn.trim(),
      }
      if (form.display_name?.trim()) body.display_name = form.display_name.trim()
      if (form.agent_port) body.agent_port = form.agent_port
      if (form.notes?.trim()) body.notes = form.notes.trim()
      const res = await hostsApi.register(body)
      const newId = res.data?.id ?? res.data?.host?.id
      if (newId) {
        navigate(`/hosts/${newId}`)
      } else {
        navigate('/hosts')
      }
    } catch (e: unknown) {
      const msg = (e as { response?: { data?: { error?: { message?: string } } } })
        ?.response?.data?.error?.message ?? 'Failed to register host'
      setErr(msg)
    } finally { setSaving(false) }
  }

  return (
    <Container maxWidth="sm" sx={{ mt: 3, mb: 6 }}>
      <Button startIcon={<ArrowBack />} onClick={() => navigate('/hosts')} sx={{ mb: 2 }}>
        Back to Hosts
      </Button>
      <Paper sx={{ p: 3 }}>
        <Typography variant="h5" fontWeight={700} gutterBottom>
          Register New Host
        </Typography>
        <Divider sx={{ mb: 3 }} />
        {err && <Alert severity="error" sx={{ mb: 2 }}>{err}</Alert>}
        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
          <TextField
            label="FQDN"
            value={form.fqdn}
            onChange={e => set('fqdn', e.target.value)}
            required
            fullWidth
            helperText="Fully qualified domain name (IP address resolved automatically)"
          />
          <TextField
            label="Display Name"
            value={form.display_name ?? ''}
            onChange={e => set('display_name', e.target.value)}
            fullWidth
            helperText="Optional friendly name for this host"
          />
          <TextField
            label="Agent Port"
            type="number"
            value={form.agent_port ?? 12443}
            onChange={e => set('agent_port', parseInt(e.target.value, 10) || 12443)}
            fullWidth
            slotProps={{ htmlInput: { min: 1, max: 65535 } }}
            helperText="Port the patch agent listens on (default 12443)"
          />
          <TextField
            label="Notes"
            value={form.notes ?? ''}
            onChange={e => set('notes', e.target.value)}
            fullWidth
            multiline
            rows={3}
            helperText="Optional notes about this host"
          />
        </Box>
        <Box sx={{ display: 'flex', justifyContent: 'flex-end', gap: 1, mt: 3 }}>
          <Button onClick={() => navigate('/hosts')} disabled={saving}>
            Cancel
          </Button>
          <Button variant="contained" onClick={handleSubmit} disabled={saving}>
            {saving ? <CircularProgress size={20} /> : 'Register Host'}
          </Button>
        </Box>
      </Paper>
    </Container>
  )
}

// ── Main page ──────────────────────────────────────────────────────────────────

export default function HostDetailPage() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const [host, setHost] = useState<Record<string, unknown> | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  // Maintenance windows state
  const [windows, setWindows] = useState<MaintenanceWindow[]>([])
  const [winLoading, setWinLoading] = useState(false)
  const [snackbar, setSnackbar] = useState<{ open: boolean; message: string; severity: 'success' | 'error' }>({
    open: false, message: '', severity: 'success',
  })

  // Create window dialog
  const [createOpen, setCreateOpen] = useState(false)
  const [createForm, setCreateForm] = useState<FormValues>(defaultForm())

  // Edit window dialog
  const [editOpen, setEditOpen] = useState(false)
  const [editWindow, setEditWindow] = useState<MaintenanceWindow | null>(null)
  const [editForm, setEditForm] = useState<FormValues>(defaultForm())

  // Delete window dialog
  const [deleteOpen, setDeleteOpen] = useState(false)
  const [deleteTarget, setDeleteTarget] = useState<MaintenanceWindow | null>(null)

  // Health checks state
  const [healthChecks, setHealthChecks] = useState<HealthCheckWithResult[]>([])
  const [hcLoading, setHcLoading] = useState(false)
  const [testingId, setTestingId] = useState<string | null>(null)

  // Create health check dialog
  const [hcCreateOpen, setHcCreateOpen] = useState(false)
  const [hcCreateForm, setHcCreateForm] = useState<HealthCheckFormValues>(defaultHealthCheckForm())

  // Edit health check dialog
  const [hcEditOpen, setHcEditOpen] = useState(false)
  const [hcEditTarget, setHcEditTarget] = useState<HealthCheckWithResult | null>(null)
  const [hcEditForm, setHcEditForm] = useState<HealthCheckFormValues>(defaultHealthCheckForm())

  // Delete health check dialog
  const [hcDeleteOpen, setHcDeleteOpen] = useState(false)
  const [hcDeleteTarget, setHcDeleteTarget] = useState<HealthCheckWithResult | null>(null)
  
  // Certificate state
  const [certExists, setCertExists] = useState(false)
  const [issueCertOpen, setIssueCertOpen] = useState(false)
  const [issuedCert, setIssuedCert] = useState<IssuedCert | null>(null)
  const [issueCertLoading, setIssueCertLoading] = useState(false)
  const [keyDialogOpen, setKeyDialogOpen] = useState(false)
  const [issueCertHostname, setIssueCertHostname] = useState('')
  const [issueCertError, setIssueCertError] = useState<string | null>(null)

  // ── Fetch host ────────────────────────────────────────────────────────────
  useEffect(() => {
    if (id === 'new') { setLoading(false); return }
    apiClient.get(`/hosts/${id}`)
      .then(r => setHost(r.data))
      .catch(() => setError('Host not found or access denied.'))
      .finally(() => setLoading(false))
  }, [id])
  
  // ── Check cert existence ───────────────────────────────────────────────────
  useEffect(() => {
    if (!id || id === 'new') return
    certsApi.list({ host_id: id })
      .then(res => {
        const certs = res.data
        const hasActive = Array.isArray(certs) && certs.some((c: { status: string }) => c.status === 'active')
        setCertExists(hasActive)
      })
      .catch(() => setCertExists(false))
  }, [id])

  // ── Fetch windows ─────────────────────────────────────────────────────────
  const fetchWindows = useCallback(async () => {
    if (!id) return
    setWinLoading(true)
    try {
      const res = await maintenanceWindowsApi.list(id)
      setWindows(res.data?.windows ?? [])
    } catch { /* ignore */ }
    finally { setWinLoading(false) }
  }, [id])

  useEffect(() => { fetchWindows() }, [fetchWindows])

  // ── Fetch health checks ───────────────────────────────────────────────────
  const fetchHealthChecks = useCallback(async () => {
    if (!id) return
    setHcLoading(true)
    try {
      const res = await healthChecksApi.list(id)
      setHealthChecks(Array.isArray(res.data) ? res.data : [])
    } catch { /* ignore */ }
    finally { setHcLoading(false) }
  }, [id])

  useEffect(() => { fetchHealthChecks() }, [fetchHealthChecks])

  const showSnack = (message: string, severity: 'success' | 'error') =>
    setSnackbar({ open: true, message, severity })

  // ── Create window ─────────────────────────────────────────────────────────
  const handleCreateSubmit = async (values: FormValues) => {
    if (!id) return
    await maintenanceWindowsApi.create(id, {
      label: values.label,
      recurrence: values.recurrence,
      start_at: new Date(values.start_at).toISOString(),
      duration_minutes: values.duration_minutes,
      recurrence_day: values.recurrence_day === '' ? undefined : values.recurrence_day,
      enabled: values.enabled,
    })
    setCreateOpen(false)
    showSnack('Window created', 'success')
    await fetchWindows()
  }

  // ── Edit window ───────────────────────────────────────────────────────────
  const handleEditClick = (w: MaintenanceWindow) => {
    setEditWindow(w)
    setEditForm({
      label: w.label,
      recurrence: w.recurrence,
      start_at: new Date(w.start_at).toISOString().slice(0, 16),
      duration_minutes: w.duration_minutes,
      recurrence_day: w.recurrence_day ?? '',
      enabled: w.enabled,
    })
    setEditOpen(true)
  }

  const handleEditSubmit = async (values: FormValues) => {
    if (!id || !editWindow) return
    await maintenanceWindowsApi.update(id, editWindow.id, {
      label: values.label,
      recurrence: values.recurrence,
      start_at: new Date(values.start_at).toISOString(),
      duration_minutes: values.duration_minutes,
      recurrence_day: values.recurrence_day === '' ? undefined : values.recurrence_day,
      enabled: values.enabled,
    })
    setEditOpen(false)
    showSnack('Window updated', 'success')
    await fetchWindows()
  }

  // ── Delete window ─────────────────────────────────────────────────────────
  const handleDeleteConfirm = async () => {
    if (!id || !deleteTarget) return
    try {
      await maintenanceWindowsApi.remove(id, deleteTarget.id)
      setDeleteOpen(false)
      showSnack('Window deleted', 'success')
      await fetchWindows()
    } catch {
      showSnack('Failed to delete window', 'error')
    }
  }

  // ── Download client cert ─────────────────────────────────────────────────
  const handleDownloadClientCert = async () => {
    if (!id) return
    try {
      const res = await certsApi.downloadClientCert(id)
      const url = URL.createObjectURL(res.data as Blob)
      const a = document.createElement('a')
      a.href = url
      a.download = 'client.crt'
      a.click()
      URL.revokeObjectURL(url)
    } catch {
      showSnack('No client certificate found for this host', 'error')
    }
  }
  
  // ── Issue client certificate ──────────────────────────────────────────────
  const handleOpenIssueCert = () => {
    setIssueCertHostname(String(host?.fqdn ?? ''))
    setIssueCertError(null)
    setIssueCertOpen(true)
  }
  
  const handleIssueCertSubmit = async () => {
    if (!id || !issueCertHostname.trim()) { setIssueCertError('Hostname is required'); return }
    setIssueCertLoading(true)
    setIssueCertError(null)
    try {
      const res = await certsApi.issue(id, issueCertHostname.trim())
      setIssuedCert(res.data)
      setIssueCertOpen(false)
      setKeyDialogOpen(true)
      setCertExists(true)
    } catch (e: unknown) {
      const msg = (e as { response?: { data?: { error?: { message?: string } } } })
        ?.response?.data?.error?.message ?? 'Failed to issue certificate'
      setIssueCertError(msg)
    } finally {
      setIssueCertLoading(false)
    }
  }

  // ── Create health check ──────────────────────────────────────────────────
  const handleHcCreateSubmit = async (values: HealthCheckFormValues) => {
    if (!id) return
    const body: CreateHealthCheckRequest = {
      name: values.name,
      check_type: values.check_type,
    }
    if (values.check_type === 'service') {
      body.service_name = values.service_name || undefined
    } else {
      body.url = values.url || undefined
      body.expected_body = values.expected_body || undefined
      body.ignore_cert_errors = values.ignore_cert_errors || undefined
      body.basic_auth_user = values.basic_auth_user || undefined
      body.basic_auth_pass = values.basic_auth_pass || undefined
    }
    await healthChecksApi.create(id, body)
    setHcCreateOpen(false)
    showSnack('Health check created', 'success')
    await fetchHealthChecks()
  }

  // ── Edit health check ────────────────────────────────────────────────────
  const handleHcEditClick = (check: HealthCheckWithResult) => {
    setHcEditTarget(check)
    setHcEditForm({
      name: check.name,
      check_type: check.check_type,
      service_name: check.service_name ?? '',
      url: check.url ?? '',
      expected_body: check.expected_body ?? '',
      ignore_cert_errors: check.ignore_cert_errors,
      basic_auth_user: check.basic_auth_user ?? '',
      basic_auth_pass: '',
      enabled: check.enabled,
    })
    setHcEditOpen(true)
  }

  const handleHcEditSubmit = async (values: HealthCheckFormValues) => {
    if (!id || !hcEditTarget) return
    const body: UpdateHealthCheckRequest = {
      name: values.name,
      enabled: values.enabled,
    }
    if (values.check_type === 'service') {
      body.service_name = values.service_name || undefined
    } else {
      body.url = values.url || undefined
      body.expected_body = values.expected_body || undefined
      body.ignore_cert_errors = values.ignore_cert_errors
      body.basic_auth_user = values.basic_auth_user || undefined
      body.basic_auth_pass = values.basic_auth_pass || undefined
    }
    await healthChecksApi.update(id, hcEditTarget.id, body)
    setHcEditOpen(false)
    showSnack('Health check updated', 'success')
    await fetchHealthChecks()
  }

  // ── Delete health check ──────────────────────────────────────────────────
  const handleHcDeleteConfirm = async () => {
    if (!id || !hcDeleteTarget) return
    try {
      await healthChecksApi.delete(id, hcDeleteTarget.id)
      setHcDeleteOpen(false)
      showSnack('Health check deleted', 'success')
      await fetchHealthChecks()
    } catch {
      showSnack('Failed to delete health check', 'error')
    }
  }

  // ── Toggle health check enabled ──────────────────────────────────────────
  const handleToggleEnabled = async (check: HealthCheckWithResult) => {
    if (!id) return
    try {
      await healthChecksApi.update(id, check.id, { enabled: !check.enabled })
      await fetchHealthChecks()
    } catch {
      showSnack('Failed to toggle health check', 'error')
    }
  }

  // ── Test health check ────────────────────────────────────────────────────
  const handleTestCheck = async (check: HealthCheckWithResult) => {
    if (!id) return
    setTestingId(check.id)
    try {
      await healthChecksApi.test(id, check.id)
      await fetchHealthChecks()
      showSnack('Health check test completed', 'success')
    } catch {
      showSnack('Health check test failed', 'error')
    } finally {
      setTestingId(null)
    }
  }

  // ── Render ────────────────────────────────────────────────────────────────
  if (loading) return <Box display="flex" justifyContent="center" mt={8}><CircularProgress /></Box>
  if (error) return <Container sx={{ mt: 4 }}><Alert severity="error">{error}</Alert></Container>

  // ── New host creation form ─────────────────────────────────────────────────
  if (id === 'new') {
    return <CreateHostForm />
  }

  return (
    <Container maxWidth="lg" sx={{ mt: 3, mb: 6 }}>
      <Button startIcon={<ArrowBack />} onClick={() => navigate('/hosts')} sx={{ mb: 2 }}>
        Back to Hosts
      </Button>

      {/* ── Host details ─────────────────────────────────────────────────── */}
      <Paper sx={{ p: 3, mb: 3 }}>
        <Box display="flex" alignItems="center" justifyContent="space-between" mb={2}>
          <Typography variant="h5" fontWeight={700}>
            {String(host?.fqdn ?? '')}
          </Typography>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            {!certExists && (
              <Button
                variant="contained"
                size="small"
                startIcon={<VpnKeyIcon />}
                onClick={handleOpenIssueCert}
              >
                Issue Certificate
              </Button>
            )}
            <Tooltip title="Download mTLS Client Certificate">
              <IconButton onClick={handleDownloadClientCert} color="primary">
                <VpnKeyIcon />
              </IconButton>
            </Tooltip>
          </Box>
        </Box>
        <Divider sx={{ mb: 2 }} />
        <Grid container spacing={2}>
          {host && Object.entries(host).map(([k, v]) =>
            v !== null && v !== '' ? (
              <Grid size={{ xs: 12, sm: 6, md: 4 }} key={k}>
                <Typography variant="caption" color="text.secondary" display="block">
                  {k.replace(/_/g, ' ').toUpperCase()}
                </Typography>
                <Typography variant="body2">{String(v)}</Typography>
              </Grid>
            ) : null
          )}
        </Grid>
      </Paper>

      {/* ── Maintenance Windows ──────────────────────────────────────────── */}
      <Paper sx={{ p: 3, mb: 3 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <ScheduleIcon color="primary" />
            <Typography variant="h6" fontWeight={600}>Maintenance Windows</Typography>
          </Box>
          <Button
            startIcon={<AddIcon />}
            variant="outlined"
            size="small"
            onClick={() => { setCreateForm(defaultForm()); setCreateOpen(true) }}
          >
            Add Window
          </Button>
        </Box>
        <Divider sx={{ mb: 2 }} />

        <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
          Queued patch jobs execute only when an enabled maintenance window is open.
        </Typography>

        {winLoading ? (
          <Box display="flex" justifyContent="center" py={3}><CircularProgress size={28} /></Box>
        ) : windows.length === 0 ? (
          <Alert severity="info">
            No maintenance windows. Queued jobs will not run until a window is configured.
          </Alert>
        ) : (
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>Label</TableCell>
                <TableCell>Schedule</TableCell>
                <TableCell>Recurrence</TableCell>
                <TableCell>Status</TableCell>
                <TableCell align="right">Actions</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {windows.map(w => (
                <TableRow key={w.id} hover>
                  <TableCell>{w.label}</TableCell>
                  <TableCell>
                    <Typography variant="body2">{scheduleDescription(w)}</Typography>
                  </TableCell>
                  <TableCell>
                    <Chip label={recurrenceLabel(w.recurrence)} size="small" />
                  </TableCell>
                  <TableCell>
                    <Chip
                      label={w.enabled ? 'Enabled' : 'Disabled'}
                      color={w.enabled ? 'success' : 'default'}
                      size="small"
                    />
                  </TableCell>
                  <TableCell align="right">
                    <Tooltip title="Edit">
                      <IconButton size="small" onClick={() => handleEditClick(w)}>
                        <EditIcon fontSize="small" />
                      </IconButton>
                    </Tooltip>
                    <Tooltip title="Delete">
                      <IconButton
                        size="small" color="error"
                        onClick={() => { setDeleteTarget(w); setDeleteOpen(true) }}
                      >
                        <DeleteIcon fontSize="small" />
                      </IconButton>
                    </Tooltip>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </Paper>

      {/* ── Health Checks ────────────────────────────────────────────────── */}
      <Paper sx={{ p: 3, mb: 3 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <MonitorHeartIcon color="primary" />
            <Typography variant="h6" fontWeight={600}>Health Checks</Typography>
          </Box>
          <Button
            startIcon={<AddIcon />}
            variant="outlined"
            size="small"
            disabled={healthChecks.length >= 5}
            onClick={() => { setHcCreateForm(defaultHealthCheckForm()); setHcCreateOpen(true) }}
          >
            Add Health Check
          </Button>
        </Box>
        <Divider sx={{ mb: 2 }} />

        <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
          Monitor host health with service and HTTP checks. Maximum 5 checks per host.
        </Typography>

        {hcLoading ? (
          <Box display="flex" justifyContent="center" py={3}><CircularProgress size={28} /></Box>
        ) : healthChecks.length === 0 ? (
          <Alert severity="info">
            No health checks configured. Add a check to monitor this host&apos;s health.
          </Alert>
        ) : (
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>Name</TableCell>
                <TableCell>Type</TableCell>
                <TableCell>Status</TableCell>
                <TableCell>Enabled</TableCell>
                <TableCell>Detail</TableCell>
                <TableCell>Latency</TableCell>
                <TableCell>Last Checked</TableCell>
                <TableCell align="right">Actions</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {healthChecks.map(check => (
                <TableRow key={check.id} hover>
                  <TableCell>{check.name}</TableCell>
                  <TableCell>
                    <Chip label={check.check_type} size="small" variant="outlined" />
                  </TableCell>
                  <TableCell>
                    {check.last_result ? (
                      check.last_result.healthy ? (
                        <Tooltip title="Healthy">
                          <CheckCircleIcon color="success" fontSize="small" />
                        </Tooltip>
                      ) : (
                        <Tooltip title="Unhealthy">
                          <CancelIcon color="error" fontSize="small" />
                        </Tooltip>
                      )
                    ) : (
                      <Tooltip title="No result yet">
                        <RemoveIcon color="disabled" fontSize="small" />
                      </Tooltip>
                    )}
                  </TableCell>
                  <TableCell>
                    <Switch
                      size="small"
                      checked={check.enabled}
                      onChange={() => handleToggleEnabled(check)}
                    />
                  </TableCell>
                  <TableCell>
                    <Typography variant="body2" sx={{ maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {check.last_result?.detail ?? '—'}
                    </Typography>
                  </TableCell>
                  <TableCell>
                    {check.last_result?.latency_ms != null ? `${check.last_result.latency_ms} ms` : '—'}
                  </TableCell>
                  <TableCell>
                    {check.last_result?.checked_at
                      ? new Date(check.last_result.checked_at).toLocaleString()
                      : '—'}
                  </TableCell>
                  <TableCell align="right">
                    <Tooltip title="Test now">
                      <IconButton
                        size="small"
                        color="primary"
                        disabled={testingId === check.id}
                        onClick={() => handleTestCheck(check)}
                      >
                        {testingId === check.id
                          ? <CircularProgress size={16} />
                          : <PlayArrowIcon fontSize="small" />}
                      </IconButton>
                    </Tooltip>
                    <Tooltip title="Edit">
                      <IconButton size="small" onClick={() => handleHcEditClick(check)}>
                        <EditIcon fontSize="small" />
                      </IconButton>
                    </Tooltip>
                    <Tooltip title="Delete">
                      <IconButton
                        size="small" color="error"
                        onClick={() => { setHcDeleteTarget(check); setHcDeleteOpen(true) }}
                      >
                        <DeleteIcon fontSize="small" />
                      </IconButton>
                    </Tooltip>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </Paper>

      {/* ── Dialogs ─────────────────────────────────────────────────────── */}
      <WindowFormDialog
        open={createOpen}
        title="Add Maintenance Window"
        initial={createForm}
        onClose={() => setCreateOpen(false)}
        onSubmit={handleCreateSubmit}
      />
      <WindowFormDialog
        open={editOpen}
        title="Edit Maintenance Window"
        initial={editForm}
        onClose={() => setEditOpen(false)}
        onSubmit={handleEditSubmit}
      />
      <Dialog open={deleteOpen} onClose={() => setDeleteOpen(false)} maxWidth="xs" fullWidth>
        <DialogTitle>Delete Window</DialogTitle>
        <DialogContent>
          <Typography>
            Delete <strong>{deleteTarget?.label}</strong>? This cannot be undone.
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDeleteOpen(false)}>Cancel</Button>
          <Button color="error" variant="contained" onClick={handleDeleteConfirm}>Delete</Button>
        </DialogActions>
      </Dialog>

      {/* Health Check Dialogs */}
      <HealthCheckFormDialog
        open={hcCreateOpen}
        title="Add Health Check"
        initial={hcCreateForm}
        onClose={() => setHcCreateOpen(false)}
        onSubmit={handleHcCreateSubmit}
      />
      <HealthCheckFormDialog
        open={hcEditOpen}
        title="Edit Health Check"
        initial={hcEditForm}
        onClose={() => setHcEditOpen(false)}
        onSubmit={handleHcEditSubmit}
      />
      <Dialog open={hcDeleteOpen} onClose={() => setHcDeleteOpen(false)} maxWidth="xs" fullWidth>
        <DialogTitle>Delete Health Check</DialogTitle>
        <DialogContent>
          <Typography>
            Delete <strong>{hcDeleteTarget?.name}</strong>? This cannot be undone.
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setHcDeleteOpen(false)}>Cancel</Button>
          <Button color="error" variant="contained" onClick={handleHcDeleteConfirm}>Delete</Button>
        </DialogActions>
      </Dialog>
      
      {/* Issue Certificate Dialog */}
      <Dialog open={issueCertOpen} onClose={() => setIssueCertOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle>Issue Client Certificate</DialogTitle>
        <DialogContent sx={{ display: 'flex', flexDirection: 'column', gap: 2, pt: 2 }}>
          {issueCertError && <Alert severity="error">{issueCertError}</Alert>}
          <TextField
            label="Hostname"
            value={issueCertHostname}
            onChange={(e) => setIssueCertHostname(e.target.value)}
            required
            fullWidth
            helperText="Common name for the certificate (usually the host FQDN)"
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setIssueCertOpen(false)} disabled={issueCertLoading}>Cancel</Button>
          <Button variant="contained" onClick={handleIssueCertSubmit} disabled={issueCertLoading}>
            {issueCertLoading ? <CircularProgress size={20} /> : 'Issue Certificate'}
          </Button>
        </DialogActions>
      </Dialog>
      
      {/* One-time key display dialog */}
      <KeyDisplayDialog
        open={keyDialogOpen}
        cert={issuedCert}
        onClose={() => setKeyDialogOpen(false)}
      />

      {/* Snackbar */}
      <Snackbar
        open={snackbar.open}
        autoHideDuration={4000}
        onClose={() => setSnackbar(p => ({ ...p, open: false }))}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'center' }}
      >
        <Alert severity={snackbar.severity} onClose={() => setSnackbar(p => ({ ...p, open: false }))}>
          {snackbar.message}
        </Alert>
      </Snackbar>
    </Container>
  )
}
