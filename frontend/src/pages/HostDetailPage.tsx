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
  Delete as DeleteIcon,
  Edit as EditIcon,
  Schedule as ScheduleIcon,
  VpnKey as VpnKeyIcon,
} from '@mui/icons-material'
import { apiClient, maintenanceWindowsApi, certsApi } from '../api/client'
import type { MaintenanceWindow, WindowRecurrence } from '../types'

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
      const day = w.recurrence_day != null ? DAY_NAMES[w.recurrence_day] ?? `Day ${w.recurrence_day}` : '?'
      return `Every ${day} at ${time} for ${dur}`
    }
    case 'monthly': {
      const day = w.recurrence_day != null ? w.recurrence_day : '?'
      return `Monthly on day ${day} at ${time} for ${dur}`
    }
  }
}

// ── Form value type ───────────────────────────────────────────────────────────

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

  // Create dialog
  const [createOpen, setCreateOpen] = useState(false)
  const [createForm, setCreateForm] = useState<FormValues>(defaultForm())

  // Edit dialog
  const [editOpen, setEditOpen] = useState(false)
  const [editWindow, setEditWindow] = useState<MaintenanceWindow | null>(null)
  const [editForm, setEditForm] = useState<FormValues>(defaultForm())

  // Delete dialog
  const [deleteOpen, setDeleteOpen] = useState(false)
  const [deleteTarget, setDeleteTarget] = useState<MaintenanceWindow | null>(null)

  // ── Fetch host ────────────────────────────────────────────────────────────
  useEffect(() => {
    apiClient.get(`/hosts/${id}`)
      .then(r => setHost(r.data))
      .catch(() => setError('Host not found or access denied.'))
      .finally(() => setLoading(false))
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

  // ── Render ────────────────────────────────────────────────────────────────
  if (loading) return <Box display="flex" justifyContent="center" mt={8}><CircularProgress /></Box>
  if (error) return <Container sx={{ mt: 4 }}><Alert severity="error">{error}</Alert></Container>

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
          <Tooltip title="Download mTLS Client Certificate">
            <IconButton onClick={handleDownloadClientCert} color="primary">
              <VpnKeyIcon />
            </IconButton>
          </Tooltip>
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
      <Paper sx={{ p: 3 }}>
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
