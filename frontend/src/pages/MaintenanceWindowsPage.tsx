import { useEffect, useState, useCallback, useRef } from 'react'
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
  FormControl,
  FormControlLabel,
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
  Toolbar,
  Tooltip,
  Typography,
} from '@mui/material'
import {
  Add as AddIcon,
  Delete as DeleteIcon,
  Edit as EditIcon,
  Refresh as RefreshIcon,
  Schedule as ScheduleIcon,
} from '@mui/icons-material'
import { maintenanceWindowsApi, hostsApi } from '../api/client'
import { useAuthStore } from '../store/authStore'
import type { Host, MaintenanceWindow, WindowRecurrence } from '../types'

// ── Helpers ───────────────────────────────────────────────────────────────────

function recurrenceLabel(r: WindowRecurrence): string {
  const map: Record<WindowRecurrence, string> = {
    once: 'One-Time',
    daily: 'Daily',
    weekly: 'Weekly',
    monthly: 'Monthly',
  }
  return map[r]
}

function recurrenceColor(r: WindowRecurrence): 'default' | 'primary' | 'secondary' | 'info' {
  const map: Record<WindowRecurrence, 'default' | 'primary' | 'secondary' | 'info'> = {
    once: 'default',
    daily: 'primary',
    weekly: 'secondary',
    monthly: 'info',
  }
  return map[r]
}

function fmtDate(iso: string): string {
  return new Date(iso).toLocaleString()
}

function fmtTimeOnly(iso: string): string {
  const d = new Date(iso)
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', timeZoneName: 'short' })
}

const DAY_NAMES = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday']

function scheduleDescription(w: MaintenanceWindow): string {
  const dur = `${w.duration_minutes} min`
  const time = fmtTimeOnly(w.start_at)
  switch (w.recurrence) {
    case 'once':
      return `Once at ${fmtDate(w.start_at)} for ${dur}`
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

// ── Default form values ───────────────────────────────────────────────────────

function nowIso(): string {
  return new Date().toISOString().slice(0, 16) // "YYYY-MM-DDTHH:MM"
}

interface FormValues {
  label: string
  recurrence: WindowRecurrence
  start_at: string
  duration_minutes: number
  recurrence_day: number | ''
  enabled: boolean
  auto_apply: boolean
}

function defaultForm(): FormValues {
  return {
    label: '',
    recurrence: 'once',
    start_at: nowIso(),
    duration_minutes: 60,
    recurrence_day: '',
    enabled: true,
    auto_apply: true,
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

  // Reset form when dialog opens with new initial values
  useEffect(() => { setForm(initial); setErr(null) }, [open, initial])

  const set = (field: keyof FormValues, value: FormValues[keyof FormValues]) =>
    setForm(prev => ({ ...prev, [field]: value }))

  const needsDay = form.recurrence === 'weekly' || form.recurrence === 'monthly'

  const handleSubmit = async () => {
    if (!form.label.trim()) { setErr('Label is required'); return }
    if (needsDay && form.recurrence_day === '') { setErr('Recurrence day is required'); return }
    setSaving(true)
    setErr(null)
    try {
      await onSubmit(form)
    } catch (e: unknown) {
      const msg = (e as { response?: { data?: { error?: { message?: string } } } })
        ?.response?.data?.error?.message ?? 'Failed to save window'
      setErr(msg)
    } finally {
      setSaving(false)
    }
  }

  return (
    <Dialog open={open} onClose={onClose} maxWidth="sm" fullWidth>
      <DialogTitle>{title}</DialogTitle>
      <DialogContent sx={{ display: 'flex', flexDirection: 'column', gap: 2, pt: 2 }}>
        {err && <Alert severity="error">{err}</Alert>}

        <TextField
          label="Label"
          value={form.label}
          onChange={e => set('label', e.target.value)}
          required
          fullWidth
        />

        <FormControl fullWidth>
          <InputLabel>Recurrence</InputLabel>
          <Select
            label="Recurrence"
            value={form.recurrence}
            onChange={e => set('recurrence', e.target.value as WindowRecurrence)}
          >
            <MenuItem value="once">One-Time</MenuItem>
            <MenuItem value="daily">Daily</MenuItem>
            <MenuItem value="weekly">Weekly</MenuItem>
            <MenuItem value="monthly">Monthly</MenuItem>
          </Select>
        </FormControl>

        <TextField
          label={form.recurrence === 'once' ? 'Start Date & Time (UTC)' : 'Reference Time (UTC)'}
          type="datetime-local"
          value={form.start_at}
          onChange={e => set('start_at', e.target.value)}
          fullWidth
          slotProps={{ inputLabel: { shrink: true } }}
          helperText={
            form.recurrence === 'once'
              ? 'When the window begins'
              : 'Time of day for the recurring window (date part ignored)'
          }
        />

        <TextField
          label="Duration (minutes)"
          type="number"
          value={form.duration_minutes}
          onChange={e => set('duration_minutes', parseInt(e.target.value, 10) || 60)}
          fullWidth
          slotProps={{ htmlInput: { min: 1, max: 1440 } }}
        />

        {form.recurrence === 'weekly' && (
          <FormControl fullWidth>
            <InputLabel>Day of Week</InputLabel>
            <Select
              label="Day of Week"
              value={form.recurrence_day}
              onChange={e => set('recurrence_day', Number(e.target.value))}
            >
              {DAY_NAMES.map((name, i) => (
                <MenuItem key={i} value={i}>{name}</MenuItem>
              ))}
            </Select>
          </FormControl>
        )}

        {form.recurrence === 'monthly' && (
          <TextField
            label="Day of Month (1-31)"
            type="number"
            value={form.recurrence_day}
            onChange={e => set('recurrence_day', parseInt(e.target.value, 10) || 1)}
            fullWidth
            slotProps={{ htmlInput: { min: 1, max: 31 } }}
          />
        )}

        <FormControlLabel
          control={
            <Switch
              checked={form.enabled}
              onChange={e => set('enabled', e.target.checked)}
            />
          }
          label="Enabled"
        />
        <FormControlLabel
          control={
            <Switch
              checked={form.auto_apply}
              onChange={e => set('auto_apply', e.target.checked)}
            />
          }
          label="Auto-Apply Patches"
        />
        <Typography variant="caption" color="text.secondary" sx={{ mt: -1 }}>
          When enabled, pending patches are automatically applied during this window.
        </Typography>
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

// ── Confirm delete dialog ──────────────────────────────────────────────────────

interface ConfirmDeleteProps {
  open: boolean
  windowLabel: string
  onClose: () => void
  onConfirm: () => Promise<void>
}

function ConfirmDeleteDialog({ open, windowLabel, onClose, onConfirm }: ConfirmDeleteProps) {
  const [loading, setLoading] = useState(false)

  const handleConfirm = async () => {
    setLoading(true)
    await onConfirm()
    setLoading(false)
  }

  return (
    <Dialog open={open} onClose={onClose} maxWidth="xs" fullWidth>
      <DialogTitle>Delete Window</DialogTitle>
      <DialogContent>
        <Typography>
          Delete maintenance window <strong>{windowLabel}</strong>? This cannot be undone.
        </Typography>
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose} disabled={loading}>Cancel</Button>
        <Button color="error" variant="contained" onClick={handleConfirm} disabled={loading}>
          {loading ? <CircularProgress size={20} /> : 'Delete'}
        </Button>
      </DialogActions>
    </Dialog>
  )
}

// ── Per-host windows table ────────────────────────────────────────────────────

interface HostWindowsTableProps {
  host: Host
  windows: MaintenanceWindow[]
  onEdit: (w: MaintenanceWindow) => void
  onDelete: (w: MaintenanceWindow) => void
  onAdd: (hostId: string) => void
  canWrite: boolean
}

function HostWindowsTable({ host, windows, onEdit, onDelete, onAdd, canWrite }: HostWindowsTableProps) {
  return (
    <Paper variant="outlined" sx={{ mb: 3 }}>
      <Box
        sx={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          px: 2,
          py: 1.5,
          backgroundColor: 'action.hover',
          borderRadius: '4px 4px 0 0',
        }}
      >
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <ScheduleIcon fontSize="small" color="primary" />
          <Typography variant="subtitle1" fontWeight={600}>
            {host.display_name}
          </Typography>
          <Typography variant="caption" color="text.secondary">
            ({host.fqdn})
          </Typography>
        </Box>
        {canWrite && <Button
          size="small"
          startIcon={<AddIcon />}
          variant="outlined"
          onClick={() => onAdd(host.id)}
        >
          Add Window
        </Button>}
      </Box>

      {windows.length === 0 ? (
        <Box px={2} py={2}>
          <Typography variant="body2" color="text.secondary">
            No maintenance windows configured. Queued jobs will not execute until a window is added.
          </Typography>
        </Box>
      ) : (
        <Table size="small">
          <TableHead>
            <TableRow>
              <TableCell>Label</TableCell>
              <TableCell>Schedule</TableCell>
              <TableCell>Recurrence</TableCell>
              <TableCell>Status</TableCell>
              <TableCell>Auto-Apply</TableCell>
              <TableCell>Created</TableCell>
              {canWrite && <TableCell align="right">Actions</TableCell>}
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
                  <Chip
                    label={recurrenceLabel(w.recurrence)}
                    color={recurrenceColor(w.recurrence)}
                    size="small"
                  />
                </TableCell>
                <TableCell>
                  <Chip
                    label={w.enabled ? 'Enabled' : 'Disabled'}
                    color={w.enabled ? 'success' : 'default'}
                    size="small"
                  />
                </TableCell>
                <TableCell>
                  <Chip
                    label={w.auto_apply ? 'On' : 'Off'}
                    color={w.auto_apply ? 'info' : 'default'}
                    size="small"
                  />
                </TableCell>
                <TableCell>{fmtDate(w.created_at)}</TableCell>
                {canWrite && <TableCell align="right">
                  <Tooltip title="Edit">
                    <IconButton size="small" onClick={() => onEdit(w)}>
                      <EditIcon fontSize="small" />
                    </IconButton>
                  </Tooltip>
                  <Tooltip title="Delete">
                    <IconButton size="small" color="error" onClick={() => onDelete(w)}>
                      <DeleteIcon fontSize="small" />
                    </IconButton>
                  </Tooltip>
                </TableCell>}
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
    </Paper>
  )
}

// ── Main page ──────────────────────────────────────────────────────────────────

export default function MaintenanceWindowsPage() {
  const user = useAuthStore(state => state.user)
  const canWrite = user?.role === 'admin' || user?.role === 'operator'
  const [hosts, setHosts] = useState<Host[]>([])
  const [windowsByHost, setWindowsByHost] = useState<Record<string, MaintenanceWindow[]>>({})
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [snackbar, setSnackbar] = useState<{ open: boolean; message: string; severity: 'success' | 'error' }>({
    open: false, message: '', severity: 'success',
  })

  // Create dialog state
  const [createOpen, setCreateOpen] = useState(false)
  const [createHostId, setCreateHostId] = useState<string | null>(null)
  const [createForm, setCreateForm] = useState<FormValues>(defaultForm())

  // Edit dialog state
  const [editOpen, setEditOpen] = useState(false)
  const [editWindow, setEditWindow] = useState<MaintenanceWindow | null>(null)
  const [editForm, setEditForm] = useState<FormValues>(defaultForm())

  // Delete dialog state
  const [deleteOpen, setDeleteOpen] = useState(false)
  const [deleteWindow, setDeleteWindow] = useState<MaintenanceWindow | null>(null)

  // ── AbortController ref for cancelling stale fetches ──────────────────────
  const abortRef = useRef<AbortController | null>(null)

  // ── Fetch hosts + all maintenance windows in 2 parallel requests ─────────
  // Uses bulk /maintenance-windows endpoint instead of N+1 per-host calls.
  // State updates are batched atomically so React never renders hosts without
  // their windows (the root cause of the "randomly missing data" bug).
  const fetchData = useCallback(async (signal?: AbortSignal) => {
    setLoading(true)
    setError(null)
    try {
      // Fetch hosts and ALL windows in parallel — 2 requests, not N+1.
      const [hostsRes, windowsRes] = await Promise.all([
        hostsApi.list({ limit: 500 }),
        maintenanceWindowsApi.listAll(),
      ])

      // If the request was aborted (e.g. component unmounted or new fetch
      // started), discard the results silently.
      if (signal?.aborted) return

      const fetchedHosts: Host[] = hostsRes.data?.hosts ?? hostsRes.data ?? []
      const allWindows: MaintenanceWindow[] = windowsRes.data?.windows ?? []

      // Group windows by host_id for O(N) lookup.
      const windowMap: Record<string, MaintenanceWindow[]> = {}
      for (const w of allWindows) {
        if (!windowMap[w.host_id]) windowMap[w.host_id] = []
        windowMap[w.host_id].push(w)
      }

      // Batch both state updates together — React 18+ auto-batches these
      // into a single render, eliminating the race condition where hosts
      // rendered with stale/empty windows.
      setHosts(fetchedHosts)
      setWindowsByHost(windowMap)
    } catch (err: unknown) {
      if (signal?.aborted) return // stale request — ignore silently
      // Only log real errors, not cancellations.
      if (err instanceof DOMException && err.name === 'AbortError') return
      setError('Failed to load hosts or maintenance windows.')
    } finally {
      if (!signal?.aborted) {
        setLoading(false)
      }
    }
  }, [])

  useEffect(() => {
    // Cancel any in-flight fetch from a previous render.
    abortRef.current?.abort()
    const controller = new AbortController()
    abortRef.current = controller
    fetchData(controller.signal)
    return () => { controller.abort() }
  }, [fetchData])

  // ── Refresh helper: cancels any in-flight fetch, starts a new one ────────
  const refreshData = useCallback(() => {
    abortRef.current?.abort()
    const controller = new AbortController()
    abortRef.current = controller
    fetchData(controller.signal)
  }, [fetchData])

  // ── Helpers ───────────────────────────────────────────────────────────────
  const showSnackbar = (message: string, severity: 'success' | 'error') =>
    setSnackbar({ open: true, message, severity })

  // ── Create window ─────────────────────────────────────────────────────────
  const handleAddClick = (hostId: string) => {
    setCreateHostId(hostId)
    setCreateForm(defaultForm())
    setCreateOpen(true)
  }

  const handleCreateSubmit = async (values: FormValues) => {
    if (!createHostId) return
    await maintenanceWindowsApi.create(createHostId, {
      label: values.label,
      recurrence: values.recurrence,
      start_at: new Date(values.start_at).toISOString(),
      duration_minutes: values.duration_minutes,
      recurrence_day: values.recurrence_day === '' ? undefined : values.recurrence_day,
      enabled: values.enabled,
      auto_apply: values.auto_apply,
    })
    setCreateOpen(false)
    showSnackbar('Maintenance window created', 'success')
    refreshData()
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
      auto_apply: w.auto_apply,
    })
    setEditOpen(true)
  }

  const handleEditSubmit = async (values: FormValues) => {
    if (!editWindow) return
    await maintenanceWindowsApi.update(editWindow.host_id, editWindow.id, {
      label: values.label,
      recurrence: values.recurrence,
      start_at: new Date(values.start_at).toISOString(),
      duration_minutes: values.duration_minutes,
      recurrence_day: values.recurrence_day === '' ? undefined : values.recurrence_day,
      enabled: values.enabled,
      auto_apply: values.auto_apply,
    })
    setEditOpen(false)
    showSnackbar('Maintenance window updated', 'success')
    refreshData()
  }

  // ── Delete window ─────────────────────────────────────────────────────────
  const handleDeleteClick = (w: MaintenanceWindow) => {
    setDeleteWindow(w)
    setDeleteOpen(true)
  }

  const handleDeleteConfirm = async () => {
    if (!deleteWindow) return
    try {
      await maintenanceWindowsApi.remove(deleteWindow.host_id, deleteWindow.id)
      setDeleteOpen(false)
      showSnackbar('Maintenance window deleted', 'success')
      refreshData()
    } catch {
      showSnackbar('Failed to delete maintenance window', 'error')
    }
  }

  // ── Render ────────────────────────────────────────────────────────────────
  return (
    <Container maxWidth="xl" sx={{ mt: 3, mb: 6 }}>
      {/* Page header */}
      <Toolbar disableGutters sx={{ mb: 2, gap: 1 }}>
        <ScheduleIcon color="primary" />
        <Typography variant="h5" fontWeight={700} sx={{ flexGrow: 1 }}>
          Maintenance Windows
        </Typography>
        <Button
          startIcon={<RefreshIcon />}
          onClick={refreshData}
          disabled={loading}
        >
          Refresh
        </Button>
      </Toolbar>

      <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
        Queued (non-immediate) patch jobs only execute during open maintenance windows.
        Configure one or more windows per host to control when patching occurs.
      </Typography>

      {loading && (
        <Box display="flex" justifyContent="center" mt={8}>
          <CircularProgress />
        </Box>
      )}

      {!loading && error && (
        <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>
      )}

      {!loading && !error && hosts.length === 0 && (
        <Alert severity="info">
          No hosts found. Register hosts first before configuring maintenance windows.
        </Alert>
      )}

      {!loading && !error && hosts.map(host => (
        <HostWindowsTable
          key={host.id}
          host={host}
          windows={windowsByHost[host.id] ?? []}
          onEdit={handleEditClick}
          onDelete={handleDeleteClick}
          onAdd={handleAddClick}
          canWrite={canWrite}
        />
      ))}
      {/* Create dialog */}
      <WindowFormDialog
        open={createOpen}
        title="Add Maintenance Window"
        initial={createForm}
        onClose={() => setCreateOpen(false)}
        onSubmit={handleCreateSubmit}
      />

      {/* Edit dialog */}
      <WindowFormDialog
        open={editOpen}
        title="Edit Maintenance Window"
        initial={editForm}
        onClose={() => setEditOpen(false)}
        onSubmit={handleEditSubmit}
      />

      {/* Delete confirm dialog */}
      <ConfirmDeleteDialog
        open={deleteOpen}
        windowLabel={deleteWindow?.label ?? ''}
        onClose={() => setDeleteOpen(false)}
        onConfirm={handleDeleteConfirm}
      />

      {/* Success/error snackbar */}
      <Snackbar
        open={snackbar.open}
        autoHideDuration={4000}
        onClose={() => setSnackbar(prev => ({ ...prev, open: false }))}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'center' }}
      >
        <Alert
          severity={snackbar.severity}
          onClose={() => setSnackbar(prev => ({ ...prev, open: false }))}
        >
          {snackbar.message}
        </Alert>
      </Snackbar>
    </Container>
  )
}
