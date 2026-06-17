import { useEffect, useState, useCallback } from 'react'
import {
  Alert,
  Box,
  Button,
  Chip,
  CircularProgress,
  Collapse,
  Container,
  Dialog,
  DialogActions,
  DialogContent,
  DialogTitle,
  IconButton,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Toolbar,
  Tooltip,
  Typography,
} from '@mui/material'
import {
  Cancel as CancelIcon,
  ExpandLess,
  ExpandMore,
  Refresh as RefreshIcon,
  Replay as ReplayIcon,
  SystemUpdate as SystemUpdateIcon,
  Wifi as WifiIcon,
  WifiOff as WifiOffIcon,
} from '@mui/icons-material'
import { jobsApi } from '../api/client'
import { useAuthStore } from '../store/authStore'
import { useJobWebSocket } from '../hooks/useJobWebSocket'
import type { JobStatus, JobKind, PatchJobSummary, PatchJob, PatchJobHost, JobWsEvent } from '../types'

// ── Status chip ───────────────────────────────────────────────────────────────
type ChipColor = 'default' | 'info' | 'warning' | 'success' | 'error'

function statusColor(status: JobStatus): ChipColor {
  const map: Record<JobStatus, ChipColor> = {
    queued: 'default',
    pending: 'info',
    running: 'warning',
    succeeded: 'success',
    failed: 'error',
    cancelled: 'default',
  }
  return map[status]
}

function StatusChip({ status }: { status: JobStatus }) {
  return <Chip label={status} color={statusColor(status)} size="small" />
}

// ── Kind label ────────────────────────────────────────────────────────────────
function kindLabel(kind: JobKind): string {
  const map: Record<JobKind, string> = {
    patch_apply: 'Patch Apply',
    patch_remove: 'Patch Remove',
    reboot: 'Reboot',
    rollback: 'Rollback',
    self_upgrade: 'Agent Upgrade',
  }
  return map[kind]
}

// ── Format date ───────────────────────────────────────────────────────────────
function fmtDate(iso?: string): string {
  if (!iso) return '—'
  return new Date(iso).toLocaleString()
}

// ── Per-host detail table ─────────────────────────────────────────────────────
function HostDetailTable({ hosts, kind }: { hosts: PatchJobHost[]; kind: JobKind }) {
  if (hosts.length === 0) {
    return (
      <Box py={2} px={3}>
        <Typography variant="body2" color="text.secondary">
          No host entries for this job.
        </Typography>
      </Box>
    )
  }
  return (
    <Box sx={{ backgroundColor: 'action.hover', px: 2, pb: 2 }}>
      <Table size="small">
        <TableHead>
          <TableRow>
            <TableCell>Host</TableCell>
            <TableCell>Status</TableCell>
            {kind === 'self_upgrade' && <TableCell>Phase</TableCell>}
            <TableCell>Agent Job ID</TableCell>
            <TableCell>Retries</TableCell>
            <TableCell>Error</TableCell>
            <TableCell>Started</TableCell>
            <TableCell>Completed</TableCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {hosts.map((h) => {
            const isReconnecting = kind === 'self_upgrade' && h.status === 'running' && h.output?.toLowerCase().includes('reconnect')
            return (
              <TableRow key={h.id}>
                <TableCell>{h.host_display_name}</TableCell>
                <TableCell>
                  <StatusChip status={h.status} />
                </TableCell>
                {kind === 'self_upgrade' && (
                  <TableCell>
                    {isReconnecting ? (
                      <Chip size="small" label="Awaiting reconnect" color="info" variant="outlined" />
                    ) : h.status === 'running' ? (
                      <Chip size="small" label="Upgrading" color="warning" variant="outlined" />
                    ) : null}
                  </TableCell>
                )}
                <TableCell>
                  <Typography variant="caption" fontFamily="monospace">
                    {h.agent_job_id ?? '—'}
                  </Typography>
                </TableCell>
                <TableCell>{h.retry_count}</TableCell>
                <TableCell>
                  {h.error_message ? (
                    <Tooltip title={h.error_message}>
                      <Typography
                        variant="caption"
                        color="error"
                        sx={{
                          maxWidth: 200,
                          display: 'block',
                          overflow: 'hidden',
                          textOverflow: 'ellipsis',
                          whiteSpace: 'nowrap',
                        }}
                      >
                        {h.error_message}
                      </Typography>
                    </Tooltip>
                  ) : (
                    '—'
                  )}
                </TableCell>
                <TableCell>{fmtDate(h.started_at)}</TableCell>
                <TableCell>{fmtDate(h.completed_at)}</TableCell>
              </TableRow>
            )
          })}
        </TableBody>
      </Table>
    </Box>
  )
}

// ── Expandable job row ────────────────────────────────────────────────────────
interface JobRowProps {
  job: PatchJobSummary
  expanded: boolean
  onToggle: (id: string) => void
  onCancel: (id: string) => void
  onRollback: (id: string) => void
  cancelLoading: boolean
  rollbackLoading: boolean
  detail: PatchJob | null
  detailLoading: boolean
  detailError: string | null
  canWrite: boolean
}

function JobRow({
  job,
  expanded,
  onToggle,
  onCancel,
  onRollback,
  cancelLoading,
  rollbackLoading,
  detail,
  detailLoading,
  detailError,
  canWrite,
}: JobRowProps) {
  const canCancel = job.status === 'queued' || job.status === 'pending'
  const canRollback = job.status === 'succeeded'

  return (
    <>
      <TableRow
        hover
        sx={{ cursor: 'pointer', '& > *': { borderBottom: expanded ? 'none' : undefined } }}
        onClick={() => onToggle(job.id)}
      >
        <TableCell padding="checkbox">
          <IconButton size="small" onClick={(e) => { e.stopPropagation(); onToggle(job.id) }}>
            {expanded ? <ExpandLess fontSize="small" /> : <ExpandMore fontSize="small" />}
          </IconButton>
        </TableCell>
        <TableCell>
          <Typography variant="caption" fontFamily="monospace">
            {fmtDate(job.created_at)}
          </Typography>
        </TableCell>
        <TableCell>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
            {job.kind === 'self_upgrade' && <SystemUpdateIcon fontSize="small" color="secondary" />}
            {kindLabel(job.kind)}
          </Box>
        </TableCell>
        <TableCell>
          <StatusChip status={job.status} />
        </TableCell>
        <TableCell>
          {job.host_names.length === 1
            ? job.host_names[0]
            : job.host_names.length > 1
              ? <Tooltip title={job.host_names.join(', ')}><span>{job.host_names[0]} +{job.host_names.length - 1}</span></Tooltip>
              : '—'}
        </TableCell>
        <TableCell align="right">
          <Typography color="success.main" fontWeight={600}>
            {job.succeeded_count}
          </Typography>
        </TableCell>
        <TableCell align="right">
          <Typography color={job.failed_count > 0 ? 'error.main' : 'text.primary'} fontWeight={600}>
            {job.failed_count}
          </Typography>
        </TableCell>
        <TableCell>
          <Chip
            label={job.immediate ? 'Immediate' : 'Scheduled'}
            size="small"
            variant="outlined"
          />
        </TableCell>
        <TableCell>
          <Typography
            variant="caption"
            sx={{
              maxWidth: 180,
              display: 'block',
              overflow: 'hidden',
              textOverflow: 'ellipsis',
              whiteSpace: 'nowrap',
            }}
          >
            {job.notes || '—'}
          </Typography>
        </TableCell>
        <TableCell onClick={(e) => e.stopPropagation()}>
          {canWrite ? <Box display="flex" gap={0.5}>
            {canCancel && (
              <Tooltip title="Cancel job">
                <span>
                  <IconButton
                    size="small"
                    color="error"
                    disabled={cancelLoading}
                    onClick={() => onCancel(job.id)}
                  >
                    {cancelLoading ? (
                      <CircularProgress size={16} />
                    ) : (
                      <CancelIcon fontSize="small" />
                    )}
                  </IconButton>
                </span>
              </Tooltip>
            )}
            {canRollback && (
              <Tooltip title="Rollback job">
                <span>
                  <IconButton
                    size="small"
                    color="warning"
                    disabled={rollbackLoading}
                    onClick={() => onRollback(job.id)}
                  >
                    {rollbackLoading ? (
                      <CircularProgress size={16} />
                    ) : (
                      <ReplayIcon fontSize="small" />
                    )}
                  </IconButton>
                </span>
              </Tooltip>
            )}
          </Box> : null}
        </TableCell>
      </TableRow>

      {/* ── Expandable detail row ── */}
      <TableRow>
        <TableCell colSpan={10} sx={{ py: 0, border: expanded ? undefined : 'none' }}>
          <Collapse in={expanded} timeout="auto" unmountOnExit>
            {detailLoading ? (
              <Box display="flex" justifyContent="center" py={2}>
                <CircularProgress size={24} />
              </Box>
            ) : detailError ? (
              <Alert severity="error" sx={{ m: 1 }}>
                {detailError}
              </Alert>
            ) : detail ? (
              <HostDetailTable hosts={detail.hosts} kind={job.kind} />
            ) : null}
          </Collapse>
        </TableCell>
      </TableRow>
    </>
  )
}

// ── JobsPage ──────────────────────────────────────────────────────────────────
export default function JobsPage() {
  const user = useAuthStore(state => state.user)
  const canWrite = user?.role === 'admin' || user?.role === 'operator'
  const [jobs, setJobs] = useState<PatchJobSummary[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [offset, setOffset] = useState(0)
  const [hasMore, setHasMore] = useState(false)
  const [loadingMore, setLoadingMore] = useState(false)

  // Expanded row detail state
  const [expandedId, setExpandedId] = useState<string | null>(null)
  const [details, setDetails] = useState<Record<string, PatchJob>>({})
  const [detailLoading, setDetailLoading] = useState<Record<string, boolean>>({})
  const [detailError, setDetailError] = useState<Record<string, string>>({})

  // Action state
  const [cancelLoadingId, setCancelLoadingId] = useState<string | null>(null)
  const [rollbackLoadingId, setRollbackLoadingId] = useState<string | null>(null)

  // Rollback confirm dialog
  const [rollbackTargetId, setRollbackTargetId] = useState<string | null>(null)
  const [actionError, setActionError] = useState<string | null>(null)

  const LIMIT = 25

  const loadJobs = useCallback(async (newOffset = 0) => {
    if (newOffset === 0) {
      setLoading(true)
      setError(null)
    } else {
      setLoadingMore(true)
    }
    try {
      const res = await jobsApi.list({ limit: LIMIT, offset: newOffset })
      const data = res.data as { jobs?: PatchJobSummary[]; total?: number } | PatchJobSummary[]
      const items: PatchJobSummary[] = Array.isArray(data) ? data : (data.jobs ?? [])
      const total: number = Array.isArray(data) ? items.length : (data.total ?? items.length)
      if (newOffset === 0) {
        setJobs(items)
      } else {
        setJobs((prev) => [...prev, ...items])
      }
      setOffset(newOffset + items.length)
      setHasMore(newOffset + items.length < total)
    } catch {
      if (newOffset === 0) setError('Failed to load jobs')
    } finally {
      setLoading(false)
      setLoadingMore(false)
    }
  }, [])

  useEffect(() => {
    loadJobs(0)
  }, [loadJobs])

  // ── WS event handler — surgical state updates ─────────────────────────────
  const handleWsEvent = useCallback((event: JobWsEvent) => {
    if (event.event_type === 'job') {
      // ── Job-level event: authoritative status + counts from backend ──
      setJobs((prev) =>
        prev.map((job) => {
          if (job.id !== event.job_id) return job
          return {
            ...job,
            status: event.status,
            succeeded_count: event.succeeded_count ?? job.succeeded_count,
            failed_count: event.failed_count ?? job.failed_count,
            host_count: event.host_count ?? job.host_count,
          }
        })
      )
    } else {
      // ── Host-level event: update detail row + optimistic counters only ──
      setJobs((prev) =>
        prev.map((job) => {
          if (job.id !== event.job_id) return job
          const updated = { ...job }
          // Optimistically increment counters when a host reaches a terminal state.
          // The authoritative rollup will arrive as a job-level event later.
          if (event.status === 'succeeded') {
            updated.succeeded_count = job.succeeded_count + 1
          } else if (event.status === 'failed') {
            updated.failed_count = job.failed_count + 1
          }
          // If any host is still running, ensure the job shows 'running'.
          // Do NOT promote host status to job status — only the job-level
          // event can set the parent job to a terminal state.
          if (event.status === 'running' && job.status === 'queued') {
            updated.status = 'running'
          }
          return updated
        })
      )

      // Update the host row in the expanded detail panel if loaded.
      setDetails((prev) => {
        const detail = prev[event.job_id]
        if (!detail) return prev
        const updatedHosts = detail.hosts.map((h) => {
          if (h.host_id !== event.host_id) return h
          return {
            ...h,
            status: event.status,
            ...(event.error_message ? { error_message: event.error_message } : {}),
            ...(event.agent_job_id  ? { agent_job_id:  event.agent_job_id  } : {}),
          }
        })
        return { ...prev, [event.job_id]: { ...detail, hosts: updatedHosts } }
      })
    }
  }, [])

  // ── WebSocket connection ──────────────────────────────────────────────────
  const { connected } = useJobWebSocket({ onEvent: handleWsEvent })

  // ── Action handlers ───────────────────────────────────────────────────────
  const handleToggleExpand = useCallback(async (id: string) => {
    if (expandedId === id) {
      setExpandedId(null)
      return
    }
    setExpandedId(id)
    if (details[id]) return
    setDetailLoading((prev) => ({ ...prev, [id]: true }))
    setDetailError((prev) => { const n = { ...prev }; delete n[id]; return n })
    try {
      const res = await jobsApi.get(id)
      setDetails((prev) => ({ ...prev, [id]: res.data as PatchJob }))
    } catch {
      setDetailError((prev) => ({ ...prev, [id]: 'Failed to load job detail' }))
    } finally {
      setDetailLoading((prev) => ({ ...prev, [id]: false }))
    }
  }, [expandedId, details])

  const handleCancel = useCallback(async (id: string) => {
    setCancelLoadingId(id)
    setActionError(null)
    try {
      await jobsApi.cancel(id)
      await loadJobs(0)
    } catch {
      setActionError(`Failed to cancel job ${id}`)
    } finally {
      setCancelLoadingId(null)
    }
  }, [loadJobs])

  const handleRollbackConfirm = useCallback(async () => {
    if (!rollbackTargetId) return
    const id = rollbackTargetId
    setRollbackTargetId(null)
    setRollbackLoadingId(id)
    setActionError(null)
    try {
      await jobsApi.rollback(id)
      await loadJobs(0)
    } catch {
      setActionError(`Failed to rollback job ${id}`)
    } finally {
      setRollbackLoadingId(null)
    }
  }, [rollbackTargetId, loadJobs])

  // ── Render ────────────────────────────────────────────────────────────────
  return (
    <Container maxWidth="xl" sx={{ mt: 3 }}>
      <Toolbar disableGutters sx={{ mb: 2 }}>
        <Typography variant="h5" fontWeight={700} sx={{ flexGrow: 1 }}>
          Jobs
        </Typography>

        {/* WS connection status indicator */}
        <Tooltip title={connected ? 'Live updates connected' : 'Live updates disconnected'}>
          <Box
            display="flex"
            alignItems="center"
            gap={0.5}
            sx={{ mr: 1, color: connected ? 'success.main' : 'text.disabled' }}
          >
            {connected
              ? <WifiIcon fontSize="small" />
              : <WifiOffIcon fontSize="small" />}
            <Typography variant="caption">
              {connected ? 'Live' : 'Offline'}
            </Typography>
          </Box>
        </Tooltip>

        <Tooltip title="Refresh">
          <span>
            <IconButton onClick={() => loadJobs(0)} disabled={loading}>
              {loading ? <CircularProgress size={20} /> : <RefreshIcon />}
            </IconButton>
          </span>
        </Tooltip>
      </Toolbar>

      {error && (
        <Alert severity="error" sx={{ mb: 2 }}>
          {error}
        </Alert>
      )}

      {actionError && (
        <Alert severity="error" sx={{ mb: 2 }} onClose={() => setActionError(null)}>
          {actionError}
        </Alert>
      )}

      <Paper variant="outlined">
        <TableContainer>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell padding="checkbox" />
                <TableCell>Created</TableCell>
                <TableCell>Kind</TableCell>
                <TableCell>Status</TableCell>
                <TableCell>Hosts</TableCell>
                <TableCell align="right">Succeeded</TableCell>
                <TableCell align="right">Failed</TableCell>
                <TableCell>Schedule</TableCell>
                <TableCell>Notes</TableCell>
                {canWrite && <TableCell>Actions</TableCell>}
              </TableRow>
            </TableHead>
            <TableBody>
              {loading && jobs.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={10} align="center" sx={{ py: 4 }}>
                    <CircularProgress size={32} />
                  </TableCell>
                </TableRow>
              ) : jobs.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={10} align="center" sx={{ py: 4 }}>
                    <Typography variant="body2" color="text.secondary">
                      No jobs found
                    </Typography>
                  </TableCell>
                </TableRow>
              ) : (
                jobs.map((job) => (
                  <JobRow
                    key={job.id}
                    job={job}
                    expanded={expandedId === job.id}
                    onToggle={handleToggleExpand}
                    onCancel={handleCancel}
                    onRollback={(id) => setRollbackTargetId(id)}
                    cancelLoading={cancelLoadingId === job.id}
                    rollbackLoading={rollbackLoadingId === job.id}
                    detail={details[job.id] ?? null}
                    detailLoading={detailLoading[job.id] ?? false}
                    detailError={detailError[job.id] ?? null}
                    canWrite={canWrite}
                  />
                ))
              )}
            </TableBody>
          </Table>
        </TableContainer>

        {hasMore && (
          <Box display="flex" justifyContent="center" py={2}>
            <Button
              variant="outlined"
              onClick={() => loadJobs(offset)}
              disabled={loadingMore}
              startIcon={loadingMore ? <CircularProgress size={16} /> : undefined}
            >
              {loadingMore ? 'Loading…' : 'Load More'}
            </Button>
          </Box>
        )}
      </Paper>

      {/* ── Rollback confirm dialog ── */}
      <Dialog
        open={rollbackTargetId !== null}
        onClose={() => setRollbackTargetId(null)}
        maxWidth="xs"
        fullWidth
      >
        <DialogTitle>Confirm Rollback</DialogTitle>
        <DialogContent>
          <Typography variant="body2">
            Are you sure you want to rollback job{' '}
            <strong>{rollbackTargetId}</strong>? This will create a new rollback job
            that attempts to revert the applied patches.
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setRollbackTargetId(null)}>Cancel</Button>
          <Button
            variant="contained"
            color="warning"
            onClick={handleRollbackConfirm}
          >
            Rollback
          </Button>
        </DialogActions>
      </Dialog>
    </Container>
  )
}
