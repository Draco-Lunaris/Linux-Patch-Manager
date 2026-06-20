import { useEffect, useState, useCallback } from 'react'
import {
  Box, Button, Checkbox, Chip, CircularProgress, Container, Dialog, DialogTitle,
  DialogContent, DialogActions, FormControl, IconButton, InputLabel, MenuItem, Paper,
  Select, Snackbar, Alert,
  Table, TableBody, TableCell, TableContainer, TableHead, TableRow,
  TablePagination, TableSortLabel, TextField, Toolbar, Tooltip, Typography,
} from '@mui/material'
import { Add as AddIcon, Refresh as RefreshIcon, Delete as DeleteIcon, CheckCircle as CheckCircleIcon, Cancel as CancelIcon, Remove as RemoveIcon, Pending as PendingIcon, GppMaybe as GppMaybeIcon, CheckCircleOutline as CheckCircleOutlineIcon, WarningAmber as WarningAmberIcon, VerifiedUser as VerifiedUserIcon, Security as SecurityIcon, SystemUpdate as SystemUpdateIcon, NewReleases as NewReleasesIcon } from '@mui/icons-material'
import { useNavigate } from 'react-router-dom'
import { apiClient, hostsApi, enrollmentApi, upgradesApi } from '../api/client'
import { useAuthStore } from '../store/authStore'
import type { Host, HostHealthStatus, EnrollmentRequest, EnrollmentConflictResponse, AvailableVersion, TriggerUpgradeRequest } from '../types'

const statusColor = (s: HostHealthStatus) =>
  s === 'healthy' ? 'success' : s === 'degraded' ? 'warning' : s === 'unreachable' ? 'error' : 'default'

export default function HostsPage() {
  const navigate = useNavigate()
  const user = useAuthStore(state => state.user)
  const canWrite = user?.role === 'admin' || user?.role === 'operator'
  const [hosts, setHosts] = useState<Host[]>([])
  const [total, setTotal] = useState(0)
  const [page, setPage] = useState(0)
  const [rowsPerPage, setRowsPerPage] = useState(25)
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [refreshing, setRefreshing] = useState<string | null>(null)
  const [deleteTarget, setDeleteTarget] = useState<Host | null>(null)
  const [snackbar, setSnackbar] = useState<{ open: boolean; message: string; severity: 'success' | 'error' }>({ open: false, message: '', severity: 'success' })

  // ── Enrollment state ────────────────────────────────────────────────────
  const [showPending, setShowPending] = useState(false)
  const [pendingEnrollments, setPendingEnrollments] = useState<EnrollmentRequest[]>([])
  const [pendingCount, setPendingCount] = useState(0)
  const [denyTarget, setDenyTarget] = useState<EnrollmentRequest | null>(null)
  const [actionLoading, setActionLoading] = useState<string | null>(null)
  const [conflictModal, setConflictModal] = useState<{ request: EnrollmentRequest; existingHost: Host } | null>(null)

  // ── Upgrade state ───────────────────────────────────────────────────────
  const [availableVersions, setAvailableVersions] = useState<AvailableVersion[]>([])
  const [selectedHostIds, setSelectedHostIds] = useState<Set<string>>(new Set())
  const [upgradeDialogOpen, setUpgradeDialogOpen] = useState(false)
  const [upgradeTargetVersion, setUpgradeTargetVersion] = useState<string | null>(null)
  const [upgradeImmediate, setUpgradeImmediate] = useState(true)
  const [upgradeLoading, setUpgradeLoading] = useState(false)
  const [canaryWarningOpen, setCanaryWarningOpen] = useState(false)

  // ── Sorting state ────────────────────────────────────────────────────────
  type SortKey = 'fqdn' | 'display_name' | 'ip_address' | 'os' | 'health_status' | 'health_check_status' | 'crl_status' | 'agent_version'
  const [sortKey, setSortKey] = useState<SortKey | null>(null)
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('asc')

  const handleSortChange = (key: SortKey) => {
    if (sortKey === key) {
      setSortDir(d => d === 'asc' ? 'desc' : 'asc')
    } else {
      setSortKey(key)
      setSortDir('asc')
    }
  }

  const getSortValue = (h: Host, key: SortKey): string => {
    switch (key) {
      case 'os': return (h.os_name ?? h.os_family ?? '').toLowerCase()
      default: return String(h[key] ?? '').toLowerCase()
    }
  }



  const load = useCallback(async () => {
    setLoading(true)
    try {
      const offset = page * rowsPerPage
      const res = await apiClient.get('/hosts', { params: { limit: rowsPerPage, offset } })
      setHosts(res.data.hosts)
      setTotal(res.data.total)
    } catch { /* handled by interceptor */ }
    finally { setLoading(false) }
  }, [page, rowsPerPage])

  const loadPending = useCallback(async () => {
    try {
      const data = await enrollmentApi.listPending()
      setPendingEnrollments(data)
      setPendingCount(data.length)
    } catch { /* handled by interceptor */ }
  }, [])

  const handleRefresh = async (e: React.MouseEvent, hostId: string) => {
    e.stopPropagation()
    setRefreshing(hostId)
    try {
      await hostsApi.refresh(hostId)
      setTimeout(() => { load(); setRefreshing(null) }, 2000)
    } catch {
      setRefreshing(null)
    }
  }

  const handleDelete = async () => {
    if (!deleteTarget) return
    try {
      await hostsApi.delete(deleteTarget.id)
      setSnackbar({ open: true, message: `Host "${deleteTarget.display_name || deleteTarget.fqdn}" deleted`, severity: 'success' })
      load()
    } catch {
      setSnackbar({ open: true, message: `Failed to delete host "${deleteTarget.display_name || deleteTarget.fqdn}"`, severity: 'error' })
    } finally {
      setDeleteTarget(null)
    }
  }

  // ── Enrollment action handlers ──────────────────────────────────────────
  const handleApprove = async (req: EnrollmentRequest) => {
    setActionLoading(req.id)
    try {
      await enrollmentApi.approve(req.id)
      setSnackbar({ open: true, message: `Host "${req.fqdn}" approved`, severity: 'success' })
      load(); loadPending()
    } catch (err: unknown) {
      const errObj = err as { response?: { status?: number; data?: EnrollmentConflictResponse }; message?: string }
      const status = errObj?.response?.status
      if (status === 409 && errObj.response?.data) {
        const conflictData = errObj.response.data as EnrollmentConflictResponse
        setConflictModal({ request: req, existingHost: conflictData.conflict.existing_host })
      } else {
        setSnackbar({ open: true, message: `Failed to approve "${req.fqdn}": ${errObj?.message || 'Unknown error'}`, severity: 'error' })
      }
    } finally {
      setActionLoading(null)
    }
  }

  const handleDeny = async () => {
    if (!denyTarget) return
    setActionLoading(denyTarget.id)
    try {
      await enrollmentApi.deny(denyTarget.id)
      setSnackbar({ open: true, message: `Enrollment "${denyTarget.fqdn}" denied`, severity: 'success' })
      loadPending()
    } catch {
      setSnackbar({ open: true, message: `Failed to deny enrollment`, severity: 'error' })
    } finally {
      setActionLoading(null)
      setDenyTarget(null)
    }
  }

  const handleConflictResolve = async (action: 'overwrite' | 'cancel') => {
    if (!conflictModal) return
    if (action === 'cancel') {
      setConflictModal(null)
      return
    }
    // For overwrite: delete the existing host first, then approve
    try {
      await hostsApi.delete(conflictModal.existingHost.id)
      await enrollmentApi.approve(conflictModal.request.id)
      setSnackbar({ open: true, message: `Overwrote existing host and approved "${conflictModal.request.fqdn}"`, severity: 'success' })
      load(); loadPending()
    } catch {
      setSnackbar({ open: true, message: `Failed to resolve conflict`, severity: 'error' })
    } finally {
      setConflictModal(null)
    }
  }

  // ── Upgrade handlers ────────────────────────────────────────────────────
  const loadAvailableVersions = useCallback(async () => {
    try {
      const res = await upgradesApi.listAvailableVersions()
      setAvailableVersions(res.data)
    } catch { /* ignore */ }
  }, [])

  const handleOpenUpgradeDialog = (hostIds: string[]) => {
    setSelectedHostIds(new Set(hostIds))
    setUpgradeTargetVersion(null)
    setUpgradeImmediate(true)
    setUpgradeDialogOpen(true)
  }

  const handleTriggerUpgrade = async () => {
    if (selectedHostIds.size === 0) return
    // If 5+ hosts selected, show canary warning first
    if (selectedHostIds.size >= 5 && !canaryWarningOpen) {
      setCanaryWarningOpen(true)
      return
    }
    setUpgradeLoading(true)
    setCanaryWarningOpen(false)
    try {
      const req: TriggerUpgradeRequest = {
        host_ids: Array.from(selectedHostIds),
        target_version: upgradeTargetVersion,
        immediate: upgradeImmediate,
      }
      const res = await upgradesApi.triggerUpgrade(req)
      const data = res.data
      const skippedInfo = data.skipped.length > 0
        ? ` (${data.skipped.length} skipped: ${data.skipped.map(s => s.reason).join(', ')})`
        : ''
      setSnackbar({ open: true, message: `Upgrade job created for ${data.host_count} host(s)${skippedInfo}`, severity: 'success' })
      setUpgradeDialogOpen(false)
      setSelectedHostIds(new Set())
      load()
    } catch (err: unknown) {
      const msg = (err as { response?: { data?: { error?: { message?: string } } } })
        ?.response?.data?.error?.message ?? 'Failed to trigger upgrade'
      setSnackbar({ open: true, message: msg, severity: 'error' })
    } finally {
      setUpgradeLoading(false)
    }
  }

  const handleToggleSelect = (hostId: string) => {
    setSelectedHostIds(prev => {
      const next = new Set(prev)
      if (next.has(hostId)) next.delete(hostId)
      else next.add(hostId)
      return next
    })
  }

  const handleToggleSelectAll = () => {
    if (selectedHostIds.size === filtered.length) {
      setSelectedHostIds(new Set())
    } else {
      setSelectedHostIds(new Set(filtered.map(h => h.id)))
    }
  }

  // Helper: check if a newer version is available for a host
  const isNewerVersionAvailable = (host: Host): boolean => {
    if (!host.agent_version) return false
    const current = host.agent_version
    return availableVersions.some(v => {
      if (v.prerelease) return false
      return v.version.localeCompare(current, undefined, { numeric: true, sensitivity: 'base' }) > 0
    })
  }

  useEffect(() => { load(); loadPending(); loadAvailableVersions() }, [load, loadPending, loadAvailableVersions])

  const filtered = hosts.filter(h =>
    h.fqdn.toLowerCase().includes(search.toLowerCase()) ||
    h.display_name.toLowerCase().includes(search.toLowerCase())
  )

  const sortedHosts = (() => {
    if (!sortKey) return filtered
    const arr = [...filtered]
    arr.sort((a, b) => {
      const va = getSortValue(a, sortKey)
      const vb = getSortValue(b, sortKey)
      const cmp = va.localeCompare(vb, undefined, { numeric: true, sensitivity: 'base' })
      return sortDir === 'asc' ? cmp : -cmp
    })
    return arr
  })()

  const handleChangePage = (_event: React.MouseEvent<HTMLButtonElement> | null, newPage: number) => {
    setPage(newPage)
  }

  const handleChangeRowsPerPage = (event: React.ChangeEvent<HTMLInputElement>) => {
    setRowsPerPage(parseInt(event.target.value, 10))
    setPage(0)
  }

  return (
    <Container maxWidth="xl" sx={{ mt: 3 }}>
      <Toolbar disableGutters sx={{ mb: 2 }}>
        <Typography variant="h5" fontWeight={700} sx={{ flexGrow: 1 }}>Hosts</Typography>
        <Tooltip title="Show pending enrollments">
          <Button
            variant={showPending ? "contained" : "outlined"}
            color="warning"
            startIcon={<PendingIcon />}
            onClick={() => setShowPending(s => !s)}
            sx={{ mr: 1 }}
            endIcon={pendingCount > 0 ? <Chip label={pendingCount} size="small" color="warning" variant="filled" sx={{ ml: 0.5 }} /> : undefined}
          >
            Pending
          </Button>
        </Tooltip>
        <TextField size="small" placeholder="Search..." value={search}
          onChange={e => setSearch(e.target.value)} sx={{ mr: 2 }} />
        <Tooltip title="Refresh"><IconButton onClick={() => { load(); loadPending(); loadAvailableVersions() }}><RefreshIcon /></IconButton></Tooltip>
        {canWrite && selectedHostIds.size > 0 && (
          <Button
            variant="outlined"
            color="secondary"
            startIcon={<SystemUpdateIcon />}
            onClick={() => handleOpenUpgradeDialog(Array.from(selectedHostIds))}
            sx={{ ml: 1 }}
          >
            Upgrade {selectedHostIds.size} Agent{selectedHostIds.size > 1 ? 's' : ''}
          </Button>
        )}
        {canWrite && <Button variant="contained" startIcon={<AddIcon />} onClick={() => navigate('/hosts/new')} sx={{ ml: 1 }}>Add Host</Button>}
      </Toolbar>
      {loading ? <Box display="flex" justifyContent="center" mt="4"><CircularProgress /></Box> : (
        <TableContainer component={Paper}>
          <Table size="small">
            <TableHead>
              <TableRow>
                {canWrite && <TableCell padding="checkbox">
                  <Checkbox
                    checked={filtered.length > 0 && selectedHostIds.size === filtered.length}
                    indeterminate={selectedHostIds.size > 0 && selectedHostIds.size < filtered.length}
                    onChange={handleToggleSelectAll}
                  />
                </TableCell>}
                <TableCell>
                  <TableSortLabel active={sortKey === 'fqdn'} direction={sortKey === 'fqdn' ? sortDir : 'asc'} onClick={() => handleSortChange('fqdn')}>FQDN</TableSortLabel>
                </TableCell>
                <TableCell>
                  <TableSortLabel active={sortKey === 'display_name'} direction={sortKey === 'display_name' ? sortDir : 'asc'} onClick={() => handleSortChange('display_name')}>Display Name</TableSortLabel>
                </TableCell>
                <TableCell>
                  <TableSortLabel active={sortKey === 'ip_address'} direction={sortKey === 'ip_address' ? sortDir : 'asc'} onClick={() => handleSortChange('ip_address')}>IP Address</TableSortLabel>
                </TableCell>
                <TableCell>
                  <TableSortLabel active={sortKey === 'os'} direction={sortKey === 'os' ? sortDir : 'asc'} onClick={() => handleSortChange('os')}>OS</TableSortLabel>
                </TableCell>
                <TableCell>
                  <TableSortLabel active={sortKey === 'health_status'} direction={sortKey === 'health_status' ? sortDir : 'asc'} onClick={() => handleSortChange('health_status')}>Health</TableSortLabel>
                </TableCell>
                <TableCell>
                  <TableSortLabel active={sortKey === 'health_check_status'} direction={sortKey === 'health_check_status' ? sortDir : 'asc'} onClick={() => handleSortChange('health_check_status')}>Checks</TableSortLabel>
                </TableCell>
                <TableCell>
                  <TableSortLabel active={sortKey === 'crl_status'} direction={sortKey === 'crl_status' ? sortDir : 'asc'} onClick={() => handleSortChange('crl_status')}>CRL</TableSortLabel>
                </TableCell>
                <TableCell>
                  <TableSortLabel active={sortKey === 'agent_version'} direction={sortKey === 'agent_version' ? sortDir : 'asc'} onClick={() => handleSortChange('agent_version')}>Agent</TableSortLabel>
                </TableCell>
                {canWrite && <TableCell>Actions</TableCell>}
              </TableRow>
            </TableHead>
            <TableBody>
              {showPending ? (
                pendingEnrollments.map(req => (
                  <TableRow key={req.id} hover sx={{ backgroundColor: '#fff8e1' }}>
                    <TableCell>
                      <Box display="flex" alignItems="center" gap={1}>
                        <GppMaybeIcon color="warning" fontSize="small" />
                        {req.fqdn}
                      </Box>
                    </TableCell>
                    <TableCell>{req.fqdn}</TableCell>
                    <TableCell>{req.ip_address}</TableCell>
                    <TableCell>{(req.os_details['name'] as string) ?? 'Unknown'}</TableCell>
                    <TableCell><Chip size="small" label="pending" color="warning" /></TableCell>
                    <TableCell></TableCell>
                    <TableCell></TableCell>
                    <TableCell>—</TableCell>
                    {canWrite && <TableCell onClick={e => e.stopPropagation()}>
                      <Tooltip title="Approve">
                        <IconButton size="small" color="success"
                          disabled={actionLoading === req.id}
                          onClick={(e) => { e.stopPropagation(); handleApprove(req) }}>
                          {actionLoading === req.id ? <CircularProgress size={16} /> : <CheckCircleOutlineIcon fontSize="small" />}
                        </IconButton>
                      </Tooltip>
                      <Tooltip title="Deny">
                        <IconButton size="small" color="error"
                          disabled={actionLoading === req.id}
                          onClick={(e) => { e.stopPropagation(); setDenyTarget(req) }}>
                          <CancelIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                    </TableCell>}
                  </TableRow>
                ))
              ) : (
                sortedHosts.map(h => (
                  <TableRow key={h.id} hover sx={{ cursor: 'pointer' }}
                    onClick={() => navigate(`/hosts/${h.id}`)}>
                    {canWrite && <TableCell padding="checkbox" onClick={e => e.stopPropagation()}>
                      <Checkbox
                        checked={selectedHostIds.has(h.id)}
                        onChange={() => handleToggleSelect(h.id)}
                      />
                    </TableCell>}
                    <TableCell>{h.fqdn}</TableCell>
                    <TableCell>{h.display_name}</TableCell>
                    <TableCell>{h.ip_address}</TableCell>
                    <TableCell>{h.os_name ?? h.os_family ?? '—'}</TableCell>
                    <TableCell>
                      <Chip size="small" label={h.health_status} color={statusColor(h.health_status)} />
                    </TableCell>
                    <TableCell>
                      {h.health_check_status === 'all_healthy' ? (
                        <Tooltip title="All checks healthy"><CheckCircleIcon color="success" fontSize="small" /></Tooltip>
                      ) : h.health_check_status === 'some_unhealthy' ? (
                        <Tooltip title="Some checks unhealthy"><CancelIcon color="error" fontSize="small" /></Tooltip>
                      ) : (
                        <Tooltip title="No checks configured"><RemoveIcon color="disabled" fontSize="small" /></Tooltip>
                      )}
                    </TableCell>
                    <TableCell>
                      {h.crl_status === 'valid' ? (
                        <Tooltip title="CRL valid"><VerifiedUserIcon color="success" fontSize="small" /></Tooltip>
                      ) : h.crl_status === 'expired' ? (
                        <Tooltip title="CRL expired"><WarningAmberIcon color="warning" fontSize="small" /></Tooltip>
                      ) : h.crl_status === 'missing' ? (
                        <Tooltip title="CRL missing"><WarningAmberIcon color="warning" fontSize="small" /></Tooltip>
                      ) : h.crl_status === 'invalid' ? (
                        <Tooltip title="CRL invalid — security event"><SecurityIcon color="error" fontSize="small" /></Tooltip>
                      ) : (
                        <Tooltip title="CRL status not available (agent version does not support CRL)"><RemoveIcon color="disabled" fontSize="small" /></Tooltip>
                      )}
                    </TableCell>
                    <TableCell>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                        {h.agent_version ?? '—'}
                        {isNewerVersionAvailable(h) && (
                          <Tooltip title="Upgrade available">
                            <NewReleasesIcon color="secondary" fontSize="small" />
                          </Tooltip>
                        )}
                      </Box>
                    </TableCell>
                    {canWrite && <TableCell onClick={e => e.stopPropagation()}>
                      <Tooltip title="Upgrade agent">
                        <IconButton size="small" color="secondary"
                          onClick={(e) => { e.stopPropagation(); handleOpenUpgradeDialog([h.id]) }}>
                          <SystemUpdateIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                      <Tooltip title="Request refresh">
                        <IconButton size="small" color="primary"
                          disabled={refreshing === h.id}
                          onClick={(e) => handleRefresh(e, h.id)}>
                          {refreshing === h.id
                            ? <CircularProgress size={16} />
                            : <RefreshIcon fontSize="small" />}
                        </IconButton>
                      </Tooltip>
                      <Tooltip title="Delete"><IconButton size="small" color="error" onClick={(e) => { e.stopPropagation(); setDeleteTarget(h) }}>
                        <DeleteIcon fontSize="small" />
                      </IconButton></Tooltip>
                    </TableCell>}
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
          {!showPending && (
            <TablePagination
              component="div"
              count={total}
              page={page}
              onPageChange={handleChangePage}
              rowsPerPage={rowsPerPage}
              onRowsPerPageChange={handleChangeRowsPerPage}
              rowsPerPageOptions={[10, 25, 50, 100]}
            />
          )}
        </TableContainer>
      )}

      <Dialog open={deleteTarget !== null} onClose={() => setDeleteTarget(null)}>
        <DialogTitle>Confirm Delete</DialogTitle>
        <DialogContent>
          Are you sure you want to delete host &ldquo;{deleteTarget?.display_name || deleteTarget?.fqdn}&rdquo;?
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDeleteTarget(null)}>Cancel</Button>
          <Button onClick={handleDelete} color="error" variant="contained">Delete</Button>
        </DialogActions>
      </Dialog>

      {/* ── Deny Confirmation Dialog ─────────────────────────────────── */}
      <Dialog open={denyTarget !== null} onClose={() => setDenyTarget(null)}>
        <DialogTitle>Confirm Deny</DialogTitle>
        <DialogContent>
          Are you sure you want to deny the enrollment for &ldquo;{denyTarget?.fqdn}&rdquo;? This action cannot be undone.
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDenyTarget(null)}>Cancel</Button>
          <Button onClick={handleDeny} color="error" variant="contained" disabled={actionLoading === denyTarget?.id}>
            {actionLoading === denyTarget?.id ? <CircularProgress size={20} /> : 'Deny'}
          </Button>
        </DialogActions>
      </Dialog>

      {/* ── Conflict Modal ───────────────────────────────────────────── */}
      <Dialog open={conflictModal !== null} onClose={() => setConflictModal(null)}>
        <DialogTitle sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <WarningAmberIcon color="warning" /> Host Collision Detected
        </DialogTitle>
        <DialogContent dividers>
          <Typography variant="body2" color="text.secondary" gutterBottom>
            Approving &ldquo;{conflictModal?.request.fqdn}&rdquo; conflicts with an existing host:
          </Typography>
          <Paper variant="outlined" sx={{ p: 2, mt: 1, mb: 2 }}>
            <Typography variant="subtitle2">Existing Host</Typography>
            <Typography>FQDN: {conflictModal?.existingHost.fqdn}</Typography>
            <Typography>IP: {conflictModal?.existingHost.ip_address}</Typography>
            <Typography>ID: {conflictModal?.existingHost.id}</Typography>
          </Paper>
          <Typography variant="body2" color="text.secondary">
            Options:
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => handleConflictResolve('cancel')}>Cancel</Button>
          <Button
            onClick={() => handleConflictResolve('overwrite')}
            color="error"
            variant="contained"
          >
            Overwrite Existing Host
          </Button>
        </DialogActions>
      </Dialog>

      {/* ── Upgrade Dialog ─────────────────────────────────────────────── */}
      <Dialog open={upgradeDialogOpen} onClose={() => setUpgradeDialogOpen(false)} maxWidth="sm" fullWidth>
        <DialogTitle sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <SystemUpdateIcon /> Upgrade Agent{selectedHostIds.size > 1 ? 's' : ''}
        </DialogTitle>
        <DialogContent sx={{ display: 'flex', flexDirection: 'column', gap: 2, pt: 2 }}>
          <Typography variant="body2" color="text.secondary">
            {selectedHostIds.size} host{selectedHostIds.size > 1 ? 's' : ''} selected for agent upgrade.
          </Typography>
          <FormControl fullWidth>
            <InputLabel>Target Version</InputLabel>
            <Select
              value={upgradeTargetVersion ?? '__latest__'}
              label="Target Version"
              onChange={e => setUpgradeTargetVersion(e.target.value === '__latest__' ? null : e.target.value)}
            >
              <MenuItem value="__latest__">Latest (auto)</MenuItem>
              {availableVersions
                .filter(v => !v.prerelease)
                .filter((v, i, arr) => arr.findIndex(x => x.version === v.version) === i)
                .map(v => (
                <MenuItem key={v.id} value={v.version}>{v.version}</MenuItem>
              ))}
            </Select>
          </FormControl>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <Button
              variant={upgradeImmediate ? 'contained' : 'outlined'}
              size="small"
              onClick={() => setUpgradeImmediate(true)}
            >
              Immediate
            </Button>
            <Button
              variant={!upgradeImmediate ? 'contained' : 'outlined'}
              size="small"
              onClick={() => setUpgradeImmediate(false)}
            >
              Scheduled
            </Button>
          </Box>
          {!upgradeImmediate && (
            <Typography variant="caption" color="text.secondary">
              Scheduled upgrades will use the next available maintenance window.
            </Typography>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setUpgradeDialogOpen(false)}>Cancel</Button>
          <Button
            variant="contained"
            color="secondary"
            onClick={handleTriggerUpgrade}
            disabled={upgradeLoading}
          >
            {upgradeLoading ? <CircularProgress size={20} /> : 'Upgrade'}
          </Button>
        </DialogActions>
      </Dialog>

      {/* ── Canary Warning Dialog ───────────────────────────────────────── */}
      <Dialog open={canaryWarningOpen} onClose={() => setCanaryWarningOpen(false)} maxWidth="xs" fullWidth>
        <DialogTitle sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
          <WarningAmberIcon color="warning" /> Fleet Safety Warning
        </DialogTitle>
        <DialogContent>
          <Typography variant="body2" gutterBottom>
            You are about to upgrade <strong>{selectedHostIds.size}</strong> hosts at once.
          </Typography>
          <Typography variant="body2" color="text.secondary">
            Consider upgrading a small canary group first (2–3 hosts) to verify the new agent version works correctly before rolling out to the entire fleet.
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setCanaryWarningOpen(false)}>Cancel</Button>
          <Button
            variant="contained"
            color="warning"
            onClick={handleTriggerUpgrade}
            disabled={upgradeLoading}
          >
            Upgrade All Anyway
          </Button>
        </DialogActions>
      </Dialog>

      <Snackbar open={snackbar.open} autoHideDuration={4000} onClose={() => setSnackbar(s => ({ ...s, open: false }))}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'center' }}>
        <Alert severity={snackbar.severity} onClose={() => setSnackbar(s => ({ ...s, open: false }))}
          sx={{ width: '100%' }}>{snackbar.message}</Alert>
      </Snackbar>
    </Container>
  )
}
