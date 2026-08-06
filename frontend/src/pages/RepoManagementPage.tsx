import { useState, useEffect, useCallback } from 'react'
import {
  Box, Typography, Paper, Divider, Button, CircularProgress, Alert,
  Table, TableBody, TableCell, TableContainer, TableHead, TableRow,
  Chip, Card, CardContent, Grid, Dialog, DialogTitle, DialogContent, DialogActions,
  Snackbar, Checkbox, IconButton, Tooltip, Switch, FormControlLabel,
} from '@mui/material'
import {
  Sync as SyncIcon, Store as PackageIcon, CloudDownload as DownloadIcon,
  Refresh as RefreshIcon, Delete as DeleteIcon, CleanHands as CleanupIcon,
  PauseCircle as PauseIcon, PlayCircle as PlayIcon,
} from '@mui/icons-material'
import { repoApi } from '../api/client'

interface SyncLog {
  id: string
  triggered_by: string
  status: string
  packages_synced: number
  packages_skipped: number
  error_message: string | null
  started_at: string
  finished_at: string | null
}

interface RepoPackage {
  id: string
  filename: string
  version: string
  distro: string
  distro_codename: string | null
  arch: string
  file_size: number
  source: string
  synced_at: string
}

interface SyncStatus {
  recent_syncs: SyncLog[]
  total_packages: number
  auto_sync_enabled?: boolean
}

interface DiskUsageInfo {
  per_distro: Record<string, number>
  total_disk_bytes: number
  packages: RepoPackage[]
  package_count: number
}

function fmtBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`
  return `${(bytes / 1024 / 1024 / 1024).toFixed(2)} GB`
}

const DISTRO_COLORS: Record<string, 'primary' | 'secondary' | 'info' | 'warning'> = {
  apt: 'primary',
  dnf: 'secondary',
  apk: 'info',
  pacman: 'warning',
}

export default function RepoManagementPage() {
  const [syncStatus, setSyncStatus] = useState<SyncStatus | null>(null)
  const [packages, setPackages] = useState<RepoPackage[]>([])
  const [diskUsage, setDiskUsage] = useState<DiskUsageInfo | null>(null)
  const [loading, setLoading] = useState(true)
  const [syncing, setSyncing] = useState(false)
  const [regenerating, setRegenerating] = useState(false)
  const [deleting, setDeleting] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [syncDialogOpen, setSyncDialogOpen] = useState(false)
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [deleteDialogOpen, setDeleteDialogOpen] = useState(false)
  const [autoSyncToggling, setAutoSyncToggling] = useState(false)
  const [snackbar, setSnackbar] = useState<{ open: boolean; message: string; severity: 'success' | 'error' }>({
    open: false, message: '', severity: 'success',
  })

  const showSnack = (message: string, severity: 'success' | 'error') =>
    setSnackbar({ open: true, message, severity })

  const fetchData = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const [statusRes, pkgRes, diskRes] = await Promise.all([
        repoApi.getSyncStatus(),
        repoApi.listPackages(),
        repoApi.getDiskUsage(),
      ])
      setSyncStatus(statusRes.data)
      setPackages((pkgRes.data as { packages: RepoPackage[] }).packages || [])
      setDiskUsage(diskRes.data)
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to load repo data')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchData()
  }, [fetchData])

  const handleSync = async () => {
    setSyncing(true)
    setSyncDialogOpen(false)
    try {
      await repoApi.triggerSync()
      showSnack('Package sync triggered', 'success')
      await fetchData()
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to trigger sync')
    } finally {
      setSyncing(false)
    }
  }

  const handleRegenerateMetadata = async () => {
    setRegenerating(true)
    try {
      await repoApi.regenerateMetadata()
      showSnack('Metadata regeneration triggered for all distro formats', 'success')
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Failed to trigger metadata regeneration'
      setError(msg)
      showSnack('Failed to trigger metadata regeneration', 'error')
    } finally {
      setRegenerating(false)
    }
  }

  const handleToggleAutoSync = async () => {
    const current = syncStatus?.auto_sync_enabled ?? true
    setAutoSyncToggling(true)
    try {
      const res = await repoApi.setAutoSync(!current)
      setSyncStatus(prev => prev ? { ...prev, auto_sync_enabled: res.data.auto_sync_enabled } : prev)
      showSnack(`Auto-sync ${!current ? 'enabled' : 'paused'}`, 'success')
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Failed to toggle auto-sync'
      setError(msg)
      showSnack('Failed to toggle auto-sync', 'error')
    } finally {
      setAutoSyncToggling(false)
    }
  }

  const handleSelectToggle = (id: string) => {
    setSelected(prev => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  const handleSelectAll = () => {
    if (selected.size === packages.length) {
      setSelected(new Set())
    } else {
      setSelected(new Set(packages.map(p => p.id)))
    }
  }

  const handleDelete = async () => {
    setDeleting(true)
    setDeleteDialogOpen(false)
    try {
      const ids = Array.from(selected)
      const res = await repoApi.deletePackages(ids)
      const data = res.data as { deleted: number; errors: string[] }
      showSnack(`Deleted ${data.deleted} package(s)`, 'success')
      if (data.errors.length > 0) {
        setError(`Partial errors: ${data.errors.join('; ')}`)
      }
      setSelected(new Set())
      await fetchData()
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Failed to delete packages'
      setError(msg)
      showSnack('Failed to delete packages', 'error')
    } finally {
      setDeleting(false)
    }
  }

  if (loading) {
    return (
      <Box sx={{ display: 'flex', justifyContent: 'center', mt: 4 }}>
        <CircularProgress />
      </Box>
    )
  }

  const lastSync = syncStatus?.recent_syncs?.[0]
  const totalPackages = syncStatus?.total_packages ?? 0
  const selectedSize = packages
    .filter(p => selected.has(p.id))
    .reduce((sum, p) => sum + p.file_size, 0)

  return (
    <Box>
      <Typography variant="h5" fontWeight={600} sx={{ mb: 3 }}>
        Package Repository Management
      </Typography>

      {error && <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError(null)}>{error}</Alert>}

      {/* Summary Cards */}
      <Grid container spacing={2} sx={{ mb: 3 }}>
        <Grid size={{ xs: 12, sm: 3 }}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <PackageIcon color="primary" />
                <Typography variant="h6">Total Packages</Typography>
              </Box>
              <Typography variant="h4" sx={{ mt: 1 }}>{totalPackages}</Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid size={{ xs: 12, sm: 3 }}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <SyncIcon color="primary" />
                <Typography variant="h6">Last Sync</Typography>
              </Box>
              <Typography variant="body2" sx={{ mt: 1 }}>
                {lastSync ? new Date(lastSync.started_at).toLocaleString() : 'Never'}
              </Typography>
              {lastSync && (
                <Chip
                  size="small"
                  label={lastSync.status}
                  color={lastSync.status === 'success' ? 'success' : lastSync.status === 'failed' ? 'error' : 'warning'}
                  sx={{ mt: 1 }}
                />
              )}
            </CardContent>
          </Card>
        </Grid>
        <Grid size={{ xs: 12, sm: 3 }}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <CleanupIcon color="primary" />
                <Typography variant="h6">Disk Usage</Typography>
              </Box>
              <Typography variant="h4" sx={{ mt: 1 }}>
                {diskUsage ? fmtBytes(diskUsage.total_disk_bytes) : '—'}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
        <Grid size={{ xs: 12, sm: 3 }}>
          <Card>
            <CardContent>
              <Typography variant="h6" sx={{ mb: 1 }}>Per Distro</Typography>
              {diskUsage && Object.entries(diskUsage.per_distro).map(([distro, size]) => (
                <Box key={distro} sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 0.5 }}>
                  <Chip label={distro} size="small" color={DISTRO_COLORS[distro] || 'default'} />
                  <Typography variant="body2">{fmtBytes(size)}</Typography>
                </Box>
              ))}
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Actions */}
      <Box sx={{ mb: 3, display: 'flex', gap: 1, flexWrap: 'wrap', alignItems: 'center' }}>
        <Button
          variant="contained"
          startIcon={syncing ? <CircularProgress size={20} /> : <SyncIcon />}
          onClick={() => setSyncDialogOpen(true)}
          disabled={syncing}
        >
          {syncing ? 'Syncing...' : 'Trigger Sync'}
        </Button>
        <Button
          variant="outlined"
          startIcon={regenerating ? <CircularProgress size={20} /> : <RefreshIcon />}
          onClick={handleRegenerateMetadata}
          disabled={regenerating}
        >
          {regenerating ? 'Regenerating...' : 'Regenerate Metadata'}
        </Button>
        {selected.size > 0 && (
          <Button
            variant="contained"
            color="error"
            startIcon={deleting ? <CircularProgress size={20} /> : <DeleteIcon />}
            onClick={() => setDeleteDialogOpen(true)}
            disabled={deleting}
          >
            {deleting ? 'Deleting...' : `Delete ${selected.size} Selected (${fmtBytes(selectedSize)})`}
          </Button>
        )}
        <Button variant="outlined" startIcon={<DownloadIcon />} onClick={fetchData}>
          Refresh
        </Button>
        <Box sx={{ flexGrow: 1 }} />
        <Tooltip title={
          (syncStatus?.auto_sync_enabled ?? true)
            ? 'Auto-sync is ON — packages are pulled from GitHub Releases every hour. Click to pause.'
            : 'Auto-sync is PAUSED — new packages will not be pulled automatically. Manual sync still works. Click to resume.'
        }>
          <FormControlLabel
            control={
              <Switch
                checked={syncStatus?.auto_sync_enabled ?? true}
                onChange={handleToggleAutoSync}
                disabled={autoSyncToggling}
                color="success"
                icon={<PauseIcon color="action" fontSize="small" />}
                checkedIcon={<PlayIcon color="success" fontSize="small" />}
              />
            }
            label={
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5 }}>
                <Typography variant="body2" fontWeight={600}>
                  Auto-Sync
                </Typography>
                {autoSyncToggling && <CircularProgress size={14} />}
              </Box>
            }
            labelPlacement="start"
          />
        </Tooltip>
      </Box>

      {/* Sync History */}
      <Paper sx={{ p: 3, mb: 3 }}>
        <Typography variant="h6" fontWeight={600} sx={{ mb: 2 }}>Sync History</Typography>
        <Divider sx={{ mb: 2 }} />
        {syncStatus?.recent_syncs?.length ? (
          <TableContainer>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>Triggered By</TableCell>
                  <TableCell>Status</TableCell>
                  <TableCell>Synced</TableCell>
                  <TableCell>Skipped</TableCell>
                  <TableCell>Started</TableCell>
                  <TableCell>Finished</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {syncStatus.recent_syncs.map((log) => (
                  <TableRow key={log.id}>
                    <TableCell>{log.triggered_by}</TableCell>
                    <TableCell>
                      <Chip
                        size="small"
                        label={log.status}
                        color={log.status === 'success' ? 'success' : log.status === 'failed' ? 'error' : 'warning'}
                      />
                    </TableCell>
                    <TableCell>{log.packages_synced}</TableCell>
                    <TableCell>{log.packages_skipped}</TableCell>
                    <TableCell>{new Date(log.started_at).toLocaleString()}</TableCell>
                    <TableCell>{log.finished_at ? new Date(log.finished_at).toLocaleString() : '—'}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        ) : (
          <Alert severity="info">No sync history available</Alert>
        )}
        {lastSync?.error_message && (
          <Alert severity="error" sx={{ mt: 2 }}>
            <Typography variant="caption">Last sync error: {lastSync.error_message}</Typography>
          </Alert>
        )}
      </Paper>

      {/* Package List with Cleanup */}
      <Paper sx={{ p: 3 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
          <Typography variant="h6" fontWeight={600}>Packages in Repository</Typography>
          {packages.length > 0 && (
            <Button size="small" onClick={handleSelectAll}>
              {selected.size === packages.length ? 'Deselect All' : 'Select All'}
            </Button>
          )}
        </Box>
        <Divider sx={{ mb: 2 }} />
        {packages.length ? (
          <TableContainer>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell padding="checkbox">
                    <Checkbox
                      size="small"
                      indeterminate={selected.size > 0 && selected.size < packages.length}
                      checked={packages.length > 0 && selected.size === packages.length}
                      onChange={handleSelectAll}
                    />
                  </TableCell>
                  <TableCell>Filename</TableCell>
                  <TableCell>Version</TableCell>
                  <TableCell>Distro</TableCell>
                  <TableCell>Codename</TableCell>
                  <TableCell>Arch</TableCell>
                  <TableCell>Size</TableCell>
                  <TableCell>Source</TableCell>
                  <TableCell>Synced</TableCell>
                  <TableCell align="right">Actions</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {packages.map((pkg) => {
                  const isSelected = selected.has(pkg.id)
                  return (
                    <TableRow key={pkg.id} hover selected={isSelected}>
                      <TableCell padding="checkbox">
                        <Checkbox
                          size="small"
                          checked={isSelected}
                          onChange={() => handleSelectToggle(pkg.id)}
                        />
                      </TableCell>
                      <TableCell sx={{ fontFamily: 'monospace', fontSize: '0.8rem' }}>{pkg.filename}</TableCell>
                      <TableCell>{pkg.version}</TableCell>
                      <TableCell>
                        <Chip label={pkg.distro} size="small" color={DISTRO_COLORS[pkg.distro] || 'default'} />
                      </TableCell>
                      <TableCell>{pkg.distro_codename || '—'}</TableCell>
                      <TableCell>{pkg.arch}</TableCell>
                      <TableCell>{(pkg.file_size / 1024 / 1024).toFixed(1)} MB</TableCell>
                      <TableCell>{pkg.source}</TableCell>
                      <TableCell>{new Date(pkg.synced_at).toLocaleDateString()}</TableCell>
                      <TableCell align="right">
                        <Tooltip title="Delete">
                          <IconButton
                            size="small"
                            color="error"
                            onClick={() => {
                              setSelected(new Set([pkg.id]))
                              setDeleteDialogOpen(true)
                            }}
                          >
                            <DeleteIcon fontSize="small" />
                          </IconButton>
                        </Tooltip>
                      </TableCell>
                    </TableRow>
                  )
                })}
              </TableBody>
            </Table>
          </TableContainer>
        ) : (
          <Alert severity="info">No packages in repository. Trigger a sync to pull from GitHub Releases.</Alert>
        )}
      </Paper>

      {/* Sync Confirmation Dialog */}
      <Dialog open={syncDialogOpen} onClose={() => setSyncDialogOpen(false)}>
        <DialogTitle>Trigger Package Sync</DialogTitle>
        <DialogContent>
          <Typography>
            This will pull the last 3 releases from GitHub and import package assets into the manager-hosted repository.
            Packages already up to date (matching sha256) will be skipped. The sync runs in the background and may take several minutes.
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setSyncDialogOpen(false)}>Cancel</Button>
          <Button variant="contained" onClick={handleSync} startIcon={<SyncIcon />}>
            Start Sync
          </Button>
        </DialogActions>
      </Dialog>

      {/* Delete Confirmation Dialog */}
      <Dialog open={deleteDialogOpen} onClose={() => setDeleteDialogOpen(false)}>
        <DialogTitle>Delete Packages</DialogTitle>
        <DialogContent>
          <Typography>
            Delete {selected.size} package(s) ({fmtBytes(selectedSize)}) from the repository?
            This will remove the files from disk and the database, then regenerate all metadata.
            This cannot be undone.
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDeleteDialogOpen(false)}>Cancel</Button>
          <Button color="error" variant="contained" onClick={handleDelete} startIcon={<DeleteIcon />}>
            Delete
          </Button>
        </DialogActions>
      </Dialog>

      <Snackbar
        open={snackbar.open}
        autoHideDuration={4000}
        onClose={() => setSnackbar((p) => ({ ...p, open: false }))}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'center' }}
      >
        <Alert
          severity={snackbar.severity}
          onClose={() => setSnackbar((p) => ({ ...p, open: false }))}
        >
          {snackbar.message}
        </Alert>
      </Snackbar>
    </Box>
  )
}