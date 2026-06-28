import { useState, useEffect, useCallback } from 'react'
import {
  Box, Typography, Paper, Divider, Button, CircularProgress, Alert,
  Table, TableBody, TableCell, TableContainer, TableHead, TableRow,
  Chip, Card, CardContent, Grid, Dialog, DialogTitle, DialogContent, DialogActions,
} from '@mui/material'
import {
  Sync as SyncIcon, Store as PackageIcon, CloudDownload as DownloadIcon,
  VerifiedUser as VerifiedIcon, WarningAmber as WarningIcon,
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
  gpg_signed: boolean
  source: string
  synced_at: string
}

interface SyncStatus {
  recent_syncs: SyncLog[]
  total_packages: number
}

export default function RepoManagementPage() {
  const [syncStatus, setSyncStatus] = useState<SyncStatus | null>(null)
  const [packages, setPackages] = useState<RepoPackage[]>([])
  const [loading, setLoading] = useState(true)
  const [syncing, setSyncing] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [syncDialogOpen, setSyncDialogOpen] = useState(false)

  const fetchData = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const [statusRes, pkgRes] = await Promise.all([
        repoApi.getSyncStatus(),
        repoApi.listPackages(),
      ])
      setSyncStatus(statusRes.data)
      setPackages((pkgRes.data as { packages: RepoPackage[] }).packages || [])
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
      await fetchData()
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Failed to trigger sync')
    } finally {
      setSyncing(false)
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

  return (
    <Box>
      <Typography variant="h5" fontWeight={600} sx={{ mb: 3 }}>
        Package Repository Management
      </Typography>

      {error && <Alert severity="error" sx={{ mb: 2 }} onClose={() => setError(null)}>{error}</Alert>}

      {/* Summary Cards */}
      <Grid container spacing={2} sx={{ mb: 3 }}>
        <Grid size={{ xs: 12, sm: 4 }}>
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
        <Grid size={{ xs: 12, sm: 4 }}>
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
        <Grid size={{ xs: 12, sm: 4 }}>
          <Card>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                <VerifiedIcon color="primary" />
                <Typography variant="h6">GPG Signed</Typography>
              </Box>
              <Typography variant="h4" sx={{ mt: 1 }}>
                {packages.filter(p => p.gpg_signed).length}
              </Typography>
            </CardContent>
          </Card>
        </Grid>
      </Grid>

      {/* Actions */}
      <Box sx={{ mb: 3, display: 'flex', gap: 1 }}>
        <Button
          variant="contained"
          startIcon={syncing ? <CircularProgress size={20} /> : <SyncIcon />}
          onClick={() => setSyncDialogOpen(true)}
          disabled={syncing}
        >
          {syncing ? 'Syncing...' : 'Trigger Sync'}
        </Button>
        <Button variant="outlined" startIcon={<DownloadIcon />} onClick={fetchData}>
          Refresh
        </Button>
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

      {/* Package List */}
      <Paper sx={{ p: 3 }}>
        <Typography variant="h6" fontWeight={600} sx={{ mb: 2 }}>Packages in Repository</Typography>
        <Divider sx={{ mb: 2 }} />
        {packages.length ? (
          <TableContainer>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell>Filename</TableCell>
                  <TableCell>Version</TableCell>
                  <TableCell>Distro</TableCell>
                  <TableCell>Codename</TableCell>
                  <TableCell>Arch</TableCell>
                  <TableCell>Size</TableCell>
                  <TableCell>Signed</TableCell>
                  <TableCell>Source</TableCell>
                  <TableCell>Synced</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {packages.map((pkg) => (
                  <TableRow key={pkg.id}>
                    <TableCell sx={{ fontFamily: 'monospace', fontSize: '0.8rem' }}>{pkg.filename}</TableCell>
                    <TableCell>{pkg.version}</TableCell>
                    <TableCell>{pkg.distro}</TableCell>
                    <TableCell>{pkg.distro_codename || '—'}</TableCell>
                    <TableCell>{pkg.arch}</TableCell>
                    <TableCell>{(pkg.file_size / 1024 / 1024).toFixed(1)} MB</TableCell>
                    <TableCell>
                      {pkg.gpg_signed ? (
                        <Chip size="small" icon={<VerifiedIcon />} label="Signed" color="success" />
                      ) : (
                        <Chip size="small" icon={<WarningIcon />} label="Unsigned" color="warning" />
                      )}
                    </TableCell>
                    <TableCell>{pkg.source}</TableCell>
                    <TableCell>{new Date(pkg.synced_at).toLocaleDateString()}</TableCell>
                  </TableRow>
                ))}
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
            The sync runs in the background and may take several minutes.
          </Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setSyncDialogOpen(false)}>Cancel</Button>
          <Button variant="contained" onClick={handleSync} startIcon={<SyncIcon />}>
            Start Sync
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  )
}
