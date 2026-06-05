import { useEffect, useState, useCallback } from 'react'
import {
  Alert,
  Box,
  Card,
  CardContent,
  CircularProgress,
  Container,
  Grid,
  IconButton,
  LinearProgress,
  Toolbar,
  Tooltip,
  Typography,
} from '@mui/material'
import {
  CheckCircle,
  Warning,
  Error as ErrorIcon,
  HourglassEmpty,
  BugReport,
  RestartAlt,
  Refresh as RefreshIcon,
  Security as SecurityIcon,
  VerifiedUser as VerifiedUserIcon,
} from '@mui/icons-material'
import { fleetApi, certsApi } from '../api/client'
import type { FleetStatus } from '../types'

// ── StatCard ─────────────────────────────────────────────────────────────────
function StatCard({
  title,
  value,
  color,
  icon,
}: {
  title: string
  value: number
  color: string
  icon: React.ReactNode
}) {
  return (
    <Card variant="outlined" sx={{ borderLeft: `4px solid ${color}`, height: '100%' }}>
      <CardContent>
        <Box display="flex" alignItems="center" gap={1} mb={0.5}>
          {icon}
          <Typography variant="h4" fontWeight={700} lineHeight={1}>
            {value}
          </Typography>
        </Box>
        <Typography variant="body2" color="text.secondary">
          {title}
        </Typography>
      </CardContent>
    </Card>
  )
}

// ── DashboardPage ─────────────────────────────────────────────────────────────
export default function DashboardPage() {
  const [status, setStatus] = useState<FleetStatus | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const load = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const res = await fleetApi.getStatus()
      setStatus(res.data)
    } catch {
      setError('Failed to load fleet status')
    } finally {
      setLoading(false)
    }
  }, [])

  // Initial load
  useEffect(() => {
    load()
  }, [load])

  // Auto-refresh every 60 seconds
  useEffect(() => {
    const t = setInterval(load, 60_000)
    return () => clearInterval(t)
  }, [load])

  // ── Download Root CA ──────────────────────────────────────────────────────
  const handleDownloadRootCa = async () => {
    try {
      const res = await certsApi.downloadRootCa()
      const url = URL.createObjectURL(res.data as Blob)
      const a = document.createElement('a')
      a.href = url
      a.download = 'ca.crt'
      a.click()
      URL.revokeObjectURL(url)
    } catch {
      // silently ignore — user will see no download; no state change needed
    }
  }


  return (
    <Container maxWidth="xl" sx={{ mt: 3 }}>
      <Toolbar disableGutters sx={{ mb: 3 }}>
        <Typography variant="h5" fontWeight={700} sx={{ flexGrow: 1 }}>
          Dashboard
        </Typography>
        <Tooltip title="Download Root CA">
          <IconButton onClick={handleDownloadRootCa}>
            <SecurityIcon />
          </IconButton>
        </Tooltip>
        <Tooltip title="Refresh">
          <span>
            <IconButton onClick={load} disabled={loading}>
              {loading ? <CircularProgress size={20} /> : <RefreshIcon />}
            </IconButton>
          </span>
        </Tooltip>
      </Toolbar>

      {error && (
        <Alert severity="error" sx={{ mb: 3 }}>
          {error}
        </Alert>
      )}

      {!loading && !status && !error && (
        <Alert severity="info">No fleet data available.</Alert>
      )}

      {status && (
        <Box>
          {/* ── Row 1: Status stat cards ── */}
          <Grid container spacing={2} sx={{ mb: 3 }}>
            <Grid size={{ xs: 12, sm: 6, md: 3 }}>
              <StatCard
                title="Healthy"
                value={status.healthy}
                color="#2e7d32"
                icon={<CheckCircle sx={{ color: '#2e7d32' }} />}
              />
            </Grid>
            <Grid size={{ xs: 12, sm: 6, md: 3 }}>
              <StatCard
                title="Degraded"
                value={status.degraded}
                color="#ed6c02"
                icon={<Warning sx={{ color: '#ed6c02' }} />}
              />
            </Grid>
            <Grid size={{ xs: 12, sm: 6, md: 3 }}>
              <StatCard
                title="Unreachable"
                value={status.unreachable}
                color="#d32f2f"
                icon={<ErrorIcon sx={{ color: '#d32f2f' }} />}
              />
            </Grid>
            <Grid size={{ xs: 12, sm: 6, md: 3 }}>
              <StatCard
                title="Pending / Unknown"
                value={status.pending}
                color="#9e9e9e"
                icon={<HourglassEmpty sx={{ color: '#9e9e9e' }} />}
              />
            </Grid>
          </Grid>

          {/* ── Row 2: Compliance bar ── */}
          <Card variant="outlined" sx={{ mb: 3 }}>
            <CardContent>
              <Box display="flex" justifyContent="space-between" alignItems="center" mb={1}>
                <Typography variant="subtitle1" fontWeight={600}>
                  Compliance
                </Typography>
                <Typography variant="h6" fontWeight={700}>
                  {status.compliance_pct.toFixed(1)}%
                </Typography>
              </Box>
              <LinearProgress
                variant="determinate"
                value={Math.min(status.compliance_pct, 100)}
                sx={{
                  height: 12,
                  borderRadius: 6,
                  backgroundColor: '#e0e0e0',
                  '& .MuiLinearProgress-bar': {
                    borderRadius: 6,
                    backgroundColor:
                      status.compliance_pct >= 90
                        ? '#2e7d32'
                        : status.compliance_pct >= 70
                        ? '#ed6c02'
                        : '#d32f2f',
                  },
                }}
              />
              <Typography variant="caption" color="text.secondary" mt={0.5} display="block">
                {status.total_hosts} total host{status.total_hosts !== 1 ? 's' : ''} in fleet
              </Typography>
            </CardContent>
          </Card>

          {/* ── Row 3: Patches + Reboot ── */}
          <Grid container spacing={2}>
            <Grid size={{ xs: 12, sm: 6 }}>
              <Card variant="outlined">
                <CardContent>
                  <Box display="flex" alignItems="center" gap={1} mb={0.5}>
                    <BugReport color="action" />
                    <Typography variant="h5" fontWeight={700}>
                      {status.total_pending_patches.toLocaleString()}
                    </Typography>
                  </Box>
                  <Typography variant="body2" color="text.secondary">
                    Pending Patches
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
            <Grid size={{ xs: 12, sm: 6 }}>
              <Card variant="outlined">
                <CardContent>
                  <Box display="flex" alignItems="center" gap={1} mb={0.5}>
                    <RestartAlt color="action" />
                    <Typography variant="h5" fontWeight={700}>
                      {status.hosts_requiring_reboot.toLocaleString()}
                    </Typography>
                  </Box>
                  <Typography variant="body2" color="text.secondary">
                    Hosts Requiring Reboot
                  </Typography>
                </CardContent>
              </Card>
            </Grid>
          </Grid>

          {/* ── Row 4: CRL Status ── */}
          <Card variant="outlined" sx={{ mt: 3 }}>
            <CardContent>
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 2 }}>
                <VerifiedUserIcon color="primary" />
                <Typography variant="subtitle1" fontWeight={600}>
                  CRL Status
                </Typography>
              </Box>
              <Grid container spacing={2}>
                <Grid size={{ xs: 6, sm: 3 }}>
                  <Box textAlign="center">
                    <Typography variant="h5" fontWeight={700} sx={{ color: '#2e7d32' }}>
                      {status.crl_valid}
                    </Typography>
                    <Typography variant="caption" color="text.secondary">Valid</Typography>
                  </Box>
                </Grid>
                <Grid size={{ xs: 6, sm: 3 }}>
                  <Box textAlign="center">
                    <Typography variant="h5" fontWeight={700} sx={{ color: '#ed6c02' }}>
                      {status.crl_expired}
                    </Typography>
                    <Typography variant="caption" color="text.secondary">Expired</Typography>
                  </Box>
                </Grid>
                <Grid size={{ xs: 6, sm: 3 }}>
                  <Box textAlign="center">
                    <Typography variant="h5" fontWeight={700} sx={{ color: '#ed6c02' }}>
                      {status.crl_missing}
                    </Typography>
                    <Typography variant="caption" color="text.secondary">Missing</Typography>
                  </Box>
                </Grid>
                <Grid size={{ xs: 6, sm: 3 }}>
                  <Box textAlign="center">
                    <Typography variant="h5" fontWeight={700} sx={{ color: '#d32f2f' }}>
                      {status.crl_invalid}
                    </Typography>
                    <Typography variant="caption" color="text.secondary">Invalid</Typography>
                  </Box>
                </Grid>
              </Grid>
              {status.crl_not_reporting > 0 && (
                <Typography variant="caption" color="text.secondary" sx={{ display: 'block', mt: 1 }}>
                  {status.crl_not_reporting} host{status.crl_not_reporting !== 1 ? 's' : ''} not reporting CRL status
                </Typography>
              )}
            </CardContent>
          </Card>
        </Box>
      )}
    </Container>
  )
}
