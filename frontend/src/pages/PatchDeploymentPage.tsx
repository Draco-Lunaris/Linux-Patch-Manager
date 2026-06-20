import { useEffect, useState, useCallback } from 'react'
import {
  Alert,
  Box,
  Button,
  Checkbox,
  Chip,
  CircularProgress,
  Container,
  FormControlLabel,
  InputAdornment,
  Paper,
  Step,
  StepLabel,
  Stepper,
  Switch,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableRow,
  TableSortLabel,
  TextField,
  Toolbar,
  Typography,
  Tooltip,
} from '@mui/material'
import { Search as SearchIcon, CheckCircle as CheckCircleIcon, Cancel as CancelIcon, Remove as RemoveIcon } from '@mui/icons-material'
import { useNavigate } from 'react-router-dom'
import { hostsApi, jobsApi } from '../api/client'
import type { Host, HostHealthStatus } from '../types'

const STEPS = ['Select Hosts', 'Review & Configure', 'Result']

// ── Health status chip ────────────────────────────────────────────────────────
function HealthChip({ status }: { status: HostHealthStatus }) {
  const map: Record<HostHealthStatus, 'success' | 'warning' | 'error' | 'default'> = {
    healthy: 'success',
    degraded: 'warning',
    unreachable: 'error',
    pending: 'default',
  }
  return <Chip label={status} color={map[status]} size="small" />
}

// ── PatchDeploymentPage ───────────────────────────────────────────────────────
export default function PatchDeploymentPage() {
  const navigate = useNavigate()
  const [activeStep, setActiveStep] = useState(0)

  // Step 0 state
  const [hosts, setHosts] = useState<Host[]>([])
  const [hostsLoading, setHostsLoading] = useState(true)
  const [hostsError, setHostsError] = useState<string | null>(null)
  const [searchQuery, setSearchQuery] = useState('')
  const [healthFilter, setHealthFilter] = useState<HostHealthStatus | ''>('')
  const [patchesFilter, setPatchesFilter] = useState<'all' | 'missing' | 'uptodate'>('all')
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set())

  // ── Sorting state ────────────────────────────────────────────────────────
  type SortKey = 'display_name' | 'fqdn' | 'ip_address' | 'health_status' | 'health_check_status' | 'patches_missing' | 'os'
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

  const getSortValue = (h: Host, key: SortKey): string | number => {
    switch (key) {
      case 'os': return (h.os_name ?? h.os_family ?? '').toLowerCase()
      case 'patches_missing': return h.patches_missing
      default: return String(h[key as keyof Host] ?? '').toLowerCase()
    }
  }

  // Step 1 state
  const [immediate, setImmediate] = useState(true)
  const [allowReboot, setAllowReboot] = useState(false)
  const [notes, setNotes] = useState('')
  const [packages, setPackages] = useState('')

  // Step 2 state
  const [submitting, setSubmitting] = useState(false)
  const [submitError, setSubmitError] = useState<string | null>(null)
  const [createdJobId, setCreatedJobId] = useState<string | null>(null)

  const loadHosts = useCallback(async () => {
    setHostsLoading(true)
    setHostsError(null)
    try {
      const res = await hostsApi.list()
      const data = res.data as { hosts?: Host[] } | Host[]
      setHosts(Array.isArray(data) ? data : (data.hosts ?? []))
    } catch {
      setHostsError('Failed to load hosts')
    } finally {
      setHostsLoading(false)
    }
  }, [])

  useEffect(() => {
    loadHosts()
  }, [loadHosts])

  const filteredHosts = hosts.filter((h) => {
    const matchesSearch =
      searchQuery === '' ||
      h.display_name.toLowerCase().includes(searchQuery.toLowerCase()) ||
      h.fqdn.toLowerCase().includes(searchQuery.toLowerCase())
    const matchesHealth = healthFilter === '' || h.health_status === healthFilter
    const matchesPatches =
      patchesFilter === 'all' ||
      (patchesFilter === 'missing' && h.patches_missing > 0) ||
      (patchesFilter === 'uptodate' && h.patches_missing === 0)
    return matchesSearch && matchesHealth && matchesPatches
  })

  const sortedHosts = (() => {
    if (!sortKey) return filteredHosts
    const arr = [...filteredHosts]
    arr.sort((a, b) => {
      const va = getSortValue(a, sortKey)
      const vb = getSortValue(b, sortKey)
      if (typeof va === 'number' && typeof vb === 'number') {
        return sortDir === 'asc' ? va - vb : vb - va
      }
      const cmp = String(va).localeCompare(String(vb), undefined, { numeric: true, sensitivity: 'base' })
      return sortDir === 'asc' ? cmp : -cmp
    })
    return arr
  })()

  const handleToggleHost = (id: string) => {
    setSelectedIds((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  const handleToggleAll = () => {
    if (selectedIds.size === filteredHosts.length) {
      setSelectedIds(new Set())
    } else {
      setSelectedIds(new Set(filteredHosts.map((h) => h.id)))
    }
  }

  const handleDeploy = async () => {
    setSubmitting(true)
    setSubmitError(null)
    try {
      const pkgList = packages
        .split(',')
        .map((p) => p.trim())
        .filter((p) => p.length > 0)
      const res = await jobsApi.create({
        host_ids: Array.from(selectedIds),
        packages: pkgList,
        immediate,
        allow_reboot: allowReboot,
        notes: notes.trim() || undefined,
      })
      const job = res.data as { id: string }
      setCreatedJobId(job.id)
      setActiveStep(2)
    } catch (err: unknown) {
      const msg =
        err instanceof Error ? err.message : 'Deployment failed. Please try again.'
      setSubmitError(msg)
      setActiveStep(2)
    } finally {
      setSubmitting(false)
    }
  }

  const handleReset = () => {
    setActiveStep(0)
    setSelectedIds(new Set())
    setImmediate(true)
    setAllowReboot(false)
    setNotes('')
    setPackages('')
    setSubmitError(null)
    setCreatedJobId(null)
  }

  const selectedHosts = hosts.filter((h) => selectedIds.has(h.id))

  return (
    <Container maxWidth="xl" sx={{ mt: 3 }}>
      <Toolbar disableGutters sx={{ mb: 3 }}>
        <Typography variant="h5" fontWeight={700} sx={{ flexGrow: 1 }}>
          Patch Deployment
        </Typography>
      </Toolbar>

      <Stepper activeStep={activeStep} sx={{ mb: 4 }}>
        {STEPS.map((label) => (
          <Step key={label}>
            <StepLabel>{label}</StepLabel>
          </Step>
        ))}
      </Stepper>

      {/* ── Step 0: Select Hosts ── */}
      {activeStep === 0 && (
        <Paper variant="outlined" sx={{ p: 3 }}>
          <Typography variant="h6" fontWeight={600} mb={2}>
            Select Target Hosts
          </Typography>

          {hostsError && (
            <Alert severity="error" sx={{ mb: 2 }}>
              {hostsError}
            </Alert>
          )}

          <Box display="flex" gap={2} mb={2} flexWrap="wrap">
            <TextField
              size="small"
              placeholder="Search by name or FQDN…"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              InputProps={{
                startAdornment: (
                  <InputAdornment position="start">
                    <SearchIcon fontSize="small" />
                  </InputAdornment>
                ),
              }}
              sx={{ minWidth: 260 }}
            />
            <TextField
              select
              size="small"
              label="Health Filter"
              value={healthFilter}
              onChange={(e) => setHealthFilter(e.target.value as HostHealthStatus | '')}
              SelectProps={{ native: true }}
              sx={{ minWidth: 160 }}
            >
              <option value="">All</option>
              <option value="healthy">Healthy</option>
              <option value="degraded">Degraded</option>
              <option value="unreachable">Unreachable</option>
              <option value="pending">Pending</option>
            </TextField>
            <TextField
              select
              size="small"
              label="Patches Missing"
              value={patchesFilter}
              onChange={(e) => setPatchesFilter(e.target.value as 'all' | 'missing' | 'uptodate')}
              SelectProps={{ native: true }}
              sx={{ minWidth: 160 }}
            >
              <option value="all">All</option>
              <option value="missing">Missing (&gt;0)</option>
              <option value="uptodate">Up to date (0)</option>
            </TextField>
          </Box>

          {hostsLoading ? (
            <Box display="flex" justifyContent="center" py={4}>
              <CircularProgress />
            </Box>
          ) : (
            <Box sx={{ overflowX: 'auto' }}>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell padding="checkbox">
                      <Checkbox
                        checked={
                          filteredHosts.length > 0 &&
                          filteredHosts.every((h) => selectedIds.has(h.id))
                        }
                        indeterminate={
                          filteredHosts.some((h) => selectedIds.has(h.id)) &&
                          !filteredHosts.every((h) => selectedIds.has(h.id))
                        }
                        onChange={handleToggleAll}
                        disabled={filteredHosts.length === 0}
                      />
                    </TableCell>
                    <TableCell>
                      <TableSortLabel active={sortKey === 'display_name'} direction={sortKey === 'display_name' ? sortDir : 'asc'} onClick={() => handleSortChange('display_name')}>Display Name</TableSortLabel>
                    </TableCell>
                    <TableCell>
                      <TableSortLabel active={sortKey === 'fqdn'} direction={sortKey === 'fqdn' ? sortDir : 'asc'} onClick={() => handleSortChange('fqdn')}>FQDN</TableSortLabel>
                    </TableCell>
                    <TableCell>
                      <TableSortLabel active={sortKey === 'ip_address'} direction={sortKey === 'ip_address' ? sortDir : 'asc'} onClick={() => handleSortChange('ip_address')}>IP Address</TableSortLabel>
                    </TableCell>
                    <TableCell>
                      <TableSortLabel active={sortKey === 'health_status'} direction={sortKey === 'health_status' ? sortDir : 'asc'} onClick={() => handleSortChange('health_status')}>Health</TableSortLabel>
                    </TableCell>
                    <TableCell>
                      <TableSortLabel active={sortKey === 'health_check_status'} direction={sortKey === 'health_check_status' ? sortDir : 'asc'} onClick={() => handleSortChange('health_check_status')}>Checks</TableSortLabel>
                    </TableCell>
                    <TableCell>
                      <TableSortLabel active={sortKey === 'patches_missing'} direction={sortKey === 'patches_missing' ? sortDir : 'asc'} onClick={() => handleSortChange('patches_missing')}>Patches</TableSortLabel>
                    </TableCell>
                    <TableCell>
                      <TableSortLabel active={sortKey === 'os'} direction={sortKey === 'os' ? sortDir : 'asc'} onClick={() => handleSortChange('os')}>OS</TableSortLabel>
                    </TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {filteredHosts.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={8} align="center">
                        <Typography variant="body2" color="text.secondary" py={2}>
                          No hosts found
                        </Typography>
                      </TableCell>
                    </TableRow>
                  ) : (
                    sortedHosts.map((host) => (
                      <TableRow
                        key={host.id}
                        hover
                        selected={selectedIds.has(host.id)}
                        sx={{ cursor: 'pointer' }}
                        onClick={() => handleToggleHost(host.id)}
                      >
                        <TableCell padding="checkbox">
                          <Checkbox
                            checked={selectedIds.has(host.id)}
                            onChange={() => handleToggleHost(host.id)}
                            onClick={(e) => e.stopPropagation()}
                          />
                        </TableCell>
                        <TableCell>{host.display_name}</TableCell>
                        <TableCell>{host.fqdn}</TableCell>
                        <TableCell>{host.ip_address}</TableCell>
                        <TableCell>
                          <HealthChip status={host.health_status} />
                        </TableCell>
                        <TableCell>
                          {host.health_check_status === 'all_healthy' ? (
                            <Tooltip title="All checks healthy"><CheckCircleIcon color="success" fontSize="small" /></Tooltip>
                          ) : host.health_check_status === 'some_unhealthy' ? (
                            <Tooltip title="Some checks unhealthy"><CancelIcon color="error" fontSize="small" /></Tooltip>
                          ) : (
                            <Tooltip title="No checks configured"><RemoveIcon color="disabled" fontSize="small" /></Tooltip>
                          )}
                        </TableCell>
                        <TableCell>
                          <Chip
                            label={host.patches_missing}
                            color={host.patches_missing > 0 ? 'error' : 'success'}
                            size="small"
                          />
                        </TableCell>
                        <TableCell>
                          {host.os_name ?? host.os_family ?? '—'}
                        </TableCell>
                      </TableRow>
                    ))
                  )}
                </TableBody>
              </Table>
            </Box>
          )}

          <Box display="flex" justifyContent="space-between" alignItems="center" mt={3}>
            <Typography variant="body2" color="text.secondary">
              {selectedIds.size} host{selectedIds.size !== 1 ? 's' : ''} selected
            </Typography>
            <Button
              variant="contained"
              onClick={() => setActiveStep(1)}
              disabled={selectedIds.size === 0}
            >
              Next
            </Button>
          </Box>
        </Paper>
      )}

      {/* ── Step 1: Review & Configure ── */}
      {activeStep === 1 && (
        <Paper variant="outlined" sx={{ p: 3 }}>
          <Typography variant="h6" fontWeight={600} mb={2}>
            Review &amp; Configure
          </Typography>

          <Typography variant="subtitle2" color="text.secondary" mb={1}>
            Selected Hosts ({selectedHosts.length})
          </Typography>
          <Box display="flex" flexWrap="wrap" gap={1} mb={3}>
            {selectedHosts.map((h) => (
              <Chip
                key={h.id}
                label={h.display_name}
                onDelete={() => handleToggleHost(h.id)}
                size="small"
              />
            ))}
          </Box>

          <Box display="flex" flexDirection="column" gap={2.5} maxWidth={560}>
            <FormControlLabel
              control={
                <Switch
                  checked={immediate}
                  onChange={(e) => setImmediate(e.target.checked)}
                />
              }
              label={
                <Box>
                  <Typography variant="body2" fontWeight={600}>
                    {immediate ? 'Apply Now' : 'Queue for Maintenance Window'}
                  </Typography>
                  <Typography variant="caption" color="text.secondary">
                    {immediate
                      ? 'Job will run immediately on the selected hosts'
                      : 'Job will run during the next scheduled maintenance window'}
                  </Typography>
                </Box>
              }
            />

            <FormControlLabel
              control={
                <Checkbox
                  checked={allowReboot}
                  onChange={(e) => setAllowReboot(e.target.checked)}
                />
              }
              label="Allow reboot after patching"
            />

            <TextField
              label="Packages (optional)"
              placeholder="Leave empty to apply all available patches, or enter comma-separated package names"
              multiline
              minRows={2}
              value={packages}
              onChange={(e) => setPackages(e.target.value)}
              fullWidth
              helperText="e.g. openssl, curl, libssl1.1"
            />

            <TextField
              label="Notes (optional)"
              placeholder="Describe the purpose of this deployment…"
              multiline
              minRows={3}
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
              fullWidth
            />
          </Box>

          <Box display="flex" gap={2} mt={4}>
            <Button variant="outlined" onClick={() => setActiveStep(0)}>
              Back
            </Button>
            <Button
              variant="contained"
              color="primary"
              onClick={handleDeploy}
              disabled={submitting}
              startIcon={submitting ? <CircularProgress size={16} color="inherit" /> : undefined}
            >
              {submitting ? 'Deploying…' : 'Deploy'}
            </Button>
          </Box>
        </Paper>
      )}

      {/* ── Step 2: Result ── */}
      {activeStep === 2 && (
        <Paper variant="outlined" sx={{ p: 3 }}>
          <Typography variant="h6" fontWeight={600} mb={3}>
            Deployment Result
          </Typography>

          {createdJobId ? (
            <Alert severity="success" sx={{ mb: 3 }}>
              <Typography fontWeight={600}>Deployment job created successfully!</Typography>
              <Typography variant="body2" mt={0.5}>
                Job ID: <strong>{createdJobId}</strong>
              </Typography>
            </Alert>
          ) : (
            <Alert severity="error" sx={{ mb: 3 }}>
              <Typography fontWeight={600}>Deployment failed</Typography>
              {submitError && (
                <Typography variant="body2" mt={0.5}>
                  {submitError}
                </Typography>
              )}
            </Alert>
          )}

          <Box display="flex" gap={2}>
            <Button variant="outlined" onClick={handleReset}>
              Deploy Another
            </Button>
            {createdJobId && (
              <Button
                variant="contained"
                onClick={() => navigate('/jobs')}
              >
                View Jobs
              </Button>
            )}
          </Box>
        </Paper>
      )}
    </Container>
  )
}
