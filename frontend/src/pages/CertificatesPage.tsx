import JSZip from 'jszip'
import { useCallback, useEffect, useState } from 'react'
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
  IconButton,
  InputLabel,
  MenuItem,
  Paper,
  Select,
  type SelectChangeEvent,
  Snackbar,
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
  ContentCopy as CopyIcon,
  Download as DownloadIcon,
  Refresh as RefreshIcon,
  Security as SecurityIcon,
} from '@mui/icons-material'
import { certsApi } from '../api/client'
import { useAuthStore } from '../store/authStore'
import type { Certificate, CertStatus, IssuedCert } from '../types'

// ── Helpers ───────────────────────────────────────────────────────────────────

function downloadBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  a.click()
  URL.revokeObjectURL(url)
}

function fmtDate(iso: string): string {
  return new Date(iso).toLocaleDateString(undefined, {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  })
}

function isExpiringSoon(iso: string): boolean {
  return new Date(iso).getTime() - Date.now() < 30 * 24 * 60 * 60 * 1000
}

function statusChip(status: CertStatus) {
  const map: Record<CertStatus, { label: string; color: 'success' | 'error' | 'warning' }> = {
    active:  { label: 'Active',  color: 'success' },
    revoked: { label: 'Revoked', color: 'error'   },
    expired: { label: 'Expired', color: 'warning'  },
  }
  const { label, color } = map[status]
  return <Chip label={label} color={color} size="small" />
}

// ── Issue Dialog ──────────────────────────────────────────────────────────────

interface IssueDialogProps {
  open: boolean
  onClose: () => void
  onIssued: (cert: IssuedCert) => void
}

function IssueDialog({ open, onClose, onIssued }: IssueDialogProps) {
  const [hostId, setHostId] = useState('')
  const [hostname, setHostname] = useState('')
  const [saving, setSaving] = useState(false)
  const [err, setErr] = useState<string | null>(null)

  useEffect(() => {
    if (open) { setHostId(''); setHostname(''); setErr(null) }
  }, [open])

  const handleSubmit = async () => {
    if (!hostId.trim()) { setErr('Host ID is required'); return }
    if (!hostname.trim()) { setErr('Hostname is required'); return }
    setSaving(true); setErr(null)
    try {
      const res = await certsApi.issue(hostId.trim(), hostname.trim())
      onIssued(res.data)
      onClose()
    } catch (e: unknown) {
      const msg = (e as { response?: { data?: { error?: { message?: string } } } })
        ?.response?.data?.error?.message ?? 'Failed to issue certificate'
      setErr(msg)
    } finally {
      setSaving(false)
    }
  }

  return (
    <Dialog open={open} onClose={onClose} maxWidth="sm" fullWidth>
      <DialogTitle>Issue Client Certificate</DialogTitle>
      <DialogContent sx={{ display: 'flex', flexDirection: 'column', gap: 2, pt: 2 }}>
        {err && <Alert severity="error">{err}</Alert>}
        <TextField
          label="Host ID (UUID)"
          value={hostId}
          onChange={(e) => setHostId(e.target.value)}
          required
          fullWidth
          placeholder="e.g. 3fa85f64-5717-4562-b3fc-2c963f66afa6"
        />
        <TextField
          label="Hostname"
          value={hostname}
          onChange={(e) => setHostname(e.target.value)}
          required
          fullWidth
          placeholder="e.g. web-01.example.com"
        />
      </DialogContent>
      <DialogActions>
        <Button onClick={onClose} disabled={saving}>Cancel</Button>
        <Button variant="contained" onClick={handleSubmit} disabled={saving}>
          {saving ? <CircularProgress size={20} /> : 'Issue'}
        </Button>
      </DialogActions>
    </Dialog>
  )
}

// ── One-Time Key Display Dialog ───────────────────────────────────────────────

interface KeyDisplayDialogProps {
  open: boolean
  cert: IssuedCert | null
  hostname?: string
  onClose: () => void
}

function KeyDisplayDialog({ open, cert, hostname, onClose }: KeyDisplayDialogProps) {
  const [copiedField, setCopiedField] = useState<'ca' | 'cert' | 'key' | 'server-cert' | 'server-key' | null>(null)
  const [downloading, setDownloading] = useState(false)

  const handleCopy = async (text: string, field: 'ca' | 'cert' | 'key' | 'server-cert' | 'server-key') => {
    await navigator.clipboard.writeText(text)
    setCopiedField(field)
    setTimeout(() => setCopiedField(null), 2000)
  }

  const handleDownloadBundle = async () => {
    if (!cert) return
    setDownloading(true)
    try {
      const zip = new JSZip()
      zip.file('ca.crt', cert.ca_root_pem)
      zip.file('client.crt', cert.cert_pem)
      zip.file('client.key', cert.key_pem)
      zip.file('server.crt', cert.server_cert_pem)
      zip.file('server.key', cert.server_key_pem)
      const blob = await zip.generateAsync({ type: 'blob' })
      downloadBlob(blob, `${hostname || 'host'}-certs.zip`)
    } finally {
      setDownloading(false)
    }
  }

  const preStyle = {
    p: 2,
    bgcolor: 'grey.100',
    borderRadius: 1,
    fontSize: 12,
    overflow: 'auto',
    maxHeight: 150,
    fontFamily: 'monospace' as const,
    whiteSpace: 'pre-wrap' as const,
    wordBreak: 'break-all' as const,
  }

  return (
    <Dialog open={open} onClose={onClose} maxWidth="md" fullWidth>
      <DialogTitle>Agent Certificate Bundle Issued — Save Your Private Keys</DialogTitle>
      <DialogContent sx={{ display: 'flex', flexDirection: 'column', gap: 2, pt: 2 }}>
        <Alert severity="warning">
          <strong>Private keys will NOT be shown again.</strong> Copy and store them securely
          before closing this dialog.
        </Alert>
        {cert && (
          <>
            <Typography variant="caption" color="text.secondary">
              Client Serial: {cert.serial_number} &nbsp;|&nbsp; Server Serial: {cert.server_serial_number} &nbsp;|&nbsp; Expires: {fmtDate(cert.expires_at)}
            </Typography>

            {/* CA Root Certificate */}
            <Box>
              <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 0.5 }}>
                <Typography variant="subtitle2">CA Root Certificate (ca.crt)</Typography>
                <Tooltip title={copiedField === 'ca' ? 'Copied!' : 'Copy CA root cert to clipboard'}>
                  <Button size="small" startIcon={<CopyIcon />} onClick={() => handleCopy(cert.ca_root_pem, 'ca')} variant="outlined">
                    {copiedField === 'ca' ? 'Copied!' : 'Copy CA Root'}
                  </Button>
                </Tooltip>
              </Box>
              <Box component="pre" sx={preStyle}>{cert.ca_root_pem}</Box>
            </Box>

            {/* Client Certificate (mTLS) */}
            <Box>
              <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 0.5 }}>
                <Typography variant="subtitle2">Client Certificate — mTLS (client.crt)</Typography>
                <Tooltip title={copiedField === 'cert' ? 'Copied!' : 'Copy client cert to clipboard'}>
                  <Button size="small" startIcon={<CopyIcon />} onClick={() => handleCopy(cert.cert_pem, 'cert')} variant="outlined">
                    {copiedField === 'cert' ? 'Copied!' : 'Copy Client Cert'}
                  </Button>
                </Tooltip>
              </Box>
              <Box component="pre" sx={preStyle}>{cert.cert_pem}</Box>
            </Box>

            {/* Client Private Key */}
            <Box>
              <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 0.5 }}>
                <Typography variant="subtitle2" color="error">Client Private Key (client.key)</Typography>
                <Tooltip title={copiedField === 'key' ? 'Copied!' : 'Copy client key to clipboard'}>
                  <Button size="small" startIcon={<CopyIcon />} onClick={() => handleCopy(cert.key_pem, 'key')} variant="outlined" color="error">
                    {copiedField === 'key' ? 'Copied!' : 'Copy Client Key'}
                  </Button>
                </Tooltip>
              </Box>
              <Box component="pre" sx={preStyle}>{cert.key_pem}</Box>
            </Box>

            {/* Server Certificate (Agent TLS) */}
            <Box>
              <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 0.5 }}>
                <Typography variant="subtitle2">Server Certificate — Agent TLS (server.crt)</Typography>
                <Tooltip title={copiedField === 'server-cert' ? 'Copied!' : 'Copy server cert to clipboard'}>
                  <Button size="small" startIcon={<CopyIcon />} onClick={() => handleCopy(cert.server_cert_pem, 'server-cert')} variant="outlined">
                    {copiedField === 'server-cert' ? 'Copied!' : 'Copy Server Cert'}
                  </Button>
                </Tooltip>
              </Box>
              <Box component="pre" sx={preStyle}>{cert.server_cert_pem}</Box>
            </Box>

            {/* Server Private Key */}
            <Box>
              <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 0.5 }}>
                <Typography variant="subtitle2" color="error">Server Private Key (server.key)</Typography>
                <Tooltip title={copiedField === 'server-key' ? 'Copied!' : 'Copy server key to clipboard'}>
                  <Button size="small" startIcon={<CopyIcon />} onClick={() => handleCopy(cert.server_key_pem, 'server-key')} variant="outlined" color="error">
                    {copiedField === 'server-key' ? 'Copied!' : 'Copy Server Key'}
                  </Button>
                </Tooltip>
              </Box>
              <Box component="pre" sx={preStyle}>{cert.server_key_pem}</Box>
            </Box>
          </>
        )}
      </DialogContent>
      <DialogActions sx={{ justifyContent: 'space-between' }}>
        <Button
          variant="outlined"
          onClick={handleDownloadBundle}
          disabled={downloading || !cert}
        >
          {downloading ? <CircularProgress size={20} /> : 'Download Bundle (.zip)'}
        </Button>
        <Button variant="contained" onClick={onClose}>I Have Saved the Keys</Button>
      </DialogActions>
    </Dialog>
  )
}

// ── Main Page ─────────────────────────────────────────────────────────────────

export default function CertificatesPage() {
  const user = useAuthStore((s) => s.user)
  const canWrite = user?.role === 'admin' || user?.role === 'operator'

  const [certs, setCerts] = useState<Certificate[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  // Filters
  const [statusFilter, setStatusFilter] = useState<string>('all')
  const [hostFilter, setHostFilter] = useState<string>('')

  // Dialogs
  const [issueOpen, setIssueOpen] = useState(false)
  const [issuedCert, setIssuedCert] = useState<IssuedCert | null>(null)
  const [keyDialogOpen, setKeyDialogOpen] = useState(false)

  // Snackbar
  const [snackbar, setSnackbar] = useState<{ open: boolean; message: string; severity: 'success' | 'error' }>({
    open: false, message: '', severity: 'success',
  })

  const showSnack = (message: string, severity: 'success' | 'error') =>
    setSnackbar({ open: true, message, severity })

  // ── Load certs ──────────────────────────────────────────────────────────────
  const load = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const params: { status?: string; host_id?: string } = {}
      if (statusFilter !== 'all') params.status = statusFilter
      if (hostFilter.trim()) params.host_id = hostFilter.trim()
      const res = await certsApi.list(params)
      setCerts(res.data)
    } catch {
      setError('Failed to load certificates')
    } finally {
      setLoading(false)
    }
  }, [statusFilter, hostFilter])

  useEffect(() => { load() }, [load])

  // ── Download Root CA ────────────────────────────────────────────────────────
  const handleDownloadRootCa = async () => {
    try {
      const res = await certsApi.downloadRootCa()
      downloadBlob(res.data as Blob, 'ca.crt')
    } catch {
      showSnack('Failed to download Root CA certificate', 'error')
    }
  }

  // ── Issue cert ──────────────────────────────────────────────────────────────
  const handleIssued = (cert: IssuedCert) => {
    setIssuedCert(cert)
    setKeyDialogOpen(true)
    void load()
  }

  // ── Renew cert ──────────────────────────────────────────────────────────────
  const handleRenew = async (certId: string) => {
    try {
      const res = await certsApi.renew(certId)
      setIssuedCert(res.data)
      setKeyDialogOpen(true)
      void load()
    } catch {
      showSnack('Failed to renew certificate', 'error')
    }
  }

  // ── Revoke cert ─────────────────────────────────────────────────────────────
  const handleRevoke = async (certId: string) => {
    if (!window.confirm('Revoke this certificate? This cannot be undone.')) return
    try {
      await certsApi.revoke(certId)
      showSnack('Certificate revoked', 'success')
      void load()
    } catch {
      showSnack('Failed to revoke certificate', 'error')
    }
  }

  // ── Render ──────────────────────────────────────────────────────────────────
  return (
    <Container maxWidth="xl" sx={{ mt: 3, mb: 6 }}>
      {/* Header */}
      <Toolbar disableGutters sx={{ mb: 3 }}>
        <SecurityIcon sx={{ mr: 1, color: 'primary.main' }} />
        <Typography variant="h5" fontWeight={700} sx={{ flexGrow: 1 }}>
          Certificate Management
        </Typography>
        {canWrite && (
          <Button
            variant="outlined"
            startIcon={<SecurityIcon />}
            onClick={() => setIssueOpen(true)}
            sx={{ mr: 1 }}
          >
            Issue Client Certificate
          </Button>
        )}
        <Tooltip title="Download Root CA">
          <Button
            variant="contained"
            startIcon={<DownloadIcon />}
            onClick={handleDownloadRootCa}
            sx={{ mr: 1 }}
          >
            Download Root CA
          </Button>
        </Tooltip>
        <Tooltip title="Refresh">
          <span>
            <IconButton onClick={load} disabled={loading}>
              {loading ? <CircularProgress size={20} /> : <RefreshIcon />}
            </IconButton>
          </span>
        </Tooltip>
      </Toolbar>

      {/* Error */}
      {error && (
        <Alert severity="error" sx={{ mb: 3 }}>
          {error}
        </Alert>
      )}

      {/* Filters */}
      <Box display="flex" gap={2} sx={{ mb: 3 }} flexWrap="wrap">
        <FormControl size="small" sx={{ minWidth: 160 }}>
          <InputLabel>Status</InputLabel>
          <Select
            label="Status"
            value={statusFilter}
            onChange={(e: SelectChangeEvent) => setStatusFilter(e.target.value)}
          >
            <MenuItem value="all">All</MenuItem>
            <MenuItem value="active">Active</MenuItem>
            <MenuItem value="revoked">Revoked</MenuItem>
            <MenuItem value="expired">Expired</MenuItem>
          </Select>
        </FormControl>
        <TextField
          size="small"
          label="Filter by Host ID"
          value={hostFilter}
          onChange={(e) => setHostFilter(e.target.value)}
          placeholder="UUID or partial…"
          sx={{ minWidth: 260 }}
        />
      </Box>

      {/* Table */}
      <Paper variant="outlined">
        {loading ? (
          <Box display="flex" justifyContent="center" py={6}>
            <CircularProgress />
          </Box>
        ) : certs.length === 0 ? (
          <Box p={4}>
            <Alert severity="info">No certificates found.</Alert>
          </Box>
        ) : (
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>Common Name</TableCell>
                <TableCell>Serial Number</TableCell>
                <TableCell>Status</TableCell>
                <TableCell>Issued At</TableCell>
                <TableCell>Expires At</TableCell>
                <TableCell>Host</TableCell>
                <TableCell align="right">Actions</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {Object.values(
                certs.reduce((acc, cert) => {
                  const groupKey = `${cert.host_id || 'unassigned'}-${cert.status}`
                  if (!acc[groupKey]) acc[groupKey] = []
                  acc[groupKey].push(cert)
                  return acc
                }, {} as Record<string, Certificate[]>)
              ).map((group) => {
                const primary = group[0]
                const isPair = group.length > 1
                const expiring = primary.status === 'active' && isExpiringSoon(primary.expires_at)
                return (
                  <TableRow key={primary.id} hover>
                    <TableCell>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        <Typography variant="body2" fontWeight={500}>
                          {primary.common_name}
                        </Typography>
                        {isPair && <Chip label={`${group.length} items`} size="small" color="secondary" variant="outlined" />}
                      </Box>
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2" sx={{ fontFamily: 'monospace', fontSize: 12 }}>
                        {primary.serial_number}
                      </Typography>
                    </TableCell>
                    <TableCell>{statusChip(primary.status)}</TableCell>
                    <TableCell>
                      <Typography variant="body2">{fmtDate(primary.issued_at)}</Typography>
                    </TableCell>
                    <TableCell>
                      <Typography
                        variant="body2"
                        sx={{ color: expiring ? 'error.main' : 'inherit', fontWeight: expiring ? 600 : 400 }}
                      >
                        {fmtDate(primary.expires_at)}
                        {expiring && ' ⚠️'}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2" sx={{ fontFamily: 'monospace', fontSize: 11 }}>
                        {primary.host_id ?? <em>Root CA</em>}
                      </Typography>
                    </TableCell>
                    <TableCell align="right">
                      {canWrite && (
                        <>
                          <Tooltip title={`Renew certificate ${isPair ? 'pair' : ''}`}>
                            <Button
                              size="small"
                              variant="outlined"
                              sx={{ mr: 1 }}
                              onClick={() => handleRenew(primary.id)}
                            >
                              Renew
                            </Button>
                          </Tooltip>
                          {primary.status === 'active' && (
                            <Tooltip title={`Revoke certificate ${isPair ? 'pair' : ''}`}>
                              <Button
                                size="small"
                                variant="outlined"
                                color="error"
                                onClick={() => handleRevoke(primary.id)}
                              >
                                Revoke
                              </Button>
                            </Tooltip>
                          )}
                        </>
                      )}
                    </TableCell>
                  </TableRow>
                )
              })}
            </TableBody>
          </Table>
        )}
      </Paper>

      {/* Issue Dialog */}
      <IssueDialog
        open={issueOpen}
        onClose={() => setIssueOpen(false)}
        onIssued={handleIssued}
      />

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
    </Container>
  )
}
