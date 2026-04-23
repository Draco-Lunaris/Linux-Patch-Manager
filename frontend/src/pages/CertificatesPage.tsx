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
  onClose: () => void
}

function KeyDisplayDialog({ open, cert, onClose }: KeyDisplayDialogProps) {
  const [copied, setCopied] = useState(false)

  const handleCopy = async () => {
    if (!cert?.key_pem) return
    await navigator.clipboard.writeText(cert.key_pem)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
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
          <Box>
            <Typography variant="caption" color="text.secondary">
              Serial: {cert.serial_number} &nbsp;|&nbsp; Expires: {fmtDate(cert.expires_at)}
            </Typography>
            <Box
              component="pre"
              sx={{
                mt: 1,
                p: 2,
                bgcolor: 'grey.100',
                borderRadius: 1,
                fontSize: 12,
                overflow: 'auto',
                maxHeight: 320,
                fontFamily: 'monospace',
                whiteSpace: 'pre-wrap',
                wordBreak: 'break-all',
              }}
            >
              {cert.key_pem}
            </Box>
          </Box>
        )}
      </DialogContent>
      <DialogActions>
        <Tooltip title={copied ? 'Copied!' : 'Copy private key to clipboard'}>
          <Button startIcon={<CopyIcon />} onClick={handleCopy} variant="outlined">
            {copied ? 'Copied!' : 'Copy Key'}
          </Button>
        </Tooltip>
        <Button variant="contained" onClick={onClose}>I Have Saved the Key</Button>
      </DialogActions>
    </Dialog>
  )
}

// ── Main Page ─────────────────────────────────────────────────────────────────

export default function CertificatesPage() {
  const user = useAuthStore((s) => s.user)
  const isAdmin = user?.role === 'admin'

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
        {isAdmin && (
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
              {certs.map((cert) => {
                const expiring = cert.status === 'active' && isExpiringSoon(cert.expires_at)
                return (
                  <TableRow key={cert.id} hover>
                    <TableCell>
                      <Typography variant="body2" fontWeight={500}>
                        {cert.common_name}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2" sx={{ fontFamily: 'monospace', fontSize: 12 }}>
                        {cert.serial_number}
                      </Typography>
                    </TableCell>
                    <TableCell>{statusChip(cert.status)}</TableCell>
                    <TableCell>
                      <Typography variant="body2">{fmtDate(cert.issued_at)}</Typography>
                    </TableCell>
                    <TableCell>
                      <Typography
                        variant="body2"
                        sx={{ color: expiring ? 'error.main' : 'inherit', fontWeight: expiring ? 600 : 400 }}
                      >
                        {fmtDate(cert.expires_at)}
                        {expiring && ' ⚠️'}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Typography variant="body2" sx={{ fontFamily: 'monospace', fontSize: 11 }}>
                        {cert.host_id ?? <em>Root CA</em>}
                      </Typography>
                    </TableCell>
                    <TableCell align="right">
                      {isAdmin && (
                        <>
                          <Tooltip title="Renew certificate">
                            <Button
                              size="small"
                              variant="outlined"
                              sx={{ mr: 1 }}
                              onClick={() => handleRenew(cert.id)}
                            >
                              Renew
                            </Button>
                          </Tooltip>
                          {cert.status === 'active' && (
                            <Tooltip title="Revoke certificate">
                              <Button
                                size="small"
                                variant="outlined"
                                color="error"
                                onClick={() => handleRevoke(cert.id)}
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
