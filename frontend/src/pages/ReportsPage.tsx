import { useEffect, useState } from 'react'
import {
  Alert,
  Box,
  Button,
  Chip,
  CircularProgress,
  Container,
  Divider,
  FormControl,
  FormHelperText,
  Grid,
  InputLabel,
  MenuItem,
  Paper,
  Select,
  Snackbar,
  TextField,
  Toolbar,
  Typography,
} from '@mui/material'
import DescriptionIcon from '@mui/icons-material/Description'
import PictureAsPdfIcon from '@mui/icons-material/PictureAsPdf'
import VerifiedUserIcon from '@mui/icons-material/VerifiedUser'
import { reportsApi, settingsApi, apiClient } from '../api/client'
import type { ReportType, ReportFormat, AuditIntegrityResult, Group } from '../types'

// ── Report metadata ───────────────────────────────────────────────────────────

const REPORT_INFO: Record<ReportType, { title: string; description: string; columns: string[] }> = {
  compliance: {
    title: 'Compliance Report',
    description:
      'Shows patch compliance percentage per host and group. Includes total packages, pending patches, and last patch timestamp.',
    columns: [
      'Host',
      'FQDN',
      'Groups',
      'Total Packages',
      'Pending Patches',
      'Compliance %',
      'Last Patched',
      'Health Status',
    ],
  },
  'patch-history': {
    title: 'Patch History',
    description:
      'Full history of patch job operations across all hosts. Filter by date range to narrow results.',
    columns: [
      'Job ID',
      'Kind',
      'Status',
      'Host',
      'FQDN',
      'Package Count',
      'Started At',
      'Completed At',
      'Duration',
      'Operator',
    ],
  },
  vulnerability: {
    title: 'Vulnerability Exposure',
    description:
      'Lists all known CVEs affecting managed hosts based on cached patch data from agents.',
    columns: ['Host', 'FQDN', 'CVE ID', 'Package', 'Severity', 'Available Version', 'Last Seen'],
  },
  audit: {
    title: 'Audit Trail',
    description:
      'Complete tamper-evident audit log of all system actions. Limited to 10,000 most recent events.',
    columns: [
      'ID',
      'Timestamp',
      'Action',
      'Actor',
      'Target Type',
      'Target ID',
      'IP Address',
      'Request ID',
    ],
  },
}

// ── Default date helpers ──────────────────────────────────────────────────────

const defaultFromDate = () =>
  new Date(Date.now() - 30 * 24 * 60 * 60 * 1000).toISOString().split('T')[0]

const defaultToDate = () => new Date().toISOString().split('T')[0]

// ── Component ─────────────────────────────────────────────────────────────────

export default function ReportsPage() {
  const [reportType, setReportType] = useState<ReportType>('compliance')
  const [fromDate, setFromDate] = useState<string>(defaultFromDate())
  const [toDate, setToDate] = useState<string>(defaultToDate())
  const [groupId, setGroupId] = useState<string>('')
  const [groups, setGroups] = useState<Group[]>([])
  const [downloading, setDownloading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [verifyingIntegrity, setVerifyingIntegrity] = useState(false)
  const [integrityResult, setIntegrityResult] = useState<AuditIntegrityResult | null>(null)

  useEffect(() => {
    apiClient.get<Group[]>('/groups').then((res) => {
      setGroups(res.data)
    }).catch(() => {
      // Groups fetch is optional; silently ignore errors
    })
  }, [])

  const info = REPORT_INFO[reportType]

  const handleDownload = async (format: ReportFormat) => {
    setDownloading(true)
    setError(null)
    try {
      const params: Record<string, string> = {}
      if (fromDate) params.from = new Date(fromDate).toISOString()
      if (toDate) params.to = new Date(toDate + 'T23:59:59Z').toISOString()
      if (reportType === 'compliance' && groupId) params.group_id = groupId

      const res = await reportsApi.download(reportType, format, params)

      // Trigger browser download
      const url = window.URL.createObjectURL(new Blob([res.data]))
      const link = document.createElement('a')
      link.href = url
      const ext = format === 'pdf' ? 'pdf' : 'csv'
      const dateStr = new Date().toISOString().split('T')[0]
      link.setAttribute('download', `${reportType}-report-${dateStr}.${ext}`)
      document.body.appendChild(link)
      link.click()
      link.remove()
      window.URL.revokeObjectURL(url)
    } catch {
      setError('Failed to generate report. Please try again.')
    } finally {
      setDownloading(false)
    }
  }

  const handleVerifyIntegrity = async () => {
    setVerifyingIntegrity(true)
    setIntegrityResult(null)
    try {
      const { data } = await settingsApi.auditIntegrity()
      setIntegrityResult(data)
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Verification failed'
      setIntegrityResult({ intact: false, rows_checked: 0, errors: [{ row_id: 0, expected_hash: '', actual_hash: msg }] })
    } finally {
      setVerifyingIntegrity(false)
    }
  }

  return (
    <Container maxWidth="xl" sx={{ mt: 3 }}>
      {/* ── Page header ── */}
      <Toolbar disableGutters sx={{ mb: 3 }}>
        <Typography variant="h5" fontWeight={700}>
          Reports
        </Typography>
      </Toolbar>

      <Grid container spacing={3}>
        {/* ── Controls card ── */}
        <Grid size={{ xs: 12, md: 4 }}>
          <Paper variant="outlined" sx={{ p: 3 }}>
            <Typography variant="subtitle1" fontWeight={600} sx={{ mb: 2 }}>
              Report Options
            </Typography>

            {/* Report Type */}
            <FormControl fullWidth sx={{ mb: 2 }}>
              <InputLabel id="report-type-label">Report Type</InputLabel>
              <Select
                labelId="report-type-label"
                value={reportType}
                label="Report Type"
                onChange={(e) => setReportType(e.target.value as ReportType)}
              >
                <MenuItem value="compliance">Compliance Report</MenuItem>
                <MenuItem value="patch-history">Patch History</MenuItem>
                <MenuItem value="vulnerability">Vulnerability Exposure</MenuItem>
                <MenuItem value="audit">Audit Trail</MenuItem>
              </Select>
            </FormControl>

            {/* Date Range */}
            <Box sx={{ display: 'flex', gap: 1.5, mb: 2 }}>
              <TextField
                label="From"
                type="date"
                value={fromDate}
                onChange={(e) => setFromDate(e.target.value)}
                InputLabelProps={{ shrink: true }}
                fullWidth
              />
              <TextField
                label="To"
                type="date"
                value={toDate}
                onChange={(e) => setToDate(e.target.value)}
                InputLabelProps={{ shrink: true }}
                fullWidth
              />
            </Box>

            {/* Group Filter — compliance only */}
            {reportType === 'compliance' && (
              <FormControl fullWidth sx={{ mb: 2 }}>
                <InputLabel id="group-filter-label">Group (optional)</InputLabel>
                <Select
                  labelId="group-filter-label"
                  value={groupId}
                  label="Group (optional)"
                  onChange={(e) => setGroupId(e.target.value)}
                >
                  <MenuItem value="">All Groups</MenuItem>
                  {groups.map((g) => (
                    <MenuItem key={g.id} value={g.id}>
                      {g.name}
                    </MenuItem>
                  ))}
                </Select>
                <FormHelperText>Filter compliance report by a specific group</FormHelperText>
              </FormControl>
            )}

            <Divider sx={{ my: 2 }} />

            {/* Download buttons */}
            <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
              <Button
                variant="contained"
                fullWidth
                startIcon={
                  downloading ? <CircularProgress size={20} color="inherit" /> : <DescriptionIcon />
                }
                onClick={() => handleDownload('csv')}
                disabled={downloading}
              >
                Download CSV
              </Button>
              <Button
                variant="outlined"
                fullWidth
                startIcon={
                  downloading ? <CircularProgress size={20} color="inherit" /> : <PictureAsPdfIcon />
                }
                onClick={() => handleDownload('pdf')}
                disabled={downloading}
              >
                Download PDF
              </Button>
            </Box>
          </Paper>

          {/* ── Audit Integrity card ── */}
          <Paper variant="outlined" sx={{ p: 3, mt: 3 }}>
            <Typography variant="subtitle1" fontWeight={600} sx={{ mb: 1 }}>
              Audit Integrity Verification
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
              Verify the audit log hash chain has not been tampered with. Each entry is cryptographically linked to the previous one.
            </Typography>
            <Button
              variant="outlined"
              fullWidth
              startIcon={verifyingIntegrity ? <CircularProgress size={20} /> : <VerifiedUserIcon />}
              onClick={handleVerifyIntegrity}
              disabled={verifyingIntegrity}
            >
              Verify Integrity
            </Button>
            {integrityResult && (
              <Alert severity={integrityResult.intact ? 'success' : 'error'} sx={{ mt: 2 }}>
                {integrityResult.intact
                  ? `✓ Chain intact — ${integrityResult.rows_checked} rows verified`
                  : `✗ Chain compromised! ${integrityResult.errors.length} error(s) in ${integrityResult.rows_checked} rows`}
                {integrityResult.errors.length > 0 && (
                  <Box sx={{ mt: 1 }}>
                    {integrityResult.errors.slice(0, 5).map((e, i) => (
                      <Typography key={i} variant="body2">
                        Row {e.row_id}: expected {e.expected_hash.substring(0, 16)}… got {e.actual_hash.substring(0, 16)}…
                      </Typography>
                    ))}
                    {integrityResult.errors.length > 5 && (
                      <Typography variant="body2">…and {integrityResult.errors.length - 5} more</Typography>
                    )}
                  </Box>
                )}
              </Alert>
            )}
          </Paper>
        </Grid>

        {/* ── Info card ── */}
        <Grid size={{ xs: 12, md: 8 }}>
          <Paper variant="outlined" sx={{ p: 3 }}>
            <Typography variant="h6" fontWeight={600} sx={{ mb: 1 }}>
              {info.title}
            </Typography>
            <Typography variant="body2" color="text.secondary" sx={{ mb: 2 }}>
              {info.description}
            </Typography>

            <Typography variant="subtitle2" fontWeight={600}>
              Columns in this report:
            </Typography>
            <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.5, mt: 1 }}>
              {info.columns.map((col) => (
                <Chip key={col} label={col} size="small" />
              ))}
            </Box>

            <Divider sx={{ my: 2 }} />

            <Typography variant="body2" sx={{ mb: 0.5 }}>
              📊 PDF includes bar charts for compliance and patch history reports.
            </Typography>
            <Typography variant="body2">
              📁 CSV is suitable for import into Excel or Google Sheets.
            </Typography>
          </Paper>
        </Grid>
      </Grid>

      {/* ── Error snackbar ── */}
      <Snackbar
        open={!!error}
        autoHideDuration={6000}
        onClose={() => setError(null)}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'center' }}
      >
        <Alert severity="error" onClose={() => setError(null)} sx={{ width: '100%' }}>
          {error}
        </Alert>
      </Snackbar>
    </Container>
  )
}
