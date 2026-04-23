import { useEffect, useState } from 'react'
import {
  Box, Button, Chip, CircularProgress, Container, IconButton,
  Paper, Table, TableBody, TableCell, TableContainer, TableHead,
  TableRow, TextField, Toolbar, Tooltip, Typography,
} from '@mui/material'
import { Add as AddIcon, Refresh as RefreshIcon, Delete as DeleteIcon } from '@mui/icons-material'
import { useNavigate } from 'react-router-dom'
import { apiClient } from '../api/client'
import type { Host, HostHealthStatus } from '../types'

const statusColor = (s: HostHealthStatus) =>
  s === 'healthy' ? 'success' : s === 'degraded' ? 'warning' : s === 'unreachable' ? 'error' : 'default'

export default function HostsPage() {
  const navigate = useNavigate()
  const [hosts, setHosts] = useState<Host[]>([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')

  const load = async () => {
    setLoading(true)
    try {
      const res = await apiClient.get('/hosts', { params: { limit: 100 } })
      setHosts(res.data.hosts)
      setTotal(res.data.total)
    } catch { /* handled by interceptor */ }
    finally { setLoading(false) }
  }

  useEffect(() => { load() }, [])

  const filtered = hosts.filter(h =>
    h.fqdn.toLowerCase().includes(search.toLowerCase()) ||
    h.display_name.toLowerCase().includes(search.toLowerCase())
  )

  return (
    <Container maxWidth="xl" sx={{ mt: 3 }}>
      <Toolbar disableGutters sx={{ mb: 2 }}>
        <Typography variant="h5" fontWeight={700} sx={{ flexGrow: 1 }}>Hosts</Typography>
        <TextField size="small" placeholder="Search..." value={search}
          onChange={e => setSearch(e.target.value)} sx={{ mr: 2 }} />
        <Tooltip title="Refresh"><IconButton onClick={load}><RefreshIcon /></IconButton></Tooltip>
        <Button variant="contained" startIcon={<AddIcon />} onClick={() => navigate('/hosts/new')} sx={{ ml: 1 }}>Add Host</Button>
      </Toolbar>
      {loading ? <Box display="flex" justifyContent="center" mt={4}><CircularProgress /></Box> : (
        <TableContainer component={Paper}>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>FQDN</TableCell>
                <TableCell>Display Name</TableCell>
                <TableCell>IP Address</TableCell>
                <TableCell>OS</TableCell>
                <TableCell>Health</TableCell>
                <TableCell>Agent</TableCell>
                <TableCell>Actions</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {filtered.map(h => (
                <TableRow key={h.id} hover sx={{ cursor: 'pointer' }}
                  onClick={() => navigate(`/hosts/${h.id}`)}>
                  <TableCell>{h.fqdn}</TableCell>
                  <TableCell>{h.display_name}</TableCell>
                  <TableCell>{h.ip_address}</TableCell>
                  <TableCell>{h.os_name ?? h.os_family ?? '—'}</TableCell>
                  <TableCell>
                    <Chip size="small" label={h.health_status} color={statusColor(h.health_status)} />
                  </TableCell>
                  <TableCell>{h.agent_version ?? '—'}</TableCell>
                  <TableCell onClick={e => e.stopPropagation()}>
                    <Tooltip title="Delete"><IconButton size="small" color="error">
                      <DeleteIcon fontSize="small" />
                    </IconButton></Tooltip>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      )}
      <Typography variant="caption" color="text.secondary" mt={1} display="block">
        Showing {filtered.length} of {total} hosts
      </Typography>
    </Container>
  )
}
