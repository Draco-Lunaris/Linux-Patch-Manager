import { useEffect, useState } from 'react'
import {
  Box, Button, Chip, CircularProgress, Container, Dialog, DialogActions,
  DialogContent, DialogTitle, IconButton, MenuItem, Paper, Select, Table,
  TableBody, TableCell, TableContainer, TableHead, TableRow, TextField, Toolbar, Tooltip, Typography,
} from '@mui/material'
import { Add as AddIcon, Lock as LockIcon } from '@mui/icons-material'
import { apiClient } from '../api/client'
import type { User } from '../types'

export default function UsersPage() {
  const [users, setUsers] = useState<User[]>([])
  const [loading, setLoading] = useState(true)
  const [open, setOpen] = useState(false)
  const [form, setForm] = useState({ username: '', email: '', role: 'operator', password: '' })

  const load = async () => {
    setLoading(true)
    try { const r = await apiClient.get('/users'); setUsers(r.data) }
    finally { setLoading(false) }
  }

  useEffect(() => { load() }, [])

  const handleCreate = async () => {
    await apiClient.post('/users', form)
    setOpen(false); setForm({ username: '', email: '', role: 'operator', password: '' })
    load()
  }

  return (
    <Container maxWidth="lg" sx={{ mt: 3 }}>
      <Toolbar disableGutters sx={{ mb: 2 }}>
        <Typography variant="h5" fontWeight={700} sx={{ flexGrow: 1 }}>Users</Typography>
        <Button variant="contained" startIcon={<AddIcon />} onClick={() => setOpen(true)}>Add User</Button>
      </Toolbar>
      {loading ? <Box display="flex" justifyContent="center" mt={4}><CircularProgress /></Box> : (
        <TableContainer component={Paper}>
          <Table size="small">
            <TableHead><TableRow>
              <TableCell>Username</TableCell><TableCell>Email</TableCell>
              <TableCell>Role</TableCell><TableCell>MFA</TableCell>
              <TableCell>Status</TableCell><TableCell>Actions</TableCell>
            </TableRow></TableHead>
            <TableBody>
              {users.map(u => (
                <TableRow key={u.id} hover>
                  <TableCell>{u.username}</TableCell>
                  <TableCell>{u.email}</TableCell>
                  <TableCell><Chip size="small" label={u.role} color={u.role === 'admin' ? 'primary' : 'default'} /></TableCell>
                  <TableCell><Chip size="small" label={u.mfa_enabled ? 'On' : 'Off'} color={u.mfa_enabled ? 'success' : 'warning'} /></TableCell>
                  <TableCell><Chip size="small" label={u.is_active ? 'Active' : 'Disabled'} color={u.is_active ? 'success' : 'error'} /></TableCell>
                  <TableCell>
                    <Tooltip title="Revoke Sessions"><IconButton size="small" color="warning" onClick={() => apiClient.post(`/users/${u.id}/revoke`)}><LockIcon fontSize="small" /></IconButton></Tooltip>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      )}
      <Dialog open={open} onClose={() => setOpen(false)} maxWidth="xs" fullWidth>
        <DialogTitle>Add User</DialogTitle>
        <DialogContent>
          <TextField fullWidth label="Username" value={form.username} onChange={e => setForm({...form, username: e.target.value})}
