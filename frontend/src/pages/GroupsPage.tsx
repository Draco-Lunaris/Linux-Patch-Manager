import { useEffect, useState } from 'react'
import {
  Box, Button, CircularProgress, Container, Dialog, DialogActions,
  DialogContent, DialogTitle, IconButton, Paper, Table, TableBody,
  TableCell, TableContainer, TableHead, TableRow, TextField, Toolbar, Tooltip, Typography,
} from '@mui/material'
import { Add as AddIcon, Delete as DeleteIcon } from '@mui/icons-material'
import { apiClient } from '../api/client'
import { useAuthStore } from '../store/authStore'
import type { Group } from '../types'

export default function GroupsPage() {
  const user = useAuthStore(state => state.user)
  const canWrite = user?.role === 'admin' || user?.role === 'operator'
  const [groups, setGroups] = useState<Group[]>([])
  const [loading, setLoading] = useState(true)
  const [open, setOpen] = useState(false)
  const [name, setName] = useState('')
  const [desc, setDesc] = useState('')

  const load = async () => {
    setLoading(true)
    try { const r = await apiClient.get('/groups'); setGroups(r.data) }
    finally { setLoading(false) }
  }

  useEffect(() => { load() }, [])

  const handleCreate = async () => {
    await apiClient.post('/groups', { name, description: desc })
    setOpen(false); setName(''); setDesc('')
    load()
  }

  const handleDelete = async (id: string) => {
    if (!confirm('Delete this group?')) return
    await apiClient.delete(`/groups/${id}`)
    load()
  }

  return (
    <Container maxWidth="lg" sx={{ mt: 3 }}>
      <Toolbar disableGutters sx={{ mb: 2 }}>
        <Typography variant="h5" fontWeight={700} sx={{ flexGrow: 1 }}>Groups</Typography>
        {canWrite && <Button variant="contained" startIcon={<AddIcon />} onClick={() => setOpen(true)}>Create Group</Button>}
      </Toolbar>
      {loading ? <Box display="flex" justifyContent="center" mt={4}><CircularProgress /></Box> : (
        <TableContainer component={Paper}>
          <Table size="small">
            <TableHead><TableRow>
              <TableCell>Name</TableCell><TableCell>Description</TableCell><TableCell>Created</TableCell>{canWrite && <TableCell>Actions</TableCell>}
            </TableRow></TableHead>
            <TableBody>
              {groups.map(g => (
                <TableRow key={g.id} hover>
                  <TableCell sx={{ fontWeight: 600 }}>{g.name}</TableCell>
                  <TableCell>{g.description || '—'}</TableCell>
                  <TableCell>{new Date(g.created_at).toLocaleDateString()}</TableCell>
                  {canWrite && <TableCell>
                    <Tooltip title="Delete"><IconButton size="small" color="error" onClick={() => handleDelete(g.id)}><DeleteIcon fontSize="small" /></IconButton></Tooltip>
                  </TableCell>}
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </TableContainer>
      )}
      <Dialog open={open} onClose={() => setOpen(false)} maxWidth="xs" fullWidth>
        <DialogTitle>Create Group</DialogTitle>
        <DialogContent>
          <TextField fullWidth label="Name" value={name} onChange={e => setName(e.target.value)} margin="normal" required />
          <TextField fullWidth label="Description" value={desc} onChange={e => setDesc(e.target.value)} margin="normal" />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setOpen(false)}>Cancel</Button>
          <Button variant="contained" onClick={handleCreate} disabled={!name}>Create</Button>
        </DialogActions>
      </Dialog>
    </Container>
  )
}
