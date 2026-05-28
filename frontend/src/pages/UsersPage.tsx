import { useEffect, useState, useMemo } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Box, Button, Chip, CircularProgress, Container, Dialog, DialogActions,
  DialogContent, DialogContentText, DialogTitle, FormControlLabel, IconButton,
  MenuItem, Paper, Select, Switch, Table, TableBody, TableCell,
  TableContainer, TableHead, TableRow, TextField, Toolbar, Tooltip, Typography,
  Snackbar, Alert, InputAdornment, FormControl, InputLabel,
  List, ListItem, ListItemIcon, ListItemText,
} from '@mui/material'
import {
  Add as AddIcon, Lock as LockIcon, Edit as EditIcon,
  VpnKey as VpnKeyIcon, Delete as DeleteIcon, Search as SearchIcon,
  Check as CheckIcon, Close as CloseIcon,
} from '@mui/icons-material'
import { usersApi } from '../api/client'
import { useAuthStore } from '../store/authStore'
import type { User, UpdateUserRequest, AdminResetPasswordRequest } from '../types'

/** Password strength checker */
function checkPasswordStrength(password: string) {
  return {
    length: password.length >= 8,
    uppercase: /[A-Z]/.test(password),
    lowercase: /[a-z]/.test(password),
    digit: /[0-9]/.test(password),
    special: /[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]/.test(password),
  }
}

function isPasswordValid(checks: ReturnType<typeof checkPasswordStrength>) {
  return checks.length && checks.uppercase && checks.lowercase && checks.digit && checks.special
}

/** Reusable password strength checklist component */
function PasswordStrengthIndicator({ password }: { password: string }) {
  if (!password) return null
  const checks = checkPasswordStrength(password)
  return (
    <Box sx={{ mt: 0.5, mb: 1 }}>
      <List dense disablePadding>
        <ListItem disableGutters sx={{ py: 0 }}>
          <ListItemIcon sx={{ minWidth: 28 }}>
            {checks.length ? <CheckIcon color="success" fontSize="small" /> : <CloseIcon color="error" fontSize="small" />}
          </ListItemIcon>
          <ListItemText primary="At least 8 characters" primaryTypographyProps={{ variant: 'caption' }} />
        </ListItem>
        <ListItem disableGutters sx={{ py: 0 }}>
          <ListItemIcon sx={{ minWidth: 28 }}>
            {checks.uppercase ? <CheckIcon color="success" fontSize="small" /> : <CloseIcon color="error" fontSize="small" />}
          </ListItemIcon>
          <ListItemText primary="At least one uppercase letter" primaryTypographyProps={{ variant: 'caption' }} />
        </ListItem>
        <ListItem disableGutters sx={{ py: 0 }}>
          <ListItemIcon sx={{ minWidth: 28 }}>
            {checks.lowercase ? <CheckIcon color="success" fontSize="small" /> : <CloseIcon color="error" fontSize="small" />}
          </ListItemIcon>
          <ListItemText primary="At least one lowercase letter" primaryTypographyProps={{ variant: 'caption' }} />
        </ListItem>
        <ListItem disableGutters sx={{ py: 0 }}>
          <ListItemIcon sx={{ minWidth: 28 }}>
            {checks.digit ? <CheckIcon color="success" fontSize="small" /> : <CloseIcon color="error" fontSize="small" />}
          </ListItemIcon>
          <ListItemText primary="At least one digit" primaryTypographyProps={{ variant: 'caption' }} />
        </ListItem>
        <ListItem disableGutters sx={{ py: 0 }}>
          <ListItemIcon sx={{ minWidth: 28 }}>
            {checks.special ? <CheckIcon color="success" fontSize="small" /> : <CloseIcon color="error" fontSize="small" />}
          </ListItemIcon>
          <ListItemText primary="At least one special character" primaryTypographyProps={{ variant: 'caption' }} />
        </ListItem>
      </List>
    </Box>
  )
}

export default function UsersPage() {
  const currentUser = useAuthStore(s => s.user)
  const navigate = useNavigate()
  const isAdmin = currentUser?.role === 'admin'

  const [users, setUsers] = useState<User[]>([])
  const [loading, setLoading] = useState(true)

  // Snackbar
  const [snack, setSnack] = useState<{ open: boolean; severity: 'success' | 'error'; message: string }>({
    open: false, severity: 'success', message: '',
  })
  const showSnack = (severity: 'success' | 'error', message: string) =>
    setSnack({ open: true, severity, message })

  // Search / filter
  const [searchText, setSearchText] = useState('')
  const [roleFilter, setRoleFilter] = useState('all')

  // Add User dialog
  const [addOpen, setAddOpen] = useState(false)
  const [addForm, setAddForm] = useState({ username: '', display_name: '', email: '', role: 'operator', password: '' })

  // Edit User dialog
  const [editOpen, setEditOpen] = useState(false)
  const [editUser, setEditUser] = useState<User | null>(null)
  const [editForm, setEditForm] = useState<UpdateUserRequest & { display_name: string; email: string; role: string; is_active: boolean; force_password_reset: boolean }>({
    display_name: '', email: '', role: 'operator', is_active: true, force_password_reset: false,
  })

  // Password Reset dialog
  const [resetOpen, setResetOpen] = useState(false)
  const [resetUser, setResetUser] = useState<User | null>(null)
  const [resetForm, setResetForm] = useState({ new_password: '', confirm_password: '', force_password_reset: true })

  // MFA Disable confirmation dialog
  const [mfaConfirmOpen, setMfaConfirmOpen] = useState(false)
  const [mfaDisableUser, setMfaDisableUser] = useState<User | null>(null)

  // Delete confirmation dialog
  const [deleteOpen, setDeleteOpen] = useState(false)
  const [deleteUser, setDeleteUser] = useState<User | null>(null)

  const addPwValid = isPasswordValid(checkPasswordStrength(addForm.password))
  const resetPwValid = isPasswordValid(checkPasswordStrength(resetForm.new_password))
  const resetPwMismatch = !!(resetForm.confirm_password && resetForm.new_password !== resetForm.confirm_password)

  const load = async () => {
    setLoading(true)
    try {
      const r = await usersApi.list()
      setUsers(r.data)
    } catch {
      showSnack('error', 'Failed to load users')
    } finally {
      setLoading(false)
    }
  }

  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(() => { load() }, [])

  // Filtered users
  const filteredUsers = useMemo(() => {
    let list = users
    if (roleFilter !== 'all') {
      list = list.filter(u => u.role === roleFilter)
    }
    if (searchText.trim()) {
      const q = searchText.toLowerCase()
      list = list.filter(u =>
        u.username.toLowerCase().includes(q) ||
        u.display_name.toLowerCase().includes(q) ||
        u.email.toLowerCase().includes(q)
      )
    }
    return list
  }, [users, roleFilter, searchText])

  // ── Handlers ────────────────────────────────────────────────────────────────

  const handleCreate = async () => {
    if (!addPwValid) {
      showSnack('error', 'Password does not meet strength requirements')
      return
    }
    try {
      await usersApi.create(addForm)
      setAddOpen(false)
      setAddForm({ username: '', display_name: '', email: '', role: 'operator', password: '' })
      showSnack('success', 'User created successfully')
      load()
    } catch {
      showSnack('error', 'Failed to create user')
    }
  }

  const handleRevoke = async (id: string) => {
    try {
      await usersApi.revokeSessions(id)
      showSnack('success', 'Sessions revoked')
    } catch {
      showSnack('error', 'Failed to revoke sessions')
    }
  }

  const openEdit = (u: User) => {
    setEditUser(u)
    setEditForm({
      display_name: u.display_name || '',
      email: u.email || '',
      role: u.role,
      is_active: u.is_active,
      force_password_reset: u.force_password_reset,
    })
    setEditOpen(true)
  }

  const handleEditSave = async () => {
    if (!editUser) return
    try {
      await usersApi.update(editUser.id, editForm)
      setEditOpen(false)
      showSnack('success', 'User updated successfully')
      load()
    } catch {
      showSnack('error', 'Failed to update user')
    }
  }

  const openReset = (u: User) => {
    setResetUser(u)
    setResetForm({ new_password: '', confirm_password: '', force_password_reset: true })
    setResetOpen(true)
  }

  const handleResetSave = async () => {
    if (!resetUser) return
    if (resetPwMismatch) {
      showSnack('error', 'Passwords do not match')
      return
    }
    if (!resetPwValid) {
      showSnack('error', 'Password does not meet strength requirements')
      return
    }
    try {
      const data: AdminResetPasswordRequest = {
        new_password: resetForm.new_password,
        force_password_reset: resetForm.force_password_reset,
      }
      await usersApi.adminResetPassword(resetUser.id, data)
      setResetOpen(false)
      showSnack('success', 'Password reset successfully')
    } catch {
      showSnack('error', 'Failed to reset password')
    }
  }

  const handleMfaDisable = (u: User) => {
    setMfaDisableUser(u)
    setMfaConfirmOpen(true)
  }

  const handleMfaDisableConfirm = async () => {
    if (!mfaDisableUser) return
    try {
      await usersApi.adminDisableMfa(mfaDisableUser.id)
      setMfaConfirmOpen(false)
      showSnack('success', 'MFA disabled successfully')
      load()
    } catch {
      showSnack('error', 'Failed to disable MFA')
    }
  }

  const openDelete = (u: User) => {
    setDeleteUser(u)
    setDeleteOpen(true)
  }

  const handleDeleteConfirm = async () => {
    if (!deleteUser) return
    try {
      await usersApi.delete(deleteUser.id)
      setDeleteOpen(false)
      showSnack('success', 'User deleted successfully')
      load()
    } catch {
      showSnack('error', 'Failed to delete user')
    }
  }

  // ── Render ─────────────────────────────────────────────────────────────────

  return (
    <Container maxWidth="lg" sx={{ mt: 3 }}>
      <Toolbar disableGutters sx={{ mb: 2 }}>
        <Typography variant="h5" fontWeight={700} sx={{ flexGrow: 1 }}>Users</Typography>
        {isAdmin && (
          <Button variant="contained" startIcon={<AddIcon />} onClick={() => setAddOpen(true)}>Add User</Button>
        )}
      </Toolbar>

      {/* Search / Filter bar */}
      <Box sx={{ display: 'flex', gap: 2, mb: 2 }}>
        <TextField
          size="small"
          placeholder="Search by username, name, or email…"
          value={searchText}
          onChange={e => setSearchText(e.target.value)}
          InputProps={{
            startAdornment: (
              <InputAdornment position="start"><SearchIcon fontSize="small" /></InputAdornment>
            ),
          }}
          sx={{ flexGrow: 1 }}
        />
        <FormControl size="small" sx={{ minWidth: 120 }}>
          <InputLabel>Role</InputLabel>
          <Select value={roleFilter} label="Role" onChange={e => setRoleFilter(e.target.value)}>
            <MenuItem value="all">All</MenuItem>
            <MenuItem value="admin">Admin</MenuItem>
            <MenuItem value="operator">Operator</MenuItem>
            <MenuItem value="reporter">Reporter</MenuItem>
          </Select>
        </FormControl>
      </Box>

      {loading ? (
        <Box display="flex" justifyContent="center" mt={4}><CircularProgress /></Box>
      ) : (
        <TableContainer component={Paper}>
          <Table size="small">
            <TableHead>
              <TableRow>
                <TableCell>Username</TableCell>
                <TableCell>Display Name</TableCell>
                <TableCell>Email</TableCell>
                <TableCell>Role</TableCell>
                <TableCell>MFA</TableCell>
                <TableCell>Status</TableCell>
                <TableCell>Actions</TableCell>
              </TableRow>
            </TableHead>
            <TableBody>
              {filteredUsers.map(u => (
                <TableRow key={u.id} hover>
                  <TableCell>{u.username}</TableCell>
                  <TableCell>{u.display_name}</TableCell>
                  <TableCell>{u.email}</TableCell>
                  <TableCell>
                    <Chip size="small" label={u.role}
                      color={u.role === 'admin' ? 'primary' : 'default'} />
                  </TableCell>
                  <TableCell>
                    {u.mfa_enabled ? (
                      <Chip size="small" label="On" color="success" />
                    ) : currentUser?.id === u.id ? (
                      <Tooltip title="Enable MFA">
                        <Chip size="small" label="Off" color="warning"
                          sx={{ cursor: 'pointer', '&:hover': { opacity: 0.8 } }}
                          onClick={() => navigate('/mfa/setup')} />
                      </Tooltip>
                    ) : (
                      <Chip size="small" label="Off" color="default" />
                    )}
                  </TableCell>
                  <TableCell>
                    <Chip size="small" label={u.is_active ? 'Active' : 'Disabled'}
                      color={u.is_active ? 'success' : 'error'} />
                  </TableCell>
                  <TableCell>
                    <Tooltip title="Edit User">
                      <IconButton size="small" color="primary" onClick={() => openEdit(u)}>
                        <EditIcon fontSize="small" />
                      </IconButton>
                    </Tooltip>
                    {isAdmin && (
                      <Tooltip title="Reset Password">
                        <IconButton size="small" color="warning" onClick={() => openReset(u)}>
                          <VpnKeyIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                    )}
                    <Tooltip title="Revoke All Sessions">
                      <IconButton size="small" color="warning" onClick={() => handleRevoke(u.id)}>
                        <LockIcon fontSize="small" />
                      </IconButton>
                    </Tooltip>
                    {isAdmin && (
                      <Tooltip title="Delete User">
                        <IconButton size="small" color="error" onClick={() => openDelete(u)}>
                          <DeleteIcon fontSize="small" />
                        </IconButton>
                      </Tooltip>
                    )}
                  </TableCell>
                </TableRow>
              ))}
              {filteredUsers.length === 0 && (
                <TableRow>
                  <TableCell colSpan={7} align="center" sx={{ py: 3, color: 'text.secondary' }}>
                    No users found
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </TableContainer>
      )}

      {/* ── Add User Dialog ──────────────────────────────────────────────────── */}
      <Dialog open={addOpen} onClose={() => setAddOpen(false)} maxWidth="xs" fullWidth>
        <DialogTitle>Add User</DialogTitle>
        <DialogContent>
          <TextField fullWidth label="Username"
            value={addForm.username}
            onChange={e => setAddForm({ ...addForm, username: e.target.value })}
            margin="normal" required />
          <TextField fullWidth label="Display Name"
            value={addForm.display_name}
            onChange={e => setAddForm({ ...addForm, display_name: e.target.value })}
            margin="normal" />
          <TextField fullWidth label="Email" type="email"
            value={addForm.email}
            onChange={e => setAddForm({ ...addForm, email: e.target.value })}
            margin="normal" required />
          <TextField fullWidth label="Password" type="password"
            value={addForm.password}
            onChange={e => setAddForm({ ...addForm, password: e.target.value })}
            margin="normal" required />
          <PasswordStrengthIndicator password={addForm.password} />
          <FormControl fullWidth sx={{ mt: 2 }}>
            <InputLabel>Role</InputLabel>
            <Select value={addForm.role} label="Role"
              onChange={e => setAddForm({ ...addForm, role: e.target.value })}>
              <MenuItem value="operator">Operator</MenuItem>
              <MenuItem value="admin">Admin</MenuItem>
              <MenuItem value="reporter">Reporter</MenuItem>
            </Select>
          </FormControl>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setAddOpen(false)}>Cancel</Button>
          <Button variant="contained" onClick={handleCreate}
            disabled={!addForm.username || !addForm.email || !addForm.password || !addPwValid}>
            Create
          </Button>
        </DialogActions>
      </Dialog>

      {/* ── Edit User Dialog ──────────────────────────────────────────────────── */}
      <Dialog open={editOpen} onClose={() => setEditOpen(false)} maxWidth="xs" fullWidth>
        <DialogTitle>Edit User</DialogTitle>
        <DialogContent>
          <TextField fullWidth label="Username"
            value={editUser?.username ?? ''}
            margin="normal" slotProps={{ input: { readOnly: true } }}
            helperText="Username cannot be changed"
          />
          <TextField fullWidth label="Display Name"
            value={editForm.display_name}
            onChange={e => setEditForm({ ...editForm, display_name: e.target.value })}
            margin="normal" />
          <TextField fullWidth label="Email" type="email"
            value={editForm.email}
            onChange={e => setEditForm({ ...editForm, email: e.target.value })}
            margin="normal" />

          {isAdmin && (
            <>
              <FormControl fullWidth sx={{ mt: 2 }}>
                <InputLabel>Role</InputLabel>
                <Select value={editForm.role} label="Role"
                  onChange={e => setEditForm({ ...editForm, role: e.target.value })}>
                  <MenuItem value="operator">Operator</MenuItem>
                  <MenuItem value="admin">Admin</MenuItem>
                  <MenuItem value="reporter">Reporter</MenuItem>
                </Select>
              </FormControl>
              <Box sx={{ display: 'flex', alignItems: 'center', mt: 2 }}>
                <FormControlLabel
                  control={
                    <Switch checked={editForm.is_active}
                      onChange={e => setEditForm({ ...editForm, is_active: e.target.checked })} />
                  }
                  label="Active"
                />
              </Box>
              <Box sx={{ display: 'flex', alignItems: 'center' }}>
                <FormControlLabel
                  control={
                    <Switch checked={editForm.force_password_reset}
                      onChange={e => setEditForm({ ...editForm, force_password_reset: e.target.checked })} />
                  }
                  label="Force Password Reset"
                />
              </Box>

              {/* MFA status */}
              <Box sx={{ mt: 2, display: 'flex', alignItems: 'center', gap: 1 }}>
                <Typography variant="body2" color="text.secondary">MFA Status:</Typography>
                <Chip size="small"
                  label={editUser?.mfa_enabled ? 'Enabled' : 'Disabled'}
                  color={editUser?.mfa_enabled ? 'success' : 'default'}
                />
                {editUser?.mfa_enabled ? (
                  <Button size="small" color="error" variant="outlined"
                    onClick={() => editUser && handleMfaDisable(editUser)}>
                    Disable MFA
                  </Button>
                ) : (
                  currentUser?.id === editUser?.id ? (
                    <Button size="small" color="primary" variant="outlined"
                      onClick={() => navigate('/mfa/setup')}>
                      Enable MFA
                    </Button>
                  ) : (
                    <Typography variant="caption" color="text.secondary">
                      User must enable MFA from their own profile settings.
                    </Typography>
                  )
                )}
              </Box>
              {editUser?.mfa_enabled ? (
                <Typography variant="caption" color="warning.main" sx={{ display: 'block', mt: 0.5 }}>
                  Disabling MFA reduces account security for this user.
                </Typography>
              ) : (
                currentUser?.id === editUser?.id && (
                  <Typography variant="caption" color="info.main" sx={{ display: 'block', mt: 0.5 }}>
                    You will be guided through authenticator app setup.
                  </Typography>
                )
              )}
            </>
          )}
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setEditOpen(false)}>Cancel</Button>
          <Button variant="contained" onClick={handleEditSave}>Save</Button>
        </DialogActions>
      </Dialog>

      {/* ── Admin Password Reset Dialog ─────────────────────────────────────── */}
      <Dialog open={resetOpen} onClose={() => setResetOpen(false)} maxWidth="xs" fullWidth>
        <DialogTitle>Reset Password for {resetUser?.username}</DialogTitle>
        <DialogContent>
          <TextField fullWidth label="New Password" type="password"
            value={resetForm.new_password}
            onChange={e => setResetForm({ ...resetForm, new_password: e.target.value })}
            margin="normal" required
          />
          <PasswordStrengthIndicator password={resetForm.new_password} />
          <TextField fullWidth label="Confirm Password" type="password"
            value={resetForm.confirm_password}
            onChange={e => setResetForm({ ...resetForm, confirm_password: e.target.value })}
            margin="normal" required
            error={resetPwMismatch}
            helperText={resetPwMismatch ? 'Passwords do not match' : ''}
          />
          <FormControlLabel
            control={
              <Switch checked={resetForm.force_password_reset}
                onChange={e => setResetForm({ ...resetForm, force_password_reset: e.target.checked })} />
            }
            label="Force password reset on next login"
            sx={{ mt: 1 }}
          />
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setResetOpen(false)}>Cancel</Button>
          <Button variant="contained" color="warning" onClick={handleResetSave}
            disabled={
              !resetForm.new_password ||
              !resetPwValid ||
              resetPwMismatch
            }>
            Reset Password
          </Button>
        </DialogActions>
      </Dialog>

      {/* ── MFA Disable Confirmation Dialog ──────────────────────────────────── */}
      <Dialog open={mfaConfirmOpen} onClose={() => setMfaConfirmOpen(false)} maxWidth="xs" fullWidth>
        <DialogTitle>Disable MFA</DialogTitle>
        <DialogContent>
          <DialogContentText>
            Are you sure you want to disable MFA for user <strong>{mfaDisableUser?.username}</strong>?
            This will reduce the security of their account.
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setMfaConfirmOpen(false)}>Cancel</Button>
          <Button variant="contained" color="error" onClick={handleMfaDisableConfirm}>
            Disable MFA
          </Button>
        </DialogActions>
      </Dialog>

      {/* ── Delete Confirmation Dialog ────────────────────────────────────────── */}
      <Dialog open={deleteOpen} onClose={() => setDeleteOpen(false)} maxWidth="xs" fullWidth>
        <DialogTitle>Delete User</DialogTitle>
        <DialogContent>
          <DialogContentText>
            Are you sure you want to delete user <strong>{deleteUser?.username}</strong>?
            This action cannot be undone.
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setDeleteOpen(false)}>Cancel</Button>
          <Button variant="contained" color="error" onClick={handleDeleteConfirm}>
            Delete
          </Button>
        </DialogActions>
      </Dialog>

      {/* ── Snackbar ──────────────────────────────────────────────────────────── */}
      <Snackbar
        open={snack.open}
        autoHideDuration={4000}
        onClose={() => setSnack(s => ({ ...s, open: false }))}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'center' }}
      >
        <Alert
          onClose={() => setSnack(s => ({ ...s, open: false }))}
          severity={snack.severity}
          variant="filled"
          sx={{ width: '100%' }}
        >
          {snack.message}
        </Alert>
      </Snackbar>
    </Container>
  )
}
