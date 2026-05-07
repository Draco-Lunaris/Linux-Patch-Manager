import { useState } from 'react'
import { Outlet, useNavigate, useLocation } from 'react-router-dom'
import {
  AppBar, Box, CssBaseline, Divider, Drawer, IconButton,
  List, ListItem, ListItemButton, ListItemIcon, ListItemText,
  Toolbar, Typography, Avatar, Menu, MenuItem, Tooltip,
} from '@mui/material'
import {
  Dashboard as DashboardIcon,
  Computer as HostsIcon,
  Group as GroupsIcon,
  Build as DeployIcon,
  Assignment as JobsIcon,
  Schedule as MaintenanceIcon,
  People as UsersIcon,
  VerifiedUser as CertsIcon,
  Assessment as ReportsIcon,
  Settings as SettingsIcon,
  Menu as MenuIcon,
  Logout as LogoutIcon,
  Person as PersonIcon,
} from '@mui/icons-material'
import { useAuthStore } from '../store/authStore'

const DRAWER_WIDTH = 240

interface NavItem {
  label: string
  path: string
  icon: React.ReactElement
  adminOnly?: boolean
}

const navGroups: { heading: string; items: NavItem[] }[] = [
  {
    heading: 'Overview',
    items: [
      { label: 'Dashboard', path: '/dashboard', icon: <DashboardIcon /> },
    ],
  },
  {
    heading: 'Fleet',
    items: [
      { label: 'Hosts', path: '/hosts', icon: <HostsIcon /> },
      { label: 'Groups', path: '/groups', icon: <GroupsIcon /> },
      { label: 'Deploy', path: '/deployment', icon: <DeployIcon /> },
    ],
  },
  {
    heading: 'Operations',
    items: [
      { label: 'Jobs', path: '/jobs', icon: <JobsIcon /> },
      { label: 'Maintenance', path: '/maintenance', icon: <MaintenanceIcon /> },
    ],
  },
  {
    heading: 'Administration',
    items: [
      { label: 'Users', path: '/users', icon: <UsersIcon />, adminOnly: true },
      { label: 'Certificates', path: '/certificates', icon: <CertsIcon />, adminOnly: true },
      { label: 'Reports', path: '/reports', icon: <ReportsIcon /> },
      { label: 'Settings', path: '/settings', icon: <SettingsIcon />, adminOnly: true },
    ],
  },
]

export default function AppLayout() {
  const navigate = useNavigate()
  const location = useLocation()
  const { user, logout } = useAuthStore()
  const [mobileOpen, setMobileOpen] = useState(false)
  const [anchorEl, setAnchorEl] = useState<null | HTMLElement>(null)

  const isAdmin = user?.role === 'admin'

  const handleDrawerToggle = () => setMobileOpen(!mobileOpen)
  const handleMenuOpen = (e: React.MouseEvent<HTMLElement>) => setAnchorEl(e.currentTarget)
  const handleMenuClose = () => setAnchorEl(null)

  const handleLogout = () => {
    handleMenuClose()
    logout()
    navigate('/login', { replace: true })
  }

  const drawer = (
    <Box sx={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
      <Toolbar sx={{ justifyContent: 'center', py: 1.5 }}>
        <Typography variant="h6" fontWeight={700} sx={{
          background: 'linear-gradient(135deg, #42A5F5 30%, #26C6DA 100%)',
          WebkitBackgroundClip: 'text',
          WebkitTextFillColor: 'transparent',
        }}>
          🐉 Patch Manager
        </Typography>
      </Toolbar>
      <Divider />
      <Box sx={{ flex: 1, overflowY: 'auto', py: 1 }}>
        {navGroups.map((group) => {
          const visibleItems = group.items.filter((item) => !item.adminOnly || isAdmin)
          if (visibleItems.length === 0) return null
          return (
            <Box key={group.heading} sx={{ mb: 1 }}>
              <Typography variant="caption" color="text.secondary" sx={{ px: 2.5, py: 0.5, fontWeight: 600, textTransform: 'uppercase', letterSpacing: 0.5 }}>
                {group.heading}
              </Typography>
              <List dense disablePadding>
                {visibleItems.map((item) => {
                  const isActive = location.pathname === item.path || location.pathname.startsWith(item.path + '/')
                  return (
                    <ListItem key={item.path} disablePadding sx={{ px: 1 }}>
                      <ListItemButton
                        selected={isActive}
                        onClick={() => navigate(item.path)}
                        sx={{
                          borderRadius: 1,
                          mx: 0.5,
                          '&.Mui-selected': {
                            bgcolor: 'primary.main',
                            color: 'primary.contrastText',
                            '&:hover': { bgcolor: 'primary.dark' },
                            '& .MuiListItemIcon-root': { color: 'primary.contrastText' },
                          },
                        }}
                      >
                        <ListItemIcon sx={{ minWidth: 36, color: isActive ? 'inherit' : 'text.secondary' }}>
                          {item.icon}
                        </ListItemIcon>
                        <ListItemText primary={item.label} primaryTypographyProps={{ fontWeight: isActive ? 600 : 400, fontSize: '0.875rem' }} />
                      </ListItemButton>
                    </ListItem>
                  )
                })}
              </List>
            </Box>
          )
        })}
      </Box>
      <Divider />
      <Box sx={{ p: 1.5 }}>
        <Typography variant="caption" color="text.secondary">
          Linux Patch Manager v0.1.0
        </Typography>
      </Box>
    </Box>
  )

  return (
    <Box sx={{ display: 'flex', height: '100vh' }}>
      <CssBaseline />

      {/* App Bar */}
      <AppBar
        position="fixed"
        elevation={0}
        sx={{
          zIndex: (theme) => theme.zIndex.drawer + 1,
          borderBottom: 1,
          borderColor: 'divider',
        }}
      >
        <Toolbar>
          <IconButton
            color="inherit"
            edge="start"
            onClick={handleDrawerToggle}
            sx={{ mr: 2, display: { md: 'none' } }}
          >
            <MenuIcon />
          </IconButton>
          <Typography variant="h6" noWrap sx={{ flexGrow: 1, fontWeight: 600 }}>
            {navGroups.flatMap((g) => g.items).find((i) => location.pathname === i.path || location.pathname.startsWith(i.path + '/'))?.label || 'Patch Manager'}
          </Typography>
          <Tooltip title={`${user?.display_name || user?.username} (${user?.role})`}>
            <IconButton onClick={handleMenuOpen} color="inherit" sx={{ ml: 1 }}>
              <Avatar sx={{ width: 32, height: 32, bgcolor: 'secondary.main', fontSize: '0.875rem' }}>
                {(user?.display_name || user?.username || '?')[0].toUpperCase()}
              </Avatar>
            </IconButton>
          </Tooltip>
          <Menu
            anchorEl={anchorEl}
            open={Boolean(anchorEl)}
            onClose={handleMenuClose}
            slotProps={{ paper: { sx: { mt: 1 } } }}
          >
            <MenuItem disabled>
              <ListItemIcon><PersonIcon fontSize="small" /></ListItemIcon>
              <ListItemText primary={user?.display_name || user?.username} secondary={user?.role} />
            </MenuItem>
            <Divider />
            <MenuItem onClick={() => { handleMenuClose(); navigate('/profile') }}>
              <ListItemIcon><PersonIcon fontSize="small" /></ListItemIcon>
              <ListItemText primary="My Profile" />
            </MenuItem>
            <MenuItem onClick={handleLogout}>
              <ListItemIcon><LogoutIcon fontSize="small" /></ListItemIcon>
              <ListItemText primary="Sign out" />
            </MenuItem>
          </Menu>
        </Toolbar>
      </AppBar>

      {/* Sidebar */}
      <Box component="nav" sx={{ width: { md: DRAWER_WIDTH }, flexShrink: { md: 0 } }}>
        {/* Mobile drawer */}
        <Drawer
          variant="temporary"
          open={mobileOpen}
          onClose={handleDrawerToggle}
          ModalProps={{ keepMounted: true }}
          sx={{ display: { xs: 'block', md: 'none' }, '& .MuiDrawer-paper': { boxSizing: 'border-box', width: DRAWER_WIDTH } }}
        >
          {drawer}
        </Drawer>
        {/* Desktop drawer */}
        <Drawer
          variant="permanent"
          sx={{ display: { xs: 'none', md: 'block' }, '& .MuiDrawer-paper': { boxSizing: 'border-box', width: DRAWER_WIDTH } }}
          open
        >
          {drawer}
        </Drawer>
      </Box>

      {/* Main content */}
      <Box component="main" sx={{ flexGrow: 1, p: 3, bgcolor: 'background.default', overflowY: 'auto' }}>
        <Toolbar />
        <Outlet />
      </Box>
    </Box>
  )
}
