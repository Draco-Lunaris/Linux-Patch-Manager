import { useEffect, useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { Alert, Box, Button, CircularProgress, Container, Divider, Grid, Paper, Typography } from '@mui/material'
import { ArrowBack } from '@mui/icons-material'
import { apiClient } from '../api/client'

export default function HostDetailPage() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const [host, setHost] = useState<Record<string, unknown> | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    apiClient.get(`/hosts/${id}`)
      .then(r => setHost(r.data))
      .catch(() => setError('Host not found or access denied.'))
      .finally(() => setLoading(false))
  }, [id])

  if (loading) return <Box display="flex" justifyContent="center" mt={8}><CircularProgress /></Box>
  if (error) return <Container sx={{ mt: 4 }}><Alert severity="error">{error}</Alert></Container>

  return (
    <Container maxWidth="lg" sx={{ mt: 3 }}>
      <Button startIcon={<ArrowBack />} onClick={() => navigate('/hosts')} sx={{ mb: 2 }}>Back to Hosts</Button>
      <Paper sx={{ p: 3 }}>
        <Typography variant="h5" fontWeight={700} mb={2}>{String(host?.fqdn ?? '')}</Typography>
        <Divider sx={{ mb: 2 }} />
        <Grid container spacing={2}>
          {host && Object.entries(host).map(([k, v]) => v !== null && v !== '' ? (
            <Grid size={{ xs: 12, sm: 6, md: 4 }} key={k}>
              <Typography variant="caption" color="text.secondary" display="block">{k.replace(/_/g, ' ').toUpperCase()}</Typography>
              <Typography variant="body2">{String(v)}</Typography>
            </Grid>
          ) : null)}
        </Grid>
      </Paper>
    </Container>
  )
}
