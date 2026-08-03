import { useEffect, useState, useCallback, useMemo } from 'react'
import {
  Box, Button, Chip, CircularProgress, Container, IconButton, InputAdornment, Paper,
  TextField, ToggleButton, ToggleButtonGroup, Toolbar, Tooltip, Typography,
  Table, TableBody, TableCell, TableContainer, TableHead, TableRow,
} from '@mui/material'
import {
  ChevronLeft as ChevronLeftIcon,
  ChevronRight as ChevronRightIcon,
  Today as TodayIcon,
  Search as SearchIcon,
  Schedule as ScheduleIcon,
} from '@mui/icons-material'
import { maintenanceWindowsApi, hostsApi } from '../api/client'
import type { Host, MaintenanceWindow, WindowRecurrence } from '../types'

// ── Types ─────────────────────────────────────────────────────────────────────

type CalendarView = 'month' | 'week' | 'day'

interface CalendarEvent {
  windowId: string
  hostId: string
  label: string
  start: Date
  end: Date
  recurrence: WindowRecurrence
  autoApply: boolean
  autoReboot: boolean
  rebootDelayMinutes: number
  enabled: boolean
  durationMinutes: number
}

// ── Date helpers ───────────────────────────────────────────────────────────────

function startOfDay(d: Date): Date {
  const r = new Date(d)
  r.setHours(0, 0, 0, 0)
  return r
}

function endOfDay(d: Date): Date {
  const r = new Date(d)
  r.setHours(23, 59, 59, 999)
  return r
}

function startOfWeek(d: Date): Date {
  const r = startOfDay(d)
  r.setDate(r.getDate() - r.getDay())
  return r
}

function startOfMonth(d: Date): Date {
  const r = startOfDay(d)
  r.setDate(1)
  return r
}

function addDays(d: Date, n: number): Date {
  const r = new Date(d)
  r.setDate(r.getDate() + n)
  return r
}

function addMonths(d: Date, n: number): Date {
  const r = new Date(d)
  r.setMonth(r.getMonth() + n)
  return r
}

function isSameDay(a: Date, b: Date): boolean {
  return a.getFullYear() === b.getFullYear() &&
    a.getMonth() === b.getMonth() &&
    a.getDate() === b.getDate()
}

function fmtTime(d: Date): string {
  return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
}

function fmtDateLabel(d: Date): string {
  return d.toLocaleDateString([], { weekday: 'short', month: 'short', day: 'numeric' })
}

function fmtMonthYear(d: Date): string {
  return d.toLocaleDateString([], { month: 'long', year: 'numeric' })
}

function fmtWeekRange(start: Date): string {
  const end = addDays(start, 6)
  const sameMonth = start.getMonth() === end.getMonth()
  if (sameMonth) {
    return `${start.toLocaleDateString([], { month: 'short', day: 'numeric' })} – ${end.getDate()}, ${end.getFullYear()}`
  }
  return `${start.toLocaleDateString([], { month: 'short', day: 'numeric' })} – ${end.toLocaleDateString([], { month: 'short', day: 'numeric' })}, ${end.getFullYear()}`
}

// ── Recurrence expansion ──────────────────────────────────────────────────────

/**
 * Expand a maintenance window into concrete occurrences that fall within
 * the given date range [rangeStart, rangeEnd].
 */
function expandWindow(w: MaintenanceWindow, rangeStart: Date, rangeEnd: Date): CalendarEvent[] {
  const events: CalendarEvent[] = []
  const baseStart = new Date(w.start_at)
  const durationMs = w.duration_minutes * 60_000

  const makeEvent = (start: Date): CalendarEvent => ({
    windowId: w.id,
    hostId: w.host_id,
    label: w.label,
    start,
    end: new Date(start.getTime() + durationMs),
    recurrence: w.recurrence,
    autoApply: w.auto_apply,
    autoReboot: w.auto_reboot,
    rebootDelayMinutes: w.reboot_delay_minutes,
    enabled: w.enabled,
    durationMinutes: w.duration_minutes,
  })

  switch (w.recurrence) {
    case 'once': {
      if (baseStart >= rangeStart && baseStart <= rangeEnd) {
        events.push(makeEvent(baseStart))
      }
      break
    }
    case 'daily': {
      // Start from the base date, iterate day by day through the range
      let cursor = new Date(baseStart)
      // Fast-forward to range start
      while (cursor < rangeStart) cursor = addDays(cursor, 1)
      while (cursor <= rangeEnd) {
        events.push(makeEvent(cursor))
        cursor = addDays(cursor, 1)
      }
      break
    }
    case 'weekly': {
      const targetDow = w.recurrence_day ?? baseStart.getDay()
      // Find first matching day-of-week on or after rangeStart
      let cursor = startOfDay(rangeStart)
      while (cursor.getDay() !== targetDow) cursor = addDays(cursor, 1)
      // Set the time from baseStart
      while (cursor <= rangeEnd) {
        const occurrence = new Date(cursor)
        occurrence.setHours(baseStart.getHours(), baseStart.getMinutes(), 0, 0)
        if (occurrence >= rangeStart) {
          events.push(makeEvent(occurrence))
        }
        cursor = addDays(cursor, 7)
      }
      break
    }
    case 'monthly': {
      const targetDay = w.recurrence_day ?? baseStart.getDate()
      // Iterate month by month through the range
      let cursor = new Date(rangeStart.getFullYear(), rangeStart.getMonth(), 1)
      while (cursor <= rangeEnd) {
        const daysInMonth = new Date(cursor.getFullYear(), cursor.getMonth() + 1, 0).getDate()
        const day = Math.min(targetDay, daysInMonth)
        const occurrence = new Date(cursor.getFullYear(), cursor.getMonth(), day,
          baseStart.getHours(), baseStart.getMinutes(), 0, 0)
        if (occurrence >= rangeStart && occurrence <= rangeEnd) {
          events.push(makeEvent(occurrence))
        }
        cursor = addMonths(cursor, 1)
      }
      break
    }
  }

  return events
}

// ── Recurrence chip helpers ───────────────────────────────────────────────────

function recurrenceColor(r: WindowRecurrence): 'default' | 'primary' | 'secondary' | 'info' {
  const map: Record<WindowRecurrence, 'default' | 'primary' | 'secondary' | 'info'> = {
    once: 'default',
    daily: 'primary',
    weekly: 'secondary',
    monthly: 'info',
  }
  return map[r]
}

function recurrenceLabel(r: WindowRecurrence): string {
  const map: Record<WindowRecurrence, string> = {
    once: 'Once',
    daily: 'Daily',
    weekly: 'Weekly',
    monthly: 'Monthly',
  }
  return map[r]
}

// ── Event tooltip content ─────────────────────────────────────────────────────

function EventTooltipContent({ ev, host }: { ev: CalendarEvent; host?: Host }) {
  return (
    <Box sx={{ p: 0.5, maxWidth: 320 }}>
      <Typography variant="subtitle2" sx={{ fontWeight: 700, mb: 0.5 }}>
        {ev.label}
      </Typography>
      <Typography variant="caption" display="block" color="text.secondary">
        <strong>Host:</strong> {host?.display_name ?? host?.fqdn ?? ev.hostId}
      </Typography>
      {host?.fqdn && (
        <Typography variant="caption" display="block" color="text.secondary">
          <strong>FQDN:</strong> {host.fqdn}
        </Typography>
      )}
      <Typography variant="caption" display="block" color="text.secondary">
        <strong>When:</strong> {fmtDateLabel(ev.start)} at {fmtTime(ev.start)} – {fmtTime(ev.end)}
      </Typography>
      <Typography variant="caption" display="block" color="text.secondary">
        <strong>Duration:</strong> {ev.durationMinutes} min
      </Typography>
      <Typography variant="caption" display="block" color="text.secondary">
        <strong>Recurrence:</strong> {recurrenceLabel(ev.recurrence)}
      </Typography>
      <Typography variant="caption" display="block" color="text.secondary">
        <strong>Auto-Apply:</strong> {ev.autoApply ? 'Yes' : 'No'}
      </Typography>
      <Typography variant="caption" display="block" color="text.secondary">
        <strong>Auto-Reboot:</strong> {ev.autoReboot ? (ev.rebootDelayMinutes > 0 ? `Yes (+${ev.rebootDelayMinutes}m)` : 'Yes') : 'No'}
      </Typography>
      {host && (
        <Typography variant="caption" display="block" color="text.secondary">
          <strong>Patches Missing:</strong> {host.patches_missing}
        </Typography>
      )}
      {host?.os_name && (
        <Typography variant="caption" display="block" color="text.secondary">
          <strong>OS:</strong> {host.os_name}
        </Typography>
      )}
      {host?.health_status && (
        <Typography variant="caption" display="block" color="text.secondary">
          <strong>Health:</strong> {host.health_status}
        </Typography>
      )}
      {!ev.enabled && (
        <Typography variant="caption" display="block" sx={{ color: 'warning.main', fontWeight: 600 }}>
          (Disabled)
        </Typography>
      )}
    </Box>
  )
}

// ── Month view ────────────────────────────────────────────────────────────────

const DAY_NAMES = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat']

function MonthView({ currentDate, events, hostMap, onDayClick }: {
  currentDate: Date
  events: CalendarEvent[]
  hostMap: Map<string, Host>
  onDayClick: (d: Date) => void
}) {
  const monthStart = startOfMonth(currentDate)
  const gridStart = startOfWeek(monthStart)
  const today = startOfDay(new Date())

  const weeks: Date[][] = []
  let cursor = new Date(gridStart)
  for (let w = 0; w < 6; w++) {
    const row: Date[] = []
    for (let d = 0; d < 7; d++) {
      row.push(new Date(cursor))
      cursor = addDays(cursor, 1)
    }
    weeks.push(row)
    // Stop if we've gone past the month and have at least 4 weeks
    if (w >= 3 && cursor.getMonth() !== currentDate.getMonth()) break
  }

  const eventsByDay = useMemo(() => {
    const map = new Map<string, CalendarEvent[]>()
    for (const ev of events) {
      const key = ev.start.toDateString()
      const arr = map.get(key)
      if (arr) arr.push(ev)
      else map.set(key, [ev])
    }
    return map
  }, [events])

  return (
    <TableContainer component={Paper} variant="outlined">
      <Table size="small" sx={{ tableLayout: 'fixed' }}>
        <TableHead>
          <TableRow>
            {DAY_NAMES.map(dn => (
              <TableCell key={dn} align="center" sx={{ fontWeight: 700, py: 1 }}>
                {dn}
              </TableCell>
            ))}
          </TableRow>
        </TableHead>
        <TableBody>
          {weeks.map((week, wi) => (
            <TableRow key={wi}>
              {week.map(day => {
                const isCurrentMonth = day.getMonth() === currentDate.getMonth()
                const isToday = isSameDay(day, today)
                const dayEvents = eventsByDay.get(day.toDateString()) ?? []
                return (
                  <TableCell
                    key={day.toISOString()}
                    onClick={() => onDayClick(day)}
                    sx={{
                      cursor: 'pointer',
                      height: 90,
                      verticalAlign: 'top',
                      bgcolor: isToday ? 'action.selected' : 'background.paper',
                      opacity: isCurrentMonth ? 1 : 0.4,
                      '&:hover': { bgcolor: 'action.hover' },
                      borderBottom: '1px solid',
                      borderColor: 'divider',
                      borderRight: '1px solid',
                      borderRightColor: 'divider',
                      p: 0.5,
                    }}
                  >
                    <Typography variant="caption" sx={{ fontWeight: isToday ? 700 : 400, display: 'block', mb: 0.25 }}>
                      {day.getDate()}
                    </Typography>
                    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 0.25, overflow: 'hidden' }}>
                      {dayEvents.slice(0, 3).map((ev, i) => (
                        <Tooltip key={`${ev.windowId}-${i}`} title={<EventTooltipContent ev={ev} host={hostMap.get(ev.hostId)} />} arrow placement="right">
                          <Chip
                            size="small"
                            label={`${hostMap.get(ev.hostId)?.display_name ?? hostMap.get(ev.hostId)?.fqdn ?? ev.hostId} · ${fmtTime(ev.start)}`}
                            color={recurrenceColor(ev.recurrence)}
                            variant={ev.enabled ? 'filled' : 'outlined'}
                            sx={{
                              fontSize: '0.65rem',
                              height: 18,
                              maxWidth: '100%',
                              '& .MuiChip-label': { overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' },
                            }}
                          />
                        </Tooltip>
                      ))}
                      {dayEvents.length > 3 && (
                        <Typography variant="caption" sx={{ fontSize: '0.65rem', color: 'text.secondary' }}>
                          +{dayEvents.length - 3} more
                        </Typography>
                      )}
                    </Box>
                  </TableCell>
                )
              })}
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </TableContainer>
  )
}

// ── Week view ─────────────────────────────────────────────────────────────────

function WeekView({ currentDate, events, hostMap }: {
  currentDate: Date
  events: CalendarEvent[]
  hostMap: Map<string, Host>
}) {
  const weekStart = startOfWeek(currentDate)
  const days = Array.from({ length: 7 }, (_, i) => addDays(weekStart, i))
  const today = startOfDay(new Date())

  const eventsByDay = useMemo(() => {
    const map = new Map<string, CalendarEvent[]>()
    for (const ev of events) {
      const key = ev.start.toDateString()
      const arr = map.get(key)
      if (arr) arr.push(ev)
      else map.set(key, [ev])
    }
    return map
  }, [events])

  return (
    <Box sx={{ display: 'grid', gridTemplateColumns: 'repeat(7, 1fr)', gap: 1 }}>
      {days.map(day => {
        const isToday = isSameDay(day, today)
        const dayEvents = eventsByDay.get(day.toDateString()) ?? []
        return (
          <Paper key={day.toISOString()} variant="outlined" sx={{
            minHeight: 200,
            bgcolor: isToday ? 'action.selected' : 'background.paper',
            p: 1,
          }}>
            <Typography variant="subtitle2" sx={{ fontWeight: isToday ? 700 : 500, mb: 1, textAlign: 'center' }}>
              {day.toLocaleDateString([], { weekday: 'short' })}
              <Box component="span" sx={{ display: 'block', fontSize: '1.1rem' }}>
                {day.getDate()}
              </Box>
            </Typography>
            <Box sx={{ display: 'flex', flexDirection: 'column', gap: 0.5 }}>
              {dayEvents.map((ev, i) => (
                <Tooltip key={`${ev.windowId}-${i}`} title={<EventTooltipContent ev={ev} host={hostMap.get(ev.hostId)} />} arrow placement="right">
                  <Chip
                    size="small"
                    label={`${hostMap.get(ev.hostId)?.display_name ?? hostMap.get(ev.hostId)?.fqdn ?? ev.hostId} · ${fmtTime(ev.start)}`}
                    color={recurrenceColor(ev.recurrence)}
                    variant={ev.enabled ? 'filled' : 'outlined'}
                    sx={{
                      justifyContent: 'flex-start',
                      fontSize: '0.7rem',
                      height: 22,
                      '& .MuiChip-label': { overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' },
                    }}
                  />
                </Tooltip>
              ))}
              {dayEvents.length === 0 && (
                <Typography variant="caption" color="text.secondary" sx={{ textAlign: 'center', py: 1 }}>
                  —
                </Typography>
              )}
            </Box>
          </Paper>
        )
      })}
    </Box>
  )
}

// ── Day view ──────────────────────────────────────────────────────────────────

function DayView({ currentDate, events, hostMap }: {
  currentDate: Date
  events: CalendarEvent[]
  hostMap: Map<string, Host>
}) {
  const dayStart = startOfDay(currentDate)
  const dayEvents = events.filter(ev => isSameDay(ev.start, dayStart))
  const today = isSameDay(dayStart, new Date())

  return (
    <Paper variant="outlined" sx={{ p: 2, minHeight: 400 }}>
      <Typography variant="h6" sx={{ mb: 2, fontWeight: today ? 700 : 500 }}>
        {currentDate.toLocaleDateString([], { weekday: 'long', month: 'long', day: 'numeric', year: 'numeric' })}
      </Typography>
      {dayEvents.length === 0 ? (
        <Typography color="text.secondary" sx={{ py: 4, textAlign: 'center' }}>
          No maintenance windows scheduled for this day.
        </Typography>
      ) : (
        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
          {dayEvents.map((ev, i) => (
            <Tooltip key={`${ev.windowId}-${i}`} title={<EventTooltipContent ev={ev} host={hostMap.get(ev.hostId)} />} arrow placement="right">
              <Paper variant="outlined" sx={{
                p: 1.5, cursor: 'default',
                borderLeft: 4, borderLeftColor: 'primary.main',
                '&:hover': { bgcolor: 'action.hover' },
              }}>
                <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, flexWrap: 'wrap' }}>
                  <Typography variant="subtitle2" sx={{ fontWeight: 600 }}>
                    {hostMap.get(ev.hostId)?.display_name ?? hostMap.get(ev.hostId)?.fqdn ?? ev.hostId}
                  </Typography>
                  <Chip size="small" label={recurrenceLabel(ev.recurrence)} color={recurrenceColor(ev.recurrence)} />
                  {!ev.enabled && <Chip size="small" label="Disabled" color="warning" variant="outlined" />}
                </Box>
                <Typography variant="body2" sx={{ mt: 0.5, fontWeight: 500 }}>
                  {ev.label}
                </Typography>
                <Typography variant="caption" color="text.secondary">
                  {fmtTime(ev.start)} – {fmtTime(ev.end)}
                </Typography>
              </Paper>
            </Tooltip>
          ))}
        </Box>
      )}
    </Paper>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function MaintenanceCalendarPage() {
  const [hosts, setHosts] = useState<Host[]>([])
  const [windows, setWindows] = useState<MaintenanceWindow[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [view, setView] = useState<CalendarView>('month')
  const [currentDate, setCurrentDate] = useState(new Date())
  const [search, setSearch] = useState('')

  const load = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const [hostsRes, windowsRes] = await Promise.all([
        hostsApi.list({ limit: 500 }),
        maintenanceWindowsApi.listAll(),
      ])
      setHosts(hostsRes.data?.hosts ?? hostsRes.data ?? [])
      setWindows(windowsRes.data?.windows ?? [])
    } catch {
      setError('Failed to load maintenance window data.')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  // Build host lookup map
  const hostMap = useMemo(() => {
    const m = new Map<string, Host>()
    for (const h of hosts) m.set(h.id, h)
    return m
  }, [hosts])

  // Filter hosts by search
  const filteredHostIds = useMemo(() => {
    if (!search.trim()) return null
    const q = search.toLowerCase()
    const ids = new Set<string>()
    for (const h of hosts) {
      if (h.fqdn.toLowerCase().includes(q) || h.display_name.toLowerCase().includes(q)) {
        ids.add(h.id)
      }
    }
    return ids
  }, [search, hosts])

  // Compute the visible date range based on view
  const { rangeStart, rangeEnd } = useMemo(() => {
    if (view === 'month') {
      const ms = startOfMonth(currentDate)
      const gs = startOfWeek(ms)
      // 6 weeks to cover any month
      return { rangeStart: gs, rangeEnd: endOfDay(addDays(gs, 42)) }
    }
    if (view === 'week') {
      const ws = startOfWeek(currentDate)
      return { rangeStart: ws, rangeEnd: endOfDay(addDays(ws, 6)) }
    }
    // day
    return { rangeStart: startOfDay(currentDate), rangeEnd: endOfDay(currentDate) }
  }, [view, currentDate])

  // Expand all windows into events within the range, filtered by search
  const events = useMemo(() => {
    const all: CalendarEvent[] = []
    for (const w of windows) {
      if (filteredHostIds && !filteredHostIds.has(w.host_id)) continue
      all.push(...expandWindow(w, rangeStart, rangeEnd))
    }
    return all.sort((a, b) => a.start.getTime() - b.start.getTime())
  }, [windows, rangeStart, rangeEnd, filteredHostIds])

  const handlePrev = () => {
    if (view === 'month') setCurrentDate(addMonths(currentDate, -1))
    else if (view === 'week') setCurrentDate(addDays(currentDate, -7))
    else setCurrentDate(addDays(currentDate, -1))
  }

  const handleNext = () => {
    if (view === 'month') setCurrentDate(addMonths(currentDate, 1))
    else if (view === 'week') setCurrentDate(addDays(currentDate, 7))
    else setCurrentDate(addDays(currentDate, 1))
  }

  const handleToday = () => setCurrentDate(new Date())

  const headerLabel = useMemo(() => {
    if (view === 'month') return fmtMonthYear(currentDate)
    if (view === 'week') return fmtWeekRange(startOfWeek(currentDate))
    return currentDate.toLocaleDateString([], { weekday: 'long', month: 'long', day: 'numeric', year: 'numeric' })
  }, [view, currentDate])

  return (
    <Container maxWidth="xl" sx={{ mt: 3, mb: 6 }}>
      {/* Toolbar */}
      <Toolbar disableGutters sx={{ mb: 2, gap: 1, flexWrap: 'wrap' }}>
        <ScheduleIcon color="primary" />
        <Typography variant="h5" fontWeight={700} sx={{ mr: 2 }}>
          Maintenance Calendar
        </Typography>

        <ToggleButtonGroup
          value={view}
          exclusive
          onChange={(_, v: CalendarView | null) => v && setView(v)}
          size="small"
          sx={{ mr: 1 }}
        >
          <ToggleButton value="day">Day</ToggleButton>
          <ToggleButton value="week">Week</ToggleButton>
          <ToggleButton value="month">Month</ToggleButton>
        </ToggleButtonGroup>

        <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5, mr: 1 }}>
          <IconButton onClick={handlePrev} size="small"><ChevronLeftIcon /></IconButton>
          <IconButton onClick={handleToday} size="small" title="Today">
            <TodayIcon />
          </IconButton>
          <IconButton onClick={handleNext} size="small"><ChevronRightIcon /></IconButton>
        </Box>

        <Typography variant="subtitle1" sx={{ fontWeight: 600, mr: 2 }}>
          {headerLabel}
        </Typography>

        <TextField
          size="small"
          placeholder="Search hosts..."
          value={search}
          onChange={e => setSearch(e.target.value)}
          sx={{ ml: 'auto', width: 240 }}
          slotProps={{
            input: {
              startAdornment: <InputAdornment position="start"><SearchIcon fontSize="small" /></InputAdornment>,
            },
          }}
        />
        <Button startIcon={<TodayIcon />} onClick={load} disabled={loading} size="small">
          Refresh
        </Button>
      </Toolbar>

      {loading && (
        <Box display="flex" justifyContent="center" mt={8}>
          <CircularProgress />
        </Box>
      )}

      {!loading && error && (
        <Paper variant="outlined" sx={{ p: 3, color: 'error.main' }}>
          {error}
        </Paper>
      )}

      {!loading && !error && (
        <>
          {events.length === 0 && (
            <Paper variant="outlined" sx={{ p: 3, textAlign: 'center', mb: 2 }}>
              <Typography color="text.secondary">
                {search.trim()
                  ? 'No maintenance windows match your search in this date range.'
                  : 'No maintenance windows scheduled in this date range.'}
              </Typography>
            </Paper>
          )}
          {view === 'month' && (
            <MonthView
              currentDate={currentDate}
              events={events}
              hostMap={hostMap}
              onDayClick={d => { setView('day'); setCurrentDate(d) }}
            />
          )}
          {view === 'week' && (
            <WeekView currentDate={currentDate} events={events} hostMap={hostMap} />
          )}
          {view === 'day' && (
            <DayView currentDate={currentDate} events={events} hostMap={hostMap} />
          )}
        </>
      )}
    </Container>
  )
}