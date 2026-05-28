/**
 * useJobWebSocket — M7
 *
 * Manages a browser WebSocket connection to the job-update relay.
 * Authentication uses single-use tickets obtained via POST /api/v1/ws/ticket.
 *
 * Features:
 * - Fetches a fresh ticket before every (re)connect
 * - Exponential backoff reconnect: 1 s → 2 s → 4 s → … → 30 s max
 * - Calls `onEvent` callback for every parsed JobWsEvent
 * - Returns { connected, lastEvent } for UI indicator use
 */

import { useEffect, useRef, useCallback, useState } from 'react'
import { wsApi } from '../api/client'
import type { JobWsEvent } from '../types'

// ── Constants ─────────────────────────────────────────────────────────────────

const BACKOFF_INITIAL_MS = 1_000
const BACKOFF_MAX_MS     = 30_000
const BACKOFF_FACTOR     = 2

// ── Types ─────────────────────────────────────────────────────────────────────

export interface JobWsOptions {
  /** Called on each inbound JobWsEvent. */
  onEvent?: (event: JobWsEvent) => void
  /** Set to false to disable the connection entirely (e.g. when logged out). */
  enabled?: boolean
}

export interface JobWsState {
  connected: boolean
  lastEvent: JobWsEvent | null
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/** Derive the correct ws(s) URL from the current page origin. */
function buildWsBase(): string {
  const proto = window.location.protocol === 'https:' ? 'wss' : 'ws'
  return `${proto}://${window.location.host}`
}

// ── Hook ──────────────────────────────────────────────────────────────────────

export function useJobWebSocket(options: JobWsOptions = {}): JobWsState {
  const { onEvent, enabled = true } = options

  const [connected, setConnected]   = useState(false)
  const [lastEvent, setLastEvent]   = useState<JobWsEvent | null>(null)

  // Stable ref to the latest onEvent callback — avoids re-triggering the
  // effect every time the parent component re-renders.
  const onEventRef = useRef(onEvent)
  useEffect(() => { onEventRef.current = onEvent }, [onEvent])

  // Internal bookkeeping refs (don't need to trigger re-renders).
  const wsRef           = useRef<WebSocket | null>(null)
  const retryTimerRef   = useRef<ReturnType<typeof setTimeout> | null>(null)
  const backoffRef      = useRef(BACKOFF_INITIAL_MS)
  const mountedRef      = useRef(true)

  const clearRetryTimer = useCallback(() => {
    if (retryTimerRef.current !== null) {
      clearTimeout(retryTimerRef.current)
      retryTimerRef.current = null
    }
  }, [])

  const closeSocket = useCallback(() => {
    if (wsRef.current) {
      // Prevent the onclose handler from scheduling another reconnect.
      wsRef.current.onclose = null
      wsRef.current.onerror = null
      wsRef.current.close()
      wsRef.current = null
    }
  }, [])

  const connect = useCallback(async () => {
    if (!mountedRef.current || !enabled) return

    // Close any existing socket before opening a new one.
    closeSocket()

    let ticket: string
    try {
      const resp = await wsApi.createTicket()
      ticket = resp.ticket
    } catch (err) {
      console.warn('[JobWS] Failed to obtain WS ticket:', err)
      scheduleReconnect()
      return
    }

    if (!mountedRef.current) return

    const url = `${buildWsBase()}/api/v1/ws/jobs?ticket=${encodeURIComponent(ticket)}`
    let ws: WebSocket
    try {
      ws = new WebSocket(url)
    } catch (err) {
      console.error('[JobWS] WebSocket constructor threw:', err)
      scheduleReconnect()
      return
    }

    wsRef.current = ws

    ws.onopen = () => {
      if (!mountedRef.current) { ws.close(); return }
      console.warn('[JobWS] Connected')
      backoffRef.current = BACKOFF_INITIAL_MS // reset backoff on successful connect
      setConnected(true)
    }

    ws.onmessage = (ev: MessageEvent) => {
      if (!mountedRef.current) return
      try {
        const event: JobWsEvent = JSON.parse(ev.data as string)
        setLastEvent(event)
        onEventRef.current?.(event)
      } catch {
        console.warn('[JobWS] Unparseable message:', ev.data)
      }
    }

    ws.onerror = () => {
      console.warn('[JobWS] Socket error')
      // onclose will fire immediately after onerror — let it handle reconnect.
    }

    ws.onclose = () => {
      if (!mountedRef.current) return
      console.warn('[JobWS] Disconnected — scheduling reconnect')
      setConnected(false)
      wsRef.current = null
      scheduleReconnect()
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [enabled, closeSocket])

  function scheduleReconnect() {
    if (!mountedRef.current) return
    clearRetryTimer()
    const delay = backoffRef.current
    backoffRef.current = Math.min(delay * BACKOFF_FACTOR, BACKOFF_MAX_MS)
    console.warn(`[JobWS] Reconnecting in ${delay} ms`)
    retryTimerRef.current = setTimeout(() => {
      if (mountedRef.current) connect()
    }, delay)
  }

  useEffect(() => {
    mountedRef.current = true

    if (enabled) {
      connect()
    }

    return () => {
      mountedRef.current = false
      clearRetryTimer()
      closeSocket()
      setConnected(false)
    }
  }, [enabled, connect, clearRetryTimer, closeSocket])

  return { connected, lastEvent }
}
