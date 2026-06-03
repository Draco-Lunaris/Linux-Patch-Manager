/// Tests for SsoCallbackPage (issue #4 — SSO token handoff).
///
/// Per `tasks/sso-token-handoff-spec.md` §6.3:
///   9. renders_processing_state_initially
///  10. calls_handoff_endpoint_on_mount
///  11. stores_tokens_and_user_on_success
///  12. shows_error_on_handoff_failure
///  13. shows_error_when_handoff_code_missing
///  14. clears_handoff_code_from_url_after_success
///
/// We mock `fetch`, the auth store, and `window.history.replaceState`
/// so the test focuses on the page's effect-driven logic (URL parsing
/// → POST exchange → store update → navigation → URL cleanup). We do
/// NOT mock `react-router-dom` — instead, we use a real
/// `MemoryRouter` and assert on side effects (the auth store mocks +
/// `replaceState` spy + visible error text).

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, waitFor, act } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import SsoCallbackPage from '../SsoCallbackPage'

// Mock the auth store — we don't want real zustand state leaking
// between tests, and we want to assert on setTokens/setUser calls.
const setTokensMock = vi.fn()
const setUserMock = vi.fn()
vi.mock('../../store/authStore', () => ({
  useAuthStore: () => ({
    setTokens: setTokensMock,
    setUser: setUserMock,
  }),
}))

// Helper: render the page with a controlled URL and let the test
// inspect the rendered output + the auth store mocks.
function renderAt(url: string) {
  return render(
    <MemoryRouter initialEntries={[url]}>
      <SsoCallbackPage />
    </MemoryRouter>,
  )
}

beforeEach(() => {
  setTokensMock.mockReset()
  setUserMock.mockReset()
  // Default fetch: never-resolving promise (keeps the page in
  // "processing" state). Individual tests override this.
  globalThis.fetch = vi.fn(() => new Promise(() => {})) as unknown as typeof fetch
})

afterEach(() => {
  vi.restoreAllMocks()
})

describe('SsoCallbackPage', () => {
  // 9. renders_processing_state_initially — on mount with a handoff
  //    code, shows the spinner and "Completing sign-in…".
  it('renders the processing state initially', async () => {
    // Wrap in act() to flush the useEffect that calls fetch.
    await act(async () => {
      renderAt('/auth/sso/callback?handoff=test-code')
    })

    expect(screen.getByText(/completing sign-in/i)).toBeInTheDocument()
    // The MUI CircularProgress renders a role="progressbar"
    expect(screen.getByRole('progressbar')).toBeInTheDocument()
  })

  // 10. calls_handoff_endpoint_on_mount — mocks fetch and asserts
  //     the POST goes to /api/v1/auth/sso/handoff with
  //     { handoff_code: <code> }.
  it('POSTs the handoff code to the backend on mount', async () => {
    const fetchMock = vi.fn().mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          access_token: 'a',
          refresh_token: 'r',
          token_type: 'Bearer',
          expires_in: 900,
          user: { id: 'u1', username: 'tester' },
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      ),
    )
    globalThis.fetch = fetchMock as unknown as typeof fetch

    await act(async () => {
      renderAt('/auth/sso/callback?handoff=abc123')
    })

    await waitFor(() => {
      expect(fetchMock).toHaveBeenCalledTimes(1)
    })
    const [url, init] = fetchMock.mock.calls[0]
    expect(url).toBe('/api/v1/auth/sso/handoff')
    expect(init.method).toBe('POST')
    expect(JSON.parse(init.body)).toEqual({ handoff_code: 'abc123' })
  })

  // 11. stores_tokens_and_user_on_success — mocks a successful
  //     response, asserts setTokens and setUser are called, and
  //     setTokens receives the correct token values.
  it('stores tokens + user on a successful exchange', async () => {
    const fetchMock = vi.fn().mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          access_token: 'access-jwt',
          refresh_token: 'refresh-raw',
          token_type: 'Bearer',
          expires_in: 900,
          user: { id: 'user-42', username: 'alice' },
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      ),
    )
    globalThis.fetch = fetchMock as unknown as typeof fetch

    await act(async () => {
      renderAt('/auth/sso/callback?handoff=ok')
    })

    await waitFor(() => {
      expect(setTokensMock).toHaveBeenCalledWith('access-jwt', 'refresh-raw')
    })
    expect(setUserMock).toHaveBeenCalledWith(
      expect.objectContaining({ id: 'user-42', username: 'alice' }),
    )
  })

  // 12. shows_error_on_handoff_failure — mocks a 400 response,
  //     asserts the error message is rendered and the spinner
  //     stops.
  it('shows an error when the backend returns 400', async () => {
    const fetchMock = vi.fn().mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          error: { code: 'invalid_handoff', message: 'Handoff code has expired' },
        }),
        { status: 400, headers: { 'Content-Type': 'application/json' } },
      ),
    )
    globalThis.fetch = fetchMock as unknown as typeof fetch

    await act(async () => {
      renderAt('/auth/sso/callback?handoff=expired')
    })

    expect(await screen.findByText(/handoff code has expired/i)).toBeInTheDocument()
    expect(screen.queryByText(/completing sign-in/i)).not.toBeInTheDocument()
    // No token storage on error
    expect(setTokensMock).not.toHaveBeenCalled()
    expect(setUserMock).not.toHaveBeenCalled()
  })

  // 13. shows_error_when_handoff_code_missing — invokes the effect
  //     with no handoff code, asserts the "Missing handoff code"
  //     error is shown.
  it('shows a missing-code error when ?handoff= is absent', async () => {
    const fetchMock = vi.fn()
    globalThis.fetch = fetchMock as unknown as typeof fetch

    await act(async () => {
      renderAt('/auth/sso/callback')
    })

    expect(await screen.findByText(/missing handoff code/i)).toBeInTheDocument()
    // No fetch call should have been made
    expect(fetchMock).not.toHaveBeenCalled()
  })

  // 14. clears_handoff_code_from_url_after_success — asserts
  //     window.history.replaceState is called to remove the
  //     ?handoff= param from the URL after a successful exchange.
  it('clears the handoff code from the URL after a successful exchange', async () => {
    const fetchMock = vi.fn().mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          access_token: 'a',
          refresh_token: 'r',
          token_type: 'Bearer',
          expires_in: 900,
          user: { id: 'u', username: 'u' },
        }),
        { status: 200, headers: { 'Content-Type': 'application/json' } },
      ),
    )
    globalThis.fetch = fetchMock as unknown as typeof fetch

    const replaceStateSpy = vi.spyOn(window.history, 'replaceState')

    await act(async () => {
      renderAt('/auth/sso/callback?handoff=secret-code')
    })

    await waitFor(() => {
      expect(replaceStateSpy).toHaveBeenCalled()
    })
    // Verify the replaceState call cleared the query string — the
    // third argument is the new URL ('/auth/sso/callback' with no
    // query).
    const args = replaceStateSpy.mock.calls[0]
    expect(args[2]).toBe('/auth/sso/callback')
  })
})
