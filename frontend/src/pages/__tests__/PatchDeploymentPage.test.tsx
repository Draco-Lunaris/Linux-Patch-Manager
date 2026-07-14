/// Tests for PatchDeploymentPage cross-page host selection.
///
/// Verifies that:
/// 1. Selecting hosts on page 1, navigating to page 2, selecting more,
///    then returning to page 1 preserves all selections.
/// 2. Deselecting a host from any page correctly updates the selection
///    count and the Step 1 review chips.
/// 3. The "select all" checkbox only affects the current page.

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import type { Host } from '../../types'

// ── Mock data ──────────────────────────────────────────────────────────────
function makeHost(id: string, name: string): Host {
  return {
    id,
    fqdn: `${name}.example.com`,
    ip_address: '10.0.0.1',
    display_name: name,
    health_status: 'healthy',
    patches_missing: 0,
    registered_at: '2024-01-01T00:00:00Z',
  }
}

// ── Mock the API client ────────────────────────────────────────────────────
const listMock = vi.fn()
vi.mock('../../api/client', () => ({
  hostsApi: {
    list: (...args: unknown[]) => listMock(...args),
  },
  jobsApi: {
    create: vi.fn().mockResolvedValue({ data: { id: 'job-1' } }),
  },
}))

// ── Mock the auth store ────────────────────────────────────────────────────
vi.mock('../../store/authStore', () => ({
  useAuthStore: () => ({
    user: { id: 'u1', username: 'admin', role: 'admin' },
  }),
}))

// Dynamic import so mocks are registered first
import PatchDeploymentPage from '../PatchDeploymentPage'

// Helper: set up multi-page mock that returns different hosts based on offset/limit.
// Respects search, health_status, and patches_missing filter params.
function setupMultiPageMock(allHosts: Host[]) {
  listMock.mockImplementation((params?: Record<string, unknown>) => {
    const limit = (params?.limit as number) ?? 25
    const offset = (params?.offset as number) ?? 0
    let filtered = allHosts

    // Apply search filter
    const search = params?.search as string | undefined
    if (search) {
      const q = search.toLowerCase()
      filtered = filtered.filter(
        (h) =>
          h.display_name.toLowerCase().includes(q) ||
          h.fqdn.toLowerCase().includes(q),
      )
    }

    // Apply health_status filter
    const healthStatus = params?.health_status as string | undefined
    if (healthStatus) {
      filtered = filtered.filter((h) => h.health_status === healthStatus)
    }

    // Apply patches_missing filter
    const patchesMissing = params?.patches_missing as string | undefined
    if (patchesMissing === 'missing') {
      filtered = filtered.filter((h) => h.patches_missing > 0)
    } else if (patchesMissing === 'uptodate') {
      filtered = filtered.filter((h) => h.patches_missing === 0)
    }

    const pageHosts = filtered.slice(offset, offset + limit)
    return Promise.resolve({
      data: {
        hosts: pageHosts,
        total: filtered.length,
        limit,
        offset,
      },
    })
  })
}

beforeEach(() => {
  listMock.mockReset()
})

afterEach(() => {
  vi.restoreAllMocks()
})

// Helper to render the page
function renderPage() {
  return render(
    <MemoryRouter>
      <PatchDeploymentPage />
    </MemoryRouter>,
  )
}

// Helper: get the checkbox for a host row by host display name
function getHostCheckbox(hostName: string) {
  const row = screen.getByText(hostName).closest('tr')
  if (!row) throw new Error(`Row for ${hostName} not found`)
  const checkbox = within(row).getByRole('checkbox')
  return checkbox
}

// Helper: get the "select all" header checkbox
function getSelectAllCheckbox() {
  const headerRow = screen.getAllByRole('checkbox')[0]
  return headerRow
}

// Helper: navigate to next/prev page
async function goToNextPage(user: ReturnType<typeof userEvent.setup>) {
  const btn = screen.getByRole('button', { name: /go to next page/i })
  await user.click(btn)
}

async function goToPrevPage(user: ReturnType<typeof userEvent.setup>) {
  const btn = screen.getByRole('button', { name: /go to previous page/i })
  await user.click(btn)
}

// Helper: change rows per page to a small number so we get multiple pages
async function changeRowsPerPage(user: ReturnType<typeof userEvent.setup>, value: string) {
  const rowsSelect = screen.getByRole('combobox', { name: /rows per page/i })
  await user.click(rowsSelect)
  const option = await screen.findByRole('option', { name: value })
  await user.click(option)
}

describe('PatchDeploymentPage cross-page selection', () => {
  it('preserves selections across pages and updates count', async () => {
    const manyHosts: Host[] = Array.from({ length: 25 }, (_, i) =>
      makeHost(`h${i}`, `host-${String.fromCharCode(97 + i)}`),
    )
    setupMultiPageMock(manyHosts)

    const user = userEvent.setup()
    renderPage()

    // Wait for page 1 to load
    await waitFor(() => {
      expect(screen.getByText('host-a')).toBeInTheDocument()
    })

    // Change to 10 per page so we get 3 pages
    await changeRowsPerPage(user, '10')

    await waitFor(() => {
      expect(screen.getByText('host-a')).toBeInTheDocument()
    })

    // Select host-a on page 1
    await user.click(getHostCheckbox('host-a'))

    await waitFor(() => {
      expect(screen.getByText(/1 host selected/i)).toBeInTheDocument()
    })

    // Navigate to page 2
    await goToNextPage(user)
    await waitFor(() => {
      expect(screen.getByText('host-k')).toBeInTheDocument()
    })

    // Select host-k on page 2
    await user.click(getHostCheckbox('host-k'))

    await waitFor(() => {
      expect(screen.getByText(/2 hosts selected/i)).toBeInTheDocument()
    })

    // Go back to page 1
    await goToPrevPage(user)
    await waitFor(() => {
      expect(screen.getByText('host-a')).toBeInTheDocument()
    })

    // host-a should still be selected
    const aRow = screen.getByText('host-a').closest('tr')
    expect(aRow).toHaveClass('Mui-selected')

    // Selection count should still be 2
    expect(screen.getByText(/2 hosts selected/i)).toBeInTheDocument()
  })

  it('select all checkbox only affects current page', async () => {
    // Use 25 hosts so we get multiple pages with rowsPerPage=10
    const manyHosts: Host[] = Array.from({ length: 25 }, (_, i) =>
      makeHost(`h${i}`, `host-${String.fromCharCode(97 + i)}`),
    )
    setupMultiPageMock(manyHosts)

    const user = userEvent.setup()
    renderPage()

    // Wait for page 1 to load (10 hosts per page by default)
    await waitFor(() => {
      expect(screen.getByText('host-a')).toBeInTheDocument()
    })

    // Change to 10 per page (should already be 25 default, let's set to 10)
    // Actually default is 25, so all 25 fit on one page. Let's change to 10.
    await changeRowsPerPage(user, '10')

    // Wait for page 1 with 10 hosts
    await waitFor(() => {
      expect(screen.getByText('host-a')).toBeInTheDocument()
    })

    // Click "select all" checkbox
    await user.click(getSelectAllCheckbox())

    // 10 hosts on page 1 should be selected
    await waitFor(() => {
      expect(screen.getByText(/10 hosts selected/i)).toBeInTheDocument()
    })

    // Navigate to page 2
    await goToNextPage(user)

    // Wait for page 2
    await waitFor(() => {
      expect(screen.getByText('host-k')).toBeInTheDocument()
    })

    // Page 2 hosts should NOT be selected
    const kRow = screen.getByText('host-k').closest('tr')
    expect(kRow).not.toHaveClass('Mui-selected')

    // Count should still be 10
    expect(screen.getByText(/10 hosts selected/i)).toBeInTheDocument()
  })

  it('deselecting a host from page 1 updates count and Step 1 review', async () => {
    const manyHosts: Host[] = Array.from({ length: 25 }, (_, i) =>
      makeHost(`h${i}`, `host-${String.fromCharCode(97 + i)}`),
    )
    setupMultiPageMock(manyHosts)

    const user = userEvent.setup()
    renderPage()

    // Wait for page 1
    await waitFor(() => {
      expect(screen.getByText('host-a')).toBeInTheDocument()
    })

    await changeRowsPerPage(user, '10')

    await waitFor(() => {
      expect(screen.getByText('host-a')).toBeInTheDocument()
    })

    // Select host-a and host-b on page 1
    await user.click(getHostCheckbox('host-a'))
    await user.click(getHostCheckbox('host-b'))

    await waitFor(() => {
      expect(screen.getByText(/2 hosts selected/i)).toBeInTheDocument()
    })

    // Navigate to page 2 and select host-k
    await goToNextPage(user)
    await waitFor(() => {
      expect(screen.getByText('host-k')).toBeInTheDocument()
    })
    await user.click(getHostCheckbox('host-k'))

    await waitFor(() => {
      expect(screen.getByText(/3 hosts selected/i)).toBeInTheDocument()
    })

    // Go back to page 1
    await goToPrevPage(user)
    await waitFor(() => {
      expect(screen.getByText('host-a')).toBeInTheDocument()
    })

    // Deselect host-b
    await user.click(getHostCheckbox('host-b'))

    // Count should now be 2
    await waitFor(() => {
      expect(screen.getByText(/2 hosts selected/i)).toBeInTheDocument()
    })

    // Navigate to Step 1
    await user.click(screen.getByRole('button', { name: /^next$/i }))

    await waitFor(() => {
      expect(screen.getByText(/Selected Hosts \(2\)/i)).toBeInTheDocument()
    })

    // Should see host-a and host-k, but NOT host-b
    expect(screen.getByText('host-a')).toBeInTheDocument()
    expect(screen.getByText('host-k')).toBeInTheDocument()
    expect(screen.queryByText('host-b')).not.toBeInTheDocument()
  })

  it('deselecting a host from page 2 updates count and Step 1 review', async () => {
    const manyHosts: Host[] = Array.from({ length: 25 }, (_, i) =>
      makeHost(`h${i}`, `host-${String.fromCharCode(97 + i)}`),
    )
    setupMultiPageMock(manyHosts)

    const user = userEvent.setup()
    renderPage()

    await waitFor(() => {
      expect(screen.getByText('host-a')).toBeInTheDocument()
    })

    await changeRowsPerPage(user, '10')

    await waitFor(() => {
      expect(screen.getByText('host-a')).toBeInTheDocument()
    })

    // Select host-a on page 1
    await user.click(getHostCheckbox('host-a'))

    // Navigate to page 2
    await goToNextPage(user)
    await waitFor(() => {
      expect(screen.getByText('host-k')).toBeInTheDocument()
    })

    // Select host-k and host-l on page 2
    await user.click(getHostCheckbox('host-k'))
    await user.click(getHostCheckbox('host-l'))

    await waitFor(() => {
      expect(screen.getByText(/3 hosts selected/i)).toBeInTheDocument()
    })

    // Deselect host-l (on page 2)
    await user.click(getHostCheckbox('host-l'))

    await waitFor(() => {
      expect(screen.getByText(/2 hosts selected/i)).toBeInTheDocument()
    })

    // Navigate to Step 1
    await user.click(screen.getByRole('button', { name: /^next$/i }))

    await waitFor(() => {
      expect(screen.getByText(/Selected Hosts \(2\)/i)).toBeInTheDocument()
    })

    expect(screen.getByText('host-a')).toBeInTheDocument()
    expect(screen.getByText('host-k')).toBeInTheDocument()
    expect(screen.queryByText('host-l')).not.toBeInTheDocument()
  })

  it('deselecting from Step 1 review chips updates count', async () => {
    const manyHosts: Host[] = Array.from({ length: 25 }, (_, i) =>
      makeHost(`h${i}`, `host-${String.fromCharCode(97 + i)}`),
    )
    setupMultiPageMock(manyHosts)

    const user = userEvent.setup()
    renderPage()

    await waitFor(() => {
      expect(screen.getByText('host-a')).toBeInTheDocument()
    })

    await changeRowsPerPage(user, '10')

    await waitFor(() => {
      expect(screen.getByText('host-a')).toBeInTheDocument()
    })

    // Select host-a on page 1
    await user.click(getHostCheckbox('host-a'))

    // Navigate to page 2
    await goToNextPage(user)
    await waitFor(() => {
      expect(screen.getByText('host-k')).toBeInTheDocument()
    })

    // Select host-k on page 2
    await user.click(getHostCheckbox('host-k'))

    await waitFor(() => {
      expect(screen.getByText(/2 hosts selected/i)).toBeInTheDocument()
    })

    // Navigate to Step 1
    await user.click(screen.getByRole('button', { name: /^next$/i }))

    await waitFor(() => {
      expect(screen.getByText(/Selected Hosts \(2\)/i)).toBeInTheDocument()
    })

    // Delete the host-a chip from the review
    const alphaChip = screen.getByText('host-a').closest('.MuiChip-root')
    expect(alphaChip).toBeInTheDocument()
    const deleteIcon = within(alphaChip as HTMLElement).getByTestId('CancelIcon')
    await user.click(deleteIcon)

    // Should now show 1 host
    await waitFor(() => {
      expect(screen.getByText(/Selected Hosts \(1\)/i)).toBeInTheDocument()
    })

    expect(screen.getByText('host-k')).toBeInTheDocument()
    expect(screen.queryByText('host-a')).not.toBeInTheDocument()
  })

  it('selections persist when applying and clearing search filters', async () => {
    const manyHosts: Host[] = Array.from({ length: 25 }, (_, i) =>
      makeHost(`h${i}`, `host-${String.fromCharCode(97 + i)}`),
    )
    setupMultiPageMock(manyHosts)

    const user = userEvent.setup()
    renderPage()

    // Wait for page 1
    await waitFor(() => {
      expect(screen.getByText('host-a')).toBeInTheDocument()
    })

    await changeRowsPerPage(user, '10')

    await waitFor(() => {
      expect(screen.getByText('host-a')).toBeInTheDocument()
    })

    // Select host-a and host-b on page 1
    await user.click(getHostCheckbox('host-a'))
    await user.click(getHostCheckbox('host-b'))

    await waitFor(() => {
      expect(screen.getByText(/2 hosts selected/i)).toBeInTheDocument()
    })

    // Apply a search filter that narrows the list
    const searchInput = screen.getByPlaceholderText(/search by name or fqdn/i)
    await user.type(searchInput, 'host-a')

    // Wait for the filtered results to load — host-a should be visible,
    // host-b should not
    await waitFor(() => {
      expect(screen.getByText('host-a')).toBeInTheDocument()
    })
    expect(screen.queryByText('host-b')).not.toBeInTheDocument()

    // Selection count should still be 2 — host-b is no longer visible
    // but remains selected
    expect(screen.getByText(/2 hosts selected/i)).toBeInTheDocument()

    // host-a should still show as selected
    const aRow = screen.getByText('host-a').closest('tr')
    expect(aRow).toHaveClass('Mui-selected')

    // Clear the search filter
    await user.clear(searchInput)

    // Wait for full list to reload
    await waitFor(() => {
      expect(screen.getByText('host-a')).toBeInTheDocument()
      expect(screen.getByText('host-b')).toBeInTheDocument()
    })

    // Both selections should still be present
    expect(screen.getByText(/2 hosts selected/i)).toBeInTheDocument()

    const bRow = screen.getByText('host-b').closest('tr')
    expect(bRow).toHaveClass('Mui-selected')

    // Navigate to Step 1 and verify both hosts are in the review
    await user.click(screen.getByRole('button', { name: /^next$/i }))

    await waitFor(() => {
      expect(screen.getByText(/Selected Hosts \(2\)/i)).toBeInTheDocument()
    })
    expect(screen.getByText('host-a')).toBeInTheDocument()
    expect(screen.getByText('host-b')).toBeInTheDocument()
  })

  it('selections persist when applying and clearing health filter', async () => {
    // Create hosts with mixed health statuses
    const mixedHosts: Host[] = Array.from({ length: 15 }, (_, i) => ({
      ...makeHost(`h${i}`, `host-${String.fromCharCode(97 + i)}`),
      health_status: i < 5 ? 'healthy' : i < 10 ? 'degraded' : 'unreachable',
    }))
    setupMultiPageMock(mixedHosts)

    const user = userEvent.setup()
    renderPage()

    await waitFor(() => {
      expect(screen.getByText('host-a')).toBeInTheDocument()
    })

    await changeRowsPerPage(user, '10')

    await waitFor(() => {
      expect(screen.getByText('host-a')).toBeInTheDocument()
    })

    // Select host-a (healthy) and host-f (degraded) on page 1
    await user.click(getHostCheckbox('host-a'))
    await user.click(getHostCheckbox('host-f'))

    await waitFor(() => {
      expect(screen.getByText(/2 hosts selected/i)).toBeInTheDocument()
    })

    // Apply health filter: "degraded" — native select, use selectOptions
    const healthSelect = screen.getByRole('combobox', { name: /health filter/i })
    await user.selectOptions(healthSelect, 'degraded')

    // Wait for filtered results — only degraded hosts should show
    await waitFor(() => {
      expect(screen.getByText('host-f')).toBeInTheDocument()
    })
    expect(screen.queryByText('host-a')).not.toBeInTheDocument()

    // Selection count should still be 2
    expect(screen.getByText(/2 hosts selected/i)).toBeInTheDocument()

    // host-f should still be selected
    const fRow = screen.getByText('host-f').closest('tr')
    expect(fRow).toHaveClass('Mui-selected')

    // Clear the health filter
    await user.selectOptions(healthSelect, '')

    // Wait for full list to reload
    await waitFor(() => {
      expect(screen.getByText('host-a')).toBeInTheDocument()
      expect(screen.getByText('host-f')).toBeInTheDocument()
    })

    // Both selections should still be present
    expect(screen.getByText(/2 hosts selected/i)).toBeInTheDocument()

    const aRow2 = screen.getByText('host-a').closest('tr')
    expect(aRow2).toHaveClass('Mui-selected')
  })

  it('selections persist across full multi-page navigation round-trip', async () => {
    // 35 hosts with 10 per page = 4 pages (10, 10, 10, 5)
    const manyHosts: Host[] = Array.from({ length: 35 }, (_, i) =>
      makeHost(`h${i}`, `host-${i.toString().padStart(2, '0')}`),
    )
    setupMultiPageMock(manyHosts)

    const user = userEvent.setup()
    renderPage()

    // Wait for initial load
    await waitFor(() => {
      expect(screen.getByText('host-00')).toBeInTheDocument()
    })

    await changeRowsPerPage(user, '10')

    await waitFor(() => {
      expect(screen.getByText('host-00')).toBeInTheDocument()
    })

    // ── Page 1: select host-00 and host-01 ─────────────────────────────
    await user.click(getHostCheckbox('host-00'))
    await user.click(getHostCheckbox('host-01'))

    await waitFor(() => {
      expect(screen.getByText(/2 hosts selected/i)).toBeInTheDocument()
    })

    // Navigate to page 2
    await goToNextPage(user)
    await waitFor(() => {
      expect(screen.getByText('host-10')).toBeInTheDocument()
    })

    // ── Page 2: select host-10 ─────────────────────────────────────────
    await user.click(getHostCheckbox('host-10'))

    await waitFor(() => {
      expect(screen.getByText(/3 hosts selected/i)).toBeInTheDocument()
    })

    // Navigate to page 3
    await goToNextPage(user)
    await waitFor(() => {
      expect(screen.getByText('host-20')).toBeInTheDocument()
    })

    // ── Page 3: select host-20 and host-21 ─────────────────────────────
    await user.click(getHostCheckbox('host-20'))
    await user.click(getHostCheckbox('host-21'))

    await waitFor(() => {
      expect(screen.getByText(/5 hosts selected/i)).toBeInTheDocument()
    })

    // Navigate to page 4 (last page)
    await goToNextPage(user)
    await waitFor(() => {
      expect(screen.getByText('host-30')).toBeInTheDocument()
    })

    // ── Page 4: select host-30 ─────────────────────────────────────────
    await user.click(getHostCheckbox('host-30'))

    await waitFor(() => {
      expect(screen.getByText(/6 hosts selected/i)).toBeInTheDocument()
    })

    // ── Navigate back to page 3 and verify host-20 and host-21 are still selected
    await goToPrevPage(user)
    await waitFor(() => {
      expect(screen.getByText('host-20')).toBeInTheDocument()
    })

    const uRow = screen.getByText('host-20').closest('tr')
    expect(uRow).toHaveClass('Mui-selected')
    const vRow = screen.getByText('host-21').closest('tr')
    expect(vRow).toHaveClass('Mui-selected')
    expect(screen.getByText(/6 hosts selected/i)).toBeInTheDocument()

    // ── Navigate back to page 2 and verify host-10 is still selected
    await goToPrevPage(user)
    await waitFor(() => {
      expect(screen.getByText('host-10')).toBeInTheDocument()
    })

    const kRow = screen.getByText('host-10').closest('tr')
    expect(kRow).toHaveClass('Mui-selected')
    expect(screen.getByText(/6 hosts selected/i)).toBeInTheDocument()

    // ── Navigate back to page 1 and verify host-00 and host-01 are still selected
    await goToPrevPage(user)
    await waitFor(() => {
      expect(screen.getByText('host-00')).toBeInTheDocument()
    })

    const aRow = screen.getByText('host-00').closest('tr')
    expect(aRow).toHaveClass('Mui-selected')
    const bRow = screen.getByText('host-01').closest('tr')
    expect(bRow).toHaveClass('Mui-selected')
    expect(screen.getByText(/6 hosts selected/i)).toBeInTheDocument()

    // ── Navigate to Step 1 and verify all 6 selected hosts appear in the review
    await user.click(screen.getByRole('button', { name: /^next$/i }))

    await waitFor(() => {
      expect(screen.getByText(/Selected Hosts \(6\)/i)).toBeInTheDocument()
    })

    // All 6 selected hosts should have chips in the review
    expect(screen.getByText('host-00')).toBeInTheDocument()
    expect(screen.getByText('host-01')).toBeInTheDocument()
    expect(screen.getByText('host-10')).toBeInTheDocument()
    expect(screen.getByText('host-20')).toBeInTheDocument()
    expect(screen.getByText('host-21')).toBeInTheDocument()
    expect(screen.getByText('host-30')).toBeInTheDocument()
  })

  it('deselecting hosts across multiple pages updates count and review chips', async () => {
    // 35 hosts with 10 per page = 4 pages (10, 10, 10, 5)
    const manyHosts: Host[] = Array.from({ length: 35 }, (_, i) =>
      makeHost(`h${i}`, `host-${i.toString().padStart(2, '0')}`),
    )
    setupMultiPageMock(manyHosts)

    const user = userEvent.setup()
    renderPage()

    await waitFor(() => {
      expect(screen.getByText('host-00')).toBeInTheDocument()
    })

    await changeRowsPerPage(user, '10')

    await waitFor(() => {
      expect(screen.getByText('host-00')).toBeInTheDocument()
    })

    // ── Page 1: select host-00, host-01, host-02 ───────────────────────
    await user.click(getHostCheckbox('host-00'))
    await user.click(getHostCheckbox('host-01'))
    await user.click(getHostCheckbox('host-02'))

    await waitFor(() => {
      expect(screen.getByText(/3 hosts selected/i)).toBeInTheDocument()
    })

    // ── Page 2: select host-10, host-11 ────────────────────────────────
    await goToNextPage(user)
    await waitFor(() => {
      expect(screen.getByText('host-10')).toBeInTheDocument()
    })
    await user.click(getHostCheckbox('host-10'))
    await user.click(getHostCheckbox('host-11'))

    await waitFor(() => {
      expect(screen.getByText(/5 hosts selected/i)).toBeInTheDocument()
    })

    // ── Page 3: select host-20 ─────────────────────────────────────────
    await goToNextPage(user)
    await waitFor(() => {
      expect(screen.getByText('host-20')).toBeInTheDocument()
    })
    await user.click(getHostCheckbox('host-20'))

    await waitFor(() => {
      expect(screen.getByText(/6 hosts selected/i)).toBeInTheDocument()
    })

    // ── Deselect host-01 on page 1 (navigate back) ─────────────────────
    await goToPrevPage(user)
    await waitFor(() => {
      expect(screen.getByText('host-10')).toBeInTheDocument()
    })
    await goToPrevPage(user)
    await waitFor(() => {
      expect(screen.getByText('host-00')).toBeInTheDocument()
    })

    await user.click(getHostCheckbox('host-01'))

    await waitFor(() => {
      expect(screen.getByText(/5 hosts selected/i)).toBeInTheDocument()
    })

    // host-01 row should no longer be selected
    const bRow = screen.getByText('host-01').closest('tr')
    expect(bRow).not.toHaveClass('Mui-selected')

    // ── Deselect host-20 on page 3 (navigate forward) ──────────────────
    await goToNextPage(user)
    await waitFor(() => {
      expect(screen.getByText('host-10')).toBeInTheDocument()
    })
    await goToNextPage(user)
    await waitFor(() => {
      expect(screen.getByText('host-20')).toBeInTheDocument()
    })

    await user.click(getHostCheckbox('host-20'))

    await waitFor(() => {
      expect(screen.getByText(/4 hosts selected/i)).toBeInTheDocument()
    })

    const uRow = screen.getByText('host-20').closest('tr')
    expect(uRow).not.toHaveClass('Mui-selected')

    // ── Deselect host-10 on page 2 (navigate back) ─────────────────────
    await goToPrevPage(user)
    await waitFor(() => {
      expect(screen.getByText('host-10')).toBeInTheDocument()
    })

    await user.click(getHostCheckbox('host-10'))

    await waitFor(() => {
      expect(screen.getByText(/3 hosts selected/i)).toBeInTheDocument()
    })

    const kRow = screen.getByText('host-10').closest('tr')
    expect(kRow).not.toHaveClass('Mui-selected')

    // ── Navigate to Step 1 and verify only the 3 remaining hosts ───────
    await goToPrevPage(user)
    await waitFor(() => {
      expect(screen.getByText('host-00')).toBeInTheDocument()
    })

    await user.click(screen.getByRole('button', { name: /^next$/i }))

    await waitFor(() => {
      expect(screen.getByText(/Selected Hosts \(3\)/i)).toBeInTheDocument()
    })

    // Remaining: host-00, host-02, host-11
    expect(screen.getByText('host-00')).toBeInTheDocument()
    expect(screen.getByText('host-02')).toBeInTheDocument()
    expect(screen.getByText('host-11')).toBeInTheDocument()

    // Deselected hosts should NOT appear
    expect(screen.queryByText('host-01')).not.toBeInTheDocument()
    expect(screen.queryByText('host-10')).not.toBeInTheDocument()
    expect(screen.queryByText('host-20')).not.toBeInTheDocument()
  })

  it('select all accounts for items across all pages, not just current page', async () => {
    // 35 hosts with 10 per page = 4 pages (10, 10, 10, 5)
    const manyHosts: Host[] = Array.from({ length: 35 }, (_, i) =>
      makeHost(`h${i}`, `host-${i.toString().padStart(2, '0')}`),
    )
    setupMultiPageMock(manyHosts)

    const user = userEvent.setup()
    renderPage()

    await waitFor(() => {
      expect(screen.getByText('host-00')).toBeInTheDocument()
    })

    await changeRowsPerPage(user, '10')

    await waitFor(() => {
      expect(screen.getByText('host-00')).toBeInTheDocument()
    })

    // ── Page 1: click "select all" → 10 selected ───────────────────────
    await user.click(getSelectAllCheckbox())

    await waitFor(() => {
      expect(screen.getByText(/10 hosts selected/i)).toBeInTheDocument()
    })

    // Header checkbox should be checked (all on this page selected)
    expect(getSelectAllCheckbox()).toBeChecked()

    // All 10 rows on page 1 should be selected
    for (let i = 0; i < 10; i++) {
      const row = screen.getByText(`host-${i.toString().padStart(2, '0')}`).closest('tr')
      expect(row).toHaveClass('Mui-selected')
    }

    // ── Navigate to page 2: header checkbox should be unchecked ────────
    await goToNextPage(user)
    await waitFor(() => {
      expect(screen.getByText('host-10')).toBeInTheDocument()
    })

    // Page 2 hosts should NOT be selected
    expect(getSelectAllCheckbox()).not.toBeChecked()
    const kRow = screen.getByText('host-10').closest('tr')
    expect(kRow).not.toHaveClass('Mui-selected')

    // Total count should still be 10 (only page 1)
    expect(screen.getByText(/10 hosts selected/i)).toBeInTheDocument()

    // ── Page 2: click "select all" → 20 total ──────────────────────────
    await user.click(getSelectAllCheckbox())

    await waitFor(() => {
      expect(screen.getByText(/20 hosts selected/i)).toBeInTheDocument()
    })

    expect(getSelectAllCheckbox()).toBeChecked()

    // ── Navigate to page 3: select all → 30 total ──────────────────────
    await goToNextPage(user)
    await waitFor(() => {
      expect(screen.getByText('host-20')).toBeInTheDocument()
    })

    expect(getSelectAllCheckbox()).not.toBeChecked()

    await user.click(getSelectAllCheckbox())

    await waitFor(() => {
      expect(screen.getByText(/30 hosts selected/i)).toBeInTheDocument()
    })

    // ── Navigate to page 4 (5 hosts): select all → 35 total ────────────
    await goToNextPage(user)
    await waitFor(() => {
      expect(screen.getByText('host-30')).toBeInTheDocument()
    })

    expect(getSelectAllCheckbox()).not.toBeChecked()

    await user.click(getSelectAllCheckbox())

    await waitFor(() => {
      expect(screen.getByText(/35 hosts selected/i)).toBeInTheDocument()
    })

    // ── Navigate back to page 1: all still selected, header checked ────
    await goToPrevPage(user)
    await waitFor(() => {
      expect(screen.getByText('host-20')).toBeInTheDocument()
    })
    await goToPrevPage(user)
    await waitFor(() => {
      expect(screen.getByText('host-10')).toBeInTheDocument()
    })
    await goToPrevPage(user)
    await waitFor(() => {
      expect(screen.getByText('host-00')).toBeInTheDocument()
    })

    expect(getSelectAllCheckbox()).toBeChecked()
    expect(screen.getByText(/35 hosts selected/i)).toBeInTheDocument()

    // ── Deselect all on page 1 → count drops by 10 to 25 ───────────────
    await user.click(getSelectAllCheckbox())

    await waitFor(() => {
      expect(screen.getByText(/25 hosts selected/i)).toBeInTheDocument()
    })

    expect(getSelectAllCheckbox()).not.toBeChecked()

    // Page 1 rows should no longer be selected
    for (let i = 0; i < 10; i++) {
      const row = screen.getByText(`host-${i.toString().padStart(2, '0')}`).closest('tr')
      expect(row).not.toHaveClass('Mui-selected')
    }

    // ── Navigate to page 2: still all selected, header checked ─────────
    await goToNextPage(user)
    await waitFor(() => {
      expect(screen.getByText('host-10')).toBeInTheDocument()
    })

    expect(getSelectAllCheckbox()).toBeChecked()
    expect(screen.getByText(/25 hosts selected/i)).toBeInTheDocument()

    // ── Indeterminate state: deselect one host on page 2 ───────────────
    await user.click(getHostCheckbox('host-10'))

    await waitFor(() => {
      expect(screen.getByText(/24 hosts selected/i)).toBeInTheDocument()
    })

    // Header checkbox should now be indeterminate (some but not all on page 2)
    expect(getSelectAllCheckbox()).toHaveAttribute('data-indeterminate', 'true')

    // ── Click select all on page 2 with indeterminate state ─────────────
    // Should select all on page 2 again → back to 25
    await user.click(getSelectAllCheckbox())

    await waitFor(() => {
      expect(screen.getByText(/25 hosts selected/i)).toBeInTheDocument()
    })

    expect(getSelectAllCheckbox()).toBeChecked()

    // ── Navigate to Step 1 and verify 25 hosts in review ───────────────
    await goToPrevPage(user)
    await waitFor(() => {
      expect(screen.getByText('host-00')).toBeInTheDocument()
    })

    await user.click(screen.getByRole('button', { name: /^next$/i }))

    await waitFor(() => {
      expect(screen.getByText(/Selected Hosts \(25\)/i)).toBeInTheDocument()
    })

    // Verify a sampling of hosts from pages 2, 3, and 4 are present
    expect(screen.getByText('host-10')).toBeInTheDocument()
    expect(screen.getByText('host-20')).toBeInTheDocument()
    expect(screen.getByText('host-30')).toBeInTheDocument()

    // Page 1 hosts should NOT be in the review (they were deselected)
    expect(screen.queryByText('host-00')).not.toBeInTheDocument()
    expect(screen.queryByText('host-09')).not.toBeInTheDocument()
  })
})