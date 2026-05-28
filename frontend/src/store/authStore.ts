import axios from 'axios'
import { create } from 'zustand'
import { persist } from 'zustand/middleware'
import type { User } from '../types'

interface AuthState {
  accessToken: string | null
  refreshToken: string | null
  user: User | null
  isAuthenticated: boolean
  isRestoring: boolean
  setTokens: (access: string, refresh: string) => void
  setUser: (user: User) => void
  logout: () => void
  restoreSession: () => Promise<void>
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set, get) => ({
      accessToken: null,
      refreshToken: null,
      user: null,
      isAuthenticated: false,
      isRestoring: true,

      setTokens: (access, refresh) =>
        set({ accessToken: access, refreshToken: refresh, isAuthenticated: true }),

      setUser: (user) => set({ user }),

      logout: () =>
        set({ accessToken: null, refreshToken: null, user: null, isAuthenticated: false, isRestoring: false }),

      restoreSession: async () => {
        const { refreshToken } = get()
        if (!refreshToken) {
          console.warn('[auth] No refresh token found, skipping restoration')
          set({ isRestoring: false })
          return
        }

        try {
          const { data } = await axios.post(
            '/api/v1/auth/refresh',
            { refresh_token: refreshToken },
            { timeout: 10000 }
          )
          console.warn('[auth] Token refresh successful')
          set({
            accessToken: data.access_token,
            refreshToken: data.refresh_token,
            user: data.user ?? get().user,
            isAuthenticated: true,
            isRestoring: false,
          })
        } catch (err: unknown) {
          const status = (err as { response?: { status?: number } })?.response?.status
          const message = (err as Error)?.message
          console.warn('[auth] Token refresh failed:', status, message)
          set({
            accessToken: null,
            refreshToken: null,
            user: null,
            isAuthenticated: false,
            isRestoring: false,
          })
        }
      },
    }),
    {
      name: 'pm-auth',
      // Only persist refresh token; access token regenerated on load
      partialize: (state) => ({ refreshToken: state.refreshToken, user: state.user }),
    }
  )
)
