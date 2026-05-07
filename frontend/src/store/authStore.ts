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
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set) => ({
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
    }),
    {
      name: 'pm-auth',
      // Only persist refresh token; access token regenerated on load
      partialize: (state) => ({ refreshToken: state.refreshToken, user: state.user }),
      onRehydrateStorage: () => {
        return (state) => {
          if (state?.refreshToken) {
            // Proactively refresh the access token using the persisted refresh token
            axios.post('/api/v1/auth/refresh', { refresh_token: state.refreshToken })
              .then(({ data }) => {
                useAuthStore.setState({
                  accessToken: data.access_token,
                  refreshToken: data.refresh_token,
                  isAuthenticated: true,
                  isRestoring: false,
                })
              })
              .catch(() => {
                // Refresh token expired or invalid — clear all auth state
                useAuthStore.setState({
                  accessToken: null,
                  refreshToken: null,
                  user: null,
                  isAuthenticated: false,
                  isRestoring: false,
                })
              })
          } else {
            // No refresh token — not logged in, skip restoration
            useAuthStore.setState({ isRestoring: false })
          }
        }
      },
    }
  )
)
