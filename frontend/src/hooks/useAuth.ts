import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useEffect } from 'react'
import { authService, tokenManager } from '@/services/auth'
import { User } from '@/services/auth'

export function useAuth() {
  const queryClient = useQueryClient()

  const {
    data: user,
    isLoading,
    error,
  } = useQuery({
    queryKey: ['auth', 'user'],
    queryFn: async () => {
      const token = tokenManager.getAccessToken()
      if (!token) {
        throw new Error('No token found')
      }

      if (tokenManager.isTokenExpired(token)) {
        throw new Error('Token expired')
      }

      const response = await authService.getCurrentUser()
      return response.user
    },
    retry: false,
    refetchOnWindowFocus: false,
    staleTime: 5 * 60 * 1000, // 5 minutes
  })

  const login = async (username: string, password: string) => {
    try {
      const response = await authService.login({ username, password })
      tokenManager.setTokens(response.access_token, response.refresh_token)
      
      // Invalidate and refetch user data
      queryClient.invalidateQueries({ queryKey: ['auth', 'user'] })
      
      return response
    } catch (error) {
      throw error
    }
  }

  const register = async (username: string, email: string, password: string) => {
    try {
      const response = await authService.register({ username, email, password })
      tokenManager.setTokens(response.access_token, response.refresh_token)
      
      // Invalidate and refetch user data
      queryClient.invalidateQueries({ queryKey: ['auth', 'user'] })
      
      return response
    } catch (error) {
      throw error
    }
  }

  const logout = async () => {
    try {
      await authService.logout()
    } catch (error) {
      // Continue with logout even if API call fails
      console.error('Logout API call failed:', error)
    } finally {
      tokenManager.clearTokens()
      queryClient.clear()
    }
  }

  const refreshToken = async () => {
    try {
      const response = await authService.refreshToken()
      tokenManager.setTokens(response.access_token, tokenManager.getRefreshToken()!)
      return response.access_token
    } catch (error) {
      tokenManager.clearTokens()
      queryClient.clear()
      throw error
    }
  }

  // Auto-refresh token when it's about to expire
  useEffect(() => {
    if (!user) return

    const token = tokenManager.getAccessToken()
    if (!token) return

    try {
      const payload = JSON.parse(atob(token.split('.')[1]))
      const exp = payload.exp * 1000 // Convert to milliseconds
      const now = Date.now()
      const timeUntilExpiry = exp - now

      // Refresh token 5 minutes before it expires
      const refreshTime = Math.max(timeUntilExpiry - 5 * 60 * 1000, 0)

      if (refreshTime > 0) {
        const timeout = setTimeout(() => {
          refreshToken().catch((error) => {
            console.error('Token refresh failed:', error)
          })
        }, refreshTime)

        return () => clearTimeout(timeout)
      }
    } catch (error) {
      console.error('Error parsing token:', error)
    }
  }, [user])

  return {
    user,
    isLoading,
    isAuthenticated: !!user,
    error,
    login,
    register,
    logout,
    refreshToken,
  }
}