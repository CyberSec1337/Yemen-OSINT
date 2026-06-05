import { apiClient, authEndpoints } from './api'

export interface LoginCredentials {
  username: string
  password: string
}

export interface RegisterData {
  username: string
  email?: string
  password: string
}

export interface User {
  id: number
  username: string
  email?: string
  is_admin: boolean
  is_active: boolean
  created_at: string
  last_login?: string
  login_count: number
}

export interface AuthResponse {
  message: string
  user: User
  access_token: string
  refresh_token: string
}

export const authService = {
  async login(credentials: LoginCredentials): Promise<AuthResponse> {
    return apiClient.post(authEndpoints.login, credentials)
  },

  async register(data: RegisterData): Promise<AuthResponse> {
    return apiClient.post(authEndpoints.register, data)
  },

  async logout(): Promise<{ message: string }> {
    return apiClient.post(authEndpoints.logout)
  },

  async getCurrentUser(): Promise<{ user: User }> {
    return apiClient.get(authEndpoints.me)
  },

  async refreshToken(): Promise<{ access_token: string }> {
    return apiClient.post(authEndpoints.refresh)
  },

  async changePassword(data: { current_password: string; new_password: string }): Promise<{ message: string }> {
    return apiClient.post(authEndpoints.changePassword, data)
  },

  async updateProfile(data: { email?: string }): Promise<{ message: string; user: User }> {
    return apiClient.put(authEndpoints.updateProfile, data)
  },

  async deleteAccount(data: { password: string }): Promise<{ message: string }> {
    return apiClient.delete(authEndpoints.deleteAccount, data)
  },
}

// Token management
export const tokenManager = {
  getAccessToken(): string | null {
    return localStorage.getItem('access_token')
  },

  getRefreshToken(): string | null {
    return localStorage.getItem('refresh_token')
  },

  setTokens(accessToken: string, refreshToken: string): void {
    localStorage.setItem('access_token', accessToken)
    localStorage.setItem('refresh_token', refreshToken)
  },

  clearTokens(): void {
    localStorage.removeItem('access_token')
    localStorage.removeItem('refresh_token')
  },

  isTokenExpired(token: string): boolean {
    try {
      const payload = JSON.parse(atob(token.split('.')[1]))
      const now = Date.now() / 1000
      return payload.exp < now
    } catch {
      return true
    }
  },
}