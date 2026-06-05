import React, { createContext, useContext, useEffect, ReactNode } from 'react'
import { useAuth } from '@/hooks/useAuth'

interface AuthContextType {
  user: any
  isLoading: boolean
  isAuthenticated: boolean
  error: any
  login: (username: string, password: string) => Promise<any>
  register: (username: string, email: string, password: string) => Promise<any>
  logout: () => Promise<void>
  refreshToken: () => Promise<string>
}

const AuthContext = createContext<AuthContextType | undefined>(undefined)

interface AuthProviderProps {
  children: ReactNode
}

export function AuthProvider({ children }: AuthProviderProps) {
  const auth = useAuth()

  return (
    <AuthContext.Provider value={auth}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuthContext() {
  const context = useContext(AuthContext)
  if (context === undefined) {
    throw new Error('useAuthContext must be used within an AuthProvider')
  }
  return context
}