import axios, { AxiosInstance, AxiosResponse } from 'axios'
import toast from 'react-hot-toast'

class ApiClient {
  private client: AxiosInstance

  constructor() {
    this.client = axios.create({
      baseURL: '/api',
      timeout: 30000,
      headers: {
        'Content-Type': 'application/json',
      },
    })

    this.setupInterceptors()
  }

  private setupInterceptors() {
    // Request interceptor
    this.client.interceptors.request.use(
      (config) => {
        const token = localStorage.getItem('access_token')
        if (token) {
          config.headers.Authorization = `Bearer ${token}`
        }
        return config
      },
      (error) => {
        return Promise.reject(error)
      }
    )

    // Response interceptor
    this.client.interceptors.response.use(
      (response: AxiosResponse) => {
        return response
      },
      (error) => {
        const { response } = error

        if (response) {
          switch (response.status) {
            case 401:
              // Unauthorized - clear token and redirect to login
              localStorage.removeItem('access_token')
              localStorage.removeItem('refresh_token')
              window.location.href = '/login'
              toast.error('Session expired. Please login again.')
              break
            case 403:
              toast.error('Access denied. You don\'t have permission to perform this action.')
              break
            case 404:
              toast.error('Resource not found.')
              break
            case 429:
              toast.error('Too many requests. Please try again later.')
              break
            case 500:
              toast.error('Server error. Please try again later.')
              break
            default:
              const message = response.data?.error || response.data?.message || 'An error occurred'
              toast.error(message)
          }
        } else if (error.code === 'ECONNABORTED') {
          toast.error('Request timeout. Please check your connection and try again.')
        } else if (error.message === 'Network Error') {
          toast.error('Network error. Please check your connection.')
        } else {
          toast.error('An unexpected error occurred.')
        }

        return Promise.reject(error)
      }
    )
  }

  async get<T>(url: string, params?: any): Promise<T> {
    const response = await this.client.get(url, { params })
    return response.data
  }

  async post<T>(url: string, data?: any): Promise<T> {
    const response = await this.client.post(url, data)
    return response.data
  }

  async put<T>(url: string, data?: any): Promise<T> {
    const response = await this.client.put(url, data)
    return response.data
  }

  async delete<T>(url: string): Promise<T> {
    const response = await this.client.delete(url)
    return response.data
  }

  async patch<T>(url: string, data?: any): Promise<T> {
    const response = await this.client.patch(url, data)
    return response.data
  }
}

export const apiClient = new ApiClient()

// API endpoints
export const authEndpoints = {
  login: '/auth/login',
  register: '/auth/register',
  logout: '/auth/logout',
  me: '/auth/me',
  refresh: '/auth/refresh',
  changePassword: '/auth/change-password',
  updateProfile: '/auth/update-profile',
  deleteAccount: '/auth/delete-account',
}

export const scanEndpoints = {
  list: '/scans',
  create: '/scans',
  get: (id: number) => `/scans/${id}`,
  delete: (id: number) => `/scans/${id}`,
  start: (id: number) => `/scans/${id}/start`,
  cancel: (id: number) => `/scans/${id}/cancel`,
  pause: (id: number) => `/scans/${id}/pause`,
  resume: (id: number) => `/scans/${id}/resume`,
  status: (id: number) => `/scans/${id}/status`,
  stats: '/scans/stats',
  engineStatus: '/scans/engine/status',
  testApis: '/scans/test-apis',
  threatAnalysis: (id: number) => `/scans/threat-analysis/${id}`,
  correlations: (id: number) => `/scans/correlations/${id}`,
}

export const resultsEndpoints = {
  getByScan: (scanId: number) => `/results/scan/${scanId}`,
  get: (id: number) => `/results/${id}`,
  search: '/results/search',
  export: '/results/export',
  stats: '/results/stats',
}

export const reportsEndpoints = {
  list: '/reports',
  create: '/reports',
  get: (id: number) => `/reports/${id}`,
  delete: (id: number) => `/reports/${id}`,
  download: (id: number) => `/reports/${id}/download`,
  templates: '/reports/templates',
  stats: '/reports/stats',
}

export const settingsEndpoints = {
  apiKeys: '/settings/api-keys',
  profile: '/settings/profile',
  preferences: '/settings/preferences',
}