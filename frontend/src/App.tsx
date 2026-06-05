import { Routes, Route, Navigate } from 'react-router-dom'
import { useAuth } from '@/hooks/useAuth'
import { Layout } from '@/components/layout/Layout'
import { Login } from '@/components/auth/Login'
import { Register } from '@/components/auth/Register'
import { Dashboard } from '@/components/dashboard/Dashboard'
import { ScanForm } from '@/components/scan/ScanForm'
import { ScanHistory } from '@/components/history/ScanHistory'
import { ResultsViewer } from '@/components/results/ResultsViewer'
import { Reports } from '@/components/reports/Reports'
import { Settings } from '@/components/settings/Settings'
import { LoadingSpinner } from '@/components/common/LoadingSpinner'

function App() {
  const { user, isLoading } = useAuth()

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-background">
        <div className="text-center">
          <LoadingSpinner className="w-8 h-8 mx-auto mb-4" />
          <p className="text-muted-foreground">Loading OSINT Platform...</p>
        </div>
      </div>
    )
  }

  if (!user) {
    return (
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/register" element={<Register />} />
        <Route path="*" element={<Navigate to="/login" replace />} />
      </Routes>
    )
  }

  return (
    <Layout>
      <Routes>
        <Route path="/" element={<Navigate to="/dashboard" replace />} />
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/scan" element={<ScanForm />} />
        <Route path="/scan/:id" element={<ScanForm />} />
        <Route path="/history" element={<ScanHistory />} />
        <Route path="/results/:scanId" element={<ResultsViewer />} />
        <Route path="/reports" element={<Reports />} />
        <Route path="/reports/:id" element={<Reports />} />
        <Route path="/settings" element={<Settings />} />
        <Route path="*" element={<Navigate to="/dashboard" replace />} />
      </Routes>
    </Layout>
  )
}

export default App