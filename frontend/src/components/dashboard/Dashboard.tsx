import React from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/common/Card'
import { Badge } from '@/components/common/Badge'
import { Button } from '@/components/common/Button'
import { LoadingSpinner } from '@/components/common/LoadingSpinner'
import { 
  Shield, 
  Search, 
  TrendingUp, 
  AlertTriangle, 
  Clock,
  Eye,
  Plus
} from 'lucide-react'
import { apiClient, scanEndpoints } from '@/services/api'
import { formatRelativeTime, getStatusColor, getSeverityColor } from '@/utils/lib'

interface DashboardStats {
  status_counts: Record<string, number>
  type_counts: Record<string, number>
  total_scans: number
  total_results: number
  recent_scans: any[]
}

export function Dashboard() {
  const {
    data: stats,
    isLoading,
    error,
  } = useQuery({
    queryKey: ['dashboard', 'stats'],
    queryFn: () => apiClient.get<DashboardStats>(scanEndpoints.stats),
    refetchInterval: 30000, // Refresh every 30 seconds
  })

  const {
    data: engineStatus,
    isLoading: isEngineLoading,
  } = useQuery({
    queryKey: ['engine', 'status'],
    queryFn: () => apiClient.get(scanEndpoints.engineStatus),
    refetchInterval: 10000, // Refresh every 10 seconds
  })

  if (isLoading || isEngineLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <LoadingSpinner size="lg" />
      </div>
    )
  }

  if (error) {
    return (
      <div className="text-center py-12">
        <AlertTriangle className="h-12 w-12 text-destructive mx-auto mb-4" />
        <h3 className="text-lg font-semibold mb-2">Failed to load dashboard</h3>
        <p className="text-muted-foreground">Please try again later</p>
      </div>
    )
  }

  const statCards = [
    {
      title: 'Total Scans',
      value: stats?.total_scans || 0,
      icon: Shield,
      description: 'All time scans',
      color: 'text-blue-600',
    },
    {
      title: 'Total Results',
      value: stats?.total_results || 0,
      icon: Search,
      description: 'Findings discovered',
      color: 'text-green-600',
    },
    {
      title: 'Active Scans',
      value: engineStatus?.user_active_scans?.length || 0,
      icon: TrendingUp,
      description: 'Currently running',
      color: 'text-orange-600',
    },
    {
      title: 'High Severity',
      value: (stats?.status_counts?.high || 0) + (stats?.status_counts?.critical || 0),
      icon: AlertTriangle,
      description: 'Requires attention',
      color: 'text-red-600',
    },
  ]

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Dashboard</h1>
          <p className="text-muted-foreground">
            Welcome to your OSINT intelligence platform
          </p>
        </div>
        <Link to="/scan">
          <Button icon={<Plus className="h-4 w-4" />}>
            New Scan
          </Button>
        </Link>
      </div>

      {/* Stats Grid */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        {statCards.map((stat) => {
          const Icon = stat.icon
          return (
            <Card key={stat.title}>
              <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                <CardTitle className="text-sm font-medium">
                  {stat.title}
                </CardTitle>
                <Icon className={`h-4 w-4 ${stat.color}`} />
              </CardHeader>
              <CardContent>
                <div className="text-2xl font-bold">{stat.value}</div>
                <p className="text-xs text-muted-foreground">
                  {stat.description}
                </p>
              </CardContent>
            </Card>
          )
        })}
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        {/* Recent Scans */}
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between">
              <CardTitle>Recent Scans</CardTitle>
              <Link to="/history">
                <Button variant="outline" size="sm">
                  View All
                </Button>
              </Link>
            </div>
            <CardDescription>
              Your latest OSINT scans
            </CardDescription>
          </CardHeader>
          <CardContent>
            {stats?.recent_scans?.length ? (
              <div className="space-y-4">
                {stats.recent_scans.slice(0, 5).map((scan: any) => (
                  <div key={scan.id} className="flex items-center justify-between p-3 border rounded-lg">
                    <div className="flex-1 min-w-0">
                      <p className="font-medium truncate">{scan.name}</p>
                      <p className="text-sm text-muted-foreground">
                        {scan.target_type} • {formatRelativeTime(scan.created_at)}
                      </p>
                    </div>
                    <div className="flex items-center space-x-2 ml-4">
                      <Badge className={getStatusColor(scan.status)}>
                        {scan.status}
                      </Badge>
                      <Link to={`/results/${scan.id}`}>
                        <Button variant="ghost" size="sm">
                          <Eye className="h-4 w-4" />
                        </Button>
                      </Link>
                    </div>
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-center py-8">
                <Search className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
                <h3 className="text-lg font-semibold mb-2">No scans yet</h3>
                <p className="text-muted-foreground mb-4">
                  Start your first OSINT scan to see results here
                </p>
                <Link to="/scan">
                  <Button icon={<Plus className="h-4 w-4" />}>
                    Start Scan
                  </Button>
                </Link>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Engine Status */}
        <Card>
          <CardHeader>
            <CardTitle>Engine Status</CardTitle>
            <CardDescription>
              OSINT engine performance and activity
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <span className="text-sm font-medium">Active Scans</span>
                <span className="text-sm text-muted-foreground">
                  {engineStatus?.engine_statistics?.active_scans || 0} / {engineStatus?.engine_statistics?.max_concurrent_scans || 5}
                </span>
              </div>
              
              <div className="flex items-center justify-between">
                <span className="text-sm font-medium">Thread Pool</span>
                <span className="text-sm text-muted-foreground">
                  {engineStatus?.engine_statistics?.thread_pool_workers || 5} workers
                </span>
              </div>

              <div className="flex items-center justify-between">
                <span className="text-sm font-medium">Total Scans</span>
                <span className="text-sm text-muted-foreground">
                  {engineStatus?.user_total_scans || 0}
                </span>
              </div>

              {engineStatus?.user_active_scans?.length > 0 && (
                <div className="border-t pt-4">
                  <p className="text-sm font-medium mb-2">Active Scan IDs</p>
                  <div className="flex flex-wrap gap-2">
                    {engineStatus.user_active_scans.map((scanId: number) => (
                      <Badge key={scanId} variant="outline">
                        #{scanId}
                      </Badge>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Quick Actions */}
      <Card>
        <CardHeader>
          <CardTitle>Quick Actions</CardTitle>
          <CardDescription>
            Common tasks and shortcuts
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
            <Link to="/scan">
              <Button variant="outline" className="w-full justify-start">
                <Search className="h-4 w-4 mr-2" />
                New Scan
              </Button>
            </Link>
            <Link to="/history">
              <Button variant="outline" className="w-full justify-start">
                <Clock className="h-4 w-4 mr-2" />
                Scan History
              </Button>
            </Link>
            <Link to="/reports">
              <Button variant="outline" className="w-full justify-start">
                <Eye className="h-4 w-4 mr-2" />
                Reports
              </Button>
            </Link>
            <Link to="/settings">
              <Button variant="outline" className="w-full justify-start">
                <Shield className="h-4 w-4 mr-2" />
                Settings
              </Button>
            </Link>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}