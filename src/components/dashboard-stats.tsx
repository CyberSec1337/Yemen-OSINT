'use client'

import { Card, CardContent } from '@/components/ui/card'
import { TrendingUp, TrendingDown, Mail, DollarSign, ShoppingCart, Users } from 'lucide-react'

interface StatCardProps {
  title: string
  value: string
  change: number
  icon: React.ReactNode
}

function StatCard({ title, value, change, icon }: StatCardProps) {
  const isPositive = change > 0
  
  return (
    <Card className="bg-slate-800 border-slate-700 text-white">
      <CardContent className="p-6">
        <div className="flex items-center justify-between">
          <div>
            <p className="text-slate-400 text-sm mb-1">{title}</p>
            <p className="text-2xl font-bold text-white">{value}</p>
            <div className="flex items-center mt-2">
              {isPositive ? (
                <TrendingUp className="w-4 h-4 text-green-400 ml-1" />
              ) : (
                <TrendingDown className="w-4 h-4 text-red-400 ml-1" />
              )}
              <span className={`text-sm ${isPositive ? 'text-green-400' : 'text-red-400'}`}>
                {isPositive ? '+' : ''}{change}%
              </span>
            </div>
          </div>
          <div className="text-blue-400">
            {icon}
          </div>
        </div>
      </CardContent>
    </Card>
  )
}

export function DashboardStats() {
  const stats = [
    {
      title: 'الرسائل المرسلة',
      value: '12,361',
      change: 14,
      icon: <Mail className="w-8 h-8" />
    },
    {
      title: 'المبيعات المحققة',
      value: '431,225',
      change: 21,
      icon: <DollarSign className="w-8 h-8" />
    },
    {
      title: 'المستخدمون الجدد',
      value: '32,441',
      change: -5,
      icon: <Users className="w-8 h-8" />
    },
    {
      title: 'كمية المبيعات',
      value: '1,324,134',
      change: 43,
      icon: <ShoppingCart className="w-8 h-8" />
    }
  ]

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
      {stats.map((stat, index) => (
        <StatCard key={index} {...stat} />
      ))}
    </div>
  )
}