'use client'

import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'

const regions = [
  { name: 'الشرق الأوسط', value: 45, color: 'bg-blue-500' },
  { name: 'أوروبا', value: 25, color: 'bg-green-500' },
  { name: 'آسيا', value: 15, color: 'bg-yellow-500' },
  { name: 'أمريكا الشمالية', value: 10, color: 'bg-purple-500' },
  { name: 'أفريقيا', value: 5, color: 'bg-red-500' },
]

export function GeographyMap() {
  return (
    <Card className="bg-slate-800 border-slate-700 text-white">
      <CardHeader>
        <CardTitle className="text-white">حركة المرور الجغرافية</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="space-y-4">
          {/* Simple world map representation */}
          <div className="relative h-64 bg-slate-700 rounded-lg overflow-hidden">
            <div className="absolute inset-0 flex items-center justify-center">
              <div className="text-center">
                <div className="text-6xl mb-4">🌍</div>
                <p className="text-slate-400">خريطة تفاعلية للحركة المرورية</p>
              </div>
            </div>
            
            {/* Region indicators */}
            <div className="absolute top-8 right-8">
              <div className="w-4 h-4 bg-blue-500 rounded-full animate-pulse"></div>
            </div>
            <div className="absolute top-16 left-12">
              <div className="w-4 h-4 bg-green-500 rounded-full animate-pulse"></div>
            </div>
            <div className="absolute bottom-12 right-20">
              <div className="w-4 h-4 bg-yellow-500 rounded-full animate-pulse"></div>
            </div>
            <div className="absolute top-20 left-32">
              <div className="w-4 h-4 bg-purple-500 rounded-full animate-pulse"></div>
            </div>
            <div className="absolute bottom-20 left-16">
              <div className="w-4 h-4 bg-red-500 rounded-full animate-pulse"></div>
            </div>
          </div>
          
          {/* Region statistics */}
          <div className="space-y-2">
            {regions.map((region, index) => (
              <div key={index} className="flex items-center justify-between">
                <div className="flex items-center space-x-reverse space-x-2">
                  <div className={`w-3 h-3 rounded-full ${region.color}`}></div>
                  <span className="text-sm text-slate-300">{region.name}</span>
                </div>
                <span className="text-sm font-medium text-white">{region.value}%</span>
              </div>
            ))}
          </div>
        </div>
      </CardContent>
    </Card>
  )
}