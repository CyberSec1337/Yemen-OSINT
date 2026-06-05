"use client";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Badge } from "@/components/ui/badge";
import { Database, Zap, Activity } from "lucide-react";

interface APIData {
  name: string;
  used: number;
  limit: number;
  status: 'online' | 'offline' | 'limited';
}

interface APIUsageChartProps {
  data?: APIData[];
  apiStatus?: any[];
  title?: string;
}

export function APIUsageChart({ data, apiStatus, title = "API Usage Overview" }: APIUsageChartProps) {
  // Process apiStatus data if provided, otherwise use direct data
  let processedData: APIData[];
  
  if (apiStatus && apiStatus.length > 0) {
    processedData = apiStatus.map(api => ({
      name: api.name,
      used: api.requestsUsed || 0,
      limit: api.requestsLimit || 1000,
      status: api.status || 'online'
    }));
  } else if (data && data.length > 0) {
    processedData = data;
  } else {
    processedData = [];
  }

  const getUsagePercentage = (used: number, limit: number) => {
    return Math.round((used / limit) * 100);
  };

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'online':
        return 'bg-green-500';
      case 'offline':
        return 'bg-red-500';
      case 'limited':
        return 'bg-yellow-500';
      default:
        return 'bg-gray-500';
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'online':
        return <Badge variant="default" className="text-xs">Online</Badge>;
      case 'offline':
        return <Badge variant="destructive" className="text-xs">Offline</Badge>;
      case 'limited':
        return <Badge variant="secondary" className="text-xs">Limited</Badge>;
      default:
        return <Badge variant="outline" className="text-xs">Unknown</Badge>;
    }
  };

  const totalUsed = processedData.reduce((sum, api) => sum + api.used, 0);
  const totalLimit = processedData.reduce((sum, api) => sum + api.limit, 0);
  const overallUsage = getUsagePercentage(totalUsed, totalLimit);

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
        <CardTitle className="text-sm font-medium flex items-center gap-2">
          <Database className="h-4 w-4" />
          {title}
        </CardTitle>
        <div className="flex items-center gap-1">
          <Activity className="h-4 w-4 text-muted-foreground" />
          <span className="text-xs text-muted-foreground">
            {processedData.filter(api => api.status === 'online').length}/{processedData.length} Active
          </span>
        </div>
      </CardHeader>
      <CardContent>
        <div className="space-y-4">
          {/* Overall Usage */}
          <div className="space-y-2">
            <div className="flex justify-between text-sm">
              <span className="text-muted-foreground">Overall Usage</span>
              <span className="font-medium">{totalUsed.toLocaleString()} / {totalLimit.toLocaleString()}</span>
            </div>
            <Progress value={overallUsage} className="h-2" />
            <div className="text-xs text-muted-foreground text-right">
              {overallUsage}% of total quota
            </div>
          </div>

          {/* Individual APIs */}
          <div className="space-y-3">
            {processedData.map((api, index) => {
              const usagePercentage = getUsagePercentage(api.used, api.limit);
              
              return (
                <div key={index} className="space-y-2">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <div className={`w-2 h-2 rounded-full ${getStatusColor(api.status)}`} />
                      <span className="text-sm font-medium truncate max-w-32">
                        {api.name}
                      </span>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="text-xs text-muted-foreground">
                        {api.used.toLocaleString()} / {api.limit.toLocaleString()}
                      </span>
                      {getStatusBadge(api.status)}
                    </div>
                  </div>
                  <Progress value={usagePercentage} className="h-1" />
                </div>
              );
            })}
          </div>

          {/* Summary Stats */}
          <div className="pt-3 border-t">
            <div className="grid grid-cols-3 gap-4 text-center">
              <div>
                <div className="text-lg font-bold text-green-600">
                  {processedData.filter(api => api.status === 'online').length}
                </div>
                <div className="text-xs text-muted-foreground">Online</div>
              </div>
              <div>
                <div className="text-lg font-bold text-yellow-600">
                  {processedData.filter(api => api.status === 'limited').length}
                </div>
                <div className="text-xs text-muted-foreground">Limited</div>
              </div>
              <div>
                <div className="text-lg font-bold text-red-600">
                  {processedData.filter(api => api.status === 'offline').length}
                </div>
                <div className="text-xs text-muted-foreground">Offline</div>
              </div>
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}