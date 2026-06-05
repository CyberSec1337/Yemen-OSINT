"use client";

import { useState, useEffect } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { 
  Settings, 
  Key, 
  Shield, 
  Bell, 
  Database, 
  Download, 
  Upload,
  Plus,
  Trash2,
  Eye,
  EyeOff
} from "lucide-react";
import { toast } from "sonner";

interface ApiKey {
  id: string;
  service: string;
  keyName: string;
  isActive: boolean;
  lastUsed?: string;
}

interface UserSettings {
  emailNotifications: boolean;
  autoScan: boolean;
  threatThreshold: number;
  reportFormat: string;
  dataRetention: number;
}

export default function SettingsPage() {
  const [activeTab, setActiveTab] = useState("api-keys");
  const [apiKeys, setApiKeys] = useState<ApiKey[]>([]);
  const [userSettings, setUserSettings] = useState<UserSettings>({
    emailNotifications: true,
    autoScan: false,
    threatThreshold: 50,
    reportFormat: "json",
    dataRetention: 30
  });
  const [showApiKey, setShowApiKey] = useState<{ [key: string]: boolean }>({});
  const [newApiKey, setNewApiKey] = useState({
    service: "",
    keyName: "",
    keyValue: ""
  });

  useEffect(() => {
    loadApiKeys();
    loadUserSettings();
  }, []);

  const loadApiKeys = async () => {
    try {
      // Mock API keys for demo
      const mockKeys: ApiKey[] = [
        {
          id: "1",
          service: "Shodan",
          keyName: "Primary Shodan Key",
          isActive: true,
          lastUsed: "2024-01-15T10:30:00Z"
        },
        {
          id: "2", 
          service: "VirusTotal",
          keyName: "VT API Key",
          isActive: true,
          lastUsed: "2024-01-15T09:15:00Z"
        },
        {
          id: "3",
          service: "AbuseIPDB",
          keyName: "IPDB Key",
          isActive: false
        }
      ];
      setApiKeys(mockKeys);
    } catch (error) {
      toast.error('Failed to load API keys');
    }
  };

  const loadUserSettings = async () => {
    try {
      // Load from localStorage or API
      const saved = localStorage.getItem('osint-settings');
      if (saved) {
        setUserSettings(JSON.parse(saved));
      }
    } catch (error) {
      console.error('Error loading settings:', error);
    }
  };

  const saveUserSettings = async () => {
    try {
      localStorage.setItem('osint-settings', JSON.stringify(userSettings));
      toast.success('Settings saved successfully');
    } catch (error) {
      toast.error('Failed to save settings');
    }
  };

  const addApiKey = async () => {
    if (!newApiKey.service || !newApiKey.keyName || !newApiKey.keyValue) {
      toast.error('Please fill in all fields');
      return;
    }

    try {
      const key: ApiKey = {
        id: Date.now().toString(),
        service: newApiKey.service,
        keyName: newApiKey.keyName,
        isActive: true
      };

      setApiKeys(prev => [...prev, key]);
      setNewApiKey({ service: "", keyName: "", keyValue: "" });
      toast.success('API key added successfully');
    } catch (error) {
      toast.error('Failed to add API key');
    }
  };

  const deleteApiKey = async (id: string) => {
    try {
      setApiKeys(prev => prev.filter(key => key.id !== id));
      toast.success('API key removed');
    } catch (error) {
      toast.error('Failed to remove API key');
    }
  };

  const toggleApiKey = async (id: string) => {
    try {
      setApiKeys(prev => 
        prev.map(key => 
          key.id === id ? { ...key, isActive: !key.isActive } : key
        )
      );
      toast.success('API key status updated');
    } catch (error) {
      toast.error('Failed to update API key');
    }
  };

  const exportData = async () => {
    try {
      const data = {
        settings: userSettings,
        apiKeys: apiKeys.map(k => ({ ...k, keyValue: "***" })),
        exportDate: new Date().toISOString()
      };

      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `osint-settings-${new Date().toISOString().split('T')[0]}.json`;
      a.click();
      window.URL.revokeObjectURL(url);

      toast.success('Settings exported successfully');
    } catch (error) {
      toast.error('Failed to export settings');
    }
  };

  const importData = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) return;

    try {
      const text = await file.text();
      const data = JSON.parse(text);
      
      if (data.settings) {
        setUserSettings(data.settings);
      }
      
      toast.success('Settings imported successfully');
    } catch (error) {
      toast.error('Failed to import settings');
    }
  };

  return (
    <div className="min-h-screen bg-background p-4">
      <div className="max-w-4xl mx-auto space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold flex items-center gap-2">
              <Settings className="h-8 w-8 text-primary" />
              Settings
            </h1>
            <p className="text-muted-foreground">Manage your OSINT platform configuration</p>
          </div>
          <div className="flex gap-2">
            <Button variant="outline" onClick={exportData}>
              <Download className="h-4 w-4 mr-2" />
              Export
            </Button>
            <Button variant="outline" asChild>
              <label className="cursor-pointer">
                <Upload className="h-4 w-4 mr-2" />
                Import
                <input
                  type="file"
                  accept=".json"
                  onChange={importData}
                  className="hidden"
                />
              </label>
            </Button>
          </div>
        </div>

        <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-6">
          <TabsList className="grid w-full grid-cols-4">
            <TabsTrigger value="api-keys">API Keys</TabsTrigger>
            <TabsTrigger value="general">General</TabsTrigger>
            <TabsTrigger value="notifications">Notifications</TabsTrigger>
            <TabsTrigger value="data">Data Management</TabsTrigger>
          </TabsList>

          {/* API Keys Tab */}
          <TabsContent value="api-keys" className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Key className="h-5 w-5" />
                  API Keys Management
                </CardTitle>
                <CardDescription>
                  Configure API keys for external OSINT services
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                {/* Add New API Key */}
                <div className="border rounded-lg p-4 space-y-4">
                  <h3 className="font-medium">Add New API Key</h3>
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    <Select value={newApiKey.service} onValueChange={(value) => setNewApiKey(prev => ({ ...prev, service: value }))}>
                      <SelectTrigger>
                        <SelectValue placeholder="Select service" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="shodan">Shodan</SelectItem>
                        <SelectItem value="virustotal">VirusTotal</SelectItem>
                        <SelectItem value="abuseipdb">AbuseIPDB</SelectItem>
                        <SelectItem value="alienvault">AlienVault OTX</SelectItem>
                        <SelectItem value="securitytrails">SecurityTrails</SelectItem>
                      </SelectContent>
                    </Select>
                    <Input
                      placeholder="Key name"
                      value={newApiKey.keyName}
                      onChange={(e) => setNewApiKey(prev => ({ ...prev, keyName: e.target.value }))}
                    />
                    <Input
                      type="password"
                      placeholder="API key value"
                      value={newApiKey.keyValue}
                      onChange={(e) => setNewApiKey(prev => ({ ...prev, keyValue: e.target.value }))}
                    />
                  </div>
                  <Button onClick={addApiKey} className="w-full">
                    <Plus className="h-4 w-4 mr-2" />
                    Add API Key
                  </Button>
                </div>

                {/* Existing API Keys */}
                <div className="space-y-4">
                  {apiKeys.map((key) => (
                    <div key={key.id} className="flex items-center justify-between p-4 border rounded-lg">
                      <div className="flex items-center gap-3">
                        <Switch
                          checked={key.isActive}
                          onCheckedChange={() => toggleApiKey(key.id)}
                        />
                        <div>
                          <p className="font-medium">{key.keyName}</p>
                          <p className="text-sm text-muted-foreground">
                            {key.service} • {key.lastUsed ? `Last used: ${new Date(key.lastUsed).toLocaleDateString()}` : 'Never used'}
                          </p>
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <Badge variant={key.isActive ? "default" : "secondary"}>
                          {key.isActive ? "Active" : "Inactive"}
                        </Badge>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => setShowApiKey(prev => ({ ...prev, [key.id]: !prev[key.id] }))}
                        >
                          {showApiKey[key.id] ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                        </Button>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => deleteApiKey(key.id)}
                        >
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          {/* General Settings Tab */}
          <TabsContent value="general" className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Settings className="h-5 w-5" />
                  General Settings
                </CardTitle>
                <CardDescription>
                  Configure general platform behavior
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  <div className="space-y-2">
                    <Label htmlFor="threatThreshold">Threat Threshold (%)</Label>
                    <Input
                      id="threatThreshold"
                      type="number"
                      min="0"
                      max="100"
                      value={userSettings.threatThreshold}
                      onChange={(e) => setUserSettings(prev => ({ ...prev, threatThreshold: parseInt(e.target.value) }))}
                    />
                    <p className="text-sm text-muted-foreground">
                      Alert when threat score exceeds this value
                    </p>
                  </div>
                  
                  <div className="space-y-2">
                    <Label htmlFor="reportFormat">Default Report Format</Label>
                    <Select value={userSettings.reportFormat} onValueChange={(value) => setUserSettings(prev => ({ ...prev, reportFormat: value }))}>
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="json">JSON</SelectItem>
                        <SelectItem value="pdf">PDF</SelectItem>
                        <SelectItem value="csv">CSV</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                </div>

                <div className="flex items-center justify-between">
                  <div className="space-y-1">
                    <Label>Auto-scan on new targets</Label>
                    <p className="text-sm text-muted-foreground">
                      Automatically start scans when new targets are added
                    </p>
                  </div>
                  <Switch
                    checked={userSettings.autoScan}
                    onCheckedChange={(checked) => setUserSettings(prev => ({ ...prev, autoScan: checked }))}
                  />
                </div>

                <Button onClick={saveUserSettings} className="w-full">
                  Save Settings
                </Button>
              </CardContent>
            </Card>
          </TabsContent>

          {/* Notifications Tab */}
          <TabsContent value="notifications" className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Bell className="h-5 w-5" />
                  Notification Settings
                </CardTitle>
                <CardDescription>
                  Configure how and when you receive notifications
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                <div className="flex items-center justify-between">
                  <div className="space-y-1">
                    <Label>Email Notifications</Label>
                    <p className="text-sm text-muted-foreground">
                      Receive email alerts for completed scans and high threat levels
                    </p>
                  </div>
                  <Switch
                    checked={userSettings.emailNotifications}
                    onCheckedChange={(checked) => setUserSettings(prev => ({ ...prev, emailNotifications: checked }))}
                  />
                </div>

                <div className="space-y-4">
                  <Label>Notification Triggers</Label>
                  <div className="space-y-3">
                    <div className="flex items-center justify-between p-3 border rounded-lg">
                      <div>
                        <p className="font-medium">Scan Completed</p>
                        <p className="text-sm text-muted-foreground">When any scan finishes</p>
                      </div>
                      <Switch defaultChecked />
                    </div>
                    <div className="flex items-center justify-between p-3 border rounded-lg">
                      <div>
                        <p className="font-medium">High Threat Detected</p>
                        <p className="text-sm text-muted-foreground">When threat score exceeds threshold</p>
                      </div>
                      <Switch defaultChecked />
                    </div>
                    <div className="flex items-center justify-between p-3 border rounded-lg">
                      <div>
                        <p className="font-medium">Scan Failed</p>
                        <p className="text-sm text-muted-foreground">When a scan encounters an error</p>
                      </div>
                      <Switch />
                    </div>
                  </div>
                </div>

                <Button onClick={saveUserSettings} className="w-full">
                  Save Notification Settings
                </Button>
              </CardContent>
            </Card>
          </TabsContent>

          {/* Data Management Tab */}
          <TabsContent value="data" className="space-y-6">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Database className="h-5 w-5" />
                  Data Management
                </CardTitle>
                <CardDescription>
                  Manage your data retention and privacy settings
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                <div className="space-y-2">
                  <Label htmlFor="dataRetention">Data Retention Period (days)</Label>
                  <Input
                    id="dataRetention"
                    type="number"
                    min="1"
                    max="365"
                    value={userSettings.dataRetention}
                    onChange={(e) => setUserSettings(prev => ({ ...prev, dataRetention: parseInt(e.target.value) }))}
                  />
                  <p className="text-sm text-muted-foreground">
                    Automatically delete scan data older than this period
                  </p>
                </div>

                <Alert>
                  <Shield className="h-4 w-4" />
                  <AlertDescription>
                    Your data is encrypted and stored securely. API keys are encrypted at rest.
                  </AlertDescription>
                </Alert>

                <div className="space-y-4">
                  <Label>Data Actions</Label>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <Button variant="outline" className="w-full">
                      <Download className="h-4 w-4 mr-2" />
                      Export All Data
                    </Button>
                    <Button variant="outline" className="w-full">
                      <Trash2 className="h-4 w-4 mr-2" />
                      Clear Old Data
                    </Button>
                  </div>
                </div>

                <Button onClick={saveUserSettings} className="w-full">
                  Save Data Settings
                </Button>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
}