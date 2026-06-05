"use client";

import { useState, useEffect } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Progress } from "@/components/ui/progress";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Checkbox } from "@/components/ui/checkbox";
import { Textarea } from "@/components/ui/textarea";
import { 
  Loader2, Search, Shield, AlertTriangle, CheckCircle, Clock, FileText, Settings, History, 
  Trash2, ChevronDown, ChevronRight, Eye, Download, Globe, Lock, Mail, Fingerprint, 
  Database, Activity, Zap, Target, TrendingUp, Users, BarChart3, PieChart, 
  Filter, RefreshCw, Play, Pause, Square, DownloadCloud, Share2, Copy, ExternalLink,
  Cpu, HardDrive, Wifi, Server, Cloud, ShieldCheck, Bug, EyeOff, Camera, MessageCircle, Phone
} from "lucide-react";
import { toast } from "sonner";
import { ThreatChart } from "@/components/charts/threat-chart";
import { APIUsageChart } from "@/components/charts/api-usage-chart";
import { TimelineChart } from "@/components/charts/timeline-chart";
import { ThemeToggle } from "@/components/theme-toggle";

interface Scan {
  id: string;
  target: string;
  scanType: string;
  status: string;
  threatScore: number;
  startedAt: string;
  completedAt?: string;
  results?: ScanResult[];
  progress?: number;
  apisUsed?: string[];
}

interface ScanResult {
  id: string;
  source: string;
  dataType: string;
  threatLevel: number;
  data: string;
  timestamp?: string;
}

interface APIStatus {
  name: string;
  status: 'online' | 'offline' | 'limited';
  requestsUsed: number;
  requestsLimit: number;
  lastChecked: string;
}

export default function OSINTPlatform() {
  const [target, setTarget] = useState("");
  const [targetType, setTargetType] = useState("auto");
  const [scanType, setScanType] = useState("comprehensive");
  const [isScanning, setIsScanning] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [currentScan, setCurrentScan] = useState<Scan | null>(null);
  const [scanHistory, setScanHistory] = useState<Scan[]>([]);
  const [scanResults, setScanResults] = useState<ScanResult[]>([]);
  const [activeTab, setActiveTab] = useState("dashboard");
  const [isLoading, setIsLoading] = useState(true);
  const [currentUserId, setCurrentUserId] = useState<string>("");
  const [expandedResults, setExpandedResults] = useState<Set<string>>(new Set());
  const [selectedAPIs, setSelectedAPIs] = useState<string[]>([]);
  const [apiStatus, setApiStatus] = useState<APIStatus[]>([]);
  const [editingApi, setEditingApi] = useState<string | null>(null);
  const [apiThreatLevels, setApiThreatLevels] = useState<{[key: string]: number}>({});
  const [isDeleting, setIsDeleting] = useState(false);
  const [deleteConfirmOpen, setDeleteConfirmOpen] = useState(false);
  const [scanToDelete, setScanToDelete] = useState<string | null>(null);
  const [selectedScans, setSelectedScans] = useState<Set<string>>(new Set());
  const [apiFormOpen, setApiFormOpen] = useState(false);
  const [editingApiData, setEditingApiData] = useState<any>(null);
  const [customApis, setCustomApis] = useState<any[]>([]);
  const [scanStats, setScanStats] = useState({
    totalScans: 0,
    avgThreatScore: 0,
    successRate: 0,
    lastScanTime: ''
  });
  
  // Results filtering state
  const [resultsSearchQuery, setResultsSearchQuery] = useState("");
  const [threatFilter, setThreatFilter] = useState("all");
  const [sourceFilter, setSourceFilter] = useState("all");
  const [sortBy, setSortBy] = useState("threat-desc");

  // Timeline events for activity tracking
  const [timelineEvents, setTimelineEvents] = useState([
    {
      id: '1',
      timestamp: new Date(Date.now() - 1000 * 60 * 5).toISOString(),
      type: 'scan_completed' as const,
      title: 'Comprehensive scan completed',
      description: 'Scan for example.com completed with 15 results',
      severity: 'medium' as const
    },
    {
      id: '2',
      timestamp: new Date(Date.now() - 1000 * 60 * 10).toISOString(),
      type: 'api_call' as const,
      title: 'VirusTotal API called',
      description: 'Querying IP reputation for 192.168.1.1',
      severity: 'low' as const
    },
    {
      id: '3',
      timestamp: new Date(Date.now() - 1000 * 60 * 15).toISOString(),
      type: 'result_found' as const,
      title: 'High threat detected',
      description: 'Critical vulnerability found in target system',
      severity: 'high' as const
    }
  ]);

  // Available APIs for scanning
  const availableAPIs = [
    { id: 'virustotal', name: 'VirusTotal', icon: <Bug className="h-4 w-4" />, description: 'Malware and URL scanning' },
    { id: 'shodan', name: 'Shodan', icon: <Server className="h-4 w-4" />, description: 'Internet-connected devices' },
    { id: 'abuseipdb', name: 'AbuseIPDB', icon: <Shield className="h-4 w-4" />, description: 'IP reputation checking' },
    { id: 'securitytrails', name: 'SecurityTrails', icon: <Globe className="h-4 w-4" />, description: 'DNS and domain intelligence' },
    { id: 'urlscan', name: 'URLScan.io', icon: <Eye className="h-4 w-4" />, description: 'URL scanning and analysis' },
    { id: 'passivetotal', name: 'PassiveTotal', icon: <Database className="h-4 w-4" />, description: 'Threat intelligence platform' },
    { id: 'threatcrowd', name: 'ThreatCrowd', icon: <Users className="h-4 w-4" />, description: 'Threat intelligence feeds' },
    { id: 'hybridanalysis', name: 'Hybrid Analysis', icon: <Bug className="h-4 w-4" />, description: 'Malware analysis sandbox' },
    { id: 'instagram', name: 'Instagram Social', icon: <Camera className="h-4 w-4" />, description: 'Instagram location and media analysis' },
    { id: 'twitter', name: 'Twitter Community', icon: <MessageCircle className="h-4 w-4" />, description: 'Twitter community and user analysis' },
    { id: 'facebook', name: 'Facebook Scraper', icon: <Users className="h-4 w-4" />, description: 'Facebook post and reaction analysis' },
    { id: 'veriphone', name: 'VeriPhone', icon: <Phone className="h-4 w-4" />, description: 'Phone number validation and intelligence' },
    { id: 'tiktok', name: 'TikTok Scraper', icon: <Camera className="h-4 w-4" />, description: 'TikTok profile and email analysis' },
    { id: 'vulners', name: 'Vulners.com', icon: <ShieldCheck className="h-4 w-4" />, description: 'Vulnerability database and CVE search' },
    { id: 'breach-directory', name: 'BreachDirectory', icon: <Database className="h-4 w-4" />, description: 'Data breach and leak lookup' }
  ];

  // Load scan history and initialize
  useEffect(() => {
    initializeApp();
    initializeAPIStatus();
  }, []);

  const initializeApp = async () => {
    console.log('Initializing Yemen Cyber Intelligent Platform...');
    try {
      const userResponse = await fetch('/api/setup', { method: 'POST' });
      if (userResponse.ok) {
        const userData = await userResponse.json();
        setCurrentUserId(userData.user.id);
        toast.success('Yemen Cyber Intelligent Platform initialized successfully');
      }
      
      await loadScanHistory();
      await loadCustomApis();
      updateScanStats();
    } catch (error) {
      console.error('Error initializing app:', error);
      toast.error('Failed to initialize app. Please refresh the page.');
    } finally {
      setIsLoading(false);
    }
  };

  const initializeAPIStatus = () => {
    const status = availableAPIs.map(api => ({
      name: api.name,
      status: 'online' as const,
      requestsUsed: Math.floor(Math.random() * 100),
      requestsLimit: 1000,
      lastChecked: new Date().toISOString()
    }));
    setApiStatus(status);
    setSelectedAPIs(availableAPIs.map(api => api.id));
    
    // Initialize threat levels for APIs
    const threatLevels: {[key: string]: number} = {};
    availableAPIs.forEach(api => {
      threatLevels[api.id] = 2; // Default medium threat level
    });
    setApiThreatLevels(threatLevels);
  };

  const loadScanHistory = async () => {
    try {
      const response = await fetch('/api/scans');
      if (response.ok) {
        const scans = await response.json();
        setScanHistory(scans);
      }
    } catch (error) {
      console.error('Error loading scan history:', error);
      toast.error('Failed to load scan history');
    }
  };

  const updateScanStats = () => {
    const completedScans = scanHistory.filter(s => s.status === 'completed');
    const avgScore = completedScans.length > 0 
      ? completedScans.reduce((acc, scan) => acc + scan.threatScore, 0) / completedScans.length 
      : 0;
    
    setScanStats({
      totalScans: scanHistory.length,
      avgThreatScore: Math.round(avgScore),
      successRate: scanHistory.length > 0 ? Math.round((completedScans.length / scanHistory.length) * 100) : 0,
      lastScanTime: scanHistory.length > 0 ? new Date(scanHistory[0].startedAt).toLocaleString() : 'Never'
    });
  };

  const loadScanResults = async (scanId: string) => {
    try {
      const response = await fetch(`/api/results?scanId=${scanId}`);
      if (response.ok) {
        const results = await response.json();
        setScanResults(results);
      }
    } catch (error) {
      console.error('Error loading scan results:', error);
      toast.error('Failed to load scan results');
    }
  };

  const detectTargetType = (input: string): string => {
    // IP Address regex
    if (/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(input)) {
      return 'ip';
    }
    // Domain regex
    if (/^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9](?:\.[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9])*$/.test(input)) {
      return 'domain';
    }
    // Email regex
    if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(input)) {
      return 'email';
    }
    // URL regex
    if (/^https?:\/\/.+/.test(input)) {
      return 'url';
    }
    // Hash regex (MD5, SHA1, SHA256)
    if (/^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/.test(input)) {
      return 'hash';
    }
    return 'unknown';
  };

  const startScan = async () => {
    if (!target) {
      toast.error("Please enter a target to scan");
      return;
    }

    if (!currentUserId) {
      toast.error("User not initialized. Please refresh the page.");
      return;
    }

    if (selectedAPIs.length === 0) {
      toast.error("Please select at least one API for scanning");
      return;
    }

    const detectedType = targetType === 'auto' ? detectTargetType(target) : targetType;
    
    setIsScanning(true);
    setScanProgress(0);
    
    try {
      const response = await fetch('/api/scans', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          target,
          scanType,
          targetType: detectedType,
          userId: currentUserId,
          apis: selectedAPIs
        })
      });

      if (response.ok) {
        const newScan = await response.json();
        setCurrentScan(newScan);
        toast.success(`Starting ${scanType} scan for ${target} using ${selectedAPIs.length} APIs`);
        
        monitorScanProgress(newScan.id);
      } else {
        const errorData = await response.json();
        throw new Error(errorData.error || 'Failed to start scan');
      }
    } catch (error) {
      console.error('Error starting scan:', error);
      toast.error(error instanceof Error ? error.message : 'Failed to start scan');
      setIsScanning(false);
    }
  };

  const monitorScanProgress = async (scanId: string) => {
    const checkProgress = async () => {
      try {
        const response = await fetch('/api/scans');
        if (response.ok) {
          const scans = await response.json();
          const updatedScan = scans.find((s: Scan) => s.id === scanId);
          
          if (updatedScan) {
            setCurrentScan(updatedScan);
            
            if (updatedScan.status === 'running') {
              setScanProgress(prev => Math.min(prev + Math.random() * 15, 90));
              setTimeout(checkProgress, 1500);
            } else if (updatedScan.status === 'completed') {
              setScanProgress(100);
              setIsScanning(false);
              loadScanHistory();
              loadScanResults(scanId);
              updateScanStats();
              toast.success(`Scan completed for ${target}`);
            } else if (updatedScan.status === 'failed') {
              setIsScanning(false);
              toast.error('Scan failed');
            }
          }
        }
      } catch (error) {
        console.error('Error monitoring scan:', error);
      }
    };

    setTimeout(checkProgress, 1000);
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case "completed":
        return <CheckCircle className="h-4 w-4 text-green-500" />;
      case "running":
        return <Loader2 className="h-4 w-4 text-blue-500 animate-spin" />;
      case "failed":
        return <AlertTriangle className="h-4 w-4 text-red-500" />;
      default:
        return <Clock className="h-4 w-4 text-gray-500" />;
    }
  };

  const getTargetIcon = (type: string) => {
    switch (type) {
      case 'ip':
        return <Wifi className="h-4 w-4" />;
      case 'domain':
        return <Globe className="h-4 w-4" />;
      case 'url':
        return <ExternalLink className="h-4 w-4" />;
      case 'email':
        return <Mail className="h-4 w-4" />;
      case 'hash':
        return <Fingerprint className="h-4 w-4" />;
      default:
        return <Target className="h-4 w-4" />;
    }
  };

  const toggleAPISelection = (apiId: string) => {
    setSelectedAPIs(prev => 
      prev.includes(apiId) 
        ? prev.filter(id => id !== apiId)
        : [...prev, apiId]
    );
  };

  const selectAllAPIs = () => {
    setSelectedAPIs(availableAPIs.map(api => api.id));
  };

  const deselectAllAPIs = () => {
    setSelectedAPIs([]);
  };

  // Helper functions for results display
  const toggleResultExpansion = (resultId: string) => {
    const newExpanded = new Set(expandedResults);
    if (newExpanded.has(resultId)) {
      newExpanded.delete(resultId);
    } else {
      newExpanded.add(resultId);
    }
    setExpandedResults(newExpanded);
  };

  const formatResultData = (data: string, dataType: string) => {
    try {
      const parsed = JSON.parse(data);
      
      switch (dataType) {
        case 'IP Reputation':
        case 'Domain Reputation':
          return {
            'Malicious Detections': parsed.malicious_detections || 0,
            'Suspicious Indicators': parsed.suspicious_indicators || 0,
            'Clean Engines': parsed.clean_engines || 0,
            'Threat Score': parsed.threat_score || 'Low',
            'Last Analysis': parsed.last_analysis || 'Unknown'
          };
        
        case 'Network Analysis':
          return {
            'Open Ports': parsed.open_ports?.join(', ') || 'None',
            'Services': parsed.services?.join(', ') || 'None identified',
            'Vulnerabilities': parsed.vulnerabilities?.slice(0, 5).join(', ') || 'None detected',
            'ASN': parsed.asn || 'Unknown',
            'Organization': parsed.organization || 'Unknown'
          };
        
        case 'Malware Analysis':
          return {
            'Malicious': parsed.malicious || 0,
            'Suspicious': parsed.suspicious || 0,
            'Clean': parsed.clean || 0,
            'Undetected': parsed.undetected || 0,
            'File Type': parsed.file_type || 'Unknown',
            'File Size': parsed.file_size || 'Unknown'
          };
        
        case 'Abuse Reports':
          return {
            'Total Reports': parsed.total_reports || 0,
            'Confidence Score': `${parsed.confidence_score || 0}%`,
            'Last Report': parsed.last_report || 'No reports',
            'Abuse Types': parsed.abuse_types?.join(', ') || 'None'
          };
        
        case 'DNS Analysis':
          return {
            'A Records': parsed.a_records?.join(', ') || 'None',
            'MX Records': parsed.mx_records?.join(', ') || 'None',
            'NS Records': parsed.ns_records?.join(', ') || 'None',
            'TXT Records': parsed.txt_records?.slice(0, 3).join(', ') || 'None',
            'Domain Age': parsed.domain_age || 'Unknown'
          };
        
        case 'URL Analysis':
          return {
            'Malicious URL': parsed.is_malicious ? 'Yes' : 'No',
            'Phishing Detected': parsed.is_phishing ? 'Yes' : 'No',
            'Category': parsed.category || 'Uncategorized',
            'Reputation Score': parsed.reputation_score || 'Unknown',
            'First Seen': parsed.first_seen || 'Unknown'
          };
        
        default:
          return parsed;
      }
    } catch {
      return { 'Raw Data': data };
    }
  };

  const getThreatLevelColor = (level: number) => {
    if (level >= 4) return 'text-red-500 bg-red-50 border-red-200';
    if (level >= 3) return 'text-orange-500 bg-orange-50 border-orange-200';
    if (level >= 2) return 'text-yellow-500 bg-yellow-50 border-yellow-200';
    return 'text-green-500 bg-green-50 border-green-200';
  };

  const getThreatLevelText = (level: number) => {
    if (level >= 4) return 'Critical';
    if (level >= 3) return 'High';
    if (level >= 2) return 'Medium';
    return 'Low';
  };

  // Results filtering functions
  const getFilteredResults = () => {
    let filtered = [...scanResults];
    
    // Apply search filter
    if (resultsSearchQuery.trim()) {
      const query = resultsSearchQuery.toLowerCase();
      filtered = filtered.filter(result => 
        result.source.toLowerCase().includes(query) ||
        result.dataType.toLowerCase().includes(query) ||
        result.data.toLowerCase().includes(query)
      );
    }
    
    // Apply threat level filter
    if (threatFilter !== 'all') {
      filtered = filtered.filter(result => {
        const level = result.threatLevel;
        switch (threatFilter) {
          case 'critical': return level >= 4;
          case 'high': return level >= 3 && level < 4;
          case 'medium': return level >= 2 && level < 3;
          case 'low': return level < 2;
          default: return true;
        }
      });
    }
    
    // Apply source filter
    if (sourceFilter !== 'all') {
      filtered = filtered.filter(result => result.source === sourceFilter);
    }
    
    // Apply sorting
    filtered.sort((a, b) => {
      switch (sortBy) {
        case 'threat-desc': return b.threatLevel - a.threatLevel;
        case 'threat-asc': return a.threatLevel - b.threatLevel;
        case 'source': return a.source.localeCompare(b.source);
        case 'time': return new Date(b.timestamp || 0).getTime() - new Date(a.timestamp || 0).getTime();
        default: return 0;
      }
    });
    
    return filtered;
  };

  const clearFilters = () => {
    setResultsSearchQuery("");
    setThreatFilter("all");
    setSourceFilter("all");
    setSortBy("threat-desc");
  };

  const copyResultData = (result: ScanResult) => {
    const data = JSON.stringify(formatResultData(result.data, result.dataType), null, 2);
    navigator.clipboard.writeText(data).then(() => {
      toast.success('Result data copied to clipboard');
    }).catch(() => {
      toast.error('Failed to copy data');
    });
  };

  const downloadResultJSON = (result: ScanResult) => {
    const data = JSON.stringify({
      source: result.source,
      dataType: result.dataType,
      threatLevel: result.threatLevel,
      timestamp: result.timestamp,
      data: formatResultData(result.data, result.dataType)
    }, null, 2);
    
    const blob = new Blob([data], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `result-${result.source}-${new Date().toISOString().split('T')[0]}.json`;
    link.click();
    URL.revokeObjectURL(url);
    toast.success('Result downloaded successfully');
  };

  // API Settings functions
  const updateAPIThreatLevel = (apiId: string, level: number) => {
    setApiThreatLevels(prev => ({
      ...prev,
      [apiId]: level
    }));
    toast.success(`Updated threat level for ${apiId}`);
  };

  const saveAPISettings = async () => {
    try {
      const response = await fetch('/api/settings/apis', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          threatLevels: apiThreatLevels,
          selectedAPIs: selectedAPIs
        })
      });

      if (response.ok) {
        toast.success('API settings saved successfully');
      } else {
        throw new Error('Failed to save settings');
      }
    } catch (error) {
      console.error('Error saving API settings:', error);
      toast.error('Failed to save API settings');
    }
  };

  // Delete scan functions
  const deleteScan = async (scanId: string) => {
    setIsDeleting(true);
    try {
      const response = await fetch('/api/scans/delete', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          scanId: scanId
        })
      });

      if (response.ok) {
        const result = await response.json();
        const deletedScan = scanHistory.find(scan => scan.id === scanId);
        toast.success(`Scan for "${deletedScan?.target || 'Unknown'}" deleted successfully`);
        
        // Remove from local state
        setScanHistory(prev => prev.filter(scan => scan.id !== scanId));
        setScanResults(prev => prev.filter(result => result.scanId !== scanId));
        
        // Refresh data
        await loadScanHistory();
        updateScanStats();
      } else {
        throw new Error('Failed to delete scan');
      }
    } catch (error) {
      console.error('Error deleting scan:', error);
      toast.error('Failed to delete scan');
    } finally {
      setIsDeleting(false);
      setDeleteConfirmOpen(false);
      setScanToDelete(null);
    }
  };

  const deleteSelectedScans = async () => {
    if (selectedScans.size === 0) {
      toast.error('No scans selected');
      return;
    }

    setIsDeleting(true);
    try {
      const deletePromises = Array.from(selectedScans).map(scanId => 
        fetch('/api/scans/delete', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ scanId })
        })
      );

      await Promise.all(deletePromises);
      
      toast.success(`Successfully deleted ${selectedScans.size} scans`);
      
      // Remove from local state
      setScanHistory(prev => prev.filter(scan => !selectedScans.has(scan.id)));
      setScanResults(prev => prev.filter(result => !selectedScans.has(result.scanId)));
      setSelectedScans(new Set());
      
      // Refresh data
      await loadScanHistory();
      await updateScanStats();
    } catch (error) {
      console.error('Error deleting selected scans:', error);
      toast.error('Failed to delete some scans');
    } finally {
      setIsDeleting(false);
    }
  };

  const clearAllScans = async () => {
    if (!currentUserId) {
      toast.error('User not authenticated');
      return;
    }

    setIsDeleting(true);
    try {
      const response = await fetch('/api/scans/clear-all', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          userId: currentUserId
        })
      });

      if (response.ok) {
        const result = await response.json();
        toast.success(result.message || 'All scans cleared successfully');
        
        // Clear local state
        setScanHistory([]);
        setScanResults([]);
        setSelectedScans(new Set());
        
        // Refresh stats
        await updateScanStats();
      } else {
        throw new Error('Failed to clear all scans');
      }
    } catch (error) {
      console.error('Error clearing all scans:', error);
      toast.error('Failed to clear all scans');
    } finally {
      setIsDeleting(false);
      setDeleteConfirmOpen(false);
    }
  };

  const confirmDeleteScan = (scanId: string) => {
    setScanToDelete(scanId);
    setDeleteConfirmOpen(true);
  };

  const toggleScanSelection = (scanId: string) => {
    setSelectedScans(prev => {
      const newSet = new Set(prev);
      if (newSet.has(scanId)) {
        newSet.delete(scanId);
      } else {
        newSet.add(scanId);
      }
      return newSet;
    });
  };

  // API Management functions
  const loadCustomApis = async () => {
    try {
      const response = await fetch('/api/apis');
      if (response.ok) {
        const apis = await response.json();
        setCustomApis(apis);
      }
    } catch (error) {
      console.error('Error loading custom APIs:', error);
    }
  };

  const saveApi = async (apiData: any) => {
    try {
      const method = apiData.id ? 'PUT' : 'POST';
      const response = await fetch('/api/apis', {
        method,
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(apiData)
      });

      if (response.ok) {
        const result = await response.json();
        toast.success(result.message);
        setApiFormOpen(false);
        setEditingApiData(null);
        await loadCustomApis();
      } else {
        throw new Error('Failed to save API');
      }
    } catch (error) {
      console.error('Error saving API:', error);
      toast.error('Failed to save API');
    }
  };

  const deleteApi = async (apiId: string) => {
    try {
      const response = await fetch(`/api/apis?id=${apiId}`, {
        method: 'DELETE'
      });

      if (response.ok) {
        const result = await response.json();
        toast.success(result.message);
        await loadCustomApis();
      } else {
        throw new Error('Failed to delete API');
      }
    } catch (error) {
      console.error('Error deleting API:', error);
      toast.error('Failed to delete API');
    }
  };

  const openApiForm = (api?: any) => {
    setEditingApiData(api || {
      name: '',
      description: '',
      endpoint: '',
      method: 'GET',
      headers: {},
      enabled: true,
      category: 'general',
      threatLevel: 2
    });
    setApiFormOpen(true);
  };

  if (isLoading) {
    return (
      <div className="min-h-screen bg-background flex items-center justify-center">
        <div className="text-center">
          <Loader2 className="h-8 w-8 animate-spin mx-auto mb-4" />
          <p className="text-lg font-medium">Initializing Yemen Cyber Intelligent Platform...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-background">
      <div className="flex">
        {/* Sidebar */}
        <div className="w-64 bg-card border-r min-h-screen p-4">
          <div className="mb-8">
            <h1 className="text-2xl font-bold text-foreground mb-2">Yemen Cyber</h1>
            <p className="text-sm text-muted-foreground">Cyber Intelligence Platform</p>
          </div>
          
          <nav className="space-y-2">
            <Button
              variant={activeTab === "dashboard" ? "default" : "ghost"}
              className="w-full justify-start"
              onClick={() => setActiveTab("dashboard")}
            >
              <BarChart3 className="h-4 w-4 mr-2" />
              Dashboard
            </Button>
            <Button
              variant={activeTab === "scan" ? "default" : "ghost"}
              className="w-full justify-start"
              onClick={() => setActiveTab("scan")}
            >
              <Search className="h-4 w-4 mr-2" />
              New Scan
            </Button>
            <Button
              variant={activeTab === "results" ? "default" : "ghost"}
              className="w-full justify-start"
              onClick={() => setActiveTab("results")}
            >
              <Eye className="h-4 w-4 mr-2" />
              Results
            </Button>
            <Button
              variant={activeTab === "history" ? "default" : "ghost"}
              className="w-full justify-start"
              onClick={() => setActiveTab("history")}
            >
              <History className="h-4 w-4 mr-2" />
              History
            </Button>
            <Button
              variant={activeTab === "settings" ? "default" : "ghost"}
              className="w-full justify-start"
              onClick={() => setActiveTab("settings")}
            >
              <Settings className="h-4 w-4 mr-2" />
              Settings
            </Button>
          </nav>

          <div className="mt-8 pt-8 border-t">
            <div className="space-y-4">
              <div className="text-sm">
                <div className="flex justify-between mb-2">
                  <span className="text-muted-foreground">Total Scans</span>
                  <span className="font-medium">{scanStats.totalScans}</span>
                </div>
                <div className="flex justify-between mb-2">
                  <span className="text-muted-foreground">Avg Threat</span>
                  <span className="font-medium">{scanStats.avgThreatScore}/4</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Success Rate</span>
                  <span className="font-medium">{scanStats.successRate}%</span>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Main Content */}
        <div className="flex-1 p-6">
          <div className="mb-6 flex justify-between items-center">
            <div>
              <h2 className="text-3xl font-bold text-foreground">
                {activeTab === "dashboard" && "Dashboard"}
                {activeTab === "scan" && "New Scan"}
                {activeTab === "results" && "Results"}
                {activeTab === "history" && "Scan History"}
                {activeTab === "settings" && "Settings"}
              </h2>
              <p className="text-muted-foreground mt-1">
                {activeTab === "dashboard" && "Overview of platform activity and threats"}
                {activeTab === "scan" && "Start a new scan using available APIs"}
                {activeTab === "results" && "View completed scan results"}
                {activeTab === "history" && "Previous scans and results history"}
                {activeTab === "settings" && "Platform settings and API configuration"}
              </p>
            </div>
            <ThemeToggle />
          </div>

          {/* Dashboard Tab */}
          {activeTab === "dashboard" && (
            <div className="space-y-6">
              {/* Stats Cards */}
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                <Card>
                  <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                    <CardTitle className="text-sm font-medium">Total Scans</CardTitle>
                    <Search className="h-4 w-4 text-muted-foreground" />
                  </CardHeader>
                  <CardContent>
                    <div className="text-2xl font-bold">{scanStats.totalScans}</div>
                    <p className="text-xs text-muted-foreground">
                      Last scan: {scanStats.lastScanTime}
                    </p>
                  </CardContent>
                </Card>
                <Card>
                  <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                    <CardTitle className="text-sm font-medium">Avg Threat Level</CardTitle>
                    <Shield className="h-4 w-4 text-muted-foreground" />
                  </CardHeader>
                  <CardContent>
                    <div className="text-2xl font-bold">{scanStats.avgThreatScore}/4</div>
                    <p className="text-xs text-muted-foreground">
                      Based on {scanHistory.filter(s => s.status === 'completed').length} completed scans
                    </p>
                  </CardContent>
                </Card>
                <Card>
                  <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                    <CardTitle className="text-sm font-medium">Success Rate</CardTitle>
                    <CheckCircle className="h-4 w-4 text-muted-foreground" />
                  </CardHeader>
                  <CardContent>
                    <div className="text-2xl font-bold">{scanStats.successRate}%</div>
                    <p className="text-xs text-muted-foreground">
                      {scanHistory.filter(s => s.status === 'completed').length} of {scanHistory.length} completed
                    </p>
                  </CardContent>
                </Card>
                <Card>
                  <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                    <CardTitle className="text-sm font-medium">APIs</CardTitle>
                    <Database className="h-4 w-4 text-muted-foreground" />
                  </CardHeader>
                  <CardContent>
                    <div className="text-2xl font-bold">{availableAPIs.length}</div>
                    <p className="text-xs text-muted-foreground">
                      {apiStatus.filter(s => s.status === 'online').length} active
                    </p>
                  </CardContent>
                </Card>
              </div>

              {/* Charts */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <ThreatChart scans={scanHistory} />
                <APIUsageChart apiStatus={apiStatus} />
              </div>

              {/* Timeline */}
              <Card>
                <CardHeader>
                  <CardTitle>Recent Activity</CardTitle>
                </CardHeader>
                <CardContent>
                  <TimelineChart events={timelineEvents} />
                </CardContent>
              </Card>
            </div>
          )}

          {/* Scan Tab */}
          {activeTab === "scan" && (
            <div className="space-y-6">
              <Card>
                <CardHeader>
                  <CardTitle>Start New Scan</CardTitle>
                  <CardDescription>
                    Enter target and select APIs to use for scanning
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div>
                      <label className="text-sm font-medium mb-2 block">Target</label>
                      <Input
                        placeholder="Enter IP, domain, email, or URL"
                        value={target}
                        onChange={(e) => setTarget(e.target.value)}
                        disabled={isScanning}
                      />
                    </div>
                    <div>
                      <label className="text-sm font-medium mb-2 block">Scan Type</label>
                      <Select value={scanType} onValueChange={setScanType} disabled={isScanning}>
                        <SelectTrigger>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="comprehensive">Comprehensive</SelectItem>
                          <SelectItem value="quick">Quick</SelectItem>
                          <SelectItem value="deep">Deep</SelectItem>
                          <SelectItem value="custom">Custom</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                  </div>

                  <div>
                    <label className="text-sm font-medium mb-2 block">Auto Type Detection</label>
                    <Select value={targetType} onValueChange={setTargetType} disabled={isScanning}>
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="auto">Auto</SelectItem>
                        <SelectItem value="ip">IP</SelectItem>
                        <SelectItem value="domain">Domain</SelectItem>
                        <SelectItem value="url">URL</SelectItem>
                        <SelectItem value="email">Email</SelectItem>
                        <SelectItem value="hash">Hash</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>

                  <div>
                    <div className="flex justify-between items-center mb-4">
                      <label className="text-sm font-medium">APIs</label>
                      <div className="space-x-2">
                        <Button variant="outline" size="sm" onClick={selectAllAPIs} disabled={isScanning}>
                          Select All
                        </Button>
                        <Button variant="outline" size="sm" onClick={deselectAllAPIs} disabled={isScanning}>
                          Deselect All
                        </Button>
                      </div>
                    </div>
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3 max-h-64 overflow-y-auto">
                      {availableAPIs.map((api) => (
                        <div key={api.id} className="flex items-center space-x-2 p-3 border rounded-lg">
                          <Checkbox
                            id={api.id}
                            checked={selectedAPIs.includes(api.id)}
                            onCheckedChange={() => toggleAPISelection(api.id)}
                            disabled={isScanning}
                          />
                          <div className="flex-1">
                            <label htmlFor={api.id} className="text-sm font-medium cursor-pointer">
                              {api.name}
                            </label>
                            <p className="text-xs text-muted-foreground">{api.description}</p>
                          </div>
                          {api.icon}
                        </div>
                      ))}
                    </div>
                  </div>

                  {isScanning && (
                    <div className="space-y-2">
                      <div className="flex justify-between text-sm">
                        <span>Scan progress...</span>
                        <span>{Math.round(scanProgress)}%</span>
                      </div>
                      <Progress value={scanProgress} className="w-full" />
                    </div>
                  )}

                  <Button 
                    onClick={startScan} 
                    disabled={isScanning || !target || selectedAPIs.length === 0}
                    className="w-full"
                  >
                    {isScanning ? (
                      <>
                        <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                        Scanning...
                      </>
                    ) : (
                      <>
                        <Search className="h-4 w-4 mr-2" />
                        Start Scan
                      </>
                    )}
                  </Button>
                </CardContent>
              </Card>
            </div>
          )}

          {/* Results Tab */}
          {activeTab === "results" && (
            <div className="space-y-6">
              {/* Results Header with Summary */}
              <Card>
                <CardHeader>
                  <div className="flex justify-between items-start">
                    <div>
                      <CardTitle className="text-2xl flex items-center gap-2">
                        <Eye className="h-6 w-6" />
                        Scan Results
                      </CardTitle>
                      <CardDescription>
                        Detailed analysis and findings from your security scans
                      </CardDescription>
                    </div>
                    {scanResults.length > 0 && (
                      <div className="flex items-center gap-2">
                        <Button variant="outline" size="sm" onClick={() => setExpandedResults(new Set(scanResults.map(r => r.id)))}>
                          <ChevronDown className="h-4 w-4 mr-1" />
                          Expand All
                        </Button>
                        <Button variant="outline" size="sm" onClick={() => setExpandedResults(new Set())}>
                          <ChevronRight className="h-4 w-4 mr-1" />
                          Collapse All
                        </Button>
                        <Button variant="outline" size="sm" onClick={() => {
                          const dataStr = JSON.stringify(scanResults, null, 2);
                          const dataBlob = new Blob([dataStr], { type: 'application/json' });
                          const url = URL.createObjectURL(dataBlob);
                          const link = document.createElement('a');
                          link.href = url;
                          link.download = `scan-results-${new Date().toISOString().split('T')[0]}.json`;
                          link.click();
                          URL.revokeObjectURL(url);
                          toast.success('All results exported successfully');
                        }}>
                          <Download className="h-4 w-4 mr-1" />
                          Export
                        </Button>
                      </div>
                    )}
                  </div>
                </CardHeader>
                {scanResults.length > 0 && (
                  <CardContent>
                    <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                      <div className="text-center p-4 bg-blue-50 dark:bg-blue-950 rounded-lg">
                        <div className="text-2xl font-bold text-blue-600 dark:text-blue-400">{scanResults.length}</div>
                        <div className="text-sm text-muted-foreground">Total Results</div>
                      </div>
                      <div className="text-center p-4 bg-red-50 dark:bg-red-950 rounded-lg">
                        <div className="text-2xl font-bold text-red-600 dark:text-red-400">
                          {scanResults.filter(r => r.threatLevel >= 4).length}
                        </div>
                        <div className="text-sm text-muted-foreground">Critical Threats</div>
                      </div>
                      <div className="text-center p-4 bg-yellow-50 dark:bg-yellow-950 rounded-lg">
                        <div className="text-2xl font-bold text-yellow-600 dark:text-yellow-400">
                          {scanResults.filter(r => r.threatLevel >= 2 && r.threatLevel < 4).length}
                        </div>
                        <div className="text-sm text-muted-foreground">Medium Threats</div>
                      </div>
                      <div className="text-center p-4 bg-green-50 dark:bg-green-950 rounded-lg">
                        <div className="text-2xl font-bold text-green-600 dark:text-green-400">
                          {scanResults.filter(r => r.threatLevel < 2).length}
                        </div>
                        <div className="text-sm text-muted-foreground">Low Threats</div>
                      </div>
                    </div>
                  </CardContent>
                )}
              </Card>

              {scanResults.length === 0 ? (
                <Card>
                  <CardContent className="text-center py-16">
                    <div className="relative">
                      <Eye className="h-16 w-16 text-muted-foreground mx-auto mb-4 opacity-50" />
                      <div className="absolute inset-0 flex items-center justify-center">
                        <Search className="h-8 w-8 text-muted-foreground opacity-30" />
                      </div>
                    </div>
                    <h3 className="text-xl font-semibold mb-2">No Scan Results Available</h3>
                    <p className="text-muted-foreground mb-6 max-w-md mx-auto">
                      Perform a security scan to see detailed results and analysis here. Results will be organized by threat level and source.
                    </p>
                    <Button onClick={() => setActiveTab("scan")} className="mx-auto">
                      <Search className="h-4 w-4 mr-2" />
                      Start New Scan
                    </Button>
                  </CardContent>
                </Card>
              ) : (
                <div className="space-y-6">
                  {/* Filter and Sort Controls */}
                  <Card>
                    <CardContent className="pt-6">
                      <div className="space-y-4">
                        {/* Search Bar */}
                        <div className="flex flex-col sm:flex-row gap-4">
                          <div className="flex-1">
                            <Input
                              placeholder="Search results by source, type, or data..."
                              value={resultsSearchQuery}
                              onChange={(e) => setResultsSearchQuery(e.target.value)}
                              className="w-full"
                            />
                          </div>
                          <Button variant="outline" onClick={clearFilters}>
                            <RefreshCw className="h-4 w-4 mr-2" />
                            Clear Filters
                          </Button>
                        </div>
                        
                        {/* Filter Badges and Sort */}
                        <div className="flex flex-wrap gap-4 items-center justify-between">
                          <div className="flex flex-wrap gap-2">
                            <Badge 
                              variant={threatFilter === "all" ? "default" : "outline"} 
                              className="cursor-pointer hover:bg-primary hover:text-primary-foreground"
                              onClick={() => setThreatFilter("all")}
                            >
                              All Results ({scanResults.length})
                            </Badge>
                            <Badge 
                              variant={threatFilter === "critical" ? "default" : "outline"} 
                              className="cursor-pointer hover:bg-red-100 hover:text-red-800 dark:hover:bg-red-900 dark:hover:text-red-200"
                              onClick={() => setThreatFilter("critical")}
                            >
                              Critical ({scanResults.filter(r => r.threatLevel >= 4).length})
                            </Badge>
                            <Badge 
                              variant={threatFilter === "high" ? "default" : "outline"} 
                              className="cursor-pointer hover:bg-orange-100 hover:text-orange-800 dark:hover:bg-orange-900 dark:hover:text-orange-200"
                              onClick={() => setThreatFilter("high")}
                            >
                              High ({scanResults.filter(r => r.threatLevel >= 3 && r.threatLevel < 4).length})
                            </Badge>
                            <Badge 
                              variant={threatFilter === "medium" ? "default" : "outline"} 
                              className="cursor-pointer hover:bg-yellow-100 hover:text-yellow-800 dark:hover:bg-yellow-900 dark:hover:text-yellow-200"
                              onClick={() => setThreatFilter("medium")}
                            >
                              Medium ({scanResults.filter(r => r.threatLevel >= 2 && r.threatLevel < 3).length})
                            </Badge>
                            <Badge 
                              variant={threatFilter === "low" ? "default" : "outline"} 
                              className="cursor-pointer hover:bg-green-100 hover:text-green-800 dark:hover:bg-green-900 dark:hover:text-green-200"
                              onClick={() => setThreatFilter("low")}
                            >
                              Low ({scanResults.filter(r => r.threatLevel < 2).length})
                            </Badge>
                          </div>
                          <Select value={sortBy} onValueChange={setSortBy}>
                            <SelectTrigger className="w-48">
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                              <SelectItem value="threat-desc">Threat Level (High to Low)</SelectItem>
                              <SelectItem value="threat-asc">Threat Level (Low to High)</SelectItem>
                              <SelectItem value="source">Source (A-Z)</SelectItem>
                              <SelectItem value="time">Most Recent</SelectItem>
                            </SelectContent>
                          </Select>
                        </div>
                        
                        {/* Source Filter */}
                        <div className="flex items-center gap-2">
                          <span className="text-sm font-medium">Source:</span>
                          <Select value={sourceFilter} onValueChange={setSourceFilter}>
                            <SelectTrigger className="w-48">
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                              <SelectItem value="all">All Sources</SelectItem>
                              {Array.from(new Set(scanResults.map(r => r.source))).map(source => (
                                <SelectItem key={source} value={source}>{source}</SelectItem>
                              ))}
                            </SelectContent>
                          </Select>
                        </div>
                      </div>
                    </CardContent>
                  </Card>

                  {/* Results Grid */}
                  <div className="grid grid-cols-1 gap-4">
                    {getFilteredResults().length === 0 ? (
                      <Card>
                        <CardContent className="text-center py-12">
                          <div className="space-y-4">
                            <Search className="h-12 w-12 text-muted-foreground mx-auto" />
                            <div>
                              <h3 className="text-lg font-medium mb-2">No Results Found</h3>
                              <p className="text-muted-foreground max-w-md mx-auto">
                                {resultsSearchQuery || threatFilter !== "all" || sourceFilter !== "all" 
                                  ? "Try adjusting your filters or search query" 
                                  : "Perform a scan to see results here"}
                              </p>
                            </div>
                            {(resultsSearchQuery || threatFilter !== "all" || sourceFilter !== "all") && (
                              <Button variant="outline" onClick={clearFilters}>
                                <RefreshCw className="h-4 w-4 mr-2" />
                                Clear Filters
                              </Button>
                            )}
                          </div>
                        </CardContent>
                      </Card>
                    ) : (
                      <div className="space-y-4">
                        {/* Results count */}
                        <div className="text-sm text-muted-foreground">
                          Showing {getFilteredResults().length} of {scanResults.length} results
                        </div>
                        
                        {getFilteredResults()
                          .map((result, index) => (
                      <Card key={result.id} className={`transition-all duration-200 hover:shadow-lg ${
                        result.threatLevel >= 4 ? 'border-red-200 dark:border-red-800 bg-red-50/50 dark:bg-red-950/20' :
                        result.threatLevel >= 2 ? 'border-yellow-200 dark:border-yellow-800 bg-yellow-50/50 dark:bg-yellow-950/20' :
                        'border-green-200 dark:border-green-800 bg-green-50/50 dark:bg-green-950/20'
                      }`}>
                        <CardHeader className="pb-3">
                          <div className="flex justify-between items-start">
                            <div className="flex-1">
                              <div className="flex items-center gap-3 mb-2">
                                <div className={`w-3 h-3 rounded-full ${
                                  result.threatLevel >= 4 ? 'bg-red-500' :
                                  result.threatLevel >= 2 ? 'bg-yellow-500' :
                                  'bg-green-500'
                                }`} />
                                <CardTitle className="text-lg font-semibold">{result.source}</CardTitle>
                                <Badge variant="secondary" className="text-xs">
                                  #{index + 1}
                                </Badge>
                              </div>
                              <CardDescription className="text-sm font-medium text-primary">
                                {result.dataType}
                              </CardDescription>
                              {result.timestamp && (
                                <div className="text-xs text-muted-foreground mt-1">
                                  {new Date(result.timestamp).toLocaleString()}
                                </div>
                              )}
                            </div>
                            <div className="flex items-center gap-2">
                              <Badge className={`${getThreatLevelColor(result.threatLevel)} text-white font-medium px-3 py-1`}>
                                <Shield className="h-3 w-3 mr-1" />
                                {getThreatLevelText(result.threatLevel)}
                              </Badge>
                              <Button
                                variant="ghost"
                                size="sm"
                                onClick={() => toggleResultExpansion(result.id)}
                                className="h-8 w-8 p-0"
                              >
                                {expandedResults.has(result.id) ? (
                                  <ChevronDown className="h-4 w-4" />
                                ) : (
                                  <ChevronRight className="h-4 w-4" />
                                )}
                              </Button>
                            </div>
                          </div>
                        </CardHeader>
                        
                        {expandedResults.has(result.id) && (
                          <CardContent className="pt-0">
                            <div className="border-t pt-4">
                              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                                {Object.entries(formatResultData(result.data, result.dataType)).map(([key, value]) => (
                                  <div key={key} className="group p-4 bg-background dark:bg-background/80 rounded-lg border hover:shadow-sm transition-shadow">
                                    <div className="flex items-start gap-3">
                                      <div className="w-2 h-2 rounded-full bg-primary/50 mt-2 flex-shrink-0" />
                                      <div className="flex-1 min-w-0">
                                        <div className="font-medium text-sm text-primary mb-1">{key}</div>
                                        <div className="text-sm text-muted-foreground break-all">
                                          {typeof value === 'string' ? value : JSON.stringify(value, null, 2)}
                                        </div>
                                      </div>
                                    </div>
                                  </div>
                                ))}
                              </div>
                              
                              {/* Action Buttons */}
                              <div className="flex gap-2 mt-4 pt-4 border-t">
                                <Button variant="outline" size="sm" onClick={() => copyResultData(result)}>
                                  <Copy className="h-4 w-4 mr-1" />
                                  Copy Data
                                </Button>
                                <Button variant="outline" size="sm" onClick={() => downloadResultJSON(result)}>
                                  <Download className="h-4 w-4 mr-1" />
                                  Download JSON
                                </Button>
                                <Button variant="outline" size="sm" onClick={() => {
                                  const shareData = {
                                    title: `Scan Result from ${result.source}`,
                                    text: `Threat Level: ${getThreatLevelText(result.threatLevel)}\nData Type: ${result.dataType}`,
                                    url: window.location.href
                                  };
                                  if (navigator.share) {
                                    navigator.share(shareData);
                                  } else {
                                    navigator.clipboard.writeText(JSON.stringify(shareData, null, 2));
                                    toast.success('Share link copied to clipboard');
                                  }
                                }}>
                                  <Share2 className="h-4 w-4 mr-1" />
                                  Share
                                </Button>
                              </div>
                            </div>
                          </CardContent>
                        )}
                      </Card>
                    ))}
                        </div>
                    )}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* History Tab */}
          {activeTab === "history" && (
            <div className="space-y-4">
              {/* Delete Controls */}
              {scanHistory.length > 0 && (
                <Card>
                  <CardContent className="p-4">
                    <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
                      <div className="flex items-center gap-2">
                        <Checkbox 
                          id="select-all"
                          checked={selectedScans.size === scanHistory.length}
                          onCheckedChange={(checked) => {
                            if (checked) {
                              setSelectedScans(new Set(scanHistory.map(scan => scan.id)));
                            } else {
                              setSelectedScans(new Set());
                            }
                          }}
                        />
                        <label htmlFor="select-all" className="text-sm font-medium">
                          Select All ({selectedScans.size} selected)
                        </label>
                      </div>
                      <div className="flex gap-2">
                        {selectedScans.size > 0 && (
                          <Button 
                            variant="destructive" 
                            size="sm"
                            onClick={deleteSelectedScans}
                            disabled={isDeleting}
                          >
                            {isDeleting ? (
                              <Loader2 className="h-4 w-4 animate-spin mr-2" />
                            ) : (
                              <Trash2 className="h-4 w-4 mr-2" />
                            )}
                            Delete Selected ({selectedScans.size})
                          </Button>
                        )}
                        <Button 
                          variant="outline" 
                          size="sm"
                          onClick={() => {
                            setScanToDelete('all');
                            setDeleteConfirmOpen(true);
                          }}
                          disabled={isDeleting}
                        >
                          {isDeleting ? (
                            <Loader2 className="h-4 w-4 animate-spin mr-2" />
                          ) : (
                            <Trash2 className="h-4 w-4 mr-2" />
                          )}
                          Clear All
                        </Button>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              )}

              {scanHistory.length === 0 ? (
                <Card>
                  <CardContent className="text-center py-12">
                    <History className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
                    <h3 className="text-lg font-medium mb-2">No History</h3>
                    <p className="text-muted-foreground">
                      No scans have been performed yet
                    </p>
                  </CardContent>
                </Card>
              ) : (
                scanHistory.map((scan) => (
                  <Card key={scan.id} className="hover:bg-muted/50 transition-colors">
                    <CardHeader>
                      <div className="flex justify-between items-start">
                        <div className="flex items-start gap-3 flex-1">
                          <Checkbox 
                            checked={selectedScans.has(scan.id)}
                            onCheckedChange={() => toggleScanSelection(scan.id)}
                            onClick={(e) => e.stopPropagation()}
                          />
                          <div className="flex-1 cursor-pointer" onClick={() => {
                            loadScanResults(scan.id);
                            setActiveTab("results");
                          }}>
                            <CardTitle className="text-lg">{scan.target}</CardTitle>
                            <CardDescription>
                              {scan.scanType} • {scan.targetType}
                            </CardDescription>
                          </div>
                        </div>
                        <div className="flex items-center space-x-2">
                          <Badge className={getThreatLevelColor(scan.threatScore)}>
                            {getThreatLevelText(scan.threatScore)}
                          </Badge>
                          {getStatusIcon(scan.status)}
                          <Button 
                            variant="ghost" 
                            size="sm"
                            onClick={(e) => {
                              e.stopPropagation();
                              confirmDeleteScan(scan.id);
                            }}
                            disabled={isDeleting}
                          >
                            <Trash2 className="h-4 w-4 text-destructive hover:text-destructive" />
                          </Button>
                        </div>
                      </div>
                    </CardHeader>
                    <CardContent>
                      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
                        <div>
                          <span className="text-muted-foreground">Started:</span>
                          <div className="font-medium">
                            {new Date(scan.startedAt).toLocaleString()}
                          </div>
                        </div>
                        <div>
                          <span className="text-muted-foreground">Completed:</span>
                          <div className="font-medium">
                            {scan.completedAt 
                              ? new Date(scan.completedAt).toLocaleString()
                              : 'Running'
                            }
                          </div>
                        </div>
                        <div>
                          <span className="text-muted-foreground">APIs Used:</span>
                          <div className="font-medium">
                            {scan.apisUsed?.length || 0} used
                          </div>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                ))
              )}
            </div>
          )}


          {/* Settings Tab */}
          {activeTab === "settings" && (
            <div className="space-y-6">
              <Card>
                <CardHeader>
                  <CardTitle>API Settings</CardTitle>
                  <CardDescription>
                    Customize threat levels for different APIs
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="space-y-4">
                    {availableAPIs.map((api) => (
                      <div key={api.id} className="flex items-center justify-between p-4 border rounded-lg">
                        <div className="flex items-center space-x-3">
                          {api.icon}
                          <div>
                            <div className="font-medium">{api.name}</div>
                            <div className="text-sm text-muted-foreground">{api.description}</div>
                          </div>
                        </div>
                        <div className="flex items-center space-x-3">
                          <label className="text-sm font-medium">Threat Level:</label>
                          <Select 
                            value={apiThreatLevels[api.id]?.toString() || '2'} 
                            onValueChange={(value) => updateAPIThreatLevel(api.id, parseInt(value))}
                          >
                            <SelectTrigger className="w-32">
                              <SelectValue />
                            </SelectTrigger>
                            <SelectContent>
                              <SelectItem value="0">Low (0)</SelectItem>
                              <SelectItem value="1">Low (1)</SelectItem>
                              <SelectItem value="2">Medium (2)</SelectItem>
                              <SelectItem value="3">High (3)</SelectItem>
                              <SelectItem value="4">Critical (4)</SelectItem>
                            </SelectContent>
                          </Select>
                        </div>
                      </div>
                    ))}
                  </div>

                  <Button onClick={saveAPISettings} className="w-full">
                    <Settings className="h-4 w-4 mr-2" />
                    Save Settings
                  </Button>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>API Status</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-3">
                    {apiStatus.map((api, index) => (
                      <div key={index} className="flex items-center justify-between p-3 border rounded-lg">
                        <div className="flex items-center space-x-2">
                          <div className={`w-2 h-2 rounded-full ${
                            api.status === 'online' ? 'bg-green-500' : 
                            api.status === 'limited' ? 'bg-yellow-500' : 'bg-red-500'
                          }`} />
                          <span className="font-medium">{api.name}</span>
                        </div>
                        <div className="text-sm text-muted-foreground">
                          {api.requestsUsed}/{api.requestsLimit} requests
                        </div>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <div className="flex justify-between items-center">
                    <div>
                      <CardTitle>Custom APIs</CardTitle>
                      <CardDescription>
                        Manage your custom API endpoints
                      </CardDescription>
                    </div>
                    <Button 
                      onClick={() => openApiForm()}
                      size="sm"
                    >
                      <Settings className="h-4 w-4 mr-2" />
                      Add API
                    </Button>
                  </div>
                </CardHeader>
                <CardContent>
                  {customApis.length === 0 ? (
                    <div className="text-center py-8">
                      <Database className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
                      <h3 className="text-lg font-medium mb-2">No Custom APIs</h3>
                      <p className="text-muted-foreground mb-4">
                        Add your own API endpoints to extend functionality
                      </p>
                      <Button onClick={() => openApiForm()}>
                        <Settings className="h-4 w-4 mr-2" />
                        Add Your First API
                      </Button>
                    </div>
                  ) : (
                    <div className="space-y-4">
                      {customApis.map((api) => (
                        <div key={api.id} className="flex items-center justify-between p-4 border rounded-lg">
                          <div className="flex-1">
                            <div className="flex items-center gap-2 mb-2">
                              <h4 className="font-medium">{api.name}</h4>
                              <Badge variant={api.enabled ? "default" : "secondary"}>
                                {api.enabled ? "Enabled" : "Disabled"}
                              </Badge>
                              <Badge variant="outline">{api.category}</Badge>
                            </div>
                            <p className="text-sm text-muted-foreground mb-2">{api.description}</p>
                            <div className="flex items-center gap-4 text-xs text-muted-foreground">
                              <span className="flex items-center gap-1">
                                <Globe className="h-3 w-3" />
                                {api.method} {api.endpoint}
                              </span>
                              <span className="flex items-center gap-1">
                                <Shield className="h-3 w-3" />
                                Threat Level: {api.threatLevel}
                              </span>
                            </div>
                          </div>
                          <div className="flex items-center gap-2">
                            <Button 
                              variant="ghost" 
                              size="sm"
                              onClick={() => openApiForm(api)}
                            >
                              <Settings className="h-4 w-4" />
                            </Button>
                            <Button 
                              variant="ghost" 
                              size="sm"
                              onClick={() => deleteApi(api.id)}
                              className="text-destructive hover:text-destructive"
                            >
                              <Trash2 className="h-4 w-4" />
                            </Button>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </CardContent>
              </Card>
            </div>
          )}
        </div>
      </div>

      {/* API Form Dialog */}
      {apiFormOpen && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <Card className="w-full max-w-2xl mx-4 max-h-[90vh] overflow-y-auto">
            <CardHeader>
              <CardTitle className="text-lg">
                {editingApiData?.id ? 'Edit API' : 'Add New API'}
              </CardTitle>
              <CardDescription>
                Configure your custom API endpoint
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="space-y-2">
                  <label className="text-sm font-medium">API Name *</label>
                  <Input
                    value={editingApiData?.name || ''}
                    onChange={(e) => setEditingApiData(prev => ({ ...prev, name: e.target.value }))}
                    placeholder="e.g., My Security API"
                  />
                </div>
                <div className="space-y-2">
                  <label className="text-sm font-medium">Category</label>
                  <Select 
                    value={editingApiData?.category || 'general'} 
                    onValueChange={(value) => setEditingApiData(prev => ({ ...prev, category: value }))}
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="general">General</SelectItem>
                      <SelectItem value="security">Security</SelectItem>
                      <SelectItem value="threat-intel">Threat Intelligence</SelectItem>
                      <SelectItem value="social">Social Media</SelectItem>
                      <SelectItem value="network">Network</SelectItem>
                      <SelectItem value="malware">Malware Analysis</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>

              <div className="space-y-2">
                <label className="text-sm font-medium">Description *</label>
                <Textarea
                  value={editingApiData?.description || ''}
                  onChange={(e) => setEditingApiData(prev => ({ ...prev, description: e.target.value }))}
                  placeholder="Describe what this API does..."
                  rows={3}
                />
              </div>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="space-y-2">
                  <label className="text-sm font-medium">Method *</label>
                  <Select 
                    value={editingApiData?.method || 'GET'} 
                    onValueChange={(value) => setEditingApiData(prev => ({ ...prev, method: value }))}
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="GET">GET</SelectItem>
                      <SelectItem value="POST">POST</SelectItem>
                      <SelectItem value="PUT">PUT</SelectItem>
                      <SelectItem value="DELETE">DELETE</SelectItem>
                      <SelectItem value="PATCH">PATCH</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-2 md:col-span-2">
                  <label className="text-sm font-medium">Endpoint *</label>
                  <Input
                    value={editingApiData?.endpoint || ''}
                    onChange={(e) => setEditingApiData(prev => ({ ...prev, endpoint: e.target.value }))}
                    placeholder="https://api.example.com/endpoint"
                  />
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="space-y-2">
                  <label className="text-sm font-medium">Threat Level</label>
                  <Select 
                    value={editingApiData?.threatLevel?.toString() || '2'} 
                    onValueChange={(value) => setEditingApiData(prev => ({ ...prev, threatLevel: parseInt(value) }))}
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="0">Low (0)</SelectItem>
                      <SelectItem value="1">Low (1)</SelectItem>
                      <SelectItem value="2">Medium (2)</SelectItem>
                      <SelectItem value="3">High (3)</SelectItem>
                      <SelectItem value="4">Critical (4)</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-2">
                  <label className="text-sm font-medium">Status</label>
                  <div className="flex items-center space-x-2 mt-2">
                    <Checkbox 
                      id="api-enabled"
                      checked={editingApiData?.enabled ?? true}
                      onCheckedChange={(checked) => setEditingApiData(prev => ({ ...prev, enabled: checked }))}
                    />
                    <label htmlFor="api-enabled" className="text-sm">
                      Enabled
                    </label>
                  </div>
                </div>
              </div>

              <div className="space-y-2">
                <label className="text-sm font-medium">Headers (JSON)</label>
                <Textarea
                  value={typeof editingApiData?.headers === 'string' ? editingApiData.headers : JSON.stringify(editingApiData?.headers || {}, null, 2)}
                  onChange={(e) => {
                    try {
                      const headers = JSON.parse(e.target.value);
                      setEditingApiData(prev => ({ ...prev, headers }));
                    } catch (error) {
                      // Invalid JSON, keep as string for now
                      setEditingApiData(prev => ({ ...prev, headers: e.target.value }));
                    }
                  }}
                  placeholder='{"Authorization": "Bearer token", "Content-Type": "application/json"}'
                  rows={4}
                />
              </div>

              <div className="flex gap-2 justify-end pt-4">
                <Button 
                  variant="outline" 
                  onClick={() => {
                    setApiFormOpen(false);
                    setEditingApiData(null);
                  }}
                >
                  Cancel
                </Button>
                <Button 
                  onClick={() => saveApi(editingApiData)}
                  disabled={!editingApiData?.name || !editingApiData?.description || !editingApiData?.endpoint}
                >
                  {editingApiData?.id ? 'Update API' : 'Create API'}
                </Button>
              </div>
            </CardContent>
          </Card>
        </div>
      )}

      {/* Delete Confirmation Dialog */}
      {deleteConfirmOpen && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <Card className="w-full max-w-md mx-4">
            <CardHeader>
              <CardTitle className="text-lg">
                {scanToDelete === 'all' ? 'Clear All History' : 'Delete Scan'}
              </CardTitle>
              <CardDescription>
                {scanToDelete === 'all' 
                  ? 'Are you sure you want to delete all scan history? This action cannot be undone.'
                  : 'Are you sure you want to delete this scan? This action cannot be undone.'
                }
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="flex gap-2 justify-end">
                <Button 
                  variant="outline" 
                  onClick={() => {
                    setDeleteConfirmOpen(false);
                    setScanToDelete(null);
                  }}
                  disabled={isDeleting}
                >
                  Cancel
                </Button>
                <Button 
                  variant="destructive" 
                  onClick={() => {
                    if (scanToDelete === 'all') {
                      clearAllScans();
                    } else if (scanToDelete) {
                      deleteScan(scanToDelete);
                    }
                  }}
                  disabled={isDeleting}
                >
                  {isDeleting ? (
                    <Loader2 className="h-4 w-4 animate-spin mr-2" />
                  ) : (
                    <Trash2 className="h-4 w-4 mr-2" />
                  )}
                  {scanToDelete === 'all' ? 'Clear All' : 'Delete'}
                </Button>
              </div>
            </CardContent>
          </Card>
        </div>
      )}
    </div>
  );
}