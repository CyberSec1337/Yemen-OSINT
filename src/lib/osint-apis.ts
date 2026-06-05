// Enhanced OSINT API Integration with Multiple Sources
import ZAI from 'z-ai-web-dev-sdk';

export interface ScanResult {
  id: string;
  source: string;
  dataType: string;
  threatLevel: number;
  data: any;
  timestamp: string;
}

export interface APIConfig {
  name: string;
  enabled: boolean;
  apiKey?: string;
  baseUrl?: string;
  rateLimit?: number;
}

export class OSINTAPIManager {
  private zai: any;
  private apis: Map<string, APIConfig> = new Map();

  constructor() {
    this.initializeAPIs();
  }

  private async initializeAPIs() {
    try {
      this.zai = await ZAI.create();
      
      // Initialize API configurations
      this.apis.set('virustotal', {
        name: 'VirusTotal',
        enabled: true,
        rateLimit: 4 // requests per minute
      });

      this.apis.set('shodan', {
        name: 'Shodan',
        enabled: true,
        rateLimit: 60 // requests per month for free tier
      });

      this.apis.set('abuseipdb', {
        name: 'AbuseIPDB',
        enabled: true,
        rateLimit: 1000 // requests per day
      });

      this.apis.set('securitytrails', {
        name: 'SecurityTrails',
        enabled: true,
        rateLimit: 50 // requests per month
      });

      this.apis.set('urlscan', {
        name: 'URLScan.io',
        enabled: true,
        rateLimit: 25 // requests per minute
      });

      this.apis.set('passivetotal', {
        name: 'PassiveTotal',
        enabled: true,
        rateLimit: 25 // requests per month
      });

      this.apis.set('threatcrowd', {
        name: 'ThreatCrowd',
        enabled: true,
        rateLimit: 100 // requests per minute
      });

      this.apis.set('hybridanalysis', {
        name: 'Hybrid Analysis',
        enabled: true,
        rateLimit: 20 // requests per minute
      });
    } catch (error) {
      console.error('Failed to initialize OSINT APIs:', error);
    }
  }

  // Enhanced IP Analysis with multiple sources
  async analyzeIP(ip: string): Promise<ScanResult[]> {
    const results: ScanResult[] = [];

    try {
      // VirusTotal IP Analysis
      const vtResult = await this.queryVirusTotalIP(ip);
      if (vtResult) results.push(vtResult);

      // Shodan IP Information
      const shodanResult = await this.queryShodanIP(ip);
      if (shodanResult) results.push(shodanResult);

      // AbuseIPDB Analysis
      const abuseResult = await this.queryAbuseIPDB(ip);
      if (abuseResult) results.push(abuseResult);

      // SecurityTrails IP Data
      const securityResult = await this.querySecurityTrailsIP(ip);
      if (securityResult) results.push(securityResult);

      // PassiveTotal IP Reputation
      const passiveResult = await this.queryPassiveTotalIP(ip);
      if (passiveResult) results.push(passiveResult);

    } catch (error) {
      console.error('Error analyzing IP:', error);
    }

    return results;
  }

  // Enhanced Domain Analysis
  async analyzeDomain(domain: string): Promise<ScanResult[]> {
    const results: ScanResult[] = [];

    try {
      // VirusTotal Domain Analysis
      const vtResult = await this.queryVirusTotalDomain(domain);
      if (vtResult) results.push(vtResult);

      // SecurityTrails Domain History
      const trailsResult = await this.querySecurityTrailsDomain(domain);
      if (trailsResult) results.push(trailsResult);

      // URLScan.io Analysis
      const urlscanResult = await this.queryURLScan(domain);
      if (urlscanResult) results.push(urlscanResult);

      // ThreatCrowd Domain Data
      const threatResult = await this.queryThreatCrowd(domain);
      if (threatResult) results.push(threatResult);

    } catch (error) {
      console.error('Error analyzing domain:', error);
    }

    return results;
  }

  // Enhanced URL Analysis
  async analyzeURL(url: string): Promise<ScanResult[]> {
    const results: ScanResult[] = [];

    try {
      // URLScan.io Analysis
      const urlscanResult = await this.queryURLScan(url);
      if (urlscanResult) results.push(urlscanResult);

      // VirusTotal URL Analysis
      const vtResult = await this.queryVirusTotalURL(url);
      if (vtResult) results.push(vtResult);

      // Hybrid Analysis
      const hybridResult = await this.queryHybridAnalysis(url);
      if (hybridResult) results.push(hybridResult);

    } catch (error) {
      console.error('Error analyzing URL:', error);
    }

    return results;
  }

  // Hash Analysis for malware detection
  async analyzeHash(hash: string): Promise<ScanResult[]> {
    const results: ScanResult[] = [];

    try {
      // VirusTotal Hash Analysis
      const vtResult = await this.queryVirusTotalHash(hash);
      if (vtResult) results.push(vtResult);

      // Hybrid Analysis
      const hybridResult = await this.queryHybridAnalysisHash(hash);
      if (hybridResult) results.push(hybridResult);

    } catch (error) {
      console.error('Error analyzing hash:', error);
    }

    return results;
  }

  // Email Analysis
  async analyzeEmail(email: string): Promise<ScanResult[]> {
    const results: ScanResult[] = [];

    try {
      // Email validation and reputation
      const emailResult = await this.queryEmailReputation(email);
      if (emailResult) results.push(emailResult);

      // Domain-based analysis
      const domain = email.split('@')[1];
      if (domain) {
        const domainResults = await this.analyzeDomain(domain);
        results.push(...domainResults);
      }

    } catch (error) {
      console.error('Error analyzing email:', error);
    }

    return results;
  }

  // API Query Methods (using web search and AI analysis)
  private async queryVirusTotalIP(ip: string): Promise<ScanResult | null> {
    try {
      const searchResult = await this.zai.functions.invoke("web_search", {
        query: `VirusTotal IP reputation ${ip} malicious detections`,
        num: 5
      });

      const analysis = await this.zai.chat.completions.create({
        messages: [
          {
            role: 'system',
            content: 'Analyze the following search results about IP reputation and provide a structured analysis including threat level, detections, and recommendations.'
          },
          {
            role: 'user',
            content: JSON.stringify(searchResult)
          }
        ]
      });

      const data = JSON.parse(analysis.choices[0].message.content || '{}');
      
      return {
        id: `vt-ip-${Date.now()}`,
        source: 'VirusTotal',
        dataType: 'IP Reputation',
        threatLevel: this.calculateThreatLevel(data),
        data: data,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      console.error('VirusTotal IP query failed:', error);
      return null;
    }
  }

  private async queryShodanIP(ip: string): Promise<ScanResult | null> {
    try {
      const searchResult = await this.zai.functions.invoke("web_search", {
        query: `Shodan IP scan ${ip} open ports services vulnerabilities`,
        num: 5
      });

      const analysis = await this.zai.chat.completions.create({
        messages: [
          {
            role: 'system',
            content: 'Analyze the Shodan search results for IP information and provide structured data about open ports, services, and potential vulnerabilities.'
          },
          {
            role: 'user',
            content: JSON.stringify(searchResult)
          }
        ]
      });

      const data = JSON.parse(analysis.choices[0].message.content || '{}');
      
      return {
        id: `shodan-ip-${Date.now()}`,
        source: 'Shodan',
        dataType: 'Network Analysis',
        threatLevel: this.calculateThreatLevel(data),
        data: data,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      console.error('Shodan IP query failed:', error);
      return null;
    }
  }

  private async queryAbuseIPDB(ip: string): Promise<ScanResult | null> {
    try {
      const searchResult = await this.zai.functions.invoke("web_search", {
        query: `AbuseIPDB ${ip} reports confidence score malicious activity`,
        num: 5
      });

      const analysis = await this.zai.chat.completions.create({
        messages: [
          {
            role: 'system',
            content: 'Analyze AbuseIPDB data and provide structured information about abuse reports, confidence scores, and malicious activity indicators.'
          },
          {
            role: 'user',
            content: JSON.stringify(searchResult)
          }
        ]
      });

      const data = JSON.parse(analysis.choices[0].message.content || '{}');
      
      return {
        id: `abuse-ip-${Date.now()}`,
        source: 'AbuseIPDB',
        dataType: 'Abuse Reports',
        threatLevel: this.calculateThreatLevel(data),
        data: data,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      console.error('AbuseIPDB query failed:', error);
      return null;
    }
  }

  private async querySecurityTrailsIP(ip: string): Promise<ScanResult | null> {
    try {
      const searchResult = await this.zai.functions.invoke("web_search", {
        query: `SecurityTrails IP ${ip} hostname DNS records infrastructure`,
        num: 5
      });

      const analysis = await this.zai.chat.completions.create({
        messages: [
          {
            role: 'system',
            content: 'Analyze SecurityTrails IP data and provide structured information about hostnames, DNS records, and infrastructure details.'
          },
          {
            role: 'user',
            content: JSON.stringify(searchResult)
          }
        ]
      });

      const data = JSON.parse(analysis.choices[0].message.content || '{}');
      
      return {
        id: `st-ip-${Date.now()}`,
        source: 'SecurityTrails',
        dataType: 'Infrastructure Analysis',
        threatLevel: this.calculateThreatLevel(data),
        data: data,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      console.error('SecurityTrails IP query failed:', error);
      return null;
    }
  }

  private async queryPassiveTotalIP(ip: string): Promise<ScanResult | null> {
    try {
      const searchResult = await this.zai.functions.invoke("web_search", {
        query: `PassiveTotal IP ${ip} reputation malware associations`,
        num: 5
      });

      const analysis = await this.zai.chat.completions.create({
        messages: [
          {
            role: 'system',
            content: 'Analyze PassiveTotal IP reputation data and provide structured information about malware associations and threat intelligence.'
          },
          {
            role: 'user',
            content: JSON.stringify(searchResult)
          }
        ]
      });

      const data = JSON.parse(analysis.choices[0].message.content || '{}');
      
      return {
        id: `pt-ip-${Date.now()}`,
        source: 'PassiveTotal',
        dataType: 'Threat Intelligence',
        threatLevel: this.calculateThreatLevel(data),
        data: data,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      console.error('PassiveTotal IP query failed:', error);
      return null;
    }
  }

  private async queryVirusTotalDomain(domain: string): Promise<ScanResult | null> {
    try {
      const searchResult = await this.zai.functions.invoke("web_search", {
        query: `VirusTotal domain ${domain} malicious detections categories`,
        num: 5
      });

      const analysis = await this.zai.chat.completions.create({
        messages: [
          {
            role: 'system',
            content: 'Analyze VirusTotal domain data and provide structured information about malicious detections, categories, and reputation.'
          },
          {
            role: 'user',
            content: JSON.stringify(searchResult)
          }
        ]
      });

      const data = JSON.parse(analysis.choices[0].message.content || '{}');
      
      return {
        id: `vt-domain-${Date.now()}`,
        source: 'VirusTotal',
        dataType: 'Domain Reputation',
        threatLevel: this.calculateThreatLevel(data),
        data: data,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      console.error('VirusTotal domain query failed:', error);
      return null;
    }
  }

  private async querySecurityTrailsDomain(domain: string): Promise<ScanResult | null> {
    try {
      const searchResult = await this.zai.functions.invoke("web_search", {
        query: `SecurityTrails domain ${domain} DNS history subdomains WHOIS`,
        num: 5
      });

      const analysis = await this.zai.chat.completions.create({
        messages: [
          {
            role: 'system',
            content: 'Analyze SecurityTrails domain data and provide structured information about DNS history, subdomains, and WHOIS information.'
          },
          {
            role: 'user',
            content: JSON.stringify(searchResult)
          }
        ]
      });

      const data = JSON.parse(analysis.choices[0].message.content || '{}');
      
      return {
        id: `st-domain-${Date.now()}`,
        source: 'SecurityTrails',
        dataType: 'DNS Analysis',
        threatLevel: this.calculateThreatLevel(data),
        data: data,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      console.error('SecurityTrails domain query failed:', error);
      return null;
    }
  }

  private async queryURLScan(target: string): Promise<ScanResult | null> {
    try {
      const searchResult = await this.zai.functions.invoke("web_search", {
        query: `URLScan.io analysis ${target} malicious indicators`,
        num: 5
      });

      const analysis = await this.zai.chat.completions.create({
        messages: [
          {
            role: 'system',
            content: 'Analyze URLScan.io data and provide structured information about malicious indicators, categories, and threats.'
          },
          {
            role: 'user',
            content: JSON.stringify(searchResult)
          }
        ]
      });

      const data = JSON.parse(analysis.choices[0].message.content || '{}');
      
      return {
        id: `urlscan-${Date.now()}`,
        source: 'URLScan.io',
        dataType: 'URL Analysis',
        threatLevel: this.calculateThreatLevel(data),
        data: data,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      console.error('URLScan query failed:', error);
      return null;
    }
  }

  private async queryThreatCrowd(target: string): Promise<ScanResult | null> {
    try {
      const searchResult = await this.zai.functions.invoke("web_search", {
        query: `ThreatCrowd ${target} antivirus detections resolutions`,
        num: 5
      });

      const analysis = await this.zai.chat.completions.create({
        messages: [
          {
            role: 'system',
            content: 'Analyze ThreatCrowd data and provide structured information about antivirus detections and resolutions.'
          },
          {
            role: 'user',
            content: JSON.stringify(searchResult)
          }
        ]
      });

      const data = JSON.parse(analysis.choices[0].message.content || '{}');
      
      return {
        id: `threatcrowd-${Date.now()}`,
        source: 'ThreatCrowd',
        dataType: 'Threat Intelligence',
        threatLevel: this.calculateThreatLevel(data),
        data: data,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      console.error('ThreatCrowd query failed:', error);
      return null;
    }
  }

  private async queryHybridAnalysis(url: string): Promise<ScanResult | null> {
    try {
      const searchResult = await this.zai.functions.invoke("web_search", {
        query: `Hybrid Analysis ${url} malware verdict threats`,
        num: 5
      });

      const analysis = await this.zai.chat.completions.create({
        messages: [
          {
            role: 'system',
            content: 'Analyze Hybrid Analysis data and provide structured information about malware verdicts and threats.'
          },
          {
            role: 'user',
            content: JSON.stringify(searchResult)
          }
        ]
      });

      const data = JSON.parse(analysis.choices[0].message.content || '{}');
      
      return {
        id: `hybrid-${Date.now()}`,
        source: 'Hybrid Analysis',
        dataType: 'Malware Analysis',
        threatLevel: this.calculateThreatLevel(data),
        data: data,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      console.error('Hybrid Analysis query failed:', error);
      return null;
    }
  }

  private async queryVirusTotalURL(url: string): Promise<ScanResult | null> {
    try {
      const searchResult = await this.zai.functions.invoke("web_search", {
        query: `VirusTotal URL scan ${url} malicious detections`,
        num: 5
      });

      const analysis = await this.zai.chat.completions.create({
        messages: [
          {
            role: 'system',
            content: 'Analyze VirusTotal URL scan results and provide structured information about malicious detections.'
          },
          {
            role: 'user',
            content: JSON.stringify(searchResult)
          }
        ]
      });

      const data = JSON.parse(analysis.choices[0].message.content || '{}');
      
      return {
        id: `vt-url-${Date.now()}`,
        source: 'VirusTotal',
        dataType: 'URL Analysis',
        threatLevel: this.calculateThreatLevel(data),
        data: data,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      console.error('VirusTotal URL query failed:', error);
      return null;
    }
  }

  private async queryVirusTotalHash(hash: string): Promise<ScanResult | null> {
    try {
      const searchResult = await this.zai.functions.invoke("web_search", {
        query: `VirusTotal hash ${hash} malware detections signatures`,
        num: 5
      });

      const analysis = await this.zai.chat.completions.create({
        messages: [
          {
            role: 'system',
            content: 'Analyze VirusTotal hash data and provide structured information about malware detections and signatures.'
          },
          {
            role: 'user',
            content: JSON.stringify(searchResult)
          }
        ]
      });

      const data = JSON.parse(analysis.choices[0].message.content || '{}');
      
      return {
        id: `vt-hash-${Date.now()}`,
        source: 'VirusTotal',
        dataType: 'Malware Analysis',
        threatLevel: this.calculateThreatLevel(data),
        data: data,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      console.error('VirusTotal hash query failed:', error);
      return null;
    }
  }

  private async queryHybridAnalysisHash(hash: string): Promise<ScanResult | null> {
    try {
      const searchResult = await this.zai.functions.invoke("web_search", {
        query: `Hybrid Analysis hash ${hash} malware family behavior`,
        num: 5
      });

      const analysis = await this.zai.chat.completions.create({
        messages: [
          {
            role: 'system',
            content: 'Analyze Hybrid Analysis hash data and provide structured information about malware family and behavior.'
          },
          {
            role: 'user',
            content: JSON.stringify(searchResult)
          }
        ]
      });

      const data = JSON.parse(analysis.choices[0].message.content || '{}');
      
      return {
        id: `hybrid-hash-${Date.now()}`,
        source: 'Hybrid Analysis',
        dataType: 'Malware Analysis',
        threatLevel: this.calculateThreatLevel(data),
        data: data,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      console.error('Hybrid Analysis hash query failed:', error);
      return null;
    }
  }

  private async queryEmailReputation(email: string): Promise<ScanResult | null> {
    try {
      const searchResult = await this.zai.functions.invoke("web_search", {
        query: `email reputation ${email} validation disposable spam`,
        num: 5
      });

      const analysis = await this.zai.chat.completions.create({
        messages: [
          {
            role: 'system',
            content: 'Analyze email reputation data and provide structured information about validity, disposable status, and spam indicators.'
          },
          {
            role: 'user',
            content: JSON.stringify(searchResult)
          }
        ]
      });

      const data = JSON.parse(analysis.choices[0].message.content || '{}');
      
      return {
        id: `email-${Date.now()}`,
        source: 'Email Analysis',
        dataType: 'Email Reputation',
        threatLevel: this.calculateThreatLevel(data),
        data: data,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      console.error('Email reputation query failed:', error);
      return null;
    }
  }

  // Calculate threat level based on analysis results
  private calculateThreatLevel(data: any): number {
    if (!data) return 1;

    let threatScore = 1;

    // Check for malicious indicators
    if (data.malicious_detections > 0) {
      threatScore += Math.min(data.malicious_detections, 3);
    }

    if (data.suspicious_indicators > 0) {
      threatScore += Math.min(data.suspicious_indicators, 2);
    }

    if (data.high_confidence_threat) {
      threatScore += 2;
    }

    if (data.known_malware_association) {
      threatScore += 3;
    }

    if (data.recent_abuse_reports > 5) {
      threatScore += 1;
    }

    return Math.min(threatScore, 5);
  }

  // Get available APIs status
  getAPIsStatus(): APIConfig[] {
    return Array.from(this.apis.values());
  }

  // Comprehensive scan with all relevant APIs
  async comprehensiveScan(target: string, targetType: 'ip' | 'domain' | 'url' | 'hash' | 'email'): Promise<ScanResult[]> {
    const allResults: ScanResult[] = [];

    switch (targetType) {
      case 'ip':
        return await this.analyzeIP(target);
      case 'domain':
        return await this.analyzeDomain(target);
      case 'url':
        return await this.analyzeURL(target);
      case 'hash':
        return await this.analyzeHash(target);
      case 'email':
        return await this.analyzeEmail(target);
      default:
        throw new Error(`Unsupported target type: ${targetType}`);
    }
  }
}

export const osintAPIManager = new OSINTAPIManager();