import { NextRequest, NextResponse } from 'next/server';

interface VulnersRequest {
  target: string;
  scanType?: string;
}

interface VulnersResult {
  source: string;
  dataType: string;
  vulnerability: {
    id: string;
    title: string;
    description: string;
    severity: string;
    score: number;
    published: string;
    modified: string;
    references: string[];
    cve?: string;
    cvss?: {
      vector: string;
      score: number;
      impact: number;
      exploitability: number;
    };
  };
  summary: {
    totalVulnerabilities: number;
    criticalCount: number;
    highCount: number;
    mediumCount: number;
    lowCount: number;
    infoCount: number;
  };
  error?: string;
}

export async function POST(request: NextRequest) {
  try {
    const body: VulnersRequest = await request.json();
    const { target, scanType = 'auto' } = body;

    if (!target) {
      return NextResponse.json(
        { error: 'Target is required for vulnerability scanning' },
        { status: 400 }
      );
    }

    // Vulners.com API integration
    const vulnersApiKey = 'OFH6182VBF3KJNU1TPF1M3ZYRB4ANBOVYVWVYMYD6XI3IFHILSZD04L02BUG4EC8';
    
    // Determine the type of search based on target
    let searchQuery = target;
    let searchType = 'all'; // Default search type
    
    // Detect target type
    if (/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(target)) {
      // IP Address - search for vulnerabilities in services running on this IP
      searchType = 'ip';
      searchQuery = target;
    } else if (/^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9](?:\.[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9])*$/.test(target)) {
      // Domain - search for domain-related vulnerabilities
      searchType = 'domain';
      searchQuery = target;
    } else if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(target)) {
      // Email - search for breach data and email-related vulnerabilities
      searchType = 'email';
      searchQuery = target;
    } else if (/^https?:\/\/.+/.test(target)) {
      // URL - extract domain and search for web vulnerabilities
      const url = new URL(target);
      searchQuery = url.hostname;
      searchType = 'web';
    } else if (/^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/.test(target)) {
      // Hash - search for malware/vulnerability signatures
      searchType = 'hash';
      searchQuery = target;
    }

    // Search for vulnerabilities using Vulners API
    const vulnersUrl = `https://vulners.com/api/v3/search/lucene/?query=${encodeURIComponent(searchQuery)}&size=20`;
    
    const vulnersResponse = await fetch(vulnersUrl, {
      method: 'GET',
      headers: {
        'X-API-KEY': vulnersApiKey,
        'Content-Type': 'application/json'
      }
    });

    if (!vulnersResponse.ok) {
      throw new Error(`Vulners API request failed with status: ${vulnersResponse.status}`);
    }

    const vulnersData = await vulnersResponse.json();
    console.log('Vulners API Response:', vulnersData);

    // Process the response and extract vulnerability information
    const vulnerabilities = vulnersData.data?.search || [];
    const summary = {
      totalVulnerabilities: vulnerabilities.length,
      criticalCount: 0,
      highCount: 0,
      mediumCount: 0,
      lowCount: 0,
      infoCount: 0
    };

    // Categorize vulnerabilities by severity
    vulnerabilities.forEach((vuln: any) => {
      const severity = vuln._source?.enchantments?.vulners_severity?.score || 0;
      if (severity >= 9.0) {
        summary.criticalCount++;
      } else if (severity >= 7.0) {
        summary.highCount++;
      } else if (severity >= 4.0) {
        summary.mediumCount++;
      } else if (severity >= 1.0) {
        summary.lowCount++;
      } else {
        summary.infoCount++;
      }
    });

    // Get the most critical vulnerability for detailed analysis
    const topVulnerability = vulnerabilities.length > 0 ? vulnerabilities[0]._source : null;

    const result: VulnersResult = {
      source: 'Vulners.com',
      dataType: 'Vulnerability Assessment',
      vulnerability: topVulnerability ? {
        id: topVulnerability.id || 'Unknown',
        title: topVulnerability.title || 'Unknown Vulnerability',
        description: topVulnerability.description || 'No description available',
        severity: topVulnerability.enchantments?.vulners_severity?.score?.toFixed(1) || 'Unknown',
        score: topVulnerability.enchantments?.vulners_severity?.score || 0,
        published: topVulnerability.published || 'Unknown',
        modified: topVulnerability.modified || 'Unknown',
        references: topVulnerability.references || [],
        cve: topVulnerability.cve?.[0] || 'None',
        cvss: topVulnerability.cvss ? {
          vector: topVulnerability.cvss.vector || 'Unknown',
          score: topVulnerability.cvss.score || 0,
          impact: topVulnerability.cvss.impact || 0,
          exploitability: topVulnerability.cvss.exploitability || 0
        } : undefined
      } : {
        id: 'None',
        title: 'No vulnerabilities found',
        description: 'No known vulnerabilities detected for this target',
        severity: '0.0',
        score: 0,
        published: 'N/A',
        modified: 'N/A',
        references: []
      },
      summary
    };

    return NextResponse.json(result);

  } catch (error) {
    console.error('Vulners API Error:', error);
    
    const errorMessage = error instanceof Error ? error.message : 'Unknown error occurred';
    
    return NextResponse.json(
      { 
        error: 'Failed to perform vulnerability assessment',
        details: errorMessage
      },
      { status: 500 }
    );
  }
}