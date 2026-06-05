import { NextRequest, NextResponse } from 'next/server';

interface BreachDirectoryRequest {
  target: string;
  scanType?: string;
}

interface BreachDirectoryResult {
  source: string;
  dataType: string;
  breachData: {
    found: boolean;
    sources: string[];
    breachCount: number;
    latestBreach?: {
      name: string;
      date: string;
      dataTypes: string[];
      description: string;
      pwnCount: number;
      isVerified: boolean;
      isFabricated: boolean;
      isSensitive: boolean;
      isRetired: boolean;
      isSpamList: boolean;
    };
    email?: string;
    phone?: string;
    username?: string;
    ip?: string;
    domain?: string;
  };
  summary: {
    totalBreaches: number;
    compromisedDataTypes: string[];
    riskLevel: string;
    recommendations: string[];
  };
  error?: string;
}

export async function POST(request: NextRequest) {
  try {
    const body: BreachDirectoryRequest = await request.json();
    const { target, scanType = 'auto' } = body;

    if (!target) {
      return NextResponse.json(
        { error: 'Target is required for breach directory lookup' },
        { status: 400 }
      );
    }

    // BreachDirectory API integration
    const apiKey = 'b18cd28339msh87a0f0139a2b758p14c568jsn00126833d73b';
    
    // Determine the type of search based on target
    let searchQuery = target;
    let searchType = 'auto';
    
    // Detect target type and format query accordingly
    if (/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(target)) {
      // IP Address
      searchType = 'ip';
      searchQuery = target;
    } else if (/^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9](?:\.[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9])*$/.test(target)) {
      // Domain
      searchType = 'domain';
      searchQuery = target;
    } else if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(target)) {
      // Email - URL encode for API
      searchType = 'email';
      searchQuery = encodeURIComponent(target);
    } else if (/^https?:\/\/.+/.test(target)) {
      // URL - extract domain
      const url = new URL(target);
      searchQuery = url.hostname;
      searchType = 'domain';
    } else if (/^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$/.test(target)) {
      // Hash
      searchType = 'hash';
      searchQuery = target;
    } else {
      // Username or other
      searchType = 'username';
      searchQuery = encodeURIComponent(target);
    }

    // Call BreachDirectory API
    const apiUrl = `https://breachdirectory.p.rapidapi.com/?func=auto&term=${searchQuery}`;
    
    const apiResponse = await fetch(apiUrl, {
      method: 'GET',
      headers: {
        'x-rapidapi-key': apiKey,
        'x-rapidapi-host': 'breachdirectory.p.rapidapi.com'
      }
    });

    if (!apiResponse.ok) {
      throw new Error(`BreachDirectory API request failed with status: ${apiResponse.status}`);
    }

    const apiData = await apiResponse.json();
    console.log('BreachDirectory API Response:', apiData);

    // Process the response and extract breach information
    const found = apiData.found || false;
    const sources = apiData.sources || [];
    const results = apiData.results || [];
    
    // Get the most recent/significant breach
    const latestBreach = results.length > 0 ? results[0] : null;

    // Determine compromised data types
    const compromisedDataTypes = new Set<string>();
    results.forEach((breach: any) => {
      if (breach.data_classes) {
        breach.data_classes.forEach((dataType: string) => {
          compromisedDataTypes.add(dataType);
        });
      }
    });

    // Calculate risk level based on breach data
    let riskLevel = 'Low';
    if (results.length > 10) {
      riskLevel = 'Critical';
    } else if (results.length > 5) {
      riskLevel = 'High';
    } else if (results.length > 0) {
      riskLevel = 'Medium';
    }

    // Generate recommendations
    const recommendations: string[] = [];
    if (found) {
      recommendations.push('Change passwords for all accounts using this email/username');
      recommendations.push('Enable two-factor authentication where available');
      recommendations.push('Monitor accounts for suspicious activity');
      
      if (compromisedDataTypes.has('Passwords')) {
        recommendations.push('Immediately change passwords for affected services');
      }
      if (compromisedDataTypes.has('Email addresses')) {
        recommendations.push('Be cautious of phishing emails');
      }
      if (compromisedDataTypes.has('Phone numbers')) {
        recommendations.push('Be aware of potential smishing attacks');
      }
    } else {
      recommendations.push('No breaches found - continue practicing good security hygiene');
      recommendations.push('Use unique, strong passwords for each service');
      recommendations.push('Enable two-factor authentication when possible');
    }

    const result: BreachDirectoryResult = {
      source: 'BreachDirectory',
      dataType: 'Breach Assessment',
      breachData: {
        found,
        sources,
        breachCount: results.length,
        latestBreach: latestBreach ? {
          name: latestBreach.title || latestBreach.name || 'Unknown',
          date: latestBreach.breach_date || latestBreach.date || 'Unknown',
          dataTypes: latestBreach.data_classes || [],
          description: latestBreach.description || 'No description available',
          pwnCount: latestBreach.pwn_count || latestBreach.records || 0,
          isVerified: latestBreach.is_verified || false,
          isFabricated: latestBreach.is_fabricated || false,
          isSensitive: latestBreach.is_sensitive || false,
          isRetired: latestBreach.is_retired || false,
          isSpamList: latestBreach.is_spam_list || false
        } : undefined,
        email: searchType === 'email' ? target : undefined,
        phone: searchType === 'phone' ? target : undefined,
        username: searchType === 'username' ? target : undefined,
        ip: searchType === 'ip' ? target : undefined,
        domain: searchType === 'domain' ? target : undefined
      },
      summary: {
        totalBreaches: results.length,
        compromisedDataTypes: Array.from(compromisedDataTypes),
        riskLevel,
        recommendations
      }
    };

    return NextResponse.json(result);

  } catch (error) {
    console.error('BreachDirectory API Error:', error);
    
    const errorMessage = error instanceof Error ? error.message : 'Unknown error occurred';
    
    return NextResponse.json(
      { 
        error: 'Failed to perform breach directory lookup',
        details: errorMessage
      },
      { status: 500 }
    );
  }
}