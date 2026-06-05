import { NextRequest, NextResponse } from 'next/server';

// AbstractAPI configuration
const ABSTRACT_API_KEYS = {
  emailReputation: '1a9186d108a84a188e61a705cf09f713',
  phoneIntelligence: '265e5f0c37774deaaf5292937d7571b1',
  vatValidation: '2efa41ef8eb04b909bd65d92eeef3425',
  ibanValidation: '82ad4cb83c1c4f18815ce533e3289d72',
  ipIntelligence: 'bf01e81c44984c28a133247fbaa828cf',
  ipGeolocation: 'f7b3253d91e74c049b3f1bd94eca38fd',
  holidays: '4c16f9efdf5547bf9988eecc2a36ab69',
  exchangeRates: '4c4fd5e044a34b83adb65b9ac9a7853e',
  companyEnrichment: '7e8974258eb04f699db8d2d932cc15a6',
  timezone: '40a50f0aa52e4a7f975c5c31def23c7d'
};

// API Endpoints
const API_ENDPOINTS = {
  emailReputation: (email: string) => 
    `https://emailreputation.abstractapi.com/v1/?api_key=${ABSTRACT_API_KEYS.emailReputation}&email=${email}`,
  
  phoneIntelligence: (phone: string) => 
    `https://phoneintelligence.abstractapi.com/v1/?api_key=${ABSTRACT_API_KEYS.phoneIntelligence}&phone=${phone}`,
  
  vatValidation: (vatNumber: string) => 
    `https://vat.abstractapi.com/v1/validate/?api_key=${ABSTRACT_API_KEYS.vatValidation}&vat_number=${vatNumber}`,
  
  ibanValidation: (iban: string) => 
    `https://ibanvalidation.abstractapi.com/v1/?api_key=${ABSTRACT_API_KEYS.ibanValidation}&iban=${iban}`,
  
  ipIntelligence: (ip: string) => 
    `https://ip-intelligence.abstractapi.com/v1/?api_key=${ABSTRACT_API_KEYS.ipIntelligence}&ip_address=${ip}`,
  
  ipGeolocation: (ip: string) => 
    `https://ipgeolocation.abstractapi.com/v1/?api_key=${ABSTRACT_API_KEYS.ipGeolocation}&ip_address=${ip}`,
  
  holidays: (country: string, year: number, month: number, day: number) => 
    `https://holidays.abstractapi.com/v1/?api_key=${ABSTRACT_API_KEYS.holidays}&country=${country}&year=${year}&month=${month}&day=${day}`,
  
  exchangeRates: (base: string, target: string) => 
    `https://exchange-rates.abstractapi.com/v1/live/?api_key=${ABSTRACT_API_KEYS.exchangeRates}&base=${base}&target=${target}`,
  
  companyEnrichment: (domain: string) => 
    `https://companyenrichment.abstractapi.com/v2/?api_key=${ABSTRACT_API_KEYS.companyEnrichment}&domain=${domain}`,
  
  timezone: (location: string) => 
    `https://timezone.abstractapi.com/v1/current_time/?api_key=${ABSTRACT_API_KEYS.timezone}&location=${encodeURIComponent(location)}`,
  
  // BGPView API
  bgpViewSearch: (query: string) => 
    `https://api.bgpview.io/search?query_term=${encodeURIComponent(query)}`
};

// Helper function to make API requests
async function makeAPIRequest(url: string): Promise<any> {
  try {
    const response = await fetch(url);
    if (!response.ok) {
      throw new Error(`API request failed: ${response.status} ${response.statusText}`);
    }
    return await response.json();
  } catch (error) {
    console.error('API request error:', error);
    throw error;
  }
}

// Email reputation check
export async function checkEmailReputation(email: string) {
  const url = API_ENDPOINTS.emailReputation(email);
  const data = await makeAPIRequest(url);
  
  return {
    source: 'AbstractAPI - Email Reputation',
    dataType: 'Email Analysis',
    data: JSON.stringify(data),
    threatLevel: calculateThreatLevel(data, 'email')
  };
}

// Phone intelligence check
export async function checkPhoneIntelligence(phone: string) {
  const url = API_ENDPOINTS.phoneIntelligence(phone);
  const data = await makeAPIRequest(url);
  
  return {
    source: 'AbstractAPI - Phone Intelligence',
    dataType: 'Phone Analysis',
    data: JSON.stringify(data),
    threatLevel: calculateThreatLevel(data, 'phone')
  };
}

// VAT validation
export async function validateVAT(vatNumber: string) {
  const url = API_ENDPOINTS.vatValidation(vatNumber);
  const data = await makeAPIRequest(url);
  
  return {
    source: 'AbstractAPI - VAT Validation',
    dataType: 'VAT Validation',
    data: JSON.stringify(data),
    threatLevel: calculateThreatLevel(data, 'vat')
  };
}

// IBAN validation
export async function validateIBAN(iban: string) {
  const url = API_ENDPOINTS.ibanValidation(iban);
  const data = await makeAPIRequest(url);
  
  return {
    source: 'AbstractAPI - IBAN Validation',
    dataType: 'IBAN Validation',
    data: JSON.stringify(data),
    threatLevel: calculateThreatLevel(data, 'iban')
  };
}

// IP intelligence check
export async function checkIPIntelligence(ip: string) {
  const url = API_ENDPOINTS.ipIntelligence(ip);
  const data = await makeAPIRequest(url);
  
  return {
    source: 'AbstractAPI - IP Intelligence',
    dataType: 'IP Analysis',
    data: JSON.stringify(data),
    threatLevel: calculateThreatLevel(data, 'ip')
  };
}

// IP geolocation check
export async function checkIPGeolocation(ip: string) {
  const url = API_ENDPOINTS.ipGeolocation(ip);
  const data = await makeAPIRequest(url);
  
  return {
    source: 'AbstractAPI - IP Geolocation',
    dataType: 'Geolocation',
    data: JSON.stringify(data),
    threatLevel: 1 // Geolocation is typically low threat
  };
}

// Holiday information
export async function getHolidays(country: string, year: number, month: number, day: number) {
  const url = API_ENDPOINTS.holidays(country, year, month, day);
  const data = await makeAPIRequest(url);
  
  return {
    source: 'AbstractAPI - Holidays',
    dataType: 'Holiday Information',
    data: JSON.stringify(data),
    threatLevel: 0 // Holiday info is not a threat
  };
}

// Exchange rates
export async function getExchangeRates(base: string, target: string) {
  const url = API_ENDPOINTS.exchangeRates(base, target);
  const data = await makeAPIRequest(url);
  
  return {
    source: 'AbstractAPI - Exchange Rates',
    dataType: 'Financial Data',
    data: JSON.stringify(data),
    threatLevel: 0 // Exchange rates are not a threat
  };
}

// Company enrichment
export async function enrichCompany(domain: string) {
  const url = API_ENDPOINTS.companyEnrichment(domain);
  const data = await makeAPIRequest(url);
  
  return {
    source: 'AbstractAPI - Company Enrichment',
    dataType: 'Company Information',
    data: JSON.stringify(data),
    threatLevel: calculateThreatLevel(data, 'company')
  };
}

// Timezone information
export async function getTimezone(location: string) {
  const url = API_ENDPOINTS.timezone(location);
  const data = await makeAPIRequest(url);
  
  return {
    source: 'AbstractAPI - Timezone',
    dataType: 'Timezone Information',
    data: JSON.stringify(data),
    threatLevel: 0 // Timezone info is not a threat
  };
}

// BGPView search
export async function searchBGPView(query: string) {
  const url = API_ENDPOINTS.bgpViewSearch(query);
  const data = await makeAPIRequest(url);
  
  return {
    source: 'BGPView - Network Intelligence',
    dataType: 'Network Analysis',
    data: JSON.stringify(data),
    threatLevel: calculateThreatLevel(data, 'bgpview')
  };
}

// Calculate threat level based on data type and content
function calculateThreatLevel(data: any, type: string): number {
  switch (type) {
    case 'email':
      if (data.is_valid === false) return 3;
      if (data.is_disposable === true) return 2;
      if (data.is_smtp_valid === false) return 2;
      return 1;
    
    case 'phone':
      if (data.is_valid === false) return 3;
      if (data.type === 'voip') return 2;
      if (data.is_prepaid === true) return 1;
      return 1;
    
    case 'ip':
      if (data.is_tor === true) return 5;
      if (data.is_vpn === true) return 3;
      if (data.is_proxy === true) return 3;
      if (data.threat_level === 'high') return 4;
      if (data.threat_level === 'medium') return 3;
      if (data.threat_level === 'low') return 2;
      return 1;
    
    case 'vat':
    case 'iban':
      if (data.is_valid === false) return 3;
      return 1;
    
    case 'company':
      // Check for suspicious indicators
      if (data.is_registered === false) return 3;
      if (data.years_in_operation < 1) return 2;
      return 1;
    
    case 'bgpview':
      // Analyze network data for threats
      if (data.data && data.data.asns) {
        // Check for suspicious ASNs
        const suspiciousASNs = data.data.asns.filter((asn: any) => 
          asn.name && (
            asn.name.toLowerCase().includes('malware') ||
            asn.name.toLowerCase().includes('botnet') ||
            asn.name.toLowerCase().includes('spam') ||
            asn.name.toLowerCase().includes('abuse')
          )
        );
        if (suspiciousASNs.length > 0) return 4;
        
        // Check for high number of prefixes (could indicate hijacking)
        if (data.data.asns.some((asn: any) => asn.prefixes && asn.prefixes.length > 1000)) return 3;
      }
      return 1;
    
    default:
      return 1;
  }
}

// Main API handler for different scan types
export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { target, scanType } = body;

    if (!target || !scanType) {
      return NextResponse.json({ error: 'Missing required fields' }, { status: 400 });
    }

    let result;

    switch (scanType) {
      case 'email':
        result = await checkEmailReputation(target);
        break;
      
      case 'phone':
        result = await checkPhoneIntelligence(target);
        break;
      
      case 'vat':
        result = await validateVAT(target);
        break;
      
      case 'iban':
        result = await validateIBAN(target);
        break;
      
      case 'ip_intelligence':
        result = await checkIPIntelligence(target);
        break;
      
      case 'ip_geolocation':
        result = await checkIPGeolocation(target);
        break;
      
      case 'company':
        result = await enrichCompany(target);
        break;
      
      case 'timezone':
        result = await getTimezone(target);
        break;
      
      case 'holidays':
        // For holidays, target should be JSON with country, year, month, day
        const { country, year, month, day } = JSON.parse(target);
        result = await getHolidays(country, year, month, day);
        break;
      
      case 'exchange_rates':
        // For exchange rates, target should be JSON with base and target
        const { base, target: targetCurrency } = JSON.parse(target);
        result = await getExchangeRates(base, targetCurrency);
        break;
      
      case 'bgpview':
        result = await searchBGPView(target);
        break;
      
      default:
        return NextResponse.json({ error: 'Unsupported scan type' }, { status: 400 });
    }

    return NextResponse.json(result);
  } catch (error) {
    console.error('AbstractAPI error:', error);
    return NextResponse.json({ error: 'Failed to execute scan' }, { status: 500 });
  }
}

// GET handler for available scan types
export async function GET() {
  const availableScans = [
    {
      type: 'email',
      description: 'Email reputation and validation analysis',
      requires: 'email address'
    },
    {
      type: 'phone',
      description: 'Phone intelligence and validation',
      requires: 'phone number'
    },
    {
      type: 'vat',
      description: 'VAT number validation',
      requires: 'VAT number'
    },
    {
      type: 'iban',
      description: 'IBAN validation',
      requires: 'IBAN number'
    },
    {
      type: 'ip_intelligence',
      description: 'IP threat intelligence analysis',
      requires: 'IP address'
    },
    {
      type: 'ip_geolocation',
      description: 'IP geolocation information',
      requires: 'IP address'
    },
    {
      type: 'company',
      description: 'Company enrichment and information',
      requires: 'domain name'
    },
    {
      type: 'timezone',
      description: 'Timezone information for location',
      requires: 'location name'
    },
    {
      type: 'holidays',
      description: 'Holiday information',
      requires: 'JSON: {country, year, month, day}'
    },
    {
      type: 'exchange_rates',
      description: 'Currency exchange rates',
      requires: 'JSON: {base, target}'
    },
    {
      type: 'bgpview',
      description: 'Network intelligence search by ASN, IP, Prefix, Name, or Description',
      requires: 'ASN, IP address, prefix, or network name'
    }
  ];

  return NextResponse.json({ availableScans });
}