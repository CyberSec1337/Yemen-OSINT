# AbstractAPI Integration Documentation

This document describes the AbstractAPI endpoints integrated into the OSINT platform, including additional network intelligence APIs.

## Available API Endpoints

### 1. Email Reputation API
- **Endpoint**: `https://emailreputation.abstractapi.com/v1/`
- **Purpose**: Analyze email reputation and validity
- **Input**: Email address (e.g., `user@example.com`)
- **Features**:
  - Email validation
  - Disposable email detection
  - SMTP validation
  - Domain reputation analysis

### 2. Phone Intelligence API
- **Endpoint**: `https://phoneintelligence.abstractapi.com/v1/`
- **Purpose**: Analyze phone numbers and get intelligence
- **Input**: Phone number with country code (e.g., `+1234567890`)
- **Features**:
  - Phone validation
  - Carrier detection
  - Phone type identification (mobile, landline, voip)
  - Country and region information

### 3. VAT Validation API
- **Endpoint**: `https://vat.abstractapi.com/v1/validate/`
- **Purpose**: Validate VAT numbers
- **Input**: VAT number (e.g., `GB123456789`)
- **Features**:
  - VAT number format validation
  - Company name retrieval
  - Country identification

### 4. IBAN Validation API
- **Endpoint**: `https://ibanvalidation.abstractapi.com/v1/`
- **Purpose**: Validate IBAN numbers
- **Input**: IBAN number (e.g., `GB82WEST12345698765432`)
- **Features**:
  - IBAN format validation
  - Bank identification
  - Country information

### 5. IP Intelligence API
- **Endpoint**: `https://ip-intelligence.abstractapi.com/v1/`
- **Purpose**: Analyze IP addresses for security threats
- **Input**: IP address (e.g., `192.168.1.1`)
- **Features**:
  - Tor detection
  - VPN/proxy detection
  - Threat level assessment
  - Malicious IP identification

### 6. IP Geolocation API
- **Endpoint**: `https://ipgeolocation.abstractapi.com/v1/`
- **Purpose**: Get geolocation data for IP addresses
- **Input**: IP address (e.g., `192.168.1.1`)
- **Features**:
  - Country, region, city information
  - Latitude and longitude
  - ISP and organization data
  - Timezone information

### 7. Holidays API
- **Endpoint**: `https://holidays.abstractapi.com/v1/`
- **Purpose**: Get holiday information
- **Input**: JSON object with country, year, month, day
- **Example**: `{"country":"US","year":2025,"month":12,"day":25}`
- **Features**:
  - Public holiday detection
  - Holiday names and types
  - Multiple country support

### 8. Exchange Rates API
- **Endpoint**: `https://exchange-rates.abstractapi.com/v1/live/`
- **Purpose**: Get real-time exchange rates
- **Input**: JSON object with base and target currencies
- **Example**: `{"base":"USD","target":"EUR"}`
- **Features**:
  - Real-time exchange rates
  - Multiple currency support
  - Historical data available

### 9. Company Enrichment API
- **Endpoint**: `https://companyenrichment.abstractapi.com/v2/`
- **Purpose**: Get detailed company information
- **Input**: Domain name (e.g., `company.com`)
- **Features**:
  - Company name and description
  - Industry classification
  - Employee count
  - Revenue information
  - Company registration details

### 10. Timezone API
- **Endpoint**: `https://timezone.abstractapi.com/v1/current_time/`
- **Purpose**: Get timezone and time information
- **Input**: Location name (e.g., `"New York, USA"`)
- **Features**:
  - Current local time
  - Timezone identification
  - UTC offset
  - Daylight saving information

### 11. BGPView API (Additional Network Intelligence)
- **Endpoint**: `https://api.bgpview.io/search`
- **Purpose**: Search network resources by ASN, IP, Prefix, Name, or Description
- **Input**: ASN, IP address, prefix, or network name
- **Examples**:
  - ASN: `AS15169`
  - IP: `8.8.8.8`
  - Prefix: `192.168.0.0/16`
  - Name: `Google`
- **Features**:
  - Autonomous System Number (ASN) lookup
  - IP address network information
  - Prefix analysis
  - Network organization details
  - Route visibility
  - Peering information

## Integration in OSINT Platform

### API Keys
All API keys are configured in the `/api/abstractapi/route.ts` file:

```typescript
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
```

### Usage in Frontend
The frontend includes all scan types in the dropdown menu:
- Comprehensive
- Domain Analysis
- IP Analysis
- Email Analysis
- Phone Intelligence
- Company Enrichment
- VAT Validation
- IBAN Validation
- IP Intelligence
- IP Geolocation
- Timezone Info
- Holiday Info
- Exchange Rates
- Network Intelligence (BGPView)

### Threat Level Calculation
Each API response is analyzed to calculate a threat level (0-5):
- **0**: No threat (informational data)
- **1**: Low threat
- **2**: Moderate-low threat
- **3**: Moderate threat
- **4**: High threat
- **5**: Critical threat

#### BGPView Specific Threat Analysis
The BGPView API includes specialized threat detection:
- **Suspicious ASN Detection**: Identifies ASNs with names containing keywords like "malware", "botnet", "spam", or "abuse"
- **Prefix Analysis**: Flags networks with unusually high numbers of prefixes (potential hijacking indicators)
- **Network Reputation**: Analyzes network organization details for risk assessment

### Error Handling
- If API calls fail, the system falls back to mock data
- All API errors are logged for debugging
- User receives appropriate error messages

## Testing

To test the API integrations:

1. **Manual Testing**: Use the OSINT platform interface to test different scan types
2. **API Testing**: Visit `/api/test-abstractapi` to test the integration
3. **Direct API Testing**: Use the `/api/abstractapi` endpoint directly

### BGPView Testing Examples
```bash
# Test with ASN
curl -X POST http://localhost:3000/api/abstractapi \
  -H "Content-Type: application/json" \
  -d '{"target":"AS15169","scanType":"bgpview"}'

# Test with IP address
curl -X POST http://localhost:3000/api/abstractapi \
  -H "Content-Type: application/json" \
  -d '{"target":"8.8.8.8","scanType":"bgpview"}'

# Test with network name
curl -X POST http://localhost:3000/api/abstractapi \
  -H "Content-Type: application/json" \
  -d '{"target":"Google","scanType":"bgpview"}'
```

## Rate Limits and Usage

- Each AbstractAPI service has its own rate limits
- BGPView API has generous rate limits for network intelligence
- Monitor usage in respective API dashboards
- Consider implementing caching for frequently accessed data
- Handle rate limit errors gracefully

## Security Considerations

- API keys are stored server-side only
- All API calls are made from the backend
- Input validation is performed before API calls
- Sensitive data is logged appropriately
- BGPView data helps identify network-level threats

## OSINT Use Cases

### BGPView for OSINT
- **Network Infrastructure Mapping**: Identify hosting providers and CDNs
- **Threat Attribution**: Link malicious activities to specific networks
- **Infrastructure Analysis**: Understand target network topology
- **Geolocation Correlation**: Cross-reference IP geolocation with ASN data
- **Supply Chain Analysis**: Map relationships between organizations

### Combined Intelligence
- **Email + BGPView**: Correlate email domains with hosting infrastructure
- **IP + BGPView**: Enhanced IP intelligence with network context
- **Company + BGPView**: Map company infrastructure and network presence

## Future Enhancements

- Add more network intelligence APIs
- Implement BGP route monitoring
- Add historical BGP data analysis
- Create network relationship mapping
- Add automated threat hunting based on BGP data
- Implement real-time BGP stream processing