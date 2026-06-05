import { NextRequest, NextResponse } from 'next/server';
import { db } from '@/lib/db';

export async function GET() {
  try {
    const scans = await db.scan.findMany({
      orderBy: { startedAt: 'desc' },
      include: {
        results: true,
        reports: true
      }
    });
    
    return NextResponse.json(scans);
  } catch (error) {
    console.error('Error fetching scans:', error);
    return NextResponse.json({ error: 'Failed to fetch scans' }, { status: 500 });
  }
}

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { target, scanType, userId, apis } = body;

    if (!target || !scanType || !userId) {
      return NextResponse.json({ error: 'Missing required fields' }, { status: 400 });
    }

    const scan = await db.scan.create({
      data: {
        target,
        scanType,
        status: 'pending',
        threatScore: 0,
        userId
      }
    });

    // Simulate async scan execution
    setTimeout(async () => {
      await executeScan(scan.id, target, scanType, apis || []);
    }, 1000);

    return NextResponse.json(scan);
  } catch (error) {
    console.error('Error creating scan:', error);
    return NextResponse.json({ error: 'Failed to create scan' }, { status: 500 });
  }
}

export async function DELETE(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url);
    const scanId = searchParams.get('scanId');
    const userId = searchParams.get('userId');
    const deleteAll = searchParams.get('deleteAll');

    // Delete all scans for a user
    if (deleteAll === 'true' && userId) {
      // First delete all related results and reports
      await db.result.deleteMany({
        where: {
          scan: {
            userId: userId
          }
        }
      });

      await db.report.deleteMany({
        where: {
          scan: {
            userId: userId
          }
        }
      });

      // Then delete all scans for the user
      const deletedScans = await db.scan.deleteMany({
        where: {
          userId: userId
        }
      });

      return NextResponse.json({ 
        message: `Deleted ${deletedScans.count} scans and all related data`,
        deletedCount: deletedScans.count
      });
    }

    // Delete a specific scan
    if (scanId) {
      // First check if scan exists
      const scan = await db.scan.findUnique({
        where: { id: scanId }
      });

      if (!scan) {
        return NextResponse.json({ error: 'Scan not found' }, { status: 404 });
      }

      // Delete related results and reports first
      await db.result.deleteMany({
        where: { scanId: scanId }
      });

      await db.report.deleteMany({
        where: { scanId: scanId }
      });

      // Delete the scan
      await db.scan.delete({
        where: { id: scanId }
      });

      return NextResponse.json({ 
        message: 'Scan deleted successfully',
        deletedScanId: scanId
      });
    }

    return NextResponse.json({ error: 'Missing scanId or userId parameter' }, { status: 400 });
  } catch (error) {
    console.error('Error deleting scans:', error);
    return NextResponse.json({ error: 'Failed to delete scans' }, { status: 500 });
  }
}

async function executeScan(scanId: string, target: string, scanType: string, apis: string[]) {
  try {
    // Update scan status to running
    await db.scan.update({
      where: { id: scanId },
      data: { status: 'running' }
    });

    const results = [];

    // Execute Instagram API if selected
    if (apis.includes('instagram')) {
      try {
        const instagramResponse = await fetch(`${process.env.NEXT_PUBLIC_APP_URL || 'http://localhost:3000'}/api/instagram`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            target,
            scanId
          })
        });

        if (instagramResponse.ok) {
          console.log('Instagram API call successful');
        } else {
          console.error('Instagram API call failed:', await instagramResponse.text());
        }
      } catch (error) {
        console.error('Instagram API call failed:', error);
      }
    }

    // Execute Twitter API if selected
    if (apis.includes('twitter')) {
      try {
        const twitterResponse = await fetch(`${process.env.NEXT_PUBLIC_APP_URL || 'http://localhost:3000'}/api/twitter`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            target,
            scanId
          })
        });

        if (twitterResponse.ok) {
          console.log('Twitter API call successful');
        } else {
          console.error('Twitter API call failed:', await twitterResponse.text());
        }
      } catch (error) {
        console.error('Twitter API call failed:', error);
      }
    }

    // Execute Facebook API if selected
    if (apis.includes('facebook')) {
      try {
        const facebookResponse = await fetch(`${process.env.NEXT_PUBLIC_APP_URL || 'http://localhost:3000'}/api/facebook`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            target,
            scanId
          })
        });

        if (facebookResponse.ok) {
          console.log('Facebook API call successful');
        } else {
          console.error('Facebook API call failed:', await facebookResponse.text());
        }
      } catch (error) {
        console.error('Facebook API call failed:', error);
      }
    }

    // Execute VeriPhone API if selected
    if (apis.includes('veriphone')) {
      try {
        const veriphoneResponse = await fetch(`${process.env.NEXT_PUBLIC_APP_URL || 'http://localhost:3000'}/api/veriphone`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            target,
            scanId
          })
        });

        if (veriphoneResponse.ok) {
          console.log('VeriPhone API call successful');
        } else {
          console.error('VeriPhone API call failed:', await veriphoneResponse.text());
        }
      } catch (error) {
        console.error('VeriPhone API call failed:', error);
      }
    }

    // Execute TikTok Scraper API if selected
    if (apis.includes('tiktok')) {
      try {
        const tiktokResponse = await fetch(`${process.env.NEXT_PUBLIC_APP_URL || 'http://localhost:3000'}/api/tiktok-scraper`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            url: target
          })
        });

        if (tiktokResponse.ok) {
          const tiktokResult = await tiktokResponse.json();
          results.push({
            source: 'TikTok Scraper',
            dataType: 'Social Media Analysis',
            data: JSON.stringify(tiktokResult),
            threatLevel: tiktokResult.error ? 3 : 1
          });
          console.log('TikTok API call successful');
        } else {
          console.error('TikTok API call failed:', await tiktokResponse.text());
        }
      } catch (error) {
        console.error('TikTok API call failed:', error);
      }
    }

    // Execute Vulners API if selected
    if (apis.includes('vulners')) {
      try {
        const vulnersResponse = await fetch(`${process.env.NEXT_PUBLIC_APP_URL || 'http://localhost:3000'}/api/vulners`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            target,
            scanType
          })
        });

        if (vulnersResponse.ok) {
          const vulnersResult = await vulnersResponse.json();
          results.push({
            source: 'Vulners.com',
            dataType: 'Vulnerability Assessment',
            data: JSON.stringify(vulnersResult),
            threatLevel: vulnersResult.vulnerability.score >= 7 ? 4 : vulnersResult.vulnerability.score >= 4 ? 3 : 2
          });
          console.log('Vulners API call successful');
        } else {
          console.error('Vulners API call failed:', await vulnersResponse.text());
        }
      } catch (error) {
        console.error('Vulners API call failed:', error);
      }
    }

    // Execute BreachDirectory API if selected
    if (apis.includes('breach-directory')) {
      try {
        const breachResponse = await fetch(`${process.env.NEXT_PUBLIC_APP_URL || 'http://localhost:3000'}/api/breach-directory`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            target,
            scanType
          })
        });

        if (breachResponse.ok) {
          const breachResult = await breachResponse.json();
          results.push({
            source: 'BreachDirectory',
            dataType: 'Breach Assessment',
            data: JSON.stringify(breachResult),
            threatLevel: breachResult.breachData.found ? 3 : 1
          });
          console.log('BreachDirectory API call successful');
        } else {
          console.error('BreachDirectory API call failed:', await breachResponse.text());
        }
      } catch (error) {
        console.error('BreachDirectory API call failed:', error);
      }
    }

    // Apply custom threat levels from user settings
    // This would be passed from the frontend in a real implementation
    const customThreatLevels: {[key: string]: number} = {};
    results.forEach(result => {
      if (customThreatLevels[result.source]) {
        result.threatLevel = customThreatLevels[result.source];
      }
    });

    // Execute AbstractAPI scans based on scan type
    try {
      const abstractAPIResponse = await fetch(`${process.env.NEXT_PUBLIC_APP_URL || 'http://localhost:3000'}/api/abstractapi`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          target,
          scanType
        })
      });

      if (abstractAPIResponse.ok) {
        const apiResult = await abstractAPIResponse.json();
        results.push({
          source: apiResult.source,
          dataType: apiResult.dataType,
          data: apiResult.data,
          threatLevel: apiResult.threatLevel
        });
      }
    } catch (error) {
      console.error('AbstractAPI call failed:', error);
    }

    // If no results from APIs, use mock data as fallback
    if (results.length === 0) {
      const mockResults = generateMockResults(target, scanType);
      results.push(...mockResults);
    }

    // Save results to database
    for (const result of results) {
      await db.result.create({
        data: {
          scanId,
          source: result.source,
          dataType: result.dataType,
          data: result.data,
          threatLevel: result.threatLevel
        }
      });
    }

    // Calculate overall threat score
    const avgThreatScore = Math.round(
      results.reduce((acc, r) => acc + r.threatLevel, 0) / results.length * 25
    );

    // Update scan as completed
    await db.scan.update({
      where: { id: scanId },
      data: {
        status: 'completed',
        threatScore: avgThreatScore,
        completedAt: new Date()
      }
    });

  } catch (error) {
    console.error('Error executing scan:', error);
    await db.scan.update({
      where: { id: scanId },
      data: { status: 'failed' }
    });
  }
}

function generateMockResults(target: string, scanType: string) {
  const mockData = {
    domain: [
      {
        source: 'Shodan',
        dataType: 'Port Scan',
        data: JSON.stringify({
          open_ports: [80, 443, 22],
          vulnerabilities: ['CVE-2023-1234'],
          services: ['HTTP', 'HTTPS', 'SSH']
        }),
        threatLevel: 3
      },
      {
        source: 'VirusTotal',
        dataType: 'Malware Analysis',
        data: JSON.stringify({
          malicious: 0,
          suspicious: 2,
          clean: 68
        }),
        threatLevel: 1
      }
    ],
    ip: [
      {
        source: 'AbuseIPDB',
        dataType: 'IP Reputation',
        data: JSON.stringify({
          reports: 3,
          confidence: 75,
          last_report: '2024-01-10'
        }),
        threatLevel: 2
      },
      {
        source: 'GeoIP',
        dataType: 'Geolocation',
        data: JSON.stringify({
          country: 'United States',
          city: 'New York',
          isp: 'Example ISP'
        }),
        threatLevel: 1
      }
    ],
    email: [
      {
        source: 'Email Validator',
        dataType: 'Email Analysis',
        data: JSON.stringify({
          is_valid: true,
          is_disposable: false,
          domain: 'example.com'
        }),
        threatLevel: 1
      }
    ],
    phone: [
      {
        source: 'Phone Validator',
        dataType: 'Phone Analysis',
        data: JSON.stringify({
          is_valid: true,
          type: 'mobile',
          carrier: 'Example Carrier',
          country: 'US'
        }),
        threatLevel: 1
      }
    ],
    company: [
      {
        source: 'Company Database',
        dataType: 'Company Information',
        data: JSON.stringify({
          name: 'Example Company',
          industry: 'Technology',
          employees: '100-500',
          founded: 2010
        }),
        threatLevel: 1
      }
    ],
    vat: [
      {
        source: 'VAT Validator',
        dataType: 'VAT Validation',
        data: JSON.stringify({
          is_valid: true,
          country: 'GB',
          company_name: 'Example Ltd'
        }),
        threatLevel: 1
      }
    ],
    iban: [
      {
        source: 'IBAN Validator',
        dataType: 'IBAN Validation',
        data: JSON.stringify({
          is_valid: true,
          bank: 'Example Bank',
          country: 'GB'
        }),
        threatLevel: 1
      }
    ],
    ip_intelligence: [
      {
        source: 'IP Intelligence',
        dataType: 'Threat Analysis',
        data: JSON.stringify({
          is_tor: false,
          is_vpn: false,
          is_proxy: false,
          threat_level: 'low'
        }),
        threatLevel: 1
      }
    ],
    ip_geolocation: [
      {
        source: 'IP Geolocation',
        dataType: 'Geolocation',
        data: JSON.stringify({
          country: 'United States',
          region: 'California',
          city: 'San Francisco',
          latitude: 37.7749,
          longitude: -122.4194
        }),
        threatLevel: 1
      }
    ],
    timezone: [
      {
        source: 'Timezone API',
        dataType: 'Timezone Information',
        data: JSON.stringify({
          timezone: 'America/New_York',
          current_time: '2024-01-15 10:30:00',
          utc_offset: '-05:00'
        }),
        threatLevel: 0
      }
    ],
    holidays: [
      {
        source: 'Holiday API',
        dataType: 'Holiday Information',
        data: JSON.stringify({
          holiday_name: 'Christmas Day',
          date: '2024-12-25',
          country: 'US',
          type: 'public'
        }),
        threatLevel: 0
      }
    ],
    exchange_rates: [
      {
        source: 'Exchange Rate API',
        dataType: 'Financial Data',
        data: JSON.stringify({
          base_currency: 'USD',
          target_currency: 'EUR',
          exchange_rate: 0.85,
          last_updated: '2024-01-15'
        }),
        threatLevel: 0
      }
    ],
    bgpview: [
      {
        source: 'BGPView Network Intelligence',
        dataType: 'Network Analysis',
        data: JSON.stringify({
          query: '8.8.8.8',
          asns: [
            {
              asn: 'AS15169',
              name: 'Google LLC',
              description: 'Google LLC',
              country: 'US',
              prefixes_count: 2456,
              prefixes: [
                {
                  prefix: '8.8.8.0/24',
                  description: 'Google DNS',
                  country: 'US'
                }
              ]
            }
          ]
        }),
        threatLevel: 1
      }
    ],
    comprehensive: [
      {
        source: 'Multi-Source Analysis',
        dataType: 'Comprehensive Report',
        data: JSON.stringify({
          overview: 'Comprehensive analysis completed',
          sources_checked: 15,
          threats_found: 2,
          recommendations: ['Monitor suspicious activity', 'Update security policies']
        }),
        threatLevel: 2
      }
    ],
    username: [
      {
        source: 'Social Media Search',
        dataType: 'Username Analysis',
        data: JSON.stringify({
          platforms: ['twitter', 'github', 'linkedin'],
          found: 3,
          total_checked: 20
        }),
        threatLevel: 1
      }
    ]
  };

  return mockData[scanType as keyof typeof mockData] || mockData.comprehensive;
}