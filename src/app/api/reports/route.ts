import { NextRequest, NextResponse } from 'next/server';
import { db } from '@/lib/db';

export async function GET(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url);
    const scanId = searchParams.get('scanId');

    let reports;
    
    if (scanId) {
      reports = await db.report.findMany({
        where: { scanId },
        orderBy: { generatedAt: 'desc' }
      });
    } else {
      reports = await db.report.findMany({
        orderBy: { generatedAt: 'desc' },
        include: {
          scan: {
            select: {
              target: true,
              scanType: true,
              threatScore: true
            }
          }
        }
      });
    }
    
    return NextResponse.json(reports);
  } catch (error) {
    console.error('Error fetching reports:', error);
    return NextResponse.json({ error: 'Failed to fetch reports' }, { status: 500 });
  }
}

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { scanId, format } = body;

    if (!scanId || !format) {
      return NextResponse.json({ error: 'Missing required fields' }, { status: 400 });
    }

    // Get scan data with results
    const scan = await db.scan.findUnique({
      where: { id: scanId },
      include: {
        results: true
      }
    });

    if (!scan) {
      return NextResponse.json({ error: 'Scan not found' }, { status: 404 });
    }

    // Generate report content based on format
    let content: string;
    
    if (format === 'json') {
      content = JSON.stringify(scan, null, 2);
    } else if (format === 'pdf') {
      // For PDF, we'll create a simple text representation
      // In a real implementation, you'd use a PDF library
      content = generateTextReport(scan);
    } else {
      content = generateTextReport(scan);
    }

    const report = await db.report.create({
      data: {
        scanId,
        format,
        content
      }
    });

    return NextResponse.json(report);
  } catch (error) {
    console.error('Error creating report:', error);
    return NextResponse.json({ error: 'Failed to create report' }, { status: 500 });
  }
}

function generateTextReport(scan: any): string {
  let report = `OSINT Scan Report\n`;
  report += `==================\n\n`;
  report += `Target: ${scan.target}\n`;
  report += `Scan Type: ${scan.scanType}\n`;
  report += `Status: ${scan.status}\n`;
  report += `Threat Score: ${scan.threatScore}%\n`;
  report += `Started: ${scan.startedAt}\n`;
  if (scan.completedAt) {
    report += `Completed: ${scan.completedAt}\n`;
  }
  report += `\nResults:\n--------\n`;
  
  scan.results.forEach((result: any, index: number) => {
    report += `\n${index + 1}. ${result.source} - ${result.dataType}\n`;
    report += `   Threat Level: ${result.threatLevel}\n`;
    report += `   Data: ${result.data}\n`;
  });
  
  return report;
}