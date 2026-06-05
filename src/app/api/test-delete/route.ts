import { NextResponse } from 'next/server';
import { db } from '@/lib/db';

export async function GET() {
  try {
    // Test the delete functionality
    const scans = await db.scan.findMany({
      orderBy: { startedAt: 'desc' },
      take: 3,
      include: {
        results: true,
        reports: true
      }
    });

    if (scans.length === 0) {
      return NextResponse.json({ 
        message: 'No scans found to test delete functionality',
        scansCount: 0
      });
    }

    // Test deleting the first scan
    const testScan = scans[0];
    const originalScanId = testScan.id;

    // Count related data before deletion
    const resultsCount = await db.result.count({
      where: { scanId: originalScanId }
    });

    const reportsCount = await db.report.count({
      where: { scanId: originalScanId }
    });

    return NextResponse.json({ 
      message: 'Delete functionality test endpoint',
      testScan: {
        id: testScan.id,
        target: testScan.target,
        scanType: testScan.scanType,
        resultsCount,
        reportsCount
      },
      totalScans: scans.length,
      instructions: [
        'To test individual scan deletion: DELETE /api/scans?scanId=' + originalScanId,
        'To test delete all: DELETE /api/scans?userId=<user-id>&deleteAll=true',
        'Use the History tab in the UI to test the delete functionality'
      ]
    });
  } catch (error) {
    console.error('Delete test error:', error);
    return NextResponse.json({ 
      error: 'Failed to test delete functionality',
      message: error instanceof Error ? error.message : 'Unknown error'
    }, { status: 500 });
  }
}