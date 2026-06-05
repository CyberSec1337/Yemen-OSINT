import { NextRequest, NextResponse } from 'next/server';
import { db } from '@/lib/db';

interface DeleteScanRequest {
  scanId: string;
}

export async function POST(request: NextRequest) {
  try {
    const body: DeleteScanRequest = await request.json();
    const { scanId } = body;

    if (!scanId) {
      return NextResponse.json(
        { error: 'Scan ID is required' },
        { status: 400 }
      );
    }

    // First, delete related results
    await db.result.deleteMany({
      where: {
        scanId: scanId
      }
    });

    // Delete related reports
    await db.report.deleteMany({
      where: {
        scanId: scanId
      }
    });

    // Delete the scan
    const deletedScan = await db.scan.delete({
      where: {
        id: scanId
      }
    });

    if (!deletedScan) {
      return NextResponse.json(
        { error: 'Scan not found' },
        { status: 404 }
      );
    }

    return NextResponse.json({
      success: true,
      message: 'Scan deleted successfully',
      deletedScanId: scanId
    });

  } catch (error) {
    console.error('Error deleting scan:', error);
    
    const errorMessage = error instanceof Error ? error.message : 'Unknown error occurred';
    
    return NextResponse.json(
      { 
        error: 'Failed to delete scan',
        details: errorMessage
      },
      { status: 500 }
    );
  }
}

export async function DELETE(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url);
    const scanId = searchParams.get('scanId');

    if (!scanId) {
      return NextResponse.json(
        { error: 'Scan ID is required' },
        { status: 400 }
      );
    }

    // First, delete related results
    await db.result.deleteMany({
      where: {
        scanId: scanId
      }
    });

    // Delete related reports
    await db.report.deleteMany({
      where: {
        scanId: scanId
      }
    });

    // Delete the scan
    const deletedScan = await db.scan.delete({
      where: {
        id: scanId
      }
    });

    if (!deletedScan) {
      return NextResponse.json(
        { error: 'Scan not found' },
        { status: 404 }
      );
    }

    return NextResponse.json({
      success: true,
      message: 'Scan deleted successfully',
      deletedScanId: scanId
    });

  } catch (error) {
    console.error('Error deleting scan:', error);
    
    const errorMessage = error instanceof Error ? error.message : 'Unknown error occurred';
    
    return NextResponse.json(
      { 
        error: 'Failed to delete scan',
        details: errorMessage
      },
      { status: 500 }
    );
  }
}