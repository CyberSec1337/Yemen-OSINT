import { NextRequest, NextResponse } from 'next/server';
import { db } from '@/lib/db';

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { userId } = body;

    if (!userId) {
      return NextResponse.json(
        { error: 'User ID is required' },
        { status: 400 }
      );
    }

    // Delete all results for the user's scans
    await db.result.deleteMany({
      where: {
        scan: {
          userId: userId
        }
      }
    });

    // Delete all reports for the user's scans
    await db.report.deleteMany({
      where: {
        scan: {
          userId: userId
        }
      }
    });

    // Delete all scans for the user
    const deleteResult = await db.scan.deleteMany({
      where: {
        userId: userId
      }
    });

    return NextResponse.json({
      success: true,
      message: `Successfully deleted ${deleteResult.count} scans`,
      deletedCount: deleteResult.count
    });

  } catch (error) {
    console.error('Error clearing all scans:', error);
    
    const errorMessage = error instanceof Error ? error.message : 'Unknown error occurred';
    
    return NextResponse.json(
      { 
        error: 'Failed to clear all scans',
        details: errorMessage
      },
      { status: 500 }
    );
  }
}

export async function DELETE(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url);
    const userId = searchParams.get('userId');

    if (!userId) {
      return NextResponse.json(
        { error: 'User ID is required' },
        { status: 400 }
      );
    }

    // Delete all results for the user's scans
    await db.result.deleteMany({
      where: {
        scan: {
          userId: userId
        }
      }
    });

    // Delete all reports for the user's scans
    await db.report.deleteMany({
      where: {
        scan: {
          userId: userId
        }
      }
    });

    // Delete all scans for the user
    const deleteResult = await db.scan.deleteMany({
      where: {
        userId: userId
      }
    });

    return NextResponse.json({
      success: true,
      message: `Successfully deleted ${deleteResult.count} scans`,
      deletedCount: deleteResult.count
    });

  } catch (error) {
    console.error('Error clearing all scans:', error);
    
    const errorMessage = error instanceof Error ? error.message : 'Unknown error occurred';
    
    return NextResponse.json(
      { 
        error: 'Failed to clear all scans',
        details: errorMessage
      },
      { status: 500 }
    );
  }
}