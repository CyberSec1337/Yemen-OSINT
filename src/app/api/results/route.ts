import { NextRequest, NextResponse } from 'next/server';
import { db } from '@/lib/db';

export async function GET(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url);
    const scanId = searchParams.get('scanId');

    let results;
    
    if (scanId) {
      results = await db.result.findMany({
        where: { scanId },
        orderBy: { createdAt: 'desc' }
      });
    } else {
      results = await db.result.findMany({
        orderBy: { createdAt: 'desc' },
        include: {
          scan: {
            select: {
              target: true,
              scanType: true
            }
          }
        }
      });
    }
    
    return NextResponse.json(results);
  } catch (error) {
    console.error('Error fetching results:', error);
    return NextResponse.json({ error: 'Failed to fetch results' }, { status: 500 });
  }
}

export async function POST(request: NextRequest) {
  try {
    const body = await request.json();
    const { scanId, source, dataType, data, threatLevel } = body;

    if (!scanId || !source || !dataType || !data) {
      return NextResponse.json({ error: 'Missing required fields' }, { status: 400 });
    }

    const result = await db.result.create({
      data: {
        scanId,
        source,
        dataType,
        data,
        threatLevel: threatLevel || 0
      }
    });

    return NextResponse.json(result);
  } catch (error) {
    console.error('Error creating result:', error);
    return NextResponse.json({ error: 'Failed to create result' }, { status: 500 });
  }
}