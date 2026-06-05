import { NextRequest, NextResponse } from 'next/server';
import { db } from '@/lib/db';

interface APIRequest {
  id?: string;
  name: string;
  description: string;
  endpoint: string;
  method: string;
  headers?: Record<string, string>;
  enabled: boolean;
  category: string;
  threatLevel: number;
}

// GET - Fetch all APIs
export async function GET() {
  try {
    const apis = await db.api.findMany({
      orderBy: { name: 'asc' }
    });

    return NextResponse.json(apis);
  } catch (error) {
    console.error('Error fetching APIs:', error);
    return NextResponse.json(
      { error: 'Failed to fetch APIs' },
      { status: 500 }
    );
  }
}

// POST - Create new API
export async function POST(request: NextRequest) {
  try {
    const body: APIRequest = await request.json();
    const { name, description, endpoint, method, headers, enabled, category, threatLevel } = body;

    if (!name || !description || !endpoint || !method) {
      return NextResponse.json(
        { error: 'Name, description, endpoint, and method are required' },
        { status: 400 }
      );
    }

    const newApi = await db.api.create({
      data: {
        name,
        description,
        endpoint,
        method,
        headers: typeof headers === 'string' ? headers : JSON.stringify(headers || {}),
        enabled: enabled ?? true,
        category: category || 'general',
        threatLevel: threatLevel ?? 2
      }
    });

    return NextResponse.json({
      success: true,
      message: 'API created successfully',
      api: newApi
    });

  } catch (error) {
    console.error('Error creating API:', error);
    return NextResponse.json(
      { error: 'Failed to create API' },
      { status: 500 }
    );
  }
}

// PUT - Update existing API
export async function PUT(request: NextRequest) {
  try {
    const body: APIRequest = await request.json();
    const { id, name, description, endpoint, method, headers, enabled, category, threatLevel } = body;

    if (!id) {
      return NextResponse.json(
        { error: 'API ID is required' },
        { status: 400 }
      );
    }

    const updatedApi = await db.api.update({
      where: { id },
      data: {
        name,
        description,
        endpoint,
        method,
        headers: typeof headers === 'string' ? headers : JSON.stringify(headers || {}),
        enabled,
        category,
        threatLevel
      }
    });

    return NextResponse.json({
      success: true,
      message: 'API updated successfully',
      api: updatedApi
    });

  } catch (error) {
    console.error('Error updating API:', error);
    return NextResponse.json(
      { error: 'Failed to update API' },
      { status: 500 }
    );
  }
}

// DELETE - Delete API
export async function DELETE(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url);
    const id = searchParams.get('id');

    if (!id) {
      return NextResponse.json(
        { error: 'API ID is required' },
        { status: 400 }
      );
    }

    const deletedApi = await db.api.delete({
      where: { id }
    });

    return NextResponse.json({
      success: true,
      message: 'API deleted successfully',
      api: deletedApi
    });

  } catch (error) {
    console.error('Error deleting API:', error);
    return NextResponse.json(
      { error: 'Failed to delete API' },
      { status: 500 }
    );
  }
}