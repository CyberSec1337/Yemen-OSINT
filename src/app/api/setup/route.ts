import { NextResponse } from 'next/server';
import { db } from '@/lib/db';
import bcrypt from 'bcryptjs';

export async function POST() {
  try {
    // Create demo user
    const hashedPassword = await bcrypt.hash('demo123', 10);
    
    const demoUser = await db.user.upsert({
      where: { email: 'demo@osint.com' },
      update: {},
      create: {
        email: 'demo@osint.com',
        password: hashedPassword,
        name: 'Demo User'
      }
    });

    return NextResponse.json({ 
      message: 'Demo user created successfully',
      user: {
        id: demoUser.id,
        email: demoUser.email,
        name: demoUser.name
      }
    });
  } catch (error) {
    console.error('Error setting up demo user:', error);
    return NextResponse.json({ error: 'Failed to setup demo user' }, { status: 500 });
  }
}