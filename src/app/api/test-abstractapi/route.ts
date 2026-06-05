import { NextResponse } from 'next/server';

export async function GET() {
  try {
    // Test multiple AbstractAPI endpoints
    const tests = [
      {
        name: 'Email Reputation',
        request: {
          target: 'test@example.com',
          scanType: 'email'
        }
      },
      {
        name: 'BGPView Network Intelligence',
        request: {
          target: 'AS15169',
          scanType: 'bgpview'
        }
      }
    ];

    const results = [];

    for (const test of tests) {
      try {
        const testResponse = await fetch(`${process.env.NEXT_PUBLIC_APP_URL || 'http://localhost:3000'}/api/abstractapi`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(test.request)
        });

        if (testResponse.ok) {
          const result = await testResponse.json();
          results.push({
            test: test.name,
            success: true,
            result: result
          });
        } else {
          const error = await testResponse.text();
          results.push({
            test: test.name,
            success: false,
            error: error
          });
        }
      } catch (error) {
        results.push({
          test: test.name,
          success: false,
          error: error instanceof Error ? error.message : 'Unknown error'
        });
      }
    }

    return NextResponse.json({ 
      success: true, 
      message: 'AbstractAPI integration tests completed',
      results: results
    });
  } catch (error) {
    console.error('AbstractAPI test error:', error);
    return NextResponse.json({ 
      success: false, 
      message: 'AbstractAPI test error',
      error: error instanceof Error ? error.message : 'Unknown error'
    }, { status: 500 });
  }
}