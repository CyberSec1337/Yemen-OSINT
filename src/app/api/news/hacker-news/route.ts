import { NextRequest, NextResponse } from 'next/server';

interface HackerNewsResult {
  source: string;
  dataType: string;
  stories: {
    top_stories: Array<{
      id: string;
      title: string;
      url?: string;
      score: number;
      by: string;
      time: number;
      descendants?: number;
      type: string;
      text?: string;
    }>;
    total_stories: number;
  };
  error?: string;
}

export async function GET(request: NextRequest) {
  try {
    // Hacker News API integration
    const options = {
      method: 'GET',
      hostname: 'hacker-news-api2.p.rapidapi.com',
      port: null,
      path: '/stories/top',
      headers: {
        'x-rapidapi-key': 'b18cd28339msh87a0f0139a2b758p14c568jsn00126833d73b',
        'x-rapidapi-host': 'hacker-news-api2.p.rapidapi.com'
      }
    };

    // Make the API request
    const response = await fetch(`https://${options.hostname}${options.path}`, {
      method: options.method,
      headers: options.headers
    });

    if (!response.ok) {
      throw new Error(`فشل طلب Hacker News API بالحالة: ${response.status}`);
    }

    const apiResponse = await response.json();
    console.log('Hacker News API Response:', apiResponse);

    const result: HackerNewsResult = {
      source: 'Hacker News',
      dataType: 'Tech News Analysis',
      stories: {
        top_stories: apiResponse.data || apiResponse.stories || [],
        total_stories: apiResponse.data?.length || apiResponse.stories?.length || 0
      }
    };

    return NextResponse.json(result);

  } catch (error) {
    console.error('Hacker News API Error:', error);
    
    const errorMessage = error instanceof Error ? error.message : 'حدث خطأ غير معروف';
    
    return NextResponse.json(
      { 
        error: 'فشل في جلب أخبار Hacker News',
        details: errorMessage
      },
      { status: 500 }
    );
  }
}