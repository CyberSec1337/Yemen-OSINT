import { NextRequest, NextResponse } from 'next/server';

interface CyberArticlesRequest {
  newspaperId?: string;
}

interface CyberArticlesResult {
  source: string;
  dataType: string;
  articles: {
    newspaperId: string;
    articles: Array<{
      id: string;
      title: string;
      description: string;
      url: string;
      publishedAt: string;
      author?: string;
      category?: string;
      tags?: string[];
      imageUrl?: string;
    }>;
    total_articles: number;
  };
  error?: string;
}

export async function GET(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url);
    const newspaperId = searchParams.get('newspaperId') || 'latest';

    // Cyber Articles API integration
    const options = {
      method: 'GET',
      hostname: 'cyber-articles.p.rapidapi.com',
      port: null,
      path: `/news/${newspaperId}`,
      headers: {
        'x-rapidapi-key': 'b18cd28339msh87a0f0139a2b758p14c568jsn00126833d73b',
        'x-rapidapi-host': 'cyber-articles.p.rapidapi.com'
      }
    };

    // Make the API request
    const response = await fetch(`https://${options.hostname}${options.path}`, {
      method: options.method,
      headers: options.headers
    });

    if (!response.ok) {
      throw new Error(`فشل طلب Cyber Articles API بالحالة: ${response.status}`);
    }

    const apiResponse = await response.json();
    console.log('Cyber Articles API Response:', apiResponse);

    const result: CyberArticlesResult = {
      source: 'Cyber Articles',
      dataType: 'News Analysis',
      articles: {
        newspaperId,
        articles: apiResponse.articles || apiResponse.data || [],
        total_articles: apiResponse.articles?.length || apiResponse.data?.length || 0
      }
    };

    return NextResponse.json(result);

  } catch (error) {
    console.error('Cyber Articles API Error:', error);
    
    const errorMessage = error instanceof Error ? error.message : 'حدث خطأ غير معروف';
    
    return NextResponse.json(
      { 
        error: 'فشل في جلب المقالات السيبرانية',
        details: errorMessage
      },
      { status: 500 }
    );
  }
}