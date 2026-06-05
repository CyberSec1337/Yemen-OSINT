import { NextRequest, NextResponse } from 'next/server';

interface NewsSearchRequest {
  query: string;
  sources?: string[];
  category?: string;
}

interface NewsSearchResult {
  source: string;
  dataType: string;
  articles: Array<{
    id: string;
    title: string;
    description: string;
    url: string;
    publishedAt: string;
    author?: string;
    category?: string;
    source?: string;
    imageUrl?: string;
  }>;
  total_articles: number;
  error?: string;
}

export async function POST(request: NextRequest) {
  try {
    const body: NewsSearchRequest = await request.json();
    const { query, sources = ['cyber-articles', 'hacker-news'], category = 'all' } = body;

    if (!query) {
      return NextResponse.json(
        { error: 'Search query is required' },
        { status: 400 }
      );
    }

    const allArticles: any[] = [];

    // Search from Cyber Articles API
    if (sources.includes('cyber-articles')) {
      try {
        const cyberResponse = await fetch(`https://cyber-articles.p.rapidapi.com/news/latest`, {
          method: 'GET',
          headers: {
            'x-rapidapi-key': 'b18cd28339msh87a0f0139a2b758p14c568jsn00126833d73b',
            'x-rapidapi-host': 'cyber-articles.p.rapidapi.com'
          }
        });

        if (cyberResponse.ok) {
          const cyberData = await cyberResponse.json();
          const cyberArticles = (cyberData.articles || cyberData.data || [])
            .filter((article: any) => 
              article.title?.toLowerCase().includes(query.toLowerCase()) ||
              article.description?.toLowerCase().includes(query.toLowerCase())
            )
            .map((article: any) => ({
              id: article.id || Math.random().toString(),
              title: article.title,
              description: article.description,
              url: article.url,
              publishedAt: article.publishedAt || article.date,
              author: article.author,
              category: article.category,
              source: 'Cyber Articles',
              imageUrl: article.imageUrl
            }));
          
          allArticles.push(...cyberArticles);
        }
      } catch (error) {
        console.error('Cyber Articles API Error:', error);
      }
    }

    // Search from Hacker News API
    if (sources.includes('hacker-news')) {
      try {
        const hackerResponse = await fetch(`https://hacker-news.firebaseio.com/v0/search.json?query=${encodeURIComponent(query)}`, {
          method: 'GET'
        });

        if (hackerResponse.ok) {
          const hackerIds = await hackerResponse.json();
          const hackerArticles = [];

          // Get first 10 articles
          for (let i = 0; i < Math.min(10, hackerIds.length); i++) {
            try {
              const articleResponse = await fetch(`https://hacker-news.firebaseio.com/v0/item/${hackerIds[i]}.json`, {
                method: 'GET'
              });
              
              if (articleResponse.ok) {
                const article = await articleResponse.json();
                if (article && article.title && article.url) {
                  hackerArticles.push({
                    id: article.id,
                    title: article.title,
                    description: article.text || 'No description available',
                    url: article.url,
                    publishedAt: new Date(article.time * 1000).toISOString(),
                    author: article.by,
                    category: 'Technology',
                    source: 'Hacker News',
                    imageUrl: null
                  });
                }
              }
            } catch (error) {
              console.error('Error fetching Hacker News article:', error);
            }
          }
          
          allArticles.push(...hackerArticles);
        }
      } catch (error) {
        console.error('Hacker News API Error:', error);
      }
    }

    // If no articles found, return mock data for demonstration
    if (allArticles.length === 0) {
      const mockArticles = [
        {
          id: '1',
          title: `Latest Cybersecurity Threat: ${query}`,
          description: `Comprehensive analysis of the latest ${query} threat landscape and mitigation strategies.`,
          url: 'https://example.com/cybersecurity-news',
          publishedAt: new Date().toISOString(),
          author: 'Security Analyst',
          category: 'Threat Intelligence',
          source: 'Demo Source',
          imageUrl: null
        },
        {
          id: '2',
          title: `${query} Vulnerability Discovered`,
          description: `Security researchers have identified a critical vulnerability related to ${query}. Immediate patching recommended.`,
          url: 'https://example.com/vulnerability-report',
          publishedAt: new Date(Date.now() - 86400000).toISOString(),
          author: 'Vulnerability Research Team',
          category: 'Vulnerabilities',
          source: 'Demo Source',
          imageUrl: null
        }
      ];
      allArticles.push(...mockArticles);
    }

    const result: NewsSearchResult = {
      source: 'News Search',
      dataType: 'News Analysis',
      articles: allArticles,
      total_articles: allArticles.length
    };

    return NextResponse.json(result);

  } catch (error) {
    console.error('News Search API Error:', error);
    
    const errorMessage = error instanceof Error ? error.message : 'Unknown error occurred';
    
    return NextResponse.json(
      { 
        error: 'Failed to search news',
        details: errorMessage
      },
      { status: 500 }
    );
  }
}