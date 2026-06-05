import { NextRequest, NextResponse } from 'next/server';

interface TikTokProfileRequest {
  url: string;
}

interface TikTokProfileResult {
  platform: string;
  profile_url: string;
  username: string;
  email?: string;
  follower_count?: number;
  following_count?: number;
  video_count?: number;
  likes_count?: number;
  bio?: string;
  verified?: boolean;
  profile_image?: string;
  error?: string;
}

export async function POST(request: NextRequest) {
  try {
    const body: TikTokProfileRequest = await request.json();
    const { url } = body;

    if (!url) {
      return NextResponse.json(
        { error: 'TikTok profile URL is required' },
        { status: 400 }
      );
    }

    // Validate TikTok URL format
    const tiktokUrlRegex = /^https?:\/\/(www\.)?tiktok\.com\/@[\w.-]+\/?$/;
    if (!tiktokUrlRegex.test(url)) {
      return NextResponse.json(
        { error: 'Invalid TikTok profile URL format. Expected format: https://www.tiktok.com/@username' },
        { status: 400 }
      );
    }

    // Call TikTok Profile Email Scraper API
    const options = {
      method: 'POST',
      hostname: 'tiktok-profile-email-scraper.p.rapidapi.com',
      port: null,
      path: '/api/tiktok-profile-lead-scraper/',
      headers: {
        'x-rapidapi-key': 'b18cd28339msh87a0f0139a2b758p14c568jsn00126833d73b',
        'x-rapidapi-host': 'tiktok-profile-email-scraper.p.rapidapi.com',
        'Content-Type': 'application/json'
      }
    };

    const apiData = JSON.stringify({ url });

    // Make the API request
    const response = await fetch(`https://${options.hostname}${options.path}`, {
      method: options.method,
      headers: options.headers,
      body: apiData
    });

    if (!response.ok) {
      throw new Error(`TikTok API request failed with status: ${response.status}`);
    }

    const apiResponse = await response.json();
    console.log('TikTok API Response:', apiResponse);

    // Process the response and extract relevant information
    const result: TikTokProfileResult = {
      platform: 'TikTok',
      profile_url: url,
      username: extractUsername(url),
      email: apiResponse.email || apiResponse.contact_email || undefined,
      follower_count: apiResponse.follower_count || apiResponse.followers || undefined,
      following_count: apiResponse.following_count || apiResponse.following || undefined,
      video_count: apiResponse.video_count || apiResponse.videos || undefined,
      likes_count: apiResponse.likes_count || apiResponse.likes || apiResponse.total_likes || undefined,
      bio: apiResponse.bio || apiResponse.description || undefined,
      verified: apiResponse.verified || apiResponse.is_verified || false,
      profile_image: apiResponse.profile_image || apiResponse.avatar_url || undefined
    };

    // If there's an error in the API response
    if (apiResponse.error) {
      result.error = apiResponse.error;
    }

    return NextResponse.json(result);

  } catch (error) {
    console.error('TikTok Profile Scraper API Error:', error);
    
    const errorMessage = error instanceof Error ? error.message : 'Unknown error occurred';
    
    return NextResponse.json(
      { 
        error: 'Failed to scrape TikTok profile',
        details: errorMessage
      },
      { status: 500 }
    );
  }
}

function extractUsername(url: string): string {
  const match = url.match(/tiktok\.com\/@([\w.-]+)/);
  return match ? match[1] : 'unknown';
}