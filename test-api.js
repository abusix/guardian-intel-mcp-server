#!/usr/bin/env node

import { GuardianIntelClient } from './dist/guardian-intel-client.js';

async function testAPI() {
  const apiKey = process.env.ABUSIX_API_KEY;
  
  if (!apiKey) {
    console.error('❌ ABUSIX_API_KEY environment variable is not set');
    console.error('Usage: ABUSIX_API_KEY="your-key" node test-api.js');
    process.exit(1);
  }

  console.log('🔑 Using API Key:', apiKey.substring(0, 8) + '...');
  console.log('🌐 Testing Guardian Intel API connection...\n');

  try {
    const client = new GuardianIntelClient({ apiKey });
    
    console.log('✅ Client created successfully');
    
    // Test 1: Health check
    console.log('\n🏥 Testing health check...');
    const isHealthy = await client.healthCheck();
    console.log(`Health check result: ${isHealthy ? '✅ Healthy' : '❌ Unhealthy'}`);
    
    // Test 2: Get tags (simplest API call)
    console.log('\n🏷️ Testing tags endpoint...');
    const tags = await client.getTags(false);
    console.log(`✅ Tags retrieved: ${tags.result.length} tags found`);
    console.log('Sample tags:', tags.result.slice(0, 3).map(t => t.name));
    
    // Test 3: IP lookup (if tags work)
    console.log('\n🔍 Testing IP lookup...');
    const lookup = await client.lookupIp('8.8.8.8');
    console.log(`✅ IP lookup successful for 8.8.8.8`);
    console.log(`Classification: ${lookup.result.classification}`);
    
  } catch (error) {
    console.error('\n❌ Error occurred:');
    console.error('Error message:', error.message);
    console.error('Error stack:', error.stack);
    
    // Provide helpful suggestions based on error type
    if (error.message.includes('403')) {
      console.error('\n💡 Suggestions for 403 Forbidden:');
      console.error('  - Check if your API key is valid and active');
      console.error('  - Verify your API key has the required permissions');
      console.error('  - Ensure you\'re using the correct API endpoint');
      console.error('  - Contact Abusix support if the key should be working');
    } else if (error.message.includes('401')) {
      console.error('\n💡 Suggestions for 401 Unauthorized:');
      console.error('  - Your API key may be invalid or expired');
      console.error('  - Double-check the API key value');
      console.error('  - Generate a new API key if needed');
    }
    
    process.exit(1);
  }
}

testAPI();