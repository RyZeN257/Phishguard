const axios = require('axios');

exports.handler = async (event) => {
  // CORS headers
  const headers = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Content-Type': 'application/json'
  };

  // Handle preflight
  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 200, headers, body: '' };
  }

  // Vérifier que c'est bien une requête POST
  if (event.httpMethod !== "POST") {
    return { statusCode: 405, headers, body: JSON.stringify({ error: "Method Not Allowed" }) };
  }

  const { url } = JSON.parse(event.body);
  const API_KEY = process.env.GOOGLE_SAFE_BROWSING_KEY;

  try {
    // Valider l'URL
    if (!url || typeof url !== 'string') {
      return {
        statusCode: 400,
        headers,
        body: JSON.stringify({ error: "URL invalide", isSafe: null })
      };
    }

    // Ajouter http:// si manquant
    const fullUrl = url.startsWith('http') ? url : `https://${url}`;

    const response = await axios.post(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${API_KEY}`,
      {
        client: { clientId: "phishguard", clientVersion: "1.0.0" },
        threatInfo: {
          threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
          platformTypes: ["ANY_PLATFORM"],
          threatEntryTypes: ["URL"],
          threatEntries: [{ url: fullUrl }]
        }
      }
    );

    // Si 'matches' existe, c'est que le site est dangereux
    const isSafe = !response.data.matches;

    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({ 
        isSafe: isSafe,
        matches: response.data.matches || null,
        debug: { url: fullUrl }
      })
    };
  } catch (error) {
    return {
      statusCode: 500,
      headers,
      body: JSON.stringify({ 
        error: error.response?.data?.error?.message || "Erreur de communication avec Google",
        details: error.message,
        isSafe: null
      })
    };
  }
};