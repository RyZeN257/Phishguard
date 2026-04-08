const axios = require('axios');

exports.handler = async (event) => {
  // On vérifie que c'est bien une requête POST
  if (event.httpMethod !== "POST") {
    return { statusCode: 405, body: "Method Not Allowed" };
  }

  const { url } = JSON.parse(event.body);
  const API_KEY = process.env.GOOGLE_SAFE_BROWSING_KEY;

  try {
    const response = await axios.post(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${API_KEY}`,
      {
        client: { clientId: "phishguard", clientVersion: "1.0.0" },
        threatInfo: {
          threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
          platformTypes: ["ANY_PLATFORM"],
          threatEntryTypes: ["URL"],
          threatEntries: [{ url: url }]
        }
      }
    );

    // Si 'matches' existe, c'est que le site est dangereux
    const isSafe = !response.data.matches;

    return {
      statusCode: 200,
      body: JSON.stringify({ isSafe: isSafe })
    };
  } catch (error) {
    return {
      statusCode: 500,
      body: JSON.stringify({ error: "Erreur de communication avec Google" })
    };
  }
};