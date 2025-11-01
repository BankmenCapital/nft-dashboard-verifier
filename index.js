// Cloudflare Worker for NFT-gated auth & XP storage
// Bindings: KV (env.XP_STORAGE), no other env vars needed

const HELIUS_RPC = `https://mainnet.helius-rpc.com/?api-key=ee8ad64e-dacb-4966-a9a6-65dfeb7d54d6`;
const COLLECTION_KEY = 'GPtMdqNwNFnZGojyxEseXviJUZiqHyHDzWySjSHFup7J'; // Your collection

// Ed25519 sig verify (from tweetnacl—install not needed, CF has crypto)
import nacl from 'https://cdn.skypack.dev/tweetnacl@v1.0.3?dts'; // ESM import for CF
import bs58 from 'https://cdn.skypack.dev/bs58@v5.0.0?dts';

addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request));
});

async function handleRequest(request) {
  const url = new URL(request.url);
  const corsHeaders = {
    'Access-Control-Allow-Origin': '*', // Tighten to your GH Pages domain later
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
  };

  if (request.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    if (url.pathname === '/auth' && request.method === 'POST') {
      const { pubkey, signature, message } = await request.json();
      if (!verifySignature(message, signature, pubkey)) {
        return Response.json({ error: 'Invalid signature' }, { status: 401, headers: corsHeaders });
      }
      const hasNFT = await checkNFTGate(pubkey);
      if (!hasNFT) {
        return Response.json({ error: 'No NFT from collection' }, { status: 403, headers: corsHeaders });
      }
      // Simple JWT-like token (pubkey-based, expires in 24h—use real JWT lib if needed)
      const token = btoa(JSON.stringify({ pubkey, exp: Date.now() + 86400000 }));
      return Response.json({ token, pubkey }, { headers: corsHeaders });
    }

    if (url.pathname === '/xp' && request.method === 'GET') {
      const token = url.searchParams.get('token');
      if (!token) return Response.json({ error: 'No token' }, { status: 401, headers: corsHeaders });
      const { pubkey } = JSON.parse(atob(token));
      if (Date.now() > JSON.parse(atob(token)).exp) return Response.json({ error: 'Token expired' }, { status: 401, headers: corsHeaders });
      const data = await XP_STORAGE.get(pubkey, { type: 'json' }) || { xp: 0, lastUpdated: Date.now() };
      return Response.json(data, { headers: corsHeaders });
    }

    if (url.pathname === '/xp' && request.method === 'POST') {
      const token = request.headers.get('Authorization')?.split(' ')[1];
      if (!token) return Response.json({ error: 'No token' }, { status: 401, headers: corsHeaders });
      const { pubkey: tokenPubkey } = JSON.parse(atob(token));
      if (Date.now() > JSON.parse(atob(token)).exp) return Response.json({ error: 'Token expired' }, { status: 401, headers: corsHeaders });
      const { pubkey, xp } = await request.json();
      if (pubkey !== tokenPubkey) return Response.json({ error: 'Pubkey mismatch' }, { status: 403, headers: corsHeaders });
      const data = { xp, lastUpdated: Date.now() };
      await XP_STORAGE.put(pubkey, JSON.stringify(data));
      return Response.json(data, { headers: corsHeaders });
    }

    return Response.json({ error: 'Not found' }, { status: 404, headers: corsHeaders });
  } catch (e) {
    return Response.json({ error: e.message }, { status: 500, headers: corsHeaders });
  }
}

function verifySignature(message, signature, pubkey) {
  const encodedMsg = new TextEncoder().encode(message);
  const sigBytes = bs58.decode(signature);
  const pubBytes = bs58.decode(pubkey);
  return nacl.sign.detached.verify(encodedMsg, sigBytes, pubBytes);
}

async function checkNFTGate(pubkey) {
  // Helius DAS API: Search assets owned by pubkey in collection
  const body = {
    jsonrpc: '2.0',
    id: '1',
    method: 'searchAssets',
    params: {
      ownerAddress: pubkey,
      groupValue: COLLECTION_KEY, // Collection key as group
      groupKey: 'collection',
      limit: 1, // Just check if any
    },
  };
  const res = await fetch(HELIUS_RPC, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  const { result } = await res.json();
  return result?.items?.length > 0;
}
