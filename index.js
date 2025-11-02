// Cloudflare Worker for NFT-gated auth & XP storage
import nacl from "tweetnacl";
import bs58 from "bs58";

const HELIUS_RPC = `https://mainnet.helius-rpc.com/?api-key=ee8ad64e-dacb-4966-a9a6-65dfeb7d54d6`;
const COLLECTION_KEY = 'GPtMdqNwNFnZGojyxEseXviJUZiqHyHDzWySjSHFup7J';

// ADD THIS IF NOT ALREADY (for KV)
const XP_STORAGE = YOUR_KV_NAMESPACE;  // e.g., BANKMEN_XP

addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request));
});

async function handleRequest(request) {
  const url = new URL(request.url);
  const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
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
      const token = btoa(JSON.stringify({ pubkey, exp: Date.now() + 86400000 }));
      return Response.json({ token, pubkey }, { headers: corsHeaders });
    }

    if (url.pathname === '/xp' && request.method === 'GET') {
      const token = url.searchParams.get('token');
      if (!token) return Response.json({ error: 'No token' }, { status: 401, headers: corsHeaders });
      let payload;
      try { payload = JSON.parse(atob(token)); } catch { return Response.json({ error: 'Invalid token' }, { status: 401, headers: corsHeaders }); }
      if (Date.now() > payload.exp) return Response.json({ error: 'Token expired' }, { status: 401, headers: corsHeaders });
      const data = await XP_STORAGE.get(payload.pubkey, { type: 'json' }) || { xp: 0, lastUpdated: Date.now() };
      return Response.json(data, { headers: corsHeaders });
    }

    if (url.pathname === '/xp' && request.method === 'POST') {
      const authHeader = request.headers.get('Authorization');
      const token = authHeader?.startsWith('Bearer ') ? authHeader.slice(7) : null;
      if (!token) return Response.json({ error: 'No token' }, { status: 401, headers: corsHeaders });
      let payload;
      try { payload = JSON.parse(atob(token)); } catch { return Response.json({ error: 'Invalid token' }, { status: 401, headers: corsHeaders }); }
      if (Date.now() > payload.exp) return Response.json({ error: 'Token expired' }, { status: 401, headers: corsHeaders });
      const { xp } = await request.json();
      const data = { xp, lastUpdated: Date.now() };
      await XP_STORAGE.put(payload.pubkey, JSON.stringify(data));
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
  const body = {
    jsonrpc: '2.0',
    id: '1',
    method: 'searchAssets',
    params: {
      ownerAddress: pubkey,
      groupKey: 'collection',
      groupValue: COLLECTION_KEY,
      limit: 1,
    },
  };
  const res = await fetch(HELIUS_RPC, { 
    method: 'POST', 
    headers: { 'Content-Type': 'application/json' }, 
    body: JSON.stringify(body) 
  });
  const { result } = await res.json();
  return result?.total > 0;  // Use total, not items.length
}
