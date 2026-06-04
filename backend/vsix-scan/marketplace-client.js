const MARKETPLACE_API = 'https://marketplace.visualstudio.com/_apis/public/gallery';
const OPENVSX_API = 'https://open-vsx.org/api';

const _cache = new Map();
const CACHE_TTL = 5 * 60 * 1000;
const RATE_LIMIT_MS = 6000;
let _lastFetchTime = 0;

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

async function rateLimitedFetch(url) {
  const now = Date.now();
  const elapsed = now - _lastFetchTime;
  if (elapsed < RATE_LIMIT_MS) {
    await sleep(RATE_LIMIT_MS - elapsed);
  }
  _lastFetchTime = Date.now();

  const cached = _cache.get(url);
  if (cached && Date.now() - cached.fetchedAt < CACHE_TTL) {
    return cached.data;
  }

  let res;
  try {
    res = await fetch(url);
    if (res.status === 429) {
      const retryAfter = parseInt(res.headers.get('Retry-After') || '10', 10);
      await sleep(retryAfter * 1000);
      res = await fetch(url);
    }
    if (!res.ok) {
      console.debug(`Marketplace API warning: ${url} returned ${res.status}`);
      return null;
    }
    const data = await res.json();
    _cache.set(url, { data, fetchedAt: Date.now() });
    return data;
  } catch (err) {
    console.debug(`Marketplace API error: ${err.message}`);
    return null;
  }
}

function _parseExtensionId(id) {
  const parts = id.split('.');
  if (parts.length < 2) {
    throw new Error(`Invalid extension ID: ${id}`);
  }
  return { publisherId: parts[0], extensionName: parts.slice(1).join('.') };
}

export async function getExtensionMetadata(publisherId, extensionName) {
  const url = `${MARKETPLACE_API}/extensionquery`;
  const body = {
    filters: [
      {
        criteria: [{ filterType: 8, value: `${publisherId}.${extensionName}` }],
      },
    ],
    flags: 914,
  };

  const cached = _cache.get(url + JSON.stringify(body));
  if (cached && Date.now() - cached.fetchedAt < CACHE_TTL) {
    return cached.data;
  }

  const now = Date.now();
  const elapsed = now - _lastFetchTime;
  if (elapsed < RATE_LIMIT_MS) {
    await sleep(RATE_LIMIT_MS - elapsed);
  }
  _lastFetchTime = Date.now();

  let res;
  try {
    res = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json;api-version=3.0-preview.1',
      },
      body: JSON.stringify(body),
    });
    if (res.status === 429) {
      const retryAfter = parseInt(res.headers.get('Retry-After') || '10', 10);
      await sleep(retryAfter * 1000);
      res = await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json;api-version=3.0-preview.1',
        },
        body: JSON.stringify(body),
      });
    }
    if (!res.ok) {
      console.debug(`Marketplace API warning: ${url} returned ${res.status}`);
      return null;
    }
    const data = await res.json();
    _cache.set(url + JSON.stringify(body), { data, fetchedAt: Date.now() });
    return data;
  } catch (err) {
    console.debug(`Marketplace API error: ${err.message}`);
    return null;
  }
}

export async function getVersionHistory(publisherId, extensionName) {
  const data = await getExtensionMetadata(publisherId, extensionName);
  if (!data?.results?.[0]?.extensions?.[0]) {
    return [];
  }

  const extension = data.results[0].extensions[0];
  const versions = extension.versions || [];

  return versions.map((v) => ({
    version: v.version,
    publishedAt: v.lastUpdated || v.publishedDate,
    publishedBy: extension.publisher?.publisherName || publisherId,
    assetSha256: v.assetUri ? null : null,
    flags: v.flags ? [String(v.flags)] : [],
  }));
}

export async function getPublisherProfile(publisherId) {
  const url = `${MARKETPLACE_API}/publishers/${publisherId}`;
  return rateLimitedFetch(url);
}

export async function getOpenVsxMetadata(namespace, name) {
  const url = `${OPENVSX_API}/${namespace}/${name}`;
  return rateLimitedFetch(url);
}

export async function getOpenVsxVersionHistory(namespace, name) {
  const data = await getOpenVsxMetadata(namespace, name);
  if (!data) {
    return [];
  }
  const versions = data.allVersions || {};
  const files = data.files || {};

  return Object.entries(versions).map(([version, publishedAt]) => ({
    version,
    publishedAt: typeof publishedAt === 'string' ? publishedAt : data.timestamp,
    publishedBy: data.namespace || namespace,
    assetSha256: files?.[version]?.sha256 || null,
    flags: [],
  }));
}

export function clearMarketplaceCache() {
  _cache.clear();
  _lastFetchTime = 0;
}
