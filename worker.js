import { onRequestOptions, onRequestPost } from './functions/api/analyze.js';

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (url.pathname === '/api/analyze') {
      if (request.method === 'OPTIONS') {
        return onRequestOptions();
      }
      if (request.method === 'POST') {
        return onRequestPost({ request, env, ctx });
      }
    }

    if (env.ASSETS) {
      return env.ASSETS.fetch(request);
    }

    return new Response('Not Found', { status: 404 });
  }
};
