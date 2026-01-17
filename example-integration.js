/*
 Copyright (c) 2026 DarkNio
 Licensed under the MIT License. See LICENSE file in project root.
*/

// Example: Start auth-server (express + puppeteer) to allow remote YouTube login/export of cookies
// Usage:
//  - place this file inside the `darkchair_api_yt` folder and run with Node.js
//  - or copy the snippet into your bot's startup sequence

try {
  // When running from inside the `darkchair_api_yt` folder use require('.')
  // If you require from the project root you can use: require('./darkchair_api_yt')
  const api = require('.');
  const authPort = process.env.AUTH_PORT || 3001;

  if (api && typeof api.startAuthServer === 'function') {
    (async () => {
      try {
        await api.startAuthServer(authPort);
        console.log(`auth-server listening on ${authPort}`);
      } catch (e) {
        console.error('Failed to start auth-server (async):', e && e.message ? e.message : e);
      }
    })();
  } else {
    console.log('auth-server module does not export startAuthServer(); skipping async start.');
  }
} catch (e) {
  console.error('Failed to start auth-server:', e && e.message ? e.message : e);
}
