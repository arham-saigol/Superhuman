#!/usr/bin/env node
const appUrl = process.env.APP_URL || 'http://localhost:3000';

const health = await fetch(`${appUrl.replace(/\/$/, '')}/api/health`);
if (!health.ok) {
  console.error(`[health-check] failed with ${health.status}`);
  process.exit(1);
}

const body = await health.json();
if (!body.ok) {
  console.error('[health-check] health endpoint returned not ok');
  process.exit(1);
}

console.log('[health-check] ok');
