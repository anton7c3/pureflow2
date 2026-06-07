import { test, before, after } from 'node:test';
import { SecRunner } from '@sectester/runner';
import { AttackParamLocation, HttpMethod } from '@sectester/scan';

const timeout = 40 * 60 * 1000;
const baseUrl = process.env.BRIGHT_TARGET_URL!;

let runner!: SecRunner;

before(async () => {
  runner = new SecRunner({
    hostname: process.env.BRIGHT_HOSTNAME!,
    projectId: process.env.BRIGHT_PROJECT_ID!
  });

  await runner.init();
});

after(() => runner.clear());

test('POST /api/mcp', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: [
        'jwt',
        'osi',
        'sqli',
        'ssrf',
        'lfi',
        'server_side_js_injection',
        'ssti',
        'proto_pollution',
        'full_path_disclosure',
        'csrf'
      ],
      attackParamLocations: [AttackParamLocation.HEADER, AttackParamLocation.BODY],
      starMetadata: {
        code_source: 'anton7c3/pureflow2:stable',
        databases: ['PostgreSQL'],
        user_roles: ['guest', 'user', 'admin']
      },
      poolSize: +process.env.SECTESTER_SCAN_POOL_SIZE! || undefined
    })
    .setFailFast(false)
    .timeout(timeout)
    .run({
      method: HttpMethod.POST,
      url: `${baseUrl}/api/mcp`,
      body: {
        jsonrpc: '2.0',
        method: 'initialize',
        id: 1
      },
      headers: {
        Accept: 'application/json',
        Authorization:
          'Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhbGljZUBleGFtcGxlLmNvbSIsImlhdCI6MTcxNzU3NDQwMCwiZXhwIjoxNzE3NTc4MDAwfQ.signature',
        'Content-Type': 'application/json'
      }
    });
});