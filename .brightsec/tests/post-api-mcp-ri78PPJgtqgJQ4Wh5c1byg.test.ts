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
      tests: ['sqli', 'osi', 'ssti', 'server_side_js_injection', 'proto_pollution', 'csrf'],
      attackParamLocations: [AttackParamLocation.BODY, AttackParamLocation.HEADER],
      starMetadata: {
        code_source: 'anton7c3/pureflow2:stable',
        databases: ['PostgreSQL'],
        user_roles: ['admin', 'user', 'guest']
      },
      poolSize: +process.env.SECTESTER_SCAN_POOL_SIZE || undefined
    })
    .setFailFast(false)
    .timeout(timeout)
    .run({
      method: HttpMethod.POST,
      url: `${baseUrl}/api/mcp`,
      body: {
        jsonrpc: '2.0',
        method: 'tools/call',
        params: {
          name: 'excerpt_text',
          arguments: {
            text: 'Q4 earnings rose 12% year-over-year, driven by strong cloud demand.'
          }
        },
        id: 13
      },
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/json',
        'Mcp-Session-Id': 'mcp_sess_7f3a9c2d1e4b'
      }
    });
});