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
      tests: ['osi', 'proto_pollution', 'csrf'],
      attackParamLocations: [AttackParamLocation.BODY, AttackParamLocation.HEADER],
      starMetadata: {
        code_source: 'anton7c3/pureflow2:stable',
        databases: ['PostgreSQL'],
        user_roles: ['guest', 'user', 'admin']
      },
      poolSize: +process.env.SECTESTER_SCAN_POOL_SIZE || undefined
    })
    .setFailFast(false)
    .timeout(timeout)
    .run({
      method: HttpMethod.POST,
      url: `${baseUrl}/api/mcp`,
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/json',
        'Mcp-Session-Id': 'mcp_sess_7f3a9c2b1d4e'
      },
      body: {
        jsonrpc: '2.0',
        method: 'tools/call',
        params: {
          name: 'spawn_process',
          arguments: {
            command: 'uname -a'
          }
        },
        id: 10
      }
    });
});