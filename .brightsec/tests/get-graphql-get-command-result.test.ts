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

test('GET /graphql getCommandResult', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: ['osi', 'graphql_introspection', 'full_path_disclosure'],
      attackParamLocations: [AttackParamLocation.QUERY],
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
      method: HttpMethod.GET,
      url: `${baseUrl}/graphql?operationName=getCommandResult&query=query%20getCommandResult(%24command%3A%20String!)%20%7B%20getCommandResult(command%3A%20%24command)%20%7D&variables=%7B%22command%22%3A%22pwd%22%7D}`,
      headers: { Accept: 'application/json' }
    });
});