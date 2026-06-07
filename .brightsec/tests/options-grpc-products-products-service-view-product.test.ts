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

test('OPTIONS /grpc/products.ProductsService/ViewProduct', { signal: AbortSignal.timeout(timeout) }, async () => {
  await runner
    .createScan({
      tests: ['http_method_fuzzing', 'full_path_disclosure'],
      attackParamLocations: [AttackParamLocation.HEADER, AttackParamLocation.PATH],
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
      method: HttpMethod.OPTIONS,
      url: `${baseUrl}/grpc/products.ProductsService/ViewProduct`,
      headers: {
        'Access-Control-Request-Headers': 'content-type,x-grpc-web,x-user-agent',
        'Access-Control-Request-Method': 'POST',
        Origin: 'http://example.com'
      }
    });
});