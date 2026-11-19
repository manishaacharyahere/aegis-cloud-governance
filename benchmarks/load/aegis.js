// Sustained mixed read load on the dashboard's API routes (k6).
//
// 20 virtual users, each a different person, ramp up over 30 s and browse for
// 2 minutes; each user stays under the per-user rate limit (600/min), as
// real people do. Thresholds fail the run if p95 or the error rate regress.
//
//   docker run --rm -i -e AEGIS_URL=http://host.docker.internal:18080 grafana/k6:1.8.2 run - < benchmarks/load/aegis.js
//
// AEGIS_URL: the API. AEGIS_TOKEN: a bearer token (OIDC mode); without it the
// development actor header is sent, one actor per virtual user.
import http from 'k6/http'
import { check, sleep } from 'k6'

const base = __ENV.AEGIS_URL || 'http://127.0.0.1:8080'
const tenant = __ENV.AEGIS_TENANT || 'demo'

const routes = [
  ['me', '/api/v1/me'],
  ['resources', '/api/v1/resources?limit=50'],
  ['resource types', '/api/v1/resources/types'],
  ['risk', '/api/v1/risk/assessments/latest?min_band=high&limit=200'],
  ['attack paths', '/api/v1/risk/attack-paths?limit=20'],
  ['coverage', '/api/v1/compliance/coverage?framework=nist-csf-2.0'],
  ['cost summary', '/api/v1/cost/summary?group_by=team'],
  ['recommendations', '/api/v1/recommendations?status=open'],
  ['remediations', '/api/v1/remediations?limit=50'],
  ['drift reports', '/api/v1/drift/reports?limit=20'],
  ['audit', '/api/v1/audit/events?limit=50'],
]

export const options = {
  scenarios: {
    browse: {
      executor: 'ramping-vus',
      stages: [{ duration: '30s', target: 20 }, { duration: '2m', target: 20 }, { duration: '10s', target: 0 }],
    },
  },
  thresholds: {
    http_req_failed: ['rate<0.01'],
    http_req_duration: ['p(95)<250', 'p(99)<600'],
  },
  summaryTrendStats: ['avg', 'med', 'p(95)', 'p(99)', 'max'],
}

// One threshold per route, so the summary lists each route's percentiles.
for (const [name] of routes) options.thresholds[`http_req_duration{route:${name}}`] = ['p(95)<500']

export default function () {
  const headers = { 'X-Aegis-Tenant': tenant, Host: __ENV.AEGIS_HOST || 'localhost' }
  if (__ENV.AEGIS_TOKEN) headers.Authorization = `Bearer ${__ENV.AEGIS_TOKEN}`
  else headers['X-Aegis-Actor'] = `load-${__VU}@aegis.local`
  const [name, path] = routes[Math.floor(Math.random() * routes.length)]
  const res = http.get(base + path, { headers, tags: { route: name } })
  check(res, { 'status 200': (r) => r.status === 200 })
  sleep(0.15 + Math.random() * 0.2) // about 3.5 requests per second per user
}
