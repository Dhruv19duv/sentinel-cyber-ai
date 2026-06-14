// Sentinel Cyber AI — k6 Load Test Suite
//
// Tests the API server and WebSocket dashboard endpoints.
// Run with:
//   k6 run tests/k6/dashboard_load_test.js
//   k6 run --vus 50 --duration 30s tests/k6/dashboard_load_test.js
//
// Install k6: https://k6.io/docs/getting-started/installation/

import http from 'k6/http';
import { check, sleep, group } from 'k6';
import { Rate, Trend, Counter } from 'k6/metrics';
import { randomString } from 'https://jslib.k6.io/k6-utils/1.2.0/index.js';

// ── Custom Metrics ──
const failureRate = new Rate('failed_requests');
const analysisDuration = new Trend('analysis_duration_ms');
const apiResponseTime = new Trend('api_response_time_ms');
const totalAnalyses = new Counter('total_analyses');

// ── Configuration ──
const BASE_URL = __ENV.BASE_URL || 'http://localhost:8080';
const DASHBOARD_URL = __ENV.DASHBOARD_URL || 'http://localhost:8500';
const API_KEY = __ENV.SENTINEL_API_KEY || '';

const headers = {
  'Content-Type': 'application/json',
};
if (API_KEY) {
  headers['Authorization'] = `Bearer ${API_KEY}`;
}

const SAMPLE_QUERIES = [
  'find vulnerabilities in: eval(request.GET.get("code"))',
  'check for SQL injection in: cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
  'analyze this for XSS: document.write("<h1>" + userInput + "</h1>")',
  'find command injection: os.system("ping " + hostname)',
  'check for path traversal: open(f"uploads/{filename}", "r").read()',
];

// ── Options ──
export const options = {
  stages: [
    { duration: '10s', target: 10 },   // Ramp up to 10 users
    { duration: '20s', target: 25 },   // Ramp up to 25 users
    { duration: '30s', target: 50 },   // Ramp up to 50 users
    { duration: '20s', target: 25 },   // Ramp down
    { duration: '10s', target: 0 },    // Cool down
  ],
  thresholds: {
    http_req_duration: ['p(95)<5000'],  // 95% of requests under 5s
    failed_requests: ['rate<0.1'],      // Less than 10% failure rate
    http_req_failed: ['rate<0.05'],     // Less than 5% HTTP errors
  },
};

// ── Setup ──
export function setup() {
  // Verify services are running
  const healthCheck = http.get(`${BASE_URL}/health`);
  check(healthCheck, {
    'API server is running': (r) => r.status === 200,
  });

  const dashboardCheck = http.get(`${DASHBOARD_URL}/`);
  check(dashboardCheck, {
    'Dashboard is running': (r) => r.status === 200,
  });

  return { baseUrl: BASE_URL, dashboardUrl: DASHBOARD_URL };
}

// ── Main Test ──
export default function(data) {
  // Simulate a real user browsing the dashboard
  group('Health & Status', function() {
    // Health check
    const healthResp = http.get(`${data.baseUrl}/health`, { headers });
    check(healthResp, {
      'health endpoint OK': (r) => r.status === 200,
    });
    apiResponseTime.add(healthResp.timings.duration);
    failureRate.add(healthResp.status !== 200);
    sleep(1);
  });

  group('Dashboard Pages', function() {
    // Dashboard home
    const dashResp = http.get(`${data.dashboardUrl}/`);
    check(dashResp, {
      'dashboard loads': (r) => r.status === 200 && r.body.includes('Sentinel'),
    });

    // API endpoints that the dashboard calls
    const statusResp = http.get(`${data.dashboardUrl}/api/status`);
    check(statusResp, {
      'status endpoint OK': (r) => r.status === 200,
    });

    const agentsResp = http.get(`${data.dashboardUrl}/api/agents`);
    check(agentsResp, {
      'agents endpoint OK': (r) => r.status === 200,
    });

    const subsystemsResp = http.get(`${data.dashboardUrl}/api/subsystems`);
    check(subsystemsResp, {
      'subsystems endpoint OK': (r) => r.status === 200,
    });

    const eventsResp = http.get(`${data.dashboardUrl}/api/events?limit=10`);
    check(eventsResp, {
      'events endpoint OK': (r) => r.status === 200,
    });

    // Integration status
    const integrationsResp = http.get(`${data.dashboardUrl}/api/integrations`);
    check(integrationsResp, {
      'integrations endpoint OK': (r) => r.status === 200,
    });

    sleep(2);
  });

  group('API Endpoints', function() {
    // Thinking status
    const thinkStatusResp = http.get(`${data.baseUrl}/api/v1/status`);
    check(thinkStatusResp, {
      'API status endpoint OK': (r) => r.status === 200,
    });

    // Agents list
    const apiAgentsResp = http.get(`${data.baseUrl}/api/v1/agents`);
    check(apiAgentsResp, {
      'API agents endpoint OK': (r) => r.status === 200,
    });

    sleep(1);
  });

  group('Analysis (POST)', function() {
    // Random query from the list
    const query = SAMPLE_QUERIES[Math.floor(Math.random() * SAMPLE_QUERIES.length)];

    const analyzeResp = http.post(`${data.dashboardUrl}/api/analyze`, JSON.stringify({
      query: query,
      parallel_agents: true,
    }), { headers });

    check(analyzeResp, {
      'analysis accepted': (r) => r.status === 200,
    });

    analysisDuration.add(analyzeResp.timings.duration);
    totalAnalyses.add(1);
    failureRate.add(analyzeResp.status !== 200);

    // Safety check
    const safetyResp = http.post(`${data.dashboardUrl}/api/safety/check`, JSON.stringify({
      content: 'Test content for safety classification',
    }), { headers });

    check(safetyResp, {
      'safety check OK': (r) => r.status === 200,
    });

    sleep(2);
  });

  // Simulate user think time between actions
  sleep(Math.random() * 3 + 1);
}

// ── Teardown ──
export function teardown(data) {
  console.log(`\n=== Load Test Complete ===`);
  console.log(`Base URL: ${data.baseUrl}`);
  console.log(`Dashboard URL: ${data.dashboardUrl}`);
}
