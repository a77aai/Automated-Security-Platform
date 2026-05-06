import fetch from 'node-fetch';
import { IRouter } from '../../../src/core/server';
import { schema } from '@osd/config-schema';

const API_BASE = process.env.AI_CONTROL_API_BASE || 'http://127.0.0.1:8777';

function normalizePayload(payload: any) {
  if (payload === undefined || payload === null) {
    return {};
  }

  if (typeof payload === 'string') {
    try {
      return JSON.parse(payload);
    } catch {
      return {};
    }
  }

  return payload;
}

async function proxyGet(path: string) {
  const res = await fetch(`${API_BASE}${path}`);
  const body = await res.text();
  return { status: res.status, body };
}

async function proxyPost(path: string, payload: any) {
  const normalized = normalizePayload(payload);

  const res = await fetch(`${API_BASE}${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(normalized),
  });

  const body = await res.text();
  return { status: res.status, body };
}

export function defineRoutes(router: IRouter) {
  router.get(
    {
      path: '/api/wazuh_ai_assistant/health',
      validate: false,
    },
    async (_context, _req, res) => {
      const out = await proxyGet('/health');
      return res.custom({
        statusCode: out.status,
        body: out.body,
        headers: { 'content-type': 'application/json' },
      });
    }
  );

  router.get(
    {
      path: '/api/wazuh_ai_assistant/actions',
      validate: {
        query: schema.object(
          {
            offset: schema.maybe(schema.string()),
            limit: schema.maybe(schema.string()),
            control_only: schema.maybe(schema.string()),
            response_id: schema.maybe(schema.string()),
            agent_id: schema.maybe(schema.string()),
          },
          { unknowns: 'allow' }
        ),
      },
    },
    async (_context, req, res) => {
      const qs = new URLSearchParams();

      if (req.query.offset) qs.set('offset', req.query.offset);
      if (req.query.limit) qs.set('limit', req.query.limit);
      if (req.query.control_only) qs.set('control_only', req.query.control_only);
      if (req.query.response_id) qs.set('response_id', req.query.response_id);
      if (req.query.agent_id) qs.set('agent_id', req.query.agent_id);

      const suffix = qs.toString() ? `?${qs.toString()}` : '';
      const out = await proxyGet(`/api/ai/actions${suffix}`);

      return res.custom({
        statusCode: out.status,
        body: out.body,
        headers: { 'content-type': 'application/json' },
      });
    }
  );

  router.get(
    {
      path: '/api/wazuh_ai_assistant/system_summary',
      validate: false,
    },
    async (_context, _req, res) => {
      const out = await proxyGet('/api/ai/system/summary');
      return res.custom({
        statusCode: out.status,
        body: out.body,
        headers: { 'content-type': 'application/json' },
      });
    }
  );

  router.get(
    {
      path: '/api/wazuh_ai_assistant/agent/{agentId}/summary',
      validate: {
        params: schema.object({
          agentId: schema.string(),
        }),
      },
    },
    async (_context, req, res) => {
      const agentId = encodeURIComponent(req.params.agentId);
      const out = await proxyGet(`/api/ai/agents/${agentId}/summary`);

      return res.custom({
        statusCode: out.status,
        body: out.body,
        headers: { 'content-type': 'application/json' },
      });
    }
  );

  router.post(
    {
      path: '/api/wazuh_ai_assistant/chat',
      validate: {
        body: schema.object(
          {
            response_id: schema.maybe(schema.string()),
            target_agent_id: schema.maybe(schema.string()),
            alert_id: schema.maybe(schema.string()),
            alert_ref: schema.maybe(schema.string()),
            question: schema.string(),
          },
          { unknowns: 'allow' }
        ),
      },
    },
    async (_context, req, res) => {
      const out = await proxyPost('/api/ai/chat', req.body);
      return res.custom({
        statusCode: out.status,
        body: out.body,
        headers: { 'content-type': 'application/json' },
      });
    }
  );

  router.post(
    {
      path: '/api/wazuh_ai_assistant/execute',
      validate: {
        body: schema.object({}, { unknowns: 'allow' }),
      },
    },
    async (_context, req, res) => {
      const out = await proxyPost('/api/ai/control/execute', req.body);
      return res.custom({
        statusCode: out.status,
        body: out.body,
        headers: { 'content-type': 'application/json' },
      });
    }
  );

  router.post(
    {
      path: '/api/wazuh_ai_assistant/rollback',
      validate: {
        body: schema.object({}, { unknowns: 'allow' }),
      },
    },
    async (_context, req, res) => {
      const out = await proxyPost('/api/ai/control/rollback', req.body);
      return res.custom({
        statusCode: out.status,
        body: out.body,
        headers: { 'content-type': 'application/json' },
      });
    }
  );

  router.get(
    {
      path: '/api/wazuh_ai_assistant/settings',
      validate: false,
    },
    async (_context, _req, res) => {
      const out = await proxyGet('/api/ai/settings');
      return res.custom({
        statusCode: out.status,
        body: out.body,
        headers: { 'content-type': 'application/json' },
      });
    }
  );

  router.post(
    {
      path: '/api/wazuh_ai_assistant/settings/rag-detection',
      validate: {
        body: schema.object({
          enabled: schema.boolean(),
        }),
      },
    },
    async (_context, req, res) => {
      const out = await proxyPost('/api/ai/settings/rag-detection', req.body);
      return res.custom({
        statusCode: out.status,
        body: out.body,
        headers: { 'content-type': 'application/json' },
      });
    }
  );

  router.post(
    {
      path: '/api/wazuh_ai_assistant/settings/rag-response',
      validate: {
        body: schema.object({
          enabled: schema.boolean(),
        }),
      },
    },
    async (_context, req, res) => {
      const out = await proxyPost('/api/ai/settings/rag-response', req.body);
      return res.custom({
        statusCode: out.status,
        body: out.body,
        headers: { 'content-type': 'application/json' },
      });
    }
  );

  router.post(
    {
      path: '/api/wazuh_ai_assistant/settings/rag-detection/config',
      validate: {
        body: schema.object(
          {
            model_type: schema.string(),
            custom_model: schema.maybe(schema.string()),
            max_threads: schema.oneOf([schema.number(), schema.string()]),
          },
          { unknowns: 'allow' }
        ),
      },
    },
    async (_context, req, res) => {
      const out = await proxyPost('/api/ai/settings/rag-detection/config', req.body);
      return res.custom({
        statusCode: out.status,
        body: out.body,
        headers: { 'content-type': 'application/json' },
      });
    }
  );

  router.post(
    {
      path: '/api/wazuh_ai_assistant/settings/rag-response/config',
      validate: {
        body: schema.object(
          {
            model_type: schema.string(),
            custom_model: schema.maybe(schema.string()),
            max_threads: schema.oneOf([schema.number(), schema.string()]),
            auto_response_min_level: schema.oneOf([schema.number(), schema.string()]),
          },
          { unknowns: 'allow' }
        ),
      },
    },
    async (_context, req, res) => {
      const out = await proxyPost('/api/ai/settings/rag-response/config', req.body);
      return res.custom({
        statusCode: out.status,
        body: out.body,
        headers: { 'content-type': 'application/json' },
      });
    }
  );
}