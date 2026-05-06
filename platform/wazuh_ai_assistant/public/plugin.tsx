import React, { useEffect, useState } from 'react';
import ReactDOM from 'react-dom';
import {
  AppMountParameters,
  AppNavLinkStatus,
  CoreSetup,
  CoreStart,
  Plugin,
  PluginInitializerContext,
  HttpStart,
  NotificationsStart,
} from '../../../src/core/public';

type SetupDeps = Record<string, never>;
type StartDeps = Record<string, never>;

type ActionEntry = {
  recommendation_alert_id: string;
  recommendation_rule_id?: string;
  recommendation_timestamp: string;
  delivery_alert_id?: string;
  execution_alert_id?: string;
  rollback_alert_id?: string;
  auto_execute?: boolean;
  execution_mode?: string;
  dedup_key: string;
  response_id: string;
  target_agent_id: string;
  target_agent_name: string;
  target_platform: string;
  recommended_action: string;
  response_command: string;
  summary: string;
  confidence: string;
  reasoning: string;
  source_level: number;
  latest_status: string;
  latest_status_timestamp: string;
  manual_steps: string[];
  evidence_to_collect: string[];
  source_description?: string;
  source_ai_analysis?: string;
  can_execute?: boolean;
  can_rollback?: boolean;
  control_visible?: boolean;
  is_actionable?: boolean;
  supports_rollback?: boolean;
  parameters: {
    ip?: string;
    path?: string;
    user?: string;
    tty?: string;
    service_name?: string;
  };
};

type ModelConfig = {
  model_type: string;
  custom_model: string;
  max_threads: number;
  auto_response_min_level?: number;
};

type SettingsPayload = {
  settings_file?: string;
  model_presets?: string[];
  rag_detection: {
    unit: string;
    enabled: boolean;
    active: boolean;
    effective_model?: string;
    config?: ModelConfig;
  };
  rag_response: {
    unit: string;
    enabled: boolean;
    active: boolean;
    effective_model?: string;
    config?: ModelConfig;
  };
};

const ACTION_OPTIONS = [
  'block_ip',
  'kill_process',
  'quarantine_file',
  'disable_user',
  'isolate_host',
];

const PAGE_SIZE = 10;

function styles() {
  return {
    fab: {
      position: 'fixed' as const,
      right: '20px',
      bottom: '20px',
      width: '56px',
      height: '56px',
      borderRadius: '50%',
      border: 'none',
      background: '#1f6feb',
      color: '#fff',
      fontWeight: 700,
      fontSize: '18px',
      cursor: 'pointer',
      zIndex: 2147483647,
      boxShadow: '0 8px 24px rgba(0,0,0,0.25)',
    },
    panel: {
      position: 'fixed' as const,
      right: '20px',
      bottom: '88px',
      width: '430px',
      height: '72vh',
      background: '#111827',
      color: '#f9fafb',
      borderRadius: '16px',
      boxShadow: '0 16px 40px rgba(0,0,0,0.35)',
      zIndex: 2147483647,
      display: 'flex',
      flexDirection: 'column' as const,
      overflow: 'hidden',
      border: '1px solid rgba(255,255,255,0.08)',
      fontFamily: 'Arial, sans-serif',
    },
    header: {
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'space-between',
      padding: '14px 16px',
      borderBottom: '1px solid rgba(255,255,255,0.08)',
      background: '#0f172a',
    },
    tabs: {
      display: 'flex',
      gap: '8px',
      padding: '10px 12px',
      borderBottom: '1px solid rgba(255,255,255,0.08)',
      background: '#111827',
    },
    tab: (active: boolean) => ({
      border: '1px solid rgba(255,255,255,0.15)',
      background: active ? '#2563eb' : '#1f2937',
      color: '#fff',
      padding: '8px 12px',
      borderRadius: '10px',
      cursor: 'pointer',
      fontSize: '13px',
    }),
    body: {
      flex: 1,
      overflowY: 'auto' as const,
      padding: '12px',
      background: '#111827',
    },
    input: {
      width: '100%',
      marginBottom: '8px',
      background: '#0f172a',
      color: '#fff',
      border: '1px solid rgba(255,255,255,0.12)',
      borderRadius: '10px',
      padding: '10px 12px',
      outline: 'none',
      fontSize: '13px',
      boxSizing: 'border-box' as const,
    },
    textarea: {
      width: '100%',
      minHeight: '110px',
      resize: 'vertical' as const,
      marginBottom: '8px',
      background: '#0f172a',
      color: '#fff',
      border: '1px solid rgba(255,255,255,0.12)',
      borderRadius: '10px',
      padding: '10px 12px',
      outline: 'none',
      fontSize: '13px',
      boxSizing: 'border-box' as const,
    },
    row: {
      display: 'flex',
      gap: '8px',
      marginBottom: '8px',
    },
    btn: (kind: 'primary' | 'secondary' | 'danger' = 'primary') => {
      const bg =
        kind === 'primary' ? '#2563eb' :
        kind === 'danger' ? '#dc2626' :
        '#374151';

      return {
        border: 'none',
        background: bg,
        color: '#fff',
        padding: '9px 12px',
        borderRadius: '10px',
        cursor: 'pointer',
        fontSize: '13px',
      };
    },
    card: {
      background: '#0f172a',
      border: '1px solid rgba(255,255,255,0.08)',
      borderRadius: '12px',
      padding: '12px',
      marginBottom: '10px',
    },
    muted: {
      opacity: 0.78,
      fontSize: '12px',
    },
    badge: {
      display: 'inline-block',
      padding: '4px 8px',
      borderRadius: '999px',
      fontSize: '11px',
      background: '#1f2937',
      border: '1px solid rgba(255,255,255,0.08)',
      marginRight: '6px',
      marginBottom: '6px',
    },
    overlay: {
      position: 'fixed' as const,
      inset: 0,
      background: 'rgba(0,0,0,0.45)',
      zIndex: 2147483647,
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
    },
    modal: {
      width: '380px',
      background: '#111827',
      color: '#fff',
      borderRadius: '16px',
      padding: '16px',
      border: '1px solid rgba(255,255,255,0.08)',
      boxShadow: '0 20px 50px rgba(0,0,0,0.35)',
    },
  };
}

function prettyParams(entry: ActionEntry) {
  const p = entry.parameters || {};
  return [p.ip, p.path, p.user, p.service_name].filter(Boolean).join(' | ') || 'No parameters';
}

function entryKey(entry: ActionEntry) {
  return entry.recommendation_alert_id || entry.dedup_key;
}

function mergeUniqueEntries(existing: ActionEntry[], incoming: ActionEntry[]) {
  const map = new Map<string, ActionEntry>();
  existing.forEach((item) => map.set(entryKey(item), item));
  incoming.forEach((item) => map.set(entryKey(item), item));
  return Array.from(map.values());
}

type AssistantErrorBoundaryProps = {
  children: React.ReactNode;
};

type AssistantErrorBoundaryState = {
  hasError: boolean;
  message: string;
};

class AssistantErrorBoundary extends React.Component<
  AssistantErrorBoundaryProps,
  AssistantErrorBoundaryState
> {
  constructor(props: AssistantErrorBoundaryProps) {
    super(props);
    this.state = {
      hasError: false,
      message: '',
    };
  }

  static getDerivedStateFromError(error: Error): AssistantErrorBoundaryState {
    return {
      hasError: true,
      message: error?.message || 'Unknown render error',
    };
  }

  componentDidCatch(error: Error, info: React.ErrorInfo) {
    // eslint-disable-next-line no-console
    console.error('[wazuhAiAssistant] render error:', error, info);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div
          style={{
            position: 'fixed',
            right: '20px',
            bottom: '20px',
            zIndex: 2147483647,
            background: '#7f1d1d',
            color: '#fff',
            padding: '12px 14px',
            borderRadius: '12px',
            maxWidth: '360px',
            boxShadow: '0 8px 24px rgba(0,0,0,0.25)',
            fontSize: '13px',
            lineHeight: 1.5,
          }}
        >
          AI Assistant crashed: {this.state.message}
        </div>
      );
    }

    return this.props.children;
  }
}

function AssistantApp({ http, notifications }: { http: HttpStart; notifications: NotificationsStart }) {
  const s = styles();

  const [open, setOpen] = useState(true);
  const [tab, setTab] = useState<'ask' | 'control' | 'settings'>('ask');

  const [question, setQuestion] = useState('Give me a quick summary about the environment');
  const [responseId, setResponseId] = useState('');
  const [agentId, setAgentId] = useState('');
  const [alertId, setAlertId] = useState('');
  const [chatAnswer, setChatAnswer] = useState<any>(null);
  const [chatLoading, setChatLoading] = useState(false);

  const [actions, setActions] = useState<ActionEntry[]>([]);
  const [actionsLoading, setActionsLoading] = useState(false);
  const [actionsOffset, setActionsOffset] = useState(0);
  const [actionsHasMore, setActionsHasMore] = useState(true);
  const [actionsTotal, setActionsTotal] = useState(0);
  const [actionOverrides, setActionOverrides] = useState<Record<string, string>>({});

  const [settings, setSettings] = useState<SettingsPayload | null>(null);
  const [settingsLoading, setSettingsLoading] = useState(false);

  const [detectionModelType, setDetectionModelType] = useState('gpt-oss:120b-cloud');
  const [detectionCustomModel, setDetectionCustomModel] = useState('');
  const [detectionMaxThreads, setDetectionMaxThreads] = useState(2);

  const [responseModelType, setResponseModelType] = useState('gpt-oss:120b-cloud');
  const [responseCustomModel, setResponseCustomModel] = useState('');
  const [responseMaxThreads, setResponseMaxThreads] = useState(2);
  const [autoResponseMinLevel, setAutoResponseMinLevel] = useState(15);

  const [confirmState, setConfirmState] = useState<null | {
    type: 'execute' | 'rollback';
    entry: ActionEntry;
  }>(null);

  const api = {
    get: async (path: string, query?: Record<string, string>) =>
      http.get(path, query ? { query } : undefined),
    post: async (path: string, body: any) =>
      http.post(path, { body: JSON.stringify(body) }),
  };

  const buildActionsQuery = (offset: number): Record<string, string> => ({
    offset: String(offset),
    limit: String(PAGE_SIZE),
    control_only: 'true',
  });

  const loadActions = async (reset = true) => {
    if (actionsLoading) return;

    const offset = reset ? 0 : actionsOffset;
    setActionsLoading(true);

    try {
      const res: any = await api.get('/api/wazuh_ai_assistant/actions', buildActionsQuery(offset));
      const payload = res?.item || {};
      const entries = payload?.entries || [];

      setActions((prev) => {
        if (reset) return entries;
        return mergeUniqueEntries(prev, entries);
      });

      const currentEntries = reset ? entries : mergeUniqueEntries(actions, entries);
      const seed: Record<string, string> = {};

      currentEntries.forEach((e: ActionEntry) => {
        seed[entryKey(e)] = e.recommended_action;
      });

      setActionOverrides((prev) => ({ ...seed, ...prev }));
      setActionsOffset(offset + entries.length);
      setActionsHasMore(Boolean(payload?.has_more));
      setActionsTotal(Number(payload?.total_entries || 0));
    } catch (e: any) {
      notifications.toasts.addDanger(`Failed loading actions: ${e?.body?.message || e.message}`);
    } finally {
      setActionsLoading(false);
    }
  };

  const refreshActionsSoon = () => {
    loadActions(true);
    window.setTimeout(() => loadActions(true), 1200);
    window.setTimeout(() => loadActions(true), 3000);
  };

  const loadSettings = async () => {
    setSettingsLoading(true);

    try {
      const res: any = await api.get('/api/wazuh_ai_assistant/settings');
      const item = res?.item || null;

      setSettings(item);

      const detectionConfig = item?.rag_detection?.config || {};
      setDetectionModelType(detectionConfig.model_type || 'gpt-oss:120b-cloud');
      setDetectionCustomModel(detectionConfig.custom_model || '');
      setDetectionMaxThreads(Number(detectionConfig.max_threads || 2));

      const responseConfig = item?.rag_response?.config || {};
      setResponseModelType(responseConfig.model_type || 'gpt-oss:120b-cloud');
      setResponseCustomModel(responseConfig.custom_model || '');
      setResponseMaxThreads(Number(responseConfig.max_threads || 2));
      setAutoResponseMinLevel(Number(responseConfig.auto_response_min_level || 15));
    } catch (e: any) {
      notifications.toasts.addDanger(`Failed loading settings: ${e?.body?.message || e.message}`);
    } finally {
      setSettingsLoading(false);
    }
  };

  useEffect(() => {
    if (!open) return;

    if (tab === 'control') {
      setActions([]);
      setActionsOffset(0);
      setActionsHasMore(true);
      setActionsTotal(0);
      loadActions(true);
    }

    if (tab === 'settings') {
      loadSettings();
    }
  }, [open, tab]);

  useEffect(() => {
    if (!open || tab !== 'control') return;

    const timer = window.setInterval(() => {
      loadActions(true);
    }, 8000);

    return () => window.clearInterval(timer);
  }, [open, tab, actionsLoading, actionsOffset]);

  const handleBodyScroll = (event: React.UIEvent<HTMLDivElement>) => {
    if (tab !== 'control' || actionsLoading || !actionsHasMore) return;

    const el = event.currentTarget;
    const nearBottom = el.scrollTop + el.clientHeight >= el.scrollHeight - 80;

    if (nearBottom) {
      loadActions(false);
    }
  };

  const askAi = async () => {
    if (!question.trim()) {
      notifications.toasts.addDanger('Question is empty');
      return;
    }

    setChatLoading(true);

    try {
      const body: any = {
        question: question.trim(),
      };

      if (responseId.trim()) body.response_id = responseId.trim();
      if (agentId.trim()) body.target_agent_id = agentId.trim();
      if (alertId.trim()) body.alert_id = alertId.trim();

      const res: any = await api.post('/api/wazuh_ai_assistant/chat', body);
      setChatAnswer(res?.answer || null);
    } catch (e: any) {
      notifications.toasts.addDanger(`Chat failed: ${e?.body?.message || e.message}`);
    } finally {
      setChatLoading(false);
    }
  };

  const doExecute = async (entry: ActionEntry) => {
    const k = entryKey(entry);
    const action = actionOverrides[k] || entry.recommended_action;

    setActions((prev) =>
      prev.map((x) =>
        entryKey(x) === k
          ? {
              ...x,
              latest_status: 'executing',
              latest_status_timestamp: new Date().toISOString(),
              can_execute: false,
              can_rollback: false,
            }
          : x
      )
    );

    try {
      await api.post('/api/wazuh_ai_assistant/execute', {
        recommendation_alert_id: entry.recommendation_alert_id,
        target_agent_id: entry.target_agent_id,
        target_agent_name: entry.target_agent_name,
        target_platform: entry.target_platform,
        action,
        summary: entry.summary,
        confidence: entry.confidence || 'high',
        reasoning: entry.reasoning,
        manual_steps: entry.manual_steps || [],
        evidence_to_collect: entry.evidence_to_collect || [],
        source_level: entry.source_level || 15,
        parameters: entry.parameters || {},
      });

      notifications.toasts.addSuccess('Execute dispatched successfully');
      setConfirmState(null);
      refreshActionsSoon();
    } catch (e: any) {
      notifications.toasts.addDanger(`Execute failed: ${e?.body?.message || e.message}`);
      refreshActionsSoon();
    }
  };

  const doRollback = async (entry: ActionEntry) => {
    const k = entryKey(entry);

    setActions((prev) =>
      prev.map((x) =>
        entryKey(x) === k
          ? {
              ...x,
              latest_status: 'rolling_back',
              latest_status_timestamp: new Date().toISOString(),
              can_execute: false,
              can_rollback: false,
            }
          : x
      )
    );

    try {
      await api.post('/api/wazuh_ai_assistant/rollback', {
        recommendation_alert_id: entry.recommendation_alert_id,
        target_agent_id: entry.target_agent_id,
        target_agent_name: entry.target_agent_name,
        target_platform: entry.target_platform,
        action: entry.recommended_action,
        summary: `Manual rollback for ${entry.recommended_action}`,
        confidence: 'high',
        source_level: entry.source_level || 15,
        parameters: entry.parameters || {},
      });

      notifications.toasts.addSuccess('Rollback dispatched successfully');
      setConfirmState(null);
      refreshActionsSoon();
    } catch (e: any) {
      notifications.toasts.addDanger(`Rollback failed: ${e?.body?.message || e.message}`);
      refreshActionsSoon();
    }
  };

  const saveDetectionConfig = async () => {
    try {
      await api.post('/api/wazuh_ai_assistant/settings/rag-detection/config', {
        model_type: detectionModelType,
        custom_model: detectionCustomModel,
        max_threads: detectionMaxThreads,
      });

      notifications.toasts.addSuccess('RAG Detection config saved and service restarted');
      loadSettings();
    } catch (e: any) {
      notifications.toasts.addDanger(`RAG Detection config failed: ${e?.body?.message || e.message}`);
    }
  };

  const saveResponseConfig = async () => {
    try {
      await api.post('/api/wazuh_ai_assistant/settings/rag-response/config', {
        model_type: responseModelType,
        custom_model: responseCustomModel,
        max_threads: responseMaxThreads,
        auto_response_min_level: autoResponseMinLevel,
      });

      notifications.toasts.addSuccess('RAG Response config saved and service restarted');
      loadSettings();
    } catch (e: any) {
      notifications.toasts.addDanger(`RAG Response config failed: ${e?.body?.message || e.message}`);
    }
  };

  const toggleService = async (kind: 'rag-detection' | 'rag-response', enabled: boolean) => {
    try {
      await api.post(`/api/wazuh_ai_assistant/settings/${kind}`, { enabled });
      notifications.toasts.addSuccess('Setting updated');
      loadSettings();
    } catch (e: any) {
      notifications.toasts.addDanger(`Settings update failed: ${e?.body?.message || e.message}`);
    }
  };

  return (
    <>
      {open && (
        <div style={s.panel}>
          <div style={s.header}>
            <div>
              <div style={{ fontWeight: 700 }}>AI Assistant</div>
              <div style={s.muted}>Wazuh floating control</div>
            </div>
            <button style={s.btn('secondary')} onClick={() => setOpen(false)}>−</button>
          </div>

          <div style={s.tabs}>
            <button style={s.tab(tab === 'ask')} onClick={() => setTab('ask')}>Ask AI</button>
            <button style={s.tab(tab === 'control')} onClick={() => setTab('control')}>Control</button>
            <button style={s.tab(tab === 'settings')} onClick={() => setTab('settings')}>Settings</button>
          </div>

          <div style={s.body} onScroll={handleBodyScroll}>
            {tab === 'ask' && (
              <div>
                <input
                  style={s.input}
                  value={responseId}
                  onChange={(e) => setResponseId(e.target.value)}
                  placeholder="response_id (optional)"
                />

                <div style={s.row}>
                  <input
                    style={s.input}
                    value={agentId}
                    onChange={(e) => setAgentId(e.target.value)}
                    placeholder="agent_id (optional)"
                  />

                  <input
                    style={s.input}
                    value={alertId}
                    onChange={(e) => setAlertId(e.target.value)}
                    placeholder="alert_id / archive ref (optional)"
                  />
                </div>

                <textarea
                  style={s.textarea}
                  value={question}
                  onChange={(e) => setQuestion(e.target.value)}
                  placeholder="Ask about any alert, any old alert from archive, any agent, or the whole system..."
                />

                <button style={s.btn('primary')} onClick={askAi} disabled={chatLoading}>
                  {chatLoading ? 'Sending...' : 'Send'}
                </button>

                {chatAnswer && (
                  <div style={{ ...s.card, marginTop: '12px' }}>
                    <div style={{ fontWeight: 700, marginBottom: '8px' }}>Answer</div>
                    <div style={{ whiteSpace: 'pre-wrap', lineHeight: 1.6 }}>{chatAnswer.answer}</div>

                    <div style={{ marginTop: '10px', ...s.muted }}>
                      Confidence: {chatAnswer.confidence}
                    </div>

                    <div style={{ marginTop: '8px' }}>
                      <strong>Next:</strong> {chatAnswer.recommended_next_step}
                    </div>
                  </div>
                )}
              </div>
            )}

            {tab === 'control' && (
              <div>
                <div
                  style={{
                    marginBottom: '10px',
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                  }}
                >
                  <button style={s.btn('secondary')} onClick={() => loadActions(true)}>
                    {actionsLoading ? 'Refreshing...' : 'Refresh'}
                  </button>

                  <div style={s.muted}>
                    Showing {actions.length} / {actionsTotal}
                  </div>
                </div>

                {actions.map((entry) => {
                  const k = entryKey(entry);
                  const selectedAction = actionOverrides[k] || entry.recommended_action;
                  const canExecute = Boolean(entry.can_execute);
                  const canRollback = Boolean(entry.can_rollback);

                  return (
                    <div key={k} style={s.card}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', gap: '8px' }}>
                        <div>
                          <div style={{ fontWeight: 700 }}>
                            {entry.target_agent_name} ({entry.target_agent_id})
                          </div>
                          <div style={s.muted}>{entry.target_platform}</div>
                        </div>

                        <div style={s.badge}>{entry.latest_status}</div>
                      </div>

                      <div style={{ marginTop: '8px' }}>
                        <div><strong>Alert ID:</strong> {entry.recommendation_alert_id}</div>
                        <div><strong>Action:</strong> {entry.recommended_action}</div>
                        <div><strong>Summary:</strong> {entry.summary}</div>
                        <div><strong>Parameters:</strong> {prettyParams(entry)}</div>
                        <div style={s.muted}>Updated: {entry.latest_status_timestamp}</div>
                      </div>

                      {canExecute && (
                        <div style={{ marginTop: '10px' }}>
                          <select
                            style={s.input}
                            value={selectedAction}
                            onChange={(e) =>
                              setActionOverrides((prev) => ({ ...prev, [k]: e.target.value }))
                            }
                          >
                            {ACTION_OPTIONS.map((a) => (
                              <option key={a} value={a}>{a}</option>
                            ))}
                          </select>
                        </div>
                      )}

                      <div style={{ display: 'flex', gap: '8px', marginTop: '8px', flexWrap: 'wrap' }}>
                        {canExecute && (
                          <button
                            style={s.btn('primary')}
                            onClick={() => setConfirmState({ type: 'execute', entry })}
                          >
                            Execute
                          </button>
                        )}

                        {canRollback && (
                          <button
                            style={s.btn('danger')}
                            onClick={() => setConfirmState({ type: 'rollback', entry })}
                          >
                            Rollback
                          </button>
                        )}
                      </div>
                    </div>
                  );
                })}

                {!actionsLoading && actions.length === 0 && (
                  <div style={s.card}>
                    <div style={{ fontWeight: 700, marginBottom: '8px' }}>No visible control items</div>
                    <div style={s.muted}>
                      Only actionable entries are shown here. Rolled-back items and non-actionable recommendations are hidden.
                    </div>
                  </div>
                )}

                {actionsLoading && (
                  <div style={s.muted}>Loading...</div>
                )}

                {!actionsLoading && actionsHasMore && actions.length > 0 && (
                  <div style={{ ...s.muted, textAlign: 'center', padding: '8px 0' }}>
                    Scroll down to load 10 more...
                  </div>
                )}
              </div>
            )}

            {tab === 'settings' && (
              <div>
                <div style={{ marginBottom: '10px' }}>
                  <button style={s.btn('secondary')} onClick={loadSettings}>
                    {settingsLoading ? 'Refreshing...' : 'Refresh'}
                  </button>
                </div>

                {settings && (
                  <>
                    <div style={s.card}>
                      <div style={{ fontWeight: 700, marginBottom: '8px' }}>AI RAG Detection</div>

                      <div style={s.muted}>
                        enabled={String(settings.rag_detection.enabled)} | active={String(settings.rag_detection.active)}
                      </div>

                      <div style={{ ...s.muted, marginTop: '6px', marginBottom: '10px' }}>
                        Effective model: {settings.rag_detection.effective_model || 'unknown'}
                      </div>

                      <label style={s.muted}>Model</label>
                      <select
                        style={s.input}
                        value={detectionModelType}
                        onChange={(e) => setDetectionModelType(e.target.value)}
                      >
                        <option value="llama3.2">llama3.2</option>
                        <option value="gpt-oss:120b-cloud">gpt-oss:120b-cloud</option>
                        <option value="other">Other model</option>
                      </select>

                      {detectionModelType === 'other' && (
                        <>
                          <label style={s.muted}>Custom model name</label>
                          <input
                            style={s.input}
                            value={detectionCustomModel}
                            onChange={(e) => setDetectionCustomModel(e.target.value)}
                            placeholder="example: mistral:latest"
                          />
                        </>
                      )}

                      <label style={s.muted}>MAX Threads</label>
                      <input
                        style={s.input}
                        type="number"
                        min={1}
                        max={64}
                        value={detectionMaxThreads}
                        onChange={(e) => setDetectionMaxThreads(Number(e.target.value || 1))}
                      />

                      <div style={{ display: 'flex', gap: '8px', marginTop: '10px', flexWrap: 'wrap' }}>
                        <button style={s.btn('primary')} onClick={saveDetectionConfig}>Save Config</button>
                        <button style={s.btn('primary')} onClick={() => toggleService('rag-detection', true)}>Enable</button>
                        <button style={s.btn('danger')} onClick={() => toggleService('rag-detection', false)}>Disable</button>
                      </div>
                    </div>

                    <div style={s.card}>
                      <div style={{ fontWeight: 700, marginBottom: '8px' }}>AI RAG Response and Mitigations</div>

                      <div style={s.muted}>
                        enabled={String(settings.rag_response.enabled)} | active={String(settings.rag_response.active)}
                      </div>

                      <div style={{ ...s.muted, marginTop: '6px', marginBottom: '10px' }}>
                        Effective model: {settings.rag_response.effective_model || 'unknown'}
                      </div>

                      <label style={s.muted}>Model</label>
                      <select
                        style={s.input}
                        value={responseModelType}
                        onChange={(e) => setResponseModelType(e.target.value)}
                      >
                        <option value="llama3.2">llama3.2</option>
                        <option value="gpt-oss:120b-cloud">gpt-oss:120b-cloud</option>
                        <option value="other">Other model</option>
                      </select>

                      {responseModelType === 'other' && (
                        <>
                          <label style={s.muted}>Custom model name</label>
                          <input
                            style={s.input}
                            value={responseCustomModel}
                            onChange={(e) => setResponseCustomModel(e.target.value)}
                            placeholder="example: mistral:latest"
                          />
                        </>
                      )}

                      <label style={s.muted}>MAX Threads</label>
                      <input
                        style={s.input}
                        type="number"
                        min={1}
                        max={64}
                        value={responseMaxThreads}
                        onChange={(e) => setResponseMaxThreads(Number(e.target.value || 1))}
                      />

                      <label style={s.muted}>Auto Response minimum level</label>
                      <select
                        style={s.input}
                        value={autoResponseMinLevel}
                        onChange={(e) => setAutoResponseMinLevel(Number(e.target.value))}
                      >
                        <option value={15}>Level 15 only</option>
                        <option value={14}>Level 14+</option>
                        <option value={13}>Level 13+</option>
                        <option value={12}>Level 12+</option>
                        <option value={11}>Level 11+</option>
                        <option value={10}>Level 10+</option>
                        <option value={9}>Level 9+</option>
                        <option value={8}>Level 8+</option>
                        <option value={7}>Level 7+</option>
                        <option value={6}>Level 6+</option>
                        <option value={5}>Level 5+</option>
                        <option value={4}>Level 4+</option>
                        <option value={3}>Level 3+</option>
                        <option value={2}>Level 2+</option>
                        <option value={1}>Level 1+</option>
                        <option value={0}>Any level</option>
                      </select>

                      <div style={{ ...s.muted, marginTop: '4px', marginBottom: '10px' }}>
                        Auto response still requires safe_for_auto_execute=True and an allowed action.
                      </div>

                      <div style={{ display: 'flex', gap: '8px', marginTop: '10px', flexWrap: 'wrap' }}>
                        <button style={s.btn('primary')} onClick={saveResponseConfig}>Save Config</button>
                        <button style={s.btn('primary')} onClick={() => toggleService('rag-response', true)}>Enable</button>
                        <button style={s.btn('danger')} onClick={() => toggleService('rag-response', false)}>Disable</button>
                      </div>
                    </div>
                  </>
                )}
              </div>
            )}
          </div>
        </div>
      )}

      {!open && (
        <button style={s.fab} onClick={() => setOpen(true)}>AI</button>
      )}

      {confirmState && (
        <div style={s.overlay}>
          <div style={s.modal}>
            <div style={{ fontWeight: 700, marginBottom: '8px' }}>
              {confirmState.type === 'execute' ? 'Confirm execute' : 'Confirm rollback'}
            </div>

            <div style={{ lineHeight: 1.6, marginBottom: '14px' }}>
              Agent: {confirmState.entry.target_agent_name} ({confirmState.entry.target_agent_id})
              <br />
              Alert ID: {confirmState.entry.recommendation_alert_id}
              <br />
              Action: {confirmState.type === 'execute'
                ? (actionOverrides[entryKey(confirmState.entry)] || confirmState.entry.recommended_action)
                : confirmState.entry.recommended_action}
            </div>

            <div style={{ display: 'flex', gap: '8px', justifyContent: 'flex-end' }}>
              <button style={s.btn('secondary')} onClick={() => setConfirmState(null)}>Cancel</button>
              <button
                style={s.btn(confirmState.type === 'execute' ? 'primary' : 'danger')}
                onClick={() => confirmState.type === 'execute' ? doExecute(confirmState.entry) : doRollback(confirmState.entry)}
              >
                Yes
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}

export class WazuhAiAssistantPlugin implements Plugin<void, void, SetupDeps, StartDeps> {
  private hostEl?: HTMLDivElement;
  private mountEl?: HTMLDivElement;
  private observer?: MutationObserver;
  private syncTimer?: number;

  constructor(private readonly initializerContext: PluginInitializerContext) {}

  public setup(core: CoreSetup<StartDeps, void>, plugins: SetupDeps) {
    core.application.register({
      id: 'wazuhAiAssistantBootstrap',
      title: 'Wazuh AI Assistant Bootstrap',
      appRoute: '/app/wazuh-ai-assistant-bootstrap',
      chromeless: true,
      navLinkStatus: AppNavLinkStatus.hidden,
      mount: async (_params: AppMountParameters) => {
        return () => undefined;
      },
    });
  }

  private isLoginRoute(): boolean {
    const p = window.location.pathname || '';

    return (
      p === '/login' ||
      p.startsWith('/login') ||
      p === '/app/login' ||
      p.startsWith('/app/login')
    );
  }

  private hasDashboardShell(): boolean {
    return Boolean(
      document.querySelector('[data-test-subj="headerGlobalNav"]') ||
      document.querySelector('[data-test-subj="userMenuButton"]') ||
      document.querySelector('[data-test-subj="toggleNavButton"]') ||
      document.querySelector('.euiHeader') ||
      document.querySelector('.app-wrapper') ||
      document.querySelector('[class*="content"]')
    );
  }

  private canRenderAssistant(): boolean {
    const p = window.location.pathname || '';

    if (this.isLoginRoute()) return false;
    if (!p.startsWith('/app/')) return false;
    if (!this.hasDashboardShell()) return false;

    return true;
  }

  private cleanupMount() {
    const legacyProbe = document.getElementById('wazuh-ai-assistant-probe');

    if (legacyProbe) {
      legacyProbe.remove();
    }

    if (this.mountEl) {
      ReactDOM.unmountComponentAtNode(this.mountEl);
    }

    if (this.hostEl && this.hostEl.parentNode) {
      this.hostEl.parentNode.removeChild(this.hostEl);
    }

    this.mountEl = undefined;
    this.hostEl = undefined;
  }

  private ensureMounted(core: CoreStart) {
    if (!document.body) return;

    if (!this.canRenderAssistant()) {
      this.cleanupMount();
      return;
    }

    let host = document.getElementById('wazuh-ai-assistant-host') as HTMLDivElement | null;

    if (!host) {
      host = document.createElement('div');
      host.id = 'wazuh-ai-assistant-host';
      document.body.appendChild(host);
    }

    this.hostEl = host;

    if (!this.mountEl) {
      this.mountEl = document.createElement('div');
      this.mountEl.id = 'wazuh-ai-assistant-root';
      host.appendChild(this.mountEl);
    }

    ReactDOM.render(
      <AssistantErrorBoundary>
        <AssistantApp http={core.http} notifications={core.notifications} />
      </AssistantErrorBoundary>,
      this.mountEl
    );
  }

  private syncMount(core: CoreStart) {
    try {
      if (this.canRenderAssistant()) {
        this.ensureMounted(core);
      } else {
        this.cleanupMount();
      }
    } catch (error) {
      // eslint-disable-next-line no-console
      console.error('[wazuhAiAssistant] sync mount failed:', error);
      this.cleanupMount();
    }
  }

  private installDomObserver(core: CoreStart) {
    if (this.observer || !document.body) return;

    this.observer = new MutationObserver(() => {
      this.syncMount(core);
    });

    this.observer.observe(document.body, {
      childList: true,
      subtree: true,
    });
  }

  public start(core: CoreStart, plugins: StartDeps) {
    const boot = () => {
      this.syncMount(core);
      this.installDomObserver(core);

      this.syncTimer = window.setInterval(() => {
        this.syncMount(core);
      }, 2000);
    };

    if (document.readyState === 'loading') {
      window.addEventListener('DOMContentLoaded', boot, { once: true });
    } else {
      window.requestAnimationFrame(boot);
    }
  }

  public stop() {
    if (this.observer) {
      this.observer.disconnect();
      this.observer = undefined;
    }

    if (this.syncTimer) {
      window.clearInterval(this.syncTimer);
      this.syncTimer = undefined;
    }

    this.cleanupMount();
  }
}