import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";

import { ApiError, api } from "../api/client";
import type { ConfigDomain } from "../api/client";

interface RuntimeValue {
  llm_api_key: string | null;
  llm_base_url: string;
  llm_model: string;
  tlp_default: string;
  enrich_concurrency: number;
  enrich_default_ttl_hours: number;
}

interface ClusteringValue {
  weights: {
    shares_receiving_wallet: number;
    shares_cashout_path: number;
    shares_cert: number;
    shares_template: number;
    shares_registrar_and_ns: number;
  };
  cert: { wildcard_san_threshold: number; wildcard_weight: number; liveness_window_days: number };
  template: { liveness_window_days: number };
  campaign: {
    score_threshold: number;
    diversity_bonus: number;
    min_size: number;
    merge_split_jaccard_threshold: number;
    active_window_days: number;
  };
}

interface ProviderEntry {
  max_requests: number;
  per_seconds: number;
  ttl_hours: number;
}
interface ProvidersValue {
  providers: Record<string, ProviderEntry>;
}

interface SourceEntry {
  name: string;
  type: string;
  url: string;
  cadence_minutes: number;
  reliability_grade: string;
  enabled: boolean;
}
interface SourcesValue {
  sources: SourceEntry[];
}

/** One domain's fetch → local-edit-state → save/reset lifecycle, shared
 * by every section below so each only has to describe its own form. */
function useConfigSection<T>(domain: ConfigDomain) {
  const queryClient = useQueryClient();
  const query = useQuery({
    queryKey: ["config", domain],
    queryFn: () => api.getConfig(domain),
  });
  const [draft, setDraft] = useState<T | null>(null);
  const [errors, setErrors] = useState<string[]>([]);

  useEffect(() => {
    if (query.data) {
      setDraft(query.data.value as T);
      setErrors([]);
    }
    // Only re-sync from the server on a fresh fetch, not on every render.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [query.data]);

  const saveMutation = useMutation({
    mutationFn: (value: T) => api.setConfig(domain, value as Record<string, unknown>),
    onSuccess: (result) => {
      setErrors([]);
      queryClient.setQueryData(["config", domain], result);
    },
    onError: (err: unknown) => {
      setErrors(err instanceof ApiError ? err.errors : ["Failed to save."]);
    },
  });

  const resetMutation = useMutation({
    mutationFn: () => api.resetConfig(domain),
    onSuccess: (result) => {
      setErrors([]);
      queryClient.setQueryData(["config", domain], result);
    },
  });

  return { query, draft, setDraft, errors, saveMutation, resetMutation };
}

function SectionHeader({
  title,
  overridden,
  onReset,
  resetting,
}: {
  title: string;
  overridden: boolean | undefined;
  onReset: () => void;
  resetting: boolean;
}): React.JSX.Element {
  return (
    <div className="row row--between">
      <h3>{title}</h3>
      <div className="row">
        <span className={`badge ${overridden ? "badge--approved" : "badge--dormant"}`}>
          {overridden ? "customized" : "file/env default"}
        </span>
        {overridden && (
          <button className="ghost" onClick={onReset} disabled={resetting}>
            Reset to default
          </button>
        )}
      </div>
    </div>
  );
}

function ErrorList({ errors }: { errors: string[] }): React.JSX.Element | null {
  if (errors.length === 0) return null;
  return (
    <div className="callout callout--danger">
      {errors.map((e) => (
        <div key={e}>{e}</div>
      ))}
    </div>
  );
}

function RuntimeSection(): React.JSX.Element {
  const { query, draft, setDraft, errors, saveMutation, resetMutation } =
    useConfigSection<RuntimeValue>("runtime");
  if (!draft) return <p className="page-subtitle">Loading…</p>;

  return (
    <div className="card">
      <SectionHeader
        title="Assessment LLM & defaults"
        overridden={query.data?.overridden}
        onReset={() => resetMutation.mutate()}
        resetting={resetMutation.isPending}
      />
      <p className="page-subtitle">
        The backend used by `lh assess draft`, any OpenAI-compatible provider (OpenAI, Azure
        OpenAI, Ollama, Groq, OpenRouter, vLLM, etc.), plus the default TLP marking and
        enrichment tuning. Takes effect immediately, no restart.
      </p>
      <ErrorList errors={errors} />
      <div className="grid-cards">
        <div className="field">
          <label>LLM API key</label>
          <input
            type="text"
            value={draft.llm_api_key ?? ""}
            placeholder="sk-..."
            onChange={(e) => setDraft({ ...draft, llm_api_key: e.target.value || null })}
          />
        </div>
        <div className="field">
          <label>LLM base URL</label>
          <input
            type="text"
            value={draft.llm_base_url}
            onChange={(e) => setDraft({ ...draft, llm_base_url: e.target.value })}
          />
        </div>
        <div className="field">
          <label>LLM model</label>
          <input
            type="text"
            value={draft.llm_model}
            onChange={(e) => setDraft({ ...draft, llm_model: e.target.value })}
          />
        </div>
        <div className="field">
          <label>Default TLP marking</label>
          <select
            value={draft.tlp_default}
            onChange={(e) => setDraft({ ...draft, tlp_default: e.target.value })}
          >
            {["TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:AMBER+STRICT", "TLP:RED"].map((tlp) => (
              <option key={tlp} value={tlp}>
                {tlp}
              </option>
            ))}
          </select>
        </div>
        <div className="field">
          <label>Enrichment concurrency</label>
          <input
            type="number"
            min={1}
            value={draft.enrich_concurrency}
            onChange={(e) =>
              setDraft({ ...draft, enrich_concurrency: Number(e.target.value) })
            }
          />
        </div>
        <div className="field">
          <label>Enrichment TTL (hours)</label>
          <input
            type="number"
            min={0}
            step="0.5"
            value={draft.enrich_default_ttl_hours}
            onChange={(e) =>
              setDraft({ ...draft, enrich_default_ttl_hours: Number(e.target.value) })
            }
          />
        </div>
      </div>
      <button className="primary" onClick={() => saveMutation.mutate(draft)} disabled={saveMutation.isPending}>
        {saveMutation.isPending ? "Saving…" : "Save"}
      </button>
    </div>
  );
}

function ClusteringSection(): React.JSX.Element {
  const { query, draft, setDraft, errors, saveMutation, resetMutation } =
    useConfigSection<ClusteringValue>("clustering");
  if (!draft) return <p className="page-subtitle">Loading…</p>;

  function num(
    group: keyof ClusteringValue,
    field: string,
    value: string,
  ): void {
    if (!draft) return;
    setDraft({
      ...draft,
      [group]: { ...(draft[group] as Record<string, number>), [field]: Number(value) },
    });
  }

  return (
    <div className="card">
      <SectionHeader
        title="Clustering weights & thresholds"
        overridden={query.data?.overridden}
        onReset={() => resetMutation.mutate()}
        resetting={resetMutation.isPending}
      />
      <p className="page-subtitle">Used by `lh cluster run` on its next invocation.</p>
      <ErrorList errors={errors} />

      <h4>Relation weights</h4>
      <div className="grid-cards">
        {Object.entries(draft.weights).map(([key, value]) => (
          <div className="field" key={key}>
            <label>{key}</label>
            <input
              type="number"
              step="0.05"
              value={value}
              onChange={(e) => num("weights", key, e.target.value)}
            />
          </div>
        ))}
      </div>

      <h4>Certificate relation</h4>
      <div className="grid-cards">
        <div className="field">
          <label>Wildcard SAN threshold</label>
          <input
            type="number"
            value={draft.cert.wildcard_san_threshold}
            onChange={(e) => num("cert", "wildcard_san_threshold", e.target.value)}
          />
        </div>
        <div className="field">
          <label>Wildcard weight</label>
          <input
            type="number"
            step="0.05"
            value={draft.cert.wildcard_weight}
            onChange={(e) => num("cert", "wildcard_weight", e.target.value)}
          />
        </div>
        <div className="field">
          <label>Liveness window (days)</label>
          <input
            type="number"
            value={draft.cert.liveness_window_days}
            onChange={(e) => num("cert", "liveness_window_days", e.target.value)}
          />
        </div>
      </div>

      <h4>Template relation</h4>
      <div className="grid-cards">
        <div className="field">
          <label>Liveness window (days)</label>
          <input
            type="number"
            value={draft.template.liveness_window_days}
            onChange={(e) => num("template", "liveness_window_days", e.target.value)}
          />
        </div>
      </div>

      <h4>Campaign scoring</h4>
      <div className="grid-cards">
        <div className="field">
          <label>Score threshold</label>
          <input
            type="number"
            step="0.05"
            value={draft.campaign.score_threshold}
            onChange={(e) => num("campaign", "score_threshold", e.target.value)}
          />
        </div>
        <div className="field">
          <label>Diversity bonus</label>
          <input
            type="number"
            step="0.05"
            value={draft.campaign.diversity_bonus}
            onChange={(e) => num("campaign", "diversity_bonus", e.target.value)}
          />
        </div>
        <div className="field">
          <label>Min campaign size</label>
          <input
            type="number"
            min={2}
            value={draft.campaign.min_size}
            onChange={(e) => num("campaign", "min_size", e.target.value)}
          />
        </div>
        <div className="field">
          <label>Merge/split Jaccard threshold</label>
          <input
            type="number"
            step="0.05"
            min={0}
            max={1}
            value={draft.campaign.merge_split_jaccard_threshold}
            onChange={(e) => num("campaign", "merge_split_jaccard_threshold", e.target.value)}
          />
        </div>
        <div className="field">
          <label>Active window (days)</label>
          <input
            type="number"
            value={draft.campaign.active_window_days}
            onChange={(e) => num("campaign", "active_window_days", e.target.value)}
          />
        </div>
      </div>

      <button className="primary" onClick={() => saveMutation.mutate(draft)} disabled={saveMutation.isPending}>
        {saveMutation.isPending ? "Saving…" : "Save"}
      </button>
    </div>
  );
}

function ProvidersSection(): React.JSX.Element {
  const { query, draft, setDraft, errors, saveMutation, resetMutation } =
    useConfigSection<ProvidersValue>("providers");
  if (!draft) return <p className="page-subtitle">Loading…</p>;

  function update(name: string, field: keyof ProviderEntry, value: string): void {
    if (!draft) return;
    setDraft({
      ...draft,
      providers: {
        ...draft.providers,
        [name]: { ...draft.providers[name], [field]: Number(value) },
      },
    });
  }

  return (
    <div className="card">
      <SectionHeader
        title="Enrichment provider tuning"
        overridden={query.data?.overridden}
        onReset={() => resetMutation.mutate()}
        resetting={resetMutation.isPending}
      />
      <p className="page-subtitle">Rate limits and freshness windows used by `lh enrich`.</p>
      <ErrorList errors={errors} />
      <table className="data-table">
        <thead>
          <tr>
            <th>Provider</th>
            <th>Max requests</th>
            <th>Per seconds</th>
            <th>TTL (hours)</th>
          </tr>
        </thead>
        <tbody>
          {Object.entries(draft.providers).map(([name, entry]) => (
            <tr key={name}>
              <td className="mono">{name}</td>
              <td>
                <input
                  type="number"
                  min={1}
                  value={entry.max_requests}
                  onChange={(e) => update(name, "max_requests", e.target.value)}
                />
              </td>
              <td>
                <input
                  type="number"
                  min={1}
                  value={entry.per_seconds}
                  onChange={(e) => update(name, "per_seconds", e.target.value)}
                />
              </td>
              <td>
                <input
                  type="number"
                  min={0}
                  step="0.5"
                  value={entry.ttl_hours}
                  onChange={(e) => update(name, "ttl_hours", e.target.value)}
                />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <button className="primary" onClick={() => saveMutation.mutate(draft)} disabled={saveMutation.isPending}>
        {saveMutation.isPending ? "Saving…" : "Save"}
      </button>
    </div>
  );
}

const RELIABILITY_GRADES = ["A", "B", "C", "D", "E", "F"];

function SourcesSection(): React.JSX.Element {
  const { query, draft, setDraft, errors, saveMutation, resetMutation } =
    useConfigSection<SourcesValue>("sources");
  if (!draft) return <p className="page-subtitle">Loading…</p>;

  function update(index: number, patch: Partial<SourceEntry>): void {
    if (!draft) return;
    const sources = draft.sources.map((s, i) => (i === index ? { ...s, ...patch } : s));
    setDraft({ sources });
  }

  return (
    <div className="card">
      <SectionHeader
        title="Collection sources"
        overridden={query.data?.overridden}
        onReset={() => resetMutation.mutate()}
        resetting={resetMutation.isPending}
      />
      <p className="page-subtitle">
        Which feeds `lh collect` runs, and how often. Adding a source not backed by a collector
        implementation has no effect. This edits which of the built-in feeds run, not new ones.
      </p>
      <ErrorList errors={errors} />
      <table className="data-table">
        <thead>
          <tr>
            <th>Name</th>
            <th>Cadence (min)</th>
            <th>Reliability</th>
            <th>Enabled</th>
          </tr>
        </thead>
        <tbody>
          {draft.sources.map((source, index) => (
            <tr key={source.name}>
              <td className="mono">{source.name}</td>
              <td>
                <input
                  type="number"
                  min={1}
                  value={source.cadence_minutes}
                  onChange={(e) => update(index, { cadence_minutes: Number(e.target.value) })}
                />
              </td>
              <td>
                <select
                  value={source.reliability_grade}
                  onChange={(e) => update(index, { reliability_grade: e.target.value })}
                >
                  {RELIABILITY_GRADES.map((grade) => (
                    <option key={grade} value={grade}>
                      {grade}
                    </option>
                  ))}
                </select>
              </td>
              <td>
                <input
                  type="checkbox"
                  checked={source.enabled}
                  onChange={(e) => update(index, { enabled: e.target.checked })}
                />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      <button className="primary" onClick={() => saveMutation.mutate(draft)} disabled={saveMutation.isPending}>
        {saveMutation.isPending ? "Saving…" : "Save"}
      </button>
    </div>
  );
}

export default function Settings(): React.JSX.Element {
  return (
    <div className="stack">
      <div>
        <h1 className="page-title">Settings</h1>
        <p className="page-subtitle">
          The same config `lh config show/set/reset` edits, a change here or on the CLI is
          visible to both immediately, no restart.
        </p>
      </div>
      <RuntimeSection />
      <ClusteringSection />
      <ProvidersSection />
      <SourcesSection />
    </div>
  );
}

