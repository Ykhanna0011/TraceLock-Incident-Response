# TraceLock Incident Response

TraceLock is a synthetic identity-incident investigation and containment demo. It uses Nemotron through Nebius Token Factory for bounded investigation, with deterministic graph analysis for containment verification. No live cloud accounts are queried or changed.

## Local setup

Install dependencies with pnpm:

```sh
pnpm install
```

Set the server-side credentials in the environment where the API server runs. Copy `.env.example` as a reference; the server does not load dotenv files automatically.

```sh
export NEBIUS_API_KEY="your-nebius-key"
export TAVILY_API_KEY="your-tavily-key"
```

`NEBIUS_API_KEY` is required to run Nemotron investigations. `TAVILY_API_KEY` enables optional external threat-intelligence enrichment. If Tavily is not configured or unavailable, the investigation continues without that enrichment. Never set either credential as a `VITE_` variable or expose it to the browser.

Start the API and frontend in separate terminals:

```sh
pnpm --filter @workspace/api-server run dev
pnpm --filter @workspace/tracelock run dev
```

## Tavily threat-intelligence enrichment

During the bounded investigation, Nemotron may call the allowlisted `lookup_threat_intelligence` tool for an IPv4 address present in the synthetic incident audit timeline. The API server sends a bounded Tavily Search API request using `TAVILY_API_KEY`, with a maximum of three results and an eight-second timeout. The tool does not accept arbitrary URLs or provide general web browsing.

Results retain their title, source URL, excerpt, publication date (when available), and relevance score (when available). They are explicitly marked as **untrusted external intelligence**, kept separate from original synthetic incident evidence, and may support investigation hypotheses only. A search result alone does not establish that an indicator is malicious.

Containment status is never set by Nemotron or Tavily. TraceLock independently recomputes reachability on the synthetic scenario graph, regardless of model output or external search results.

To enable Tavily in production, add `TAVILY_API_KEY` to the API service's runtime environment (for example, the `tracelock-api` service in Render). The key is not needed to build or run the demo's deterministic containment features.

## Checks

```sh
pnpm --filter @workspace/api-server test
pnpm --filter @workspace/api-server typecheck
pnpm --filter @workspace/tracelock typecheck
pnpm build
```
