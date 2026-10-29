import { isIP } from "node:net";
import { z } from "zod/v4";

export const TAVILY_SEARCH_URL = "https://api.tavily.com/search";
const REQUEST_TIMEOUT_MS = 8_000;
const MAX_RESPONSE_BYTES = 256 * 1024;
const MAX_RESULTS = 3;
const MAX_TITLE_LENGTH = 200;
const MAX_URL_LENGTH = 2_048;
const MAX_EXCERPT_LENGTH = 800;

const TavilyResponseSchema = z.object({
  results: z.array(z.object({
    title: z.string().min(1).max(500),
    url: z.string().url().max(MAX_URL_LENGTH).refine((value) => {
      const protocol = new URL(value).protocol;
      return protocol === "https:" || protocol === "http:";
    }),
    content: z.string().max(100_000),
    score: z.number().min(0).max(1).optional(),
    published_date: z.string().max(100).nullable().optional(),
  }).passthrough()).max(MAX_RESULTS),
}).passthrough();

export type TavilySearchResult = {
  title: string;
  url: string;
  excerpt: string;
  publishedAt: string | null;
  relevanceScore: number | null;
};

export class TavilyClientError extends Error {
  readonly statusCode: number;
  readonly code:
    | "missing-api-key"
    | "rate-limited"
    | "timeout"
    | "provider-error"
    | "invalid-response";

  constructor(
    message: string,
    statusCode: number,
    code: TavilyClientError["code"],
  ) {
    super(message);
    this.name = "TavilyClientError";
    this.statusCode = statusCode;
    this.code = code;
  }
}

export type TavilyThreatIntelligenceClient = {
  search(indicator: string): Promise<TavilySearchResult[]>;
};

async function readResponse(response: Response): Promise<string> {
  const contentLength = Number(response.headers.get("content-length"));
  if (Number.isFinite(contentLength) && contentLength > MAX_RESPONSE_BYTES) {
    throw new TavilyClientError(
      "Tavily returned a response that exceeded the allowed size.",
      502,
      "invalid-response",
    );
  }
  if (!response.body) {
    throw new TavilyClientError(
      "Tavily returned an empty response.",
      502,
      "invalid-response",
    );
  }

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let totalBytes = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      totalBytes += value.byteLength;
      if (totalBytes > MAX_RESPONSE_BYTES) {
        await reader.cancel();
        throw new TavilyClientError(
          "Tavily returned a response that exceeded the allowed size.",
          502,
          "invalid-response",
        );
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  const bytes = new Uint8Array(totalBytes);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(bytes);
}

export function createTavilyClient(options: {
  apiKey?: string;
  fetchImpl?: typeof fetch;
} = {}): TavilyThreatIntelligenceClient {
  const apiKey = options.apiKey ?? process.env.TAVILY_API_KEY;
  const fetchImpl = options.fetchImpl ?? fetch;

  return {
    async search(indicator): Promise<TavilySearchResult[]> {
      if (!apiKey?.trim()) {
        throw new TavilyClientError(
          "Threat intelligence is unavailable because TAVILY_API_KEY is not configured.",
          503,
          "missing-api-key",
        );
      }
      if (isIP(indicator) !== 4) {
        throw new TavilyClientError(
          "Threat intelligence lookup requires a valid IPv4 indicator.",
          400,
          "invalid-response",
        );
      }

      let response: Response;
      try {
        response = await fetchImpl(TAVILY_SEARCH_URL, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            api_key: apiKey,
            query: `Threat intelligence reporting and reputation for ${indicator}`,
            search_depth: "basic",
            max_results: MAX_RESULTS,
            include_answer: false,
            include_raw_content: false,
          }),
          signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
        });
      } catch (error) {
        const errorName = error instanceof Error ? error.name : "";
        if (errorName === "TimeoutError" || errorName === "AbortError") {
          throw new TavilyClientError(
            "Tavily threat intelligence lookup timed out.",
            504,
            "timeout",
          );
        }
        throw new TavilyClientError(
          "Could not connect to Tavily threat intelligence.",
          502,
          "provider-error",
        );
      }

      if (response.status === 429) {
        throw new TavilyClientError(
          "Tavily is rate-limiting threat intelligence requests. Please try again shortly.",
          429,
          "rate-limited",
        );
      }
      if (!response.ok) {
        const message = response.status === 401 || response.status === 403
          ? "Tavily rejected the configured API credential."
          : "Tavily could not complete the threat intelligence lookup.";
        throw new TavilyClientError(message, 502, "provider-error");
      }

      let payload: unknown;
      try {
        payload = JSON.parse(await readResponse(response));
      } catch (error) {
        if (error instanceof TavilyClientError) throw error;
        const errorName = error instanceof Error ? error.name : "";
        if (errorName === "TimeoutError" || errorName === "AbortError") {
          throw new TavilyClientError(
            "Tavily threat intelligence lookup timed out.",
            504,
            "timeout",
          );
        }
        throw new TavilyClientError(
          "Tavily returned an unreadable threat intelligence response.",
          502,
          "invalid-response",
        );
      }

      const parsed = TavilyResponseSchema.safeParse(payload);
      if (!parsed.success) {
        throw new TavilyClientError(
          "Tavily returned a response in an unsupported format.",
          502,
          "invalid-response",
        );
      }

      return parsed.data.results.map((result) => ({
        title: result.title.slice(0, MAX_TITLE_LENGTH),
        url: result.url,
        excerpt: result.content.slice(0, MAX_EXCERPT_LENGTH),
        publishedAt: result.published_date ?? null,
        relevanceScore: result.score ?? null,
      }));
    },
  };
}
