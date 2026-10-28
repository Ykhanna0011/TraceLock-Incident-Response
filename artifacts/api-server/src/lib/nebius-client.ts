import { z } from "zod/v4";

export const NEBIUS_BASE_URL = "https://api.tokenfactory.nebius.com/v1";
export const NEBIUS_MODEL_ID = "nvidia/Nemotron-3_5-Lightning";
const DEFAULT_TIMEOUT_MS = 30_000;
const MAX_PROVIDER_RESPONSE_BYTES = 64 * 1024;

export type ChatToolCall = {
  id: string;
  type: string;
  function: {
    name: string;
    arguments: string;
  };
};

export type ChatMessage = {
  role: "system" | "user" | "assistant" | "tool";
  content: string | null;
  name?: string;
  tool_call_id?: string;
  tool_calls?: ChatToolCall[] | null;
};

export type ChatTool = {
  type: "function";
  function: {
    name: string;
    description: string;
    parameters: Record<string, unknown>;
  };
};

export type ChatCompletionOptions = {
  messages: ChatMessage[];
  tools?: ChatTool[];
  toolChoice?: "auto" | "none" | {
    type: "function";
    function: { name: string };
  };
  responseFormat?: { type: "json_object" };
  timeoutMs?: number;
  maxTokens?: number;
};

const ProviderResponseSchema = z.object({
  choices: z.array(z.object({
    message: z.object({
      role: z.string(),
      content: z.union([z.string(), z.null()]).optional(),
      tool_calls: z.array(z.object({
        id: z.string().min(1).max(128),
        type: z.literal("function"),
        function: z.object({
          name: z.string().min(1).max(100),
          arguments: z.string().max(2_048),
        }),
      }).passthrough()).max(8).nullable().optional(),
    }).passthrough(),
  }).passthrough()).min(1),
}).passthrough();

export type ChatCompletionResponse = z.infer<typeof ProviderResponseSchema>;

export class NebiusClientError extends Error {
  readonly statusCode: number;
  readonly code: "missing-api-key" | "rate-limited" | "timeout" | "provider-error" | "invalid-response";
  readonly upstreamStatus?: number;

  constructor(
    message: string,
    statusCode: number,
    code: "missing-api-key" | "rate-limited" | "timeout" | "provider-error" | "invalid-response",
    upstreamStatus?: number,
  ) {
    super(message);
    this.name = "NebiusClientError";
    this.statusCode = statusCode;
    this.code = code;
    this.upstreamStatus = upstreamStatus;
  }
}

export type NebiusChatClient = {
  complete(options: ChatCompletionOptions): Promise<ChatCompletionResponse>;
};

async function readProviderResponse(response: Response): Promise<string> {
  const contentLength = Number(response.headers.get("content-length"));
  if (Number.isFinite(contentLength) && contentLength > MAX_PROVIDER_RESPONSE_BYTES) {
    throw new NebiusClientError(
      "Nebius returned a response that exceeded the allowed size.",
      502,
      "invalid-response",
      response.status,
    );
  }
  if (!response.body) return "";

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let totalBytes = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      totalBytes += value.byteLength;
      if (totalBytes > MAX_PROVIDER_RESPONSE_BYTES) {
        await reader.cancel();
        throw new NebiusClientError(
          "Nebius returned a response that exceeded the allowed size.",
          502,
          "invalid-response",
          response.status,
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

export function createNebiusClient(options: {
  apiKey?: string;
  fetchImpl?: typeof fetch;
} = {}): NebiusChatClient {
  const apiKey = options.apiKey ?? process.env.NEBIUS_API_KEY;
  const fetchImpl = options.fetchImpl ?? fetch;

  if (!apiKey?.trim()) {
    throw new NebiusClientError(
      "Nemotron investigation is unavailable because NEBIUS_API_KEY is not configured.",
      503,
      "missing-api-key",
    );
  }

  return {
    async complete(request): Promise<ChatCompletionResponse> {
      let response: Response;
      try {
        response = await fetchImpl(`${NEBIUS_BASE_URL}/chat/completions`, {
          method: "POST",
          headers: {
            Authorization: `Bearer ${apiKey}`,
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            model: NEBIUS_MODEL_ID,
            messages: request.messages,
            tools: request.tools,
            tool_choice: request.toolChoice,
            response_format: request.responseFormat,
            temperature: 0.2,
            max_tokens: request.maxTokens ?? 1400,
          }),
          signal: AbortSignal.timeout(request.timeoutMs ?? DEFAULT_TIMEOUT_MS),
        });
      } catch (error) {
        const errorName = error instanceof Error ? error.name : "";
        if (errorName === "TimeoutError" || errorName === "AbortError") {
          throw new NebiusClientError(
            "Nemotron did not respond before the request timed out.",
            504,
            "timeout",
          );
        }
        throw new NebiusClientError(
          "Could not connect to Nebius Token Factory.",
          502,
          "provider-error",
        );
      }

      if (response.status === 429) {
        throw new NebiusClientError(
          "Nebius Token Factory is rate-limiting requests. Please try again shortly.",
          429,
          "rate-limited",
          response.status,
        );
      }

      if (!response.ok) {
        const message = response.status === 401 || response.status === 403
          ? "Nebius rejected the configured API credential."
          : response.status === 404
            ? `The configured Nebius account could not use model ${NEBIUS_MODEL_ID}.`
            : "Nebius Token Factory could not complete the investigation.";
        throw new NebiusClientError(
          message,
          502,
          "provider-error",
          response.status,
        );
      }

      let payload: unknown;
      try {
        payload = JSON.parse(await readProviderResponse(response));
      } catch (error) {
        if (error instanceof NebiusClientError) throw error;
        const errorName = error instanceof Error ? error.name : "";
        if (errorName === "TimeoutError" || errorName === "AbortError") {
          throw new NebiusClientError(
            "Nemotron did not respond before the request timed out.",
            504,
            "timeout",
          );
        }
        throw new NebiusClientError(
          "Nebius returned an unreadable model response.",
          502,
          "invalid-response",
          response.status,
        );
      }

      const parsed = ProviderResponseSchema.safeParse(payload);
      if (!parsed.success) {
        throw new NebiusClientError(
          "Nebius returned a model response in an unsupported format.",
          502,
          "invalid-response",
          response.status,
        );
      }

      return parsed.data;
    },
  };
}
