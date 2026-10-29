import assert from "node:assert/strict";
import test from "node:test";
import {
  createTavilyClient,
  TavilyClientError,
  TAVILY_SEARCH_URL,
} from "./tavily-client.ts";

const validPayload = {
  results: [{
    title: "Threat report",
    url: "https://intel.example/reports/indicator",
    content: "A relevant threat report excerpt.",
    score: 0.87,
    published_date: "2026-10-28",
  }],
};

test("sends a bounded authenticated Tavily search and preserves source metadata", async () => {
  let request;
  const client = createTavilyClient({
    apiKey: "test-tavily-key",
    fetchImpl: async (url, options) => {
      request = { url, options };
      return new Response(JSON.stringify(validPayload), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    },
  });

  const results = await client.search("185.231.72.14");
  const body = JSON.parse(request.options.body);

  assert.equal(request.url, TAVILY_SEARCH_URL);
  assert.equal(request.options.method, "POST");
  assert.equal(body.api_key, "test-tavily-key");
  assert.match(body.query, /185\.231\.72\.14/);
  assert.equal(body.max_results, 3);
  assert.equal(body.include_raw_content, false);
  assert.equal(results[0].title, validPayload.results[0].title);
  assert.equal(results[0].url, validPayload.results[0].url);
  assert.equal(results[0].excerpt, validPayload.results[0].content);
  assert.equal(results[0].publishedAt, "2026-10-28");
  assert.equal(results[0].relevanceScore, 0.87);
  assert.equal(request.options.signal.aborted, false);
});

test("reports missing credentials without making a request", async () => {
  let requestCount = 0;
  const client = createTavilyClient({
    apiKey: " ",
    fetchImpl: async () => {
      requestCount += 1;
      return new Response();
    },
  });

  await assert.rejects(
    client.search("185.231.72.14"),
    (error) => error instanceof TavilyClientError &&
      error.code === "missing-api-key" &&
      error.statusCode === 503,
  );
  assert.equal(requestCount, 0);
});

test("maps Tavily HTTP and rate-limit errors to sanitized client errors", async () => {
  const rateLimited = createTavilyClient({
    apiKey: "test-key",
    fetchImpl: async () => new Response("private upstream detail", { status: 429 }),
  });
  const providerError = createTavilyClient({
    apiKey: "test-key",
    fetchImpl: async () => new Response("private upstream detail", { status: 500 }),
  });

  await assert.rejects(
    rateLimited.search("185.231.72.14"),
    (error) => error instanceof TavilyClientError &&
      error.code === "rate-limited" &&
      error.statusCode === 429 &&
      !error.message.includes("private upstream detail"),
  );
  await assert.rejects(
    providerError.search("185.231.72.14"),
    (error) => error instanceof TavilyClientError &&
      error.code === "provider-error" &&
      error.statusCode === 502 &&
      !error.message.includes("private upstream detail"),
  );
});

test("normalizes request timeouts and malformed responses", async () => {
  const timedOut = createTavilyClient({
    apiKey: "test-key",
    fetchImpl: async () => {
      throw Object.assign(new Error("private request detail"), { name: "TimeoutError" });
    },
  });
  const malformedJson = createTavilyClient({
    apiKey: "test-key",
    fetchImpl: async () => new Response("not-json"),
  });
  const malformedPayload = createTavilyClient({
    apiKey: "test-key",
    fetchImpl: async () => new Response(JSON.stringify({
      results: [{ title: "No URL", content: "Invalid source" }],
    })),
  });

  await assert.rejects(
    timedOut.search("185.231.72.14"),
    (error) => error instanceof TavilyClientError &&
      error.code === "timeout" &&
      error.statusCode === 504 &&
      !error.message.includes("private request detail"),
  );
  await assert.rejects(
    malformedJson.search("185.231.72.14"),
    (error) => error instanceof TavilyClientError && error.code === "invalid-response",
  );
  await assert.rejects(
    malformedPayload.search("185.231.72.14"),
    (error) => error instanceof TavilyClientError && error.code === "invalid-response",
  );
});

test("rejects non-HTTP source URLs and invalid indicators", async () => {
  const badUrl = createTavilyClient({
    apiKey: "test-key",
    fetchImpl: async () => new Response(JSON.stringify({
      results: [{ ...validPayload.results[0], url: "javascript:alert(1)" }],
    })),
  });
  let requestCount = 0;
  const client = createTavilyClient({
    apiKey: "test-key",
    fetchImpl: async () => {
      requestCount += 1;
      return new Response(JSON.stringify(validPayload));
    },
  });

  await assert.rejects(
    badUrl.search("185.231.72.14"),
    (error) => error instanceof TavilyClientError && error.code === "invalid-response",
  );
  await assert.rejects(client.search("not-an-ip"));
  assert.equal(requestCount, 0);
});
