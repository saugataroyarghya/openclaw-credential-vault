import type { InjectionParams } from "../types.js";

export function injectCredential(params: {
  headers: Record<string, string>;
  url: string;
  credential: string;
  injection: InjectionParams;
}): { headers: Record<string, string>; url: string } {
  const { headers, url, credential, injection } = params;

  switch (injection.strategy) {
    case "bearer": {
      return {
        headers: { ...headers, Authorization: `Bearer ${credential}` },
        url,
      };
    }

    case "header": {
      const name = injection.headerName ?? "Authorization";
      const value = injection.headerPrefix
        ? `${injection.headerPrefix} ${credential}`
        : credential;
      return {
        headers: { ...headers, [name]: value },
        url,
      };
    }

    case "query": {
      const paramName = injection.queryParamName ?? "api_key";
      const parsed = new URL(url);
      parsed.searchParams.set(paramName, credential);
      return {
        headers: { ...headers },
        url: parsed.toString(),
      };
    }

    default: {
      const _exhaustive: never = injection.strategy;
      throw new Error(`Unknown injection strategy: ${_exhaustive}`);
    }
  }
}
