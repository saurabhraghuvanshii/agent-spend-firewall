/**
 * Listen on a LOOPBACK address only (T013, D-036). Used by the proxy CLI when `ASF_API_PORT` is set.
 */
import { serve, type ServerType } from "@hono/node-server";
import { err, ok, type Result } from "@asf/core";
import type { Api } from "./app.js";
import { isLoopbackHost } from "./security.js";

export interface RunningApi {
  readonly host: string;
  readonly port: number;
  /** Ends event streams and closes the listener (and its open connections). Idempotent. */
  close(): Promise<void>;
}

export function startApiServer(api: Api, host: string, port: number): Promise<Result<RunningApi>> {
  if (!isLoopbackHost(host)) {
    return Promise.resolve(err("api.bad_host", "the API only binds to a loopback address"));
  }
  return new Promise((resolve) => {
    let settled = false;
    const onError = (e: Error): void => {
      if (settled) return;
      settled = true;
      const code = "code" in e && typeof e.code === "string" ? e.code : e.name;
      resolve(
        err("api.listen_failed", `the API could not listen on ${host}:${String(port)} (${code})`),
      );
    };
    const server: ServerType = serve({ fetch: api.app.fetch, hostname: host, port }, () => {
      if (settled) return;
      settled = true;
      let closing: Promise<void> | undefined;
      resolve(
        ok({
          host,
          port,
          close: () => {
            closing ??= new Promise<void>((done) => {
              api.close();
              server.close(() => {
                done();
              });
              if ("closeAllConnections" in server) server.closeAllConnections();
            });
            return closing;
          },
        }),
      );
    });
    server.once("error", onError);
  });
}
