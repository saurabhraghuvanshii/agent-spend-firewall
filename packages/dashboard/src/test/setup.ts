import { cleanup } from "@testing-library/react";
import { afterEach } from "vitest";

// jsdom has no canvas: the decorative background then draws nothing (AsciiField handles a null context).
HTMLCanvasElement.prototype.getContext = (() =>
  null) as typeof HTMLCanvasElement.prototype.getContext;

afterEach(() => {
  cleanup();
  window.sessionStorage.clear();
  window.localStorage.clear();
});
