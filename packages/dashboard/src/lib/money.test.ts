import { describe, expect, it } from "vitest";
import { formatPaise } from "./money";

describe("formatPaise", () => {
  it.each([
    [0, "₹0.00"],
    [1, "₹0.01"],
    [9, "₹0.09"],
    [10, "₹0.10"],
    [99, "₹0.99"],
    [100, "₹1.00"],
    [101, "₹1.01"],
    [50_000, "₹500.00"],
    [12_345_678, "₹1,23,456.78"],
    [10_000_000_00, "₹1,00,00,000.00"],
  ])("%d paise ⇒ %s (Indian grouping)", (paise, expected) => {
    expect(formatPaise(paise)).toBe(expected);
  });

  it("is exact at Number.MAX_SAFE_INTEGER (no float rounding)", () => {
    expect(formatPaise(Number.MAX_SAFE_INTEGER)).toBe("₹9,00,71,99,25,47,409.91");
  });

  it("formats bigints beyond the safe range exactly", () => {
    expect(formatPaise(123_456_789_012_345_678_901n)).toBe("₹12,34,56,78,90,12,34,56,789.01");
  });

  it("formats negative amounts with a leading minus", () => {
    expect(formatPaise(-50)).toBe("-₹0.50");
    expect(formatPaise(-12_345n)).toBe("-₹123.45");
  });

  it.each([1.5, 0.1, Number.NaN, Number.POSITIVE_INFINITY, Number.MAX_SAFE_INTEGER + 2])(
    "rejects a non-integer / unsafe number %d",
    (bad) => {
      expect(formatPaise(bad)).toBeUndefined();
    },
  );
});
