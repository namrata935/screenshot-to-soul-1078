import { describe, expect, it } from "vitest";
import { correlatedRisk, riskLevel } from "@/lib/mock-data";

describe("risk scoring", () => {
  it("bands: Low <35, Medium 35–69, High 70–99, Critical 100+", () => {
    expect(riskLevel(34)).toBe("Low");
    expect(riskLevel(35)).toBe("Medium");
    expect(riskLevel(69)).toBe("Medium");
    expect(riskLevel(70)).toBe("High");
    expect(riskLevel(99)).toBe("High");
    expect(riskLevel(100)).toBe("Critical");
  });
  it("applies 1.5x only within 60 seconds", () => {
    expect(correlatedRisk(40, 40, 60)).toBe(120);
    expect(correlatedRisk(40, 40, 61)).toBe(80);
  });
});
