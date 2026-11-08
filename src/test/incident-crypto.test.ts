import { describe, it, expect } from "vitest";
import {
  computeIncidentHash,
  computeIncidentHashSync,
  verifyIncidentIntegrity,
  canonicalizeIncident,
} from "@/lib/incident-crypto";

describe("Incident Forensic Cryptography", () => {
  const sampleIncident = {
    id: "INC-2041",
    time: "2026-11-01 16:59:00",
    type: "Violence Detected",
    source: "CAM-014 Lobby",
    severity: "High",
    description: "Violence Detected reported from CAM-014 Lobby. Automated triage assigned risk score 92.",
    prevHash: "0000000000000000000000000000000000000000000000000000000000000000",
  };

  it("canonicalizes incident deterministically", () => {
    const canonical = canonicalizeIncident(sampleIncident);
    expect(canonical).toContain("INC-2041");
    expect(canonical).toContain("Violence Detected");
    expect(canonical).toContain("0000000000000000000000000000000000000000000000000000000000000000");
  });

  it("computes deterministic SHA-256 hash", async () => {
    const hashAsync = await computeIncidentHash(sampleIncident);
    const hashSync = computeIncidentHashSync(sampleIncident);

    expect(hashAsync).toHaveLength(64);
    expect(hashSync).toHaveLength(64);
    expect(hashAsync).toBe(hashSync);
  });

  it("verifies untampered incident as valid", async () => {
    const validHash = await computeIncidentHash(sampleIncident);
    const res = await verifyIncidentIntegrity({
      ...sampleIncident,
      hash: validHash,
    });

    expect(res.verified).toBe(true);
    expect(res.computedHash).toBe(validHash);
  });

  it("detects tampering when payload is altered", async () => {
    const originalHash = await computeIncidentHash(sampleIncident);

    // Tampered payload (e.g. attacker downgrades severity or edits text)
    const tamperedIncident = {
      ...sampleIncident,
      severity: "Low", // Modified from High
      hash: originalHash, // Keeps old hash
    };

    const res = await verifyIncidentIntegrity(tamperedIncident);
    expect(res.verified).toBe(false);
    expect(res.computedHash).not.toBe(originalHash);
  });

  it("demonstrates avalanche effect on minor byte change", async () => {
    const hash1 = await computeIncidentHash(sampleIncident);
    const hash2 = await computeIncidentHash({
      ...sampleIncident,
      description: sampleIncident.description + ".", // 1 char difference
    });

    expect(hash1).not.toBe(hash2);
    // Differences should be substantial across the 64-char hex string
    let matchingChars = 0;
    for (let i = 0; i < hash1.length; i++) {
      if (hash1[i] === hash2[i]) matchingChars++;
    }
    expect(matchingChars).toBeLessThan(20);
  });
});

