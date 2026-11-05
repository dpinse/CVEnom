import "@testing-library/jest-dom/vitest";
import { cleanup } from "@testing-library/react";
import { afterEach } from "vitest";

// vitest runs without `globals`, so RTL cannot register its own auto-cleanup: unmount every
// rendered tree after each test here, for every file (per-file cleanups are harmless duplicates).
afterEach(cleanup);
