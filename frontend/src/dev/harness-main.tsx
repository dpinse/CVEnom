import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import "../fonts.css";
import "../styles/tokens.css";
import "../styles/base.css";
import "../styles/shell.css";
import "../styles/globe.css";
import "../styles/volume.css";
import "./harness.css";
import GlobeHarness from "./GlobeHarness";

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <GlobeHarness />
  </StrictMode>,
);
