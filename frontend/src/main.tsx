import { QueryClientProvider } from "@tanstack/react-query";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import App from "./App";
import { authStore } from "./lib/api";
import { bindQueryCacheToAuth, createQueryClient } from "./lib/queries";
import "./fonts.css";
import "./styles/tokens.css";
import "./styles/base.css";
import "./styles/shell.css";
import "./styles/globe.css";
import "./styles/volume.css";
import "./styles/lanes.css";
import "./styles/dashboard.css";
import "./styles/drawer.css";
import "./styles/search.css";
import "./styles/threat.css";
import "./styles/auth.css";
import "./styles/admin.css";
import { initTheme } from "./lib/theme";

initTheme();
const queryClient = createQueryClient();
// Login, logout, a peer tab's logout or user switch, or a failed refresh: drop the old identity's data.
bindQueryCacheToAuth(queryClient, authStore);

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <App />
    </QueryClientProvider>
  </StrictMode>,
);
