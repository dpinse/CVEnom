import { QueryClientProvider } from "@tanstack/react-query";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import App from "./App";
import { createQueryClient } from "./lib/queries";
import "./fonts.css";
import "./styles/tokens.css";
import "./styles/base.css";
import "./styles/shell.css";
import "./styles/globe.css";
import "./styles/velocity.css";
import "./styles/lanes.css";
import "./styles/drawer.css";
import "./styles/search.css";
import "./styles/auth.css";
import "./styles/admin.css";
import { initTheme } from "./lib/theme";

initTheme();
const queryClient = createQueryClient();

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <App />
    </QueryClientProvider>
  </StrictMode>,
);
