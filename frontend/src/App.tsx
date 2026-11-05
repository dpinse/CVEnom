import { BrowserRouter } from "react-router-dom";
import { GlobeProvider } from "./components/GlobeContext";
import { AppRoutes } from "./routes";

export default function App() {
  return (
    <BrowserRouter>
      <GlobeProvider>
        <AppRoutes />
      </GlobeProvider>
    </BrowserRouter>
  );
}
