import { BrowserRouter, Route, Routes } from "react-router-dom";
import { Layout } from "./components/Layout";
import { AlertDetailPage } from "./pages/AlertDetailPage";
import { AlertQueuePage } from "./pages/AlertQueuePage";
import { InvestigationPage } from "./pages/InvestigationPage";
import { NotFoundPage } from "./pages/NotFoundPage";
import { ReportPage } from "./pages/ReportPage";

export function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route element={<Layout />}>
          <Route index element={<AlertQueuePage />} />
          <Route path="alerts/:id" element={<AlertDetailPage />} />
          <Route path="investigations/:id" element={<InvestigationPage />} />
          <Route path="investigations/:id/report" element={<ReportPage />} />
          <Route path="*" element={<NotFoundPage />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
