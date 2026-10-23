import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import { Layout } from "./components/Layout";
import { CaseDetailPage } from "./pages/CaseDetailPage";
import { CasesPage } from "./pages/CasesPage";
import { DetectionLab } from "./pages/DetectionLab";
import { EvaluationLab } from "./pages/EvaluationLab";
import { PipelinePage } from "./pages/PipelinePage";
import { SocConsole } from "./pages/SocConsole";
import { ThreatLab } from "./pages/ThreatLab";

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route element={<Layout />}>
          <Route index element={<SocConsole />} />
          <Route path="cases" element={<CasesPage />} />
          <Route path="cases/:caseId" element={<CaseDetailPage />} />
          <Route path="detection" element={<DetectionLab />} />
          <Route path="pipeline" element={<PipelinePage />} />
          <Route path="evaluation" element={<EvaluationLab />} />
          <Route path="threat-lab" element={<ThreatLab />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
