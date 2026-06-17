import React from "react";
import { BrowserRouter, Routes, Route, Navigate, useLocation } from "react-router-dom";
import { ToastProvider } from "./components/ui/ToastContext";
import { AuthProvider } from "./contexts/AuthContext";
import { useAuth } from "./hooks/useAuth";
import { LogProvider } from "./contexts/LogContext";
import { ThemeProvider } from "./contexts/ThemeContext";
import { P2PProvider } from "./contexts/P2PContext";

// Layouts
import { PublicLayout } from "./layouts/PublicLayout";
import { DashboardLayout } from "./layouts/DashboardLayout";

// Pages
import { LandingPage } from "./pages/LandingPage";
import { LoginPage } from "./pages/LoginPage";
import { RegisterPage } from "./pages/RegisterPage";
import { AuditVault } from "./pages/AuditVault";
import { MyVaultPage } from "./pages/MyVaultPage";
import { SharedVaultPage } from "./pages/SharedVaultPage";
import { ContactsPage } from "./pages/ContactsPage";
import { WorkspaceAdminPage } from "./pages/WorkspaceAdminPage";
import { SecurityPage } from "./pages/SecurityPage";
import { OverviewPage } from "./pages/OverviewPage";
import { P2PTransferPage } from "./pages/P2PTransferPage";
import { WorkspaceSharePage } from "./pages/WorkspaceSharePage";
import { SettingsPage } from "./pages/SettingsPage";
import { rememberPendingInviteUrl } from "./utils/trust";

// Protected Route Wrapper
const ProtectedRoute = ({ children }: { children: React.ReactNode }) => {
  const { isAuthenticated } = useAuth();
  const location = useLocation();
  if (!isAuthenticated) {
    if (typeof window !== 'undefined') {
      rememberPendingInviteUrl(`${window.location.origin}${location.pathname}${location.search}`);
    }
    return <Navigate to="/login" replace />;
  }
  return <>{children}</>;
};

function AppRoutes() {
  return (
    <BrowserRouter>
      <Routes>
        <Route element={<PublicLayout />}>
          <Route path="/" element={<LandingPage />} />
          <Route path="/login" element={<LoginPage />} />
          <Route path="/register" element={<RegisterPage />} />
        </Route>

        <Route path="/dashboard" element={<ProtectedRoute><P2PProvider><DashboardLayout /></P2PProvider></ProtectedRoute>}>
          <Route index element={<Navigate to="/dashboard/overview" replace />} />
          <Route path="overview" element={<OverviewPage />} />
          <Route path="inbox" element={<Navigate to="/dashboard/shared" replace />} />
          <Route path="send" element={<Navigate to="/dashboard/files" replace />} />
          <Route path="files" element={<MyVaultPage />} />
          <Route path="vault" element={<Navigate to="/dashboard/files" replace />} />
          <Route path="shared" element={<SharedVaultPage />} />
          <Route path="workspace-share" element={<WorkspaceSharePage />} />
          <Route path="p2p" element={<P2PTransferPage />} />
          <Route path="contacts" element={<ContactsPage />} />
          <Route path="activity" element={<AuditVault />} />
          <Route path="audit" element={<Navigate to="/dashboard/activity" replace />} />
          <Route path="workspace-admin" element={<WorkspaceAdminPage />} />
          <Route path="security" element={<SecurityPage />} />
          <Route path="settings" element={<SettingsPage />} />
        </Route>

        {/* Fallback */}
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  );
}

function App() {
  return (
    <ThemeProvider>
      <AuthProvider>
        <LogProvider>
          <ToastProvider>
            <AppRoutes />
          </ToastProvider>
        </LogProvider>
      </AuthProvider>
    </ThemeProvider>
  );
}

export default App;
