import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { AuthProvider } from './context/AuthContext';
import { QueryClientProvider } from '@tanstack/react-query';
import { queryClient } from './queryClient';
import { ProtectedRoute, AuthRoute, SetupRoute } from './components/RouteGuards';
import Layout from './components/Layout';
import Dashboard from './pages/Dashboard';
import Repositories from './pages/Repositories';
import RepoDetail from './pages/RepoDetail';
import Vulnerabilities from './pages/Vulnerabilities';
import Settings from './pages/Settings';
import Login from './pages/Login';
import SetupWizard from './pages/SetupWizard';
import './index.css';

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <AuthProvider>
          <Routes>
            {/* Public routes */}
            <Route path="/login" element={<AuthRoute><Login /></AuthRoute>} />
            <Route path="/setup" element={<SetupRoute><SetupWizard /></SetupRoute>} />
  
            {/* Protected routes */}
            <Route path="/" element={<ProtectedRoute><Layout /></ProtectedRoute>}>
              <Route index element={<Dashboard />} />
              <Route path="repositories" element={<Repositories />} />
              <Route path="repositories/:id" element={<RepoDetail />} />
              <Route path="vulnerabilities" element={<Vulnerabilities />} />
              <Route path="settings" element={<Settings />} />
            </Route>
          </Routes>
        </AuthProvider>
      </BrowserRouter>
    </QueryClientProvider>
  );
}
