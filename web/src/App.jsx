import { BrowserRouter, Routes, Route } from 'react-router-dom'
import DashboardLayout from './layouts/DashboardLayout'
import AuthGuard from './components/AuthGuard'
import Login from './pages/Login'
import MFAVerify from './pages/MFAVerify'
import FirstRunSetup from './pages/FirstRunSetup'
import Overview from './pages/Overview'
import Alerts from './pages/Alerts'
import Cases from './pages/Cases'
import Hunt from './pages/Hunt'
import Rules from './pages/Rules'
import Sources from './pages/Sources'
import Settings from './pages/Settings'

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        {/* Public routes */}
        <Route path="/login" element={<Login />} />
        <Route path="/login/mfa" element={<MFAVerify />} />
        <Route path="/setup" element={<FirstRunSetup />} />

        {/* Protected routes — requires authentication */}
        <Route element={<AuthGuard />}>
          <Route element={<DashboardLayout />}>
            <Route index element={<Overview />} />
            <Route path="alerts" element={<Alerts />} />
            <Route path="cases" element={<Cases />} />
            <Route path="hunt" element={<Hunt />} />
            <Route path="rules" element={<Rules />} />
            <Route path="sources" element={<Sources />} />
            <Route path="settings" element={<Settings />} />
          </Route>
        </Route>
      </Routes>
    </BrowserRouter>
  )
}
