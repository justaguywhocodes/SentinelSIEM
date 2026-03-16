import { BrowserRouter, Routes, Route } from 'react-router-dom'
import DashboardLayout from './layouts/DashboardLayout'
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
        <Route element={<DashboardLayout />}>
          <Route index element={<Overview />} />
          <Route path="alerts" element={<Alerts />} />
          <Route path="cases" element={<Cases />} />
          <Route path="hunt" element={<Hunt />} />
          <Route path="rules" element={<Rules />} />
          <Route path="sources" element={<Sources />} />
          <Route path="settings" element={<Settings />} />
        </Route>
      </Routes>
    </BrowserRouter>
  )
}
