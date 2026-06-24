/** 应用根组件：路由配置。 */
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { Route, Routes } from 'react-router-dom'
import { Layout } from './components/Layout'
import { Dashboard } from './pages/Dashboard'
import { Playground } from './pages/Playground'
import { Rules } from './pages/Rules'
import { Audit } from './pages/Audit'
import { Gateway } from './pages/Gateway'
import { Identities } from './pages/Identities'
import { Settings } from './pages/Settings'

const queryClient = new QueryClient({
  defaultOptions: {
    queries: { refetchOnWindowFocus: false, retry: 1 },
  },
})

export default function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <Routes>
        <Route path="/" element={<Layout />}>
          <Route index element={<Dashboard />} />
          <Route path="playground" element={<Playground />} />
          <Route path="rules" element={<Rules />} />
          <Route path="audit" element={<Audit />} />
          <Route path="gateway" element={<Gateway />} />
          <Route path="identities" element={<Identities />} />
          <Route path="settings" element={<Settings />} />
        </Route>
      </Routes>
    </QueryClientProvider>
  )
}
