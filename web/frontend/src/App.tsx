import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { Navbar } from './components/common/Navbar';
import { Footer } from './components/common/Footer';
import { DemoPage } from './pages/DemoPage';
import { IntegrityDemoPage } from './pages/IntegrityDemoPage';

function App() {
  return (
    <BrowserRouter>
      <div className="min-h-screen flex flex-col bg-base-100">
        <Navbar />
        <main className="flex-1">
          <Routes>
            <Route path="/" element={<DemoPage />} />
            <Route path="/integrity" element={<IntegrityDemoPage />} />
          </Routes>
        </main>
        {/* <Footer /> */}
      </div>
    </BrowserRouter>
  );
}

export default App;
