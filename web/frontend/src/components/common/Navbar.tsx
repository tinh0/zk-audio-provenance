import { Shield } from 'lucide-react';
import { Link, useLocation } from 'react-router-dom';

export function Navbar() {
  const location = useLocation();

  return (
    <div className="navbar bg-base-200 shadow-sm">
      <div className="navbar-start">
        <Link to="/" className="btn btn-ghost text-xl gap-2">
          <Shield className="w-6 h-6 text-primary" />
          HyperVerITAS Media
        </Link>
      </div>
      <div className="navbar-center">
        <ul className="menu menu-horizontal px-1 gap-1">
          <li>
            <Link to="/" className={location.pathname === '/' ? 'active' : ''}>
              Demo
            </Link>
          </li>
          <li>
            <Link to="/integrity" className={location.pathname === '/integrity' ? 'active' : ''}>
              End to End Demo
            </Link>
          </li>
        </ul>
      </div>
      <div className="navbar-end">
        <span className="text-sm text-base-content/60 pr-4 hidden sm:inline">
          Zero-Knowledge Proofs for Media Provenance
        </span>
      </div>
    </div>
  );
}
