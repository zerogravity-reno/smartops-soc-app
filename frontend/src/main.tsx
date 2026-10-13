import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
// Self-hosted: no font or icon CDN at runtime.
import '@fontsource-variable/geist';
import '@fontsource-variable/geist-mono';
import '@phosphor-icons/web/regular/style.css';
import '@phosphor-icons/web/bold/style.css';
import App from './App';
import './style.css';

createRoot(document.getElementById('root')!).render(<StrictMode><App /></StrictMode>);
