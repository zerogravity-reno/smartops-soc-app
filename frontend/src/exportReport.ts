const INLINE_EXPORT_CSS = `
@page { size: A4 landscape; margin: 10mm; }
@media print {
  :root { color-scheme: dark; }
  html, body { width: auto; min-height: 0; background: var(--bg) !important; print-color-adjust: exact; -webkit-print-color-adjust: exact; }
  body::after { position: absolute; }
  .topbar { position: static; background: var(--surface); }
  .shell { display: grid; grid-template-columns: 31% minmax(0, 1fr); grid-template-areas: "strip strip" "verdict verdict" "rail rail" "ledger ledger"; min-height: 0; }
  .queue { display: none; }
  .strip { padding: 14px 0 12px; border-bottom: 1px solid var(--line); }
  .verdict { margin: 12px 0 0; box-shadow: none; break-inside: avoid; }
  .rail { position: static; height: auto; overflow: visible; display: grid; grid-template-columns: 1.1fr 1.2fr .9fr; border-left: 0; border-bottom: 1px solid var(--line); background: transparent; }
  .rail-sec { padding: 12px 14px; border-bottom: 0; border-right: 1px solid var(--line); }
  .rail-sec:last-child { border-right: 0; }
  .ledger-wrap { padding: 14px 0 18px; }
  .stg, .card, .task, .fetch, details { break-inside: avoid; }
  .stg-body { break-inside: auto; }
  pre, .code-lines, .xr-log { max-height: none; overflow: visible; }
}
`;

function safeFilePart(value: string) {
  return value.replace(/[^a-z0-9._-]+/gi, '-').replace(/^-+|-+$/g, '') || 'run';
}

async function dataUri(url: string) {
  const response = await fetch(url);
  if (!response.ok) throw new Error(`Could not embed ${new URL(url).pathname}.`);
  const blob = await response.blob();
  const bytes = new Uint8Array(await blob.arrayBuffer());
  let binary = '';
  for (const chunk of Array.from(bytes)) binary += String.fromCharCode(chunk);
  return `data:${blob.type || 'application/octet-stream'};base64,${btoa(binary)}`;
}

async function resolvedCss(css: string, stylesheetUrl: string) {
  const urls: string[] = [];
  const marked = css.replace(/url\(\s*(['"]?)([^'"\)]+)\1\s*\)/g, (match, _quote, raw: string) => {
    if (/^(data:|#|https?:)/i.test(raw)) return match;
    urls.push(new URL(raw, stylesheetUrl).href);
    return `__SMARTOPS_ASSET_${urls.length - 1}__`;
  });
  const assets = await Promise.all(urls.map(dataUri));
  return marked.replace(/__SMARTOPS_ASSET_(\d+)__/g, (_placeholder, index) => `url("${assets[Number(index)]}")`);
}

function preserveControlValues(root: HTMLElement) {
  const source = document.documentElement;
  root.querySelectorAll<HTMLInputElement>('input').forEach((input, index) => {
    const original = source.querySelectorAll<HTMLInputElement>('input')[index];
    if (!original) return;
    input.setAttribute('value', original.value);
    input.toggleAttribute('checked', original.checked);
  });
  root.querySelectorAll<HTMLTextAreaElement>('textarea').forEach((textarea, index) => {
    textarea.textContent = source.querySelectorAll<HTMLTextAreaElement>('textarea')[index]?.value || '';
  });
  root.querySelectorAll<HTMLSelectElement>('select').forEach((select, index) => {
    const original = source.querySelectorAll<HTMLSelectElement>('select')[index];
    if (!original) return;
    select.querySelectorAll('option').forEach((option, optionIndex) => option.toggleAttribute('selected', original.options[optionIndex]?.selected || false));
  });
}

export async function exportCurrentRun(runId?: string) {
  const root = document.documentElement.cloneNode(true) as HTMLElement;
  preserveControlValues(root);
  root.querySelectorAll('.dev, .toast, .dev-btn, .strip-actions').forEach(node => node.remove());
  root.querySelectorAll('script').forEach(node => node.remove());

  const sourceLinks = [...document.querySelectorAll<HTMLLinkElement>('link[rel="stylesheet"]')];
  const exportedLinks = [...root.querySelectorAll<HTMLLinkElement>('link[rel="stylesheet"]')];
  const css = await Promise.all(sourceLinks.map(async link => {
    const response = await fetch(link.href);
    if (!response.ok) throw new Error(`Could not load the application stylesheet.`);
    return resolvedCss(await response.text(), link.href);
  }));
  exportedLinks.forEach((link, index) => {
    const style = document.createElement('style');
    style.textContent = css[index] || '';
    link.replaceWith(style);
  });
  const printStyle = document.createElement('style');
  printStyle.textContent = INLINE_EXPORT_CSS;
  root.querySelector('head')?.append(printStyle);

  const output = '<!DOCTYPE html>\n' + root.outerHTML;
  const blob = new Blob([output], { type: 'text/html;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = `smartops-${safeFilePart(runId || 'run')}-report.html`;
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}
