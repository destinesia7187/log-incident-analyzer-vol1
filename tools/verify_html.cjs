// Optional visual smoke: npm install --no-save playwright, then node tools/verify_html.cjs.
const { chromium } = require('playwright');
const fs = require('node:fs');
const path = require('node:path');

(async () => {
  const browser = await chromium.launch({ channel: process.env.LIA_BROWSER_CHANNEL || 'msedge', headless: true });
  const page = await browser.newPage({ viewport: { width: 1280, height: 900 } });
  const errors = [], requests = [];
  page.on('pageerror', e => errors.push(String(e)));
  await page.route('**/*', route => { requests.push(route.request().url()); return route.abort(); });
  await page.setContent(fs.readFileSync(path.join(__dirname, '../examples/demo/report.html'), 'utf8'));
  if (await page.locator('article').count() !== 1) throw new Error('Missing demo case');
  if (await page.locator('script').count()) throw new Error('Scripts in static report');
  await page.getByRole('link').first().click();
  const output = path.join(__dirname, '../reports/visual');
  fs.mkdirSync(output, { recursive: true });
  await page.screenshot({ path: path.join(output, 'desktop-preview.png'), fullPage: false });
  await page.screenshot({ path: path.join(output, 'desktop.png'), fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 });
  await page.screenshot({ path: path.join(output, 'mobile.png'), fullPage: true });
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth > innerWidth);
  const result = { browser: 'headless ' + (process.env.LIA_BROWSER_CHANNEL || 'msedge'), version: browser.version(), page_errors: errors, external_requests: requests, mobile_overflow: overflow, passed: !errors.length && !requests.length && !overflow };
  fs.writeFileSync(path.join(output, 'browser-smoke.json'), JSON.stringify(result, null, 2));
  await browser.close();
  console.log(JSON.stringify(result));
  if (!result.passed) process.exitCode = 1;
})().catch(error => { console.error(error); process.exitCode = 1; });
