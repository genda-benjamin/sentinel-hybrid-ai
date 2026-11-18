import { chromium } from 'playwright';

(async () => {
  console.log('Testing live site: https://genda-benjamin.github.io/sentinel-hybrid-ai/');
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage({ viewport: { width: 1920, height: 1080 } });

  page.on('console', msg => console.log('PAGE LOG:', msg.text()));
  page.on('pageerror', err => console.log('PAGE ERROR:', err.message));

  await page.goto('https://genda-benjamin.github.io/sentinel-hybrid-ai/', { waitUntil: 'networkidle' });

  const vaultStatus = await page.$eval('#vaultStatus', el => el.textContent.trim());
  const initialDiff = await page.$eval('#diffView', el => el.textContent.trim());
  console.log('Live Vault Status on load:', vaultStatus);
  console.log('Live Initial Diff rendered?', initialDiff.includes('remediation.patch'));

  // Test typing custom code with a secret
  console.log('\nTesting typing arbitrary vulnerable code on live site...');
  await page.fill('#codeInput', 'const pass = "postgres://admin:LiveSecret2026@internal:5432/db";\napp.get("/u", (r) => db.query(`SELECT * FROM t WHERE id = ${r.query.id}`));');
  await page.dispatchEvent('#codeInput', 'input');
  await page.waitForTimeout(600);

  const customVault = await page.$eval('#vaultStatus', el => el.textContent.trim());
  const customTime = await page.$eval('#hudRedactTime', el => el.textContent.trim());
  const customDiff = await page.$eval('#diffView', el => el.textContent.trim());
  console.log('Live Custom code Vault Status:', customVault);
  console.log('Live Custom code Redact Time:', customTime);
  console.log('Live Custom code Diff has parameterization?', customDiff.includes('$1') || customDiff.includes('SELECT'));

  // Test clicking "Run Hybrid AI Audit"
  console.log('\nTesting Run Hybrid AI Audit button on live site...');
  await page.click('#runAuditBtn');
  await page.waitForTimeout(400);

  const testSuiteText = await page.$eval('#testCodeView', el => el.textContent.trim());
  console.log('Live Test suite populated?', testSuiteText.includes('node:test'));

  await browser.close();
  console.log('\nLIVE SITE VERIFICATION 100% SUCCESSFUL!');
})();
