const { test, expect } = require('../console-audit');

const PDNS_API_URL = process.env.PDNS_API_URL || 'http://pdns-server:8081';
const PDNS_API_KEY = process.env.PDNS_API_KEY || 'changeme';
const TEST_ZONE = 'browser-test.example';
const ADMIN_USERNAME = process.env.BROWSER_TEST_USERNAME || 'browser-admin';
const ROLE_SECURITY_USERS = {
  operator: {
    username: 'browser-role-operator',
    password: 'BrowserOperator123!',
    roleName: 'Operator',
  },
  targets: [
    {
      username: 'browser-role-user',
      roleName: 'User',
    },
    {
      username: 'browser-role-operator-target',
      roleName: 'Operator',
    },
  ],
};
const pdnsHeaders = {
  'X-API-Key': PDNS_API_KEY,
  Accept: 'application/json',
};

function basicAuthHeaders(username, password) {
  return {
    Authorization: `Basic ${Buffer.from(`${username}:${password}`).toString('base64')}`,
  };
}

function collectBrowserFailures(page) {
  const failures = [];

  page.on('requestfailed', (request) => {
    const type = request.resourceType();
    if (['document', 'stylesheet', 'script', 'xhr', 'fetch'].includes(type)) {
      failures.push(
        `requestfailed: ${request.method()} ${request.url()} ${request.failure()?.errorText || ''}`,
      );
    }
  });

  return failures;
}

async function captureStep(page, testInfo, name) {
  const screenshotPath = testInfo.outputPath(`${name}.png`);
  await page.screenshot({ path: screenshotPath, fullPage: true });
  await testInfo.attach(name, {
    path: screenshotPath,
    contentType: 'image/png',
  });
}

async function removeExistingRecords(request, records) {
  const zoneUrl = `${PDNS_API_URL}/api/v1/servers/localhost/zones/${TEST_ZONE}.`;
  const zoneResponse = await request.get(zoneUrl, { headers: pdnsHeaders });
  expect(zoneResponse.ok()).toBeTruthy();

  const targetRecords = new Set(
    records.map((record) => `${record.name.toLowerCase()}.${TEST_ZONE}.|${record.type}`),
  );
  const zone = await zoneResponse.json();
  const deletions = zone.rrsets
    .filter((rrset) => targetRecords.has(`${rrset.name.toLowerCase()}|${rrset.type}`))
    .map((rrset) => ({
      name: rrset.name,
      type: rrset.type,
      changetype: 'DELETE',
      records: [],
    }));

  if (deletions.length === 0) {
    return;
  }

  const deleteResponse = await request.patch(zoneUrl, {
    headers: {
      ...pdnsHeaders,
      'Content-Type': 'application/json',
    },
    data: { rrsets: deletions },
  });
  expect(deleteResponse.status()).toBe(204);
}

async function addRecord(page, record) {
  await page.getByRole('button', { name: /Add Record/i }).click();

  const row = page.locator('#tbl_records tbody tr:has(#record_type)');
  await expect(row).toHaveCount(1);
  await row.locator('#edit-row-focus').fill(record.name);
  await row.locator('#record_type').selectOption(record.type);

  const dataInput = row.locator('#current_edit_record_data');
  if (record.type === 'TXT') {
    await dataInput.click();
    const helper = page.locator('#modal_custom_record');
    await expect(helper).toBeVisible();
    await helper.locator('#record-helper-txt-0').fill(record.value);
    await helper.getByRole('button', { name: /Save/i }).click();
    await expect(helper).toBeHidden();
  } else if (record.type === 'CAA') {
    await dataInput.click();
    const helper = page.locator('#modal_custom_record');
    await expect(helper).toBeVisible();
    await helper.locator('#record-helper-caa-0').fill(record.flag);
    await helper.locator('#record-helper-caa-1').fill(record.tag);
    await helper.locator('#record-helper-caa-2').fill(record.value);
    await helper.getByRole('button', { name: /Save/i }).click();
    await expect(helper).toBeHidden();
  } else {
    await dataInput.fill(record.value);
  }

  await row.locator('.button_save').click();
  await expect(page.locator('#unsaved-changes-banner')).toBeVisible();
}

async function getApiUser(request, username, headers) {
  const response = await request.get(
    `/api/v1/pdnsadmin/users/${username}`,
    { headers },
  );
  expect(response.status()).toBe(200);
  return response.json();
}

async function assertApiRole(request, username, roleName, headers) {
  const user = await getApiUser(request, username, headers);
  expect(user.role.name).toBe(roleName);
}

test('generated CSS avoids browser parser diagnostics', async ({ page }, testInfo) => {
  await page.goto('/dashboard/', { waitUntil: 'networkidle' });
  const stylesheetUrl = await page.locator(
    'link[rel="stylesheet"][href*="/generated/main.css"]',
  ).getAttribute('href');
  expect(stylesheetUrl).not.toBeNull();

  const response = await page.request.get(stylesheetUrl);
  expect(response.ok()).toBeTruthy();
  const css = await response.text();
  const diagnostics = [];

  const charsetOffsets = [...css.matchAll(/@charset\b/gi)]
    .map((match) => match.index)
    .filter((offset) => offset !== 0);
  if (charsetOffsets.length > 0) {
    diagnostics.push(
      `ruleset ignored: ${charsetOffsets.length} @charset rule(s) occur after the start of main.css`,
    );
  }

  if (testInfo.project.name.startsWith('firefox-')) {
    const firefoxChecks = [
      {
        pattern: /-webkit-text-size-adjust\s*:/g,
        message: 'invalid -webkit-text-size-adjust declaration',
      },
      {
        pattern: /::?-moz-focus-inner\b/g,
        message: 'unsupported -moz-focus-inner selector',
      },
      {
        pattern: /::?-moz-focus-outer\b/g,
        message: 'unsupported -moz-focus-outer selector',
      },
      {
        pattern: /prefers-contrast\s*:\s*high/g,
        message: 'invalid prefers-contrast media feature value "high"',
      },
      {
        pattern: /::-webkit-slider-thumb:active\b/g,
        message: 'unsupported -webkit-slider-thumb:active selector',
      },
    ];

    for (const check of firefoxChecks) {
      const count = [...css.matchAll(check.pattern)].length;
      if (count > 0) {
        diagnostics.push(`${check.message} (${count} occurrence(s))`);
      }
    }
  }

  await page.evaluate((messages) => {
    for (const message of messages) {
      console.warn(`stylesheet parser audit: ${message}`);
    }
  }, diagnostics);
});

test('authenticated pages render without browser or layout failures', async ({ page }, testInfo) => {
  const failures = collectBrowserFailures(page);
  const pages = [
    ['/dashboard/', 'Dashboard'],
    ['/domain/browser-test.example', 'Zone Editor'],
    ['/admin/setting/basic', 'Basic Settings'],
    ['/admin/setting/pdns', 'PowerDNS Settings'],
  ];

  for (const [url, label] of pages) {
    const response = await page.goto(url, { waitUntil: 'networkidle' });
    expect(response, `${label} should return a response`).not.toBeNull();
    expect(response.status(), `${label} status`).toBeLessThan(400);
    await expect(page.locator('.app-header')).toBeVisible();
    await expect(page.locator('.app-sidebar')).toBeVisible();
    await expect(page.locator('.app-content-header h1')).toBeVisible();
    await expect(page.locator('.breadcrumb')).toBeVisible();

    const layout = await page.evaluate(() => ({
      overflow: document.documentElement.scrollWidth - document.documentElement.clientWidth,
      theme: document.documentElement.getAttribute('data-bs-theme'),
      bodyBackground: getComputedStyle(document.body).backgroundColor,
    }));
    expect(layout.overflow, `${label} has horizontal page overflow`).toBeLessThanOrEqual(1);
    expect(layout.theme).toMatch(/^(light|dark)$/);
    expect(layout.bodyBackground).not.toBe('rgba(0, 0, 0, 0)');

    await page.screenshot({
      path: testInfo.outputPath(`${label.toLowerCase().replaceAll(' ', '-')}.png`),
      fullPage: true,
    });
  }

  expect(failures, failures.join('\n')).toEqual([]);
});

test('zone template records can be cancelled, saved, and edited readably', async ({ page }, testInfo) => {
  const templateName = `layout-${testInfo.project.name}`;

  await page.goto('/admin/templates', { waitUntil: 'networkidle' });
  const existingTemplate = page.getByRole('link', {
    name: templateName,
    exact: true,
  });

  if (!(await existingTemplate.count())) {
    await page.goto('/admin/template/create', { waitUntil: 'networkidle' });
    await page.locator('#name').fill(templateName);
    await page.locator('#description').fill('Browser layout regression test');
    await Promise.all([
      page.waitForURL(/\/admin\/templates(?:\/list)?$/),
      page.getByRole('button', { name: 'Save Template' }).click(),
    ]);
  }

  await page.goto(`/admin/template/${templateName}/edit`, {
    waitUntil: 'networkidle',
  });
  await page.getByRole('button', { name: 'Add Record' }).click();

  const editRow = page.locator('#tbl_records tbody tr:has(#record_type)');
  await expect(editRow).toHaveCount(1);
  await editRow.locator('#record_status').selectOption('true');

  const recordTypes = await editRow.locator('#record_type option').allTextContents();
  expect(recordTypes).toEqual([...recordTypes].sort());

  const widths = await editRow.evaluate((row) => Object.fromEntries(
    ['name', 'type', 'status', 'ttl'].map((column) => [
      column,
      row.querySelector(`.record-${column}-column`).getBoundingClientRect().width,
    ]),
  ));
  expect(widths.name).toBeGreaterThanOrEqual(159);
  expect(widths.type).toBeGreaterThanOrEqual(127);
  expect(widths.status).toBeGreaterThanOrEqual(127);
  expect(widths.ttl).toBeGreaterThanOrEqual(159);

  for (const fieldId of ['record_type', 'record_status', 'record_ttl']) {
    await expect(editRow.locator(`#${fieldId}`)).toHaveClass(/form-select/);
  }

  await editRow.locator('.button_cancel').click();
  await expect(page.locator('#tbl_records tbody tr:has(#record_type)')).toHaveCount(0);

  await page.getByRole('button', { name: /Add Record/i }).click();
  const savedEditRow = page.locator('#tbl_records tbody tr:has(#record_type)');
  const recordName = `browser-${testInfo.project.name}`;
  await savedEditRow.locator('#edit-row-focus').fill(recordName);
  await savedEditRow.locator('#current_edit_record_data').fill('192.0.2.20');
  await savedEditRow.locator('.button_save').click();
  await expect(page.locator('#tbl_records tbody tr:has(#record_type)')).toHaveCount(0);

  const savedRow = page.locator('#tbl_records tbody tr').filter({ hasText: recordName });
  await expect(savedRow).toHaveCount(1);
  await expect(savedRow).toContainText('192.0.2.20');

  const tableSearch = page.locator('#tbl_records_wrapper .dt-search input');
  await tableSearch.fill('no matching record');
  await expect(savedRow).toHaveCount(0);
  await page.getByRole('button', { name: /Add Record/i }).click();
  await expect(tableSearch).toHaveValue('');
  const replacementEditRow = page.locator('#tbl_records tbody tr:has(#record_type)');
  await expect(replacementEditRow).toHaveCount(1);
  await replacementEditRow.locator('.button_cancel').click();

  const pageOverflow = await page.evaluate(() => (
    document.documentElement.scrollWidth - document.documentElement.clientWidth
  ));
  expect(pageOverflow).toBeLessThanOrEqual(1);
});

test('dashboard v2 table controls search, sort, page, and fit on mobile', async ({ page }) => {
  const zones = Array.from({ length: 12 }, (_, index) => {
    const name = `table-${String(index + 1).padStart(2, '0')}.example`;
    return {
      id: index + 1,
      name,
      dnssec: false,
      type: 'Master',
      serial: 100 + index,
      notifiedSerial: 100 + index,
      primary: '',
      account: 'Browser Test',
      permissions: {
        manageZone: true,
        viewHistory: true,
        removeZone: true,
        manageDnssec: true,
      },
      urls: {
        records: `/domain/${name}`,
        settings: `/domain/${name}/setting`,
        changelog: `/domain/${name}/changelog`,
        remove: '/domain/remove',
        dnssecEnableV2: `/dashboard/v2/dnssec/${name}/enable`,
        dnssecStatusV2: `/dashboard/v2/dnssec/${name}/status`,
      },
    };
  });

  await page.route(/\/dashboard\/v2\/domains\/forward(?:\?.*)?$/, async (route) => {
    const requestUrl = new URL(route.request().url());
    const search = (requestUrl.searchParams.get('search[value]') || '').toLowerCase();
    const sortColumn = Number(requestUrl.searchParams.get('order[0][column]') || 0);
    const sortDirection = requestUrl.searchParams.get('order[0][dir]') || 'asc';
    const sortFields = ['name', 'dnssec', 'type', 'serial', 'primary', 'account'];
    const sortField = sortFields[sortColumn] || 'name';
    const filteredZones = zones
      .filter((zone) => zone.name.toLowerCase().includes(search))
      .sort((left, right) => {
        const leftValue = left[sortField];
        const rightValue = right[sortField];
        const comparison = typeof leftValue === 'string'
          ? leftValue.localeCompare(rightValue)
          : Number(leftValue) - Number(rightValue);
        return sortDirection === 'desc' ? -comparison : comparison;
      });
    const start = Number(requestUrl.searchParams.get('start') || 0);
    const length = Number(requestUrl.searchParams.get('length') || 10);

    await route.fulfill({
      json: {
        draw: Number(requestUrl.searchParams.get('draw') || 0),
        recordsTotal: zones.length,
        recordsFiltered: filteredZones.length,
        data: filteredZones.slice(start, start + length),
      },
    });
  });

  await page.goto('/dashboard/v2/', { waitUntil: 'networkidle' });

  const table = page.locator('#tbl_domain_list_forward_v2');
  await expect(table).toBeVisible();
  const toolbar = page.locator('#tab_forward_v2 .dashboard-v2-table-toolbar');
  const footer = page.locator('#tab_forward_v2 .dashboard-v2-table-footer');
  const search = toolbar.getByRole('searchbox', { name: 'Search zones' });
  const pageLength = toolbar.getByRole('combobox', { name: 'Rows per page' });
  await expect(search).toHaveAttribute(
    'placeholder',
    'Search zones — use ^ and $ for start and end',
  );
  await expect(pageLength).toBeVisible();
  await pageLength.selectOption('10');
  await expect(table.locator('tbody tr')).toHaveCount(10);
  await expect(footer).toContainText(/Showing 1.*10 of 12 zones/);
  await expect(footer.getByText('Next', { exact: true })).toBeVisible();

  await footer.getByText('Next', { exact: true }).click();
  await expect(table.locator('tbody tr')).toHaveCount(2);
  await expect(footer).toContainText(/Showing 11.*12 of 12 zones/);
  await footer.getByText('Prev', { exact: true }).click();
  await expect(table.locator('tbody tr')).toHaveCount(10);

  await pageLength.selectOption('25');
  await expect(table.locator('tbody tr')).toHaveCount(12);
  await expect(footer).toContainText('Showing 12 of 12 zones');

  await table.locator('thead th').nth(0).click();
  await expect(table.locator('tbody tr').first()).toContainText('table-12.example');
  await table.locator('thead th').nth(0).click();
  await expect(table.locator('tbody tr').first()).toContainText('table-01.example');
  const sortIndicator = await table.locator('thead th').nth(0).evaluate(
    (header) => getComputedStyle(header.querySelector('.dt-column-order'), '::after').content,
  );
  expect(sortIndicator).toBe('"↑"');
  await table.locator('thead th').nth(0).click();
  await expect(table.locator('tbody tr').first()).toContainText('table-12.example');
  const descendingIndicator = await table.locator('thead th').nth(0).evaluate(
    (header) => getComputedStyle(header.querySelector('.dt-column-order'), '::after').content,
  );
  expect(descendingIndicator).toBe('"↓"');

  await search.fill('table-11');
  await expect(table.locator('tbody tr')).toHaveCount(1);
  await expect(table.locator('tbody tr').first()).toContainText('table-11.example');
  await expect(footer).toContainText('Showing 1 of 1 zones');

  await page.setViewportSize({ width: 390, height: 844 });
  await expect(toolbar.getByRole('searchbox', { name: 'Search zones' })).toBeVisible();
  await expect(toolbar.getByRole('combobox', { name: 'Rows per page' })).toBeVisible();
  await expect(footer).toContainText('Showing 1 of 1 zones');
  await expect(
    page.locator('#tab_forward_v2 .dt-layout-table'),
  ).toHaveCSS('overflow-x', 'auto');
  const horizontalOverflow = await page.evaluate(() => (
    document.documentElement.scrollWidth - document.documentElement.clientWidth
  ));
  expect(horizontalOverflow).toBeLessThanOrEqual(1);
});

test('theme toggle switches between auto, light, and dark modes', async ({ page }) => {
  await page.goto('/dashboard/', { waitUntil: 'networkidle' });
  await page.evaluate(() => window.localStorage.removeItem('lte-theme'));
  await page.reload({ waitUntil: 'networkidle' });

  const toggleButton = page.locator('[data-theme-toggle]');
  const getExpectedTheme = async (theme) => {
    if (theme === 'auto') {
      return page.evaluate(() => (
        window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
      ));
    }
    return theme;
  };

  for (const theme of ['auto', 'light', 'dark']) {
    await toggleButton.click();
    const option = page.locator(`[data-theme-option="${theme}"]`);
    await expect(option).toBeVisible();
    await option.click();

    const expectedTheme = await getExpectedTheme(theme);
    await expect(page.locator('html')).toHaveAttribute('data-bs-theme', expectedTheme);
    await expect(option).toHaveAttribute('aria-pressed', 'true');

    for (const optionTheme of ['auto', 'light', 'dark']) {
      const state = await page.locator(`[data-theme-option="${optionTheme}"]`).getAttribute('aria-pressed');
      expect(state).toBe(optionTheme === theme ? 'true' : 'false');
    }

    await expect.poll(async () => page.evaluate(() => window.localStorage.getItem('lte-theme'))).toBe(theme);
  }
});

test('creates and submits project-specific core DNS records', async ({ page, request }, testInfo) => {
  test.setTimeout(90_000);
  const failures = collectBrowserFailures(page);
  const projectName = testInfo.project.name;
  const records = [
    { name: `${projectName}-A`, type: 'A', value: '192.0.2.10' },
    { name: `${projectName}-AAAA`, type: 'AAAA', value: '2001:db8::10' },
    {
      name: `${projectName}-TXT`,
      type: 'TXT',
      value: `PowerDNS-Admin browser test for ${projectName}`,
    },
    {
      name: `${projectName}-CNAME`,
      type: 'CNAME',
      value: `${TEST_ZONE}.`,
    },
    {
      name: `${projectName}-CAA`,
      type: 'CAA',
      flag: '0',
      tag: 'issue',
      value: 'letsencrypt.org',
    },
  ];

  await removeExistingRecords(request, records);
  await page.goto(`/domain/${TEST_ZONE}`, { waitUntil: 'networkidle' });

  for (const record of records) {
    await test.step(`create ${record.name}`, async () => {
      await addRecord(page, record);
      await captureStep(page, testInfo, `${record.name}-saved`);
    });
  }

  const banner = page.locator('#unsaved-changes-banner');
  await expect(banner).toBeVisible();

  await page.evaluate(() => {
    const spacer = document.createElement('div');
    spacer.dataset.browserTestSpacer = 'true';
    spacer.style.height = '2000px';
    document.querySelector('#zone-editor-card').after(spacer);

    const appMain = document.querySelector('.app-main');
    if (appMain && appMain.scrollHeight > appMain.clientHeight) {
      appMain.scrollTo(0, appMain.scrollHeight);
    } else {
      window.scrollTo(0, document.body.scrollHeight);
    }
  });
  await expect(banner).toBeVisible();
  await expect(banner).toHaveClass(/is-floating/);
  const floatingPosition = await banner.evaluate((element) => ({
    position: getComputedStyle(element).position,
    top: element.getBoundingClientRect().top,
  }));
  expect(floatingPosition.position).toBe('fixed');
  expect(floatingPosition.top).toBeGreaterThanOrEqual(0);
  await banner.getByRole('button', { name: 'Review Changes' }).click();
  const reviewModal = page.locator('#modal_review_changes');
  await expect(reviewModal).toBeVisible();
  await expect(reviewModal.locator('#review-changes-body tr')).not.toHaveCount(0);
  await reviewModal.locator('.modal-footer').getByRole('button', { name: 'Close' }).click();
  await expect(banner).toHaveClass(/is-floating/);

  const applyResponsePromise = page.waitForResponse(
    (response) => response.url().includes(`/domain/${TEST_ZONE}/apply`)
      && response.request().method() === 'POST',
  );
  await banner.getByRole('button', { name: 'Apply Changes' }).click();
  await expect(page.locator('#modal_apply_changes')).toBeVisible();
  await page.locator('#button_apply_confirm').click();

  const applyResponse = await applyResponsePromise;
  expect(applyResponse.ok()).toBeTruthy();
  await expect(page.locator('#modal_success')).toBeVisible();
  await page.waitForTimeout(2_500);
  await page.waitForLoadState('networkidle');
  await captureStep(page, testInfo, `${projectName}-submitted`);

  const zoneResponse = await request.get(
    `${PDNS_API_URL}/api/v1/servers/localhost/zones/${TEST_ZONE}.`,
    { headers: pdnsHeaders },
  );
  expect(zoneResponse.ok()).toBeTruthy();
  const zone = await zoneResponse.json();

  for (const record of records) {
    const expectedName = `${record.name}.${TEST_ZONE}.`.toLowerCase();
    const rrset = zone.rrsets.find(
      (candidate) => candidate.name.toLowerCase() === expectedName
        && candidate.type === record.type,
    );
    expect(rrset, `${record.name} should have been submitted`).toBeTruthy();
    expect(rrset.records.some((candidate) => candidate.disabled === false)).toBeTruthy();
  }

  expect(failures, failures.join('\n')).toEqual([]);
});

test('operator cannot promote users or operators to Administrator', async ({
  browser,
  consoleAudit,
  playwright,
}, testInfo) => {
  test.setTimeout(90_000);
  const operatorContext = await browser.newContext({
    baseURL: process.env.BASE_URL || 'http://powerdns-admin',
    colorScheme: testInfo.project.use.colorScheme,
    storageState: {
      cookies: [],
      origins: [],
    },
  });
  await operatorContext.clearCookies();
  const page = await operatorContext.newPage();
  consoleAudit.monitorPage(page);
  consoleAudit.expectMessage(
    'Failed to load resource: the server responded with a status of 400 (BAD REQUEST)',
    { type: 'error' },
  );
  const failures = collectBrowserFailures(page);
  const operator = ROLE_SECURITY_USERS.operator;
  const operatorHeaders = basicAuthHeaders(operator.username, operator.password);
  const operatorApi = await playwright.request.newContext({
    baseURL: process.env.BASE_URL || 'http://powerdns-admin',
    extraHTTPHeaders: operatorHeaders,
    storageState: {
      cookies: [],
      origins: [],
    },
  });
  const administrator = await getApiUser(
    operatorApi, ADMIN_USERNAME, operatorHeaders,
  );

  for (const target of ROLE_SECURITY_USERS.targets) {
    const targetUser = await getApiUser(
      operatorApi, target.username, operatorHeaders,
    );

    for (const rolePayload of [
      { role_name: 'Administrator' },
      { role_id: administrator.role.id },
    ]) {
      const response = await operatorApi.put(
        `/api/v1/pdnsadmin/users/${targetUser.id}`,
        {
          headers: operatorHeaders,
          data: rolePayload,
        },
      );
      expect(response.status()).toBe(401);
    }

    await assertApiRole(
      operatorApi, target.username, target.roleName, operatorHeaders,
    );
  }

  await page.goto('/login');
  await page.getByRole('textbox', { name: 'Username' }).fill(operator.username);
  await page.locator('input[name="password"]').fill(operator.password);
  await Promise.all([
    page.waitForURL(/\/dashboard\//, { waitUntil: 'networkidle' }),
    page.getByRole('button', { name: 'Sign In' }).click(),
  ]);

  await page.goto('/admin/manage-user', { waitUntil: 'networkidle' });
  for (const target of ROLE_SECURITY_USERS.targets) {
    const roleSelector = page.locator(`select#${target.username}`);
    await expect(roleSelector).toBeVisible();
    await expect(
      roleSelector.locator('option[value="Administrator"]'),
    ).toHaveCount(0);
  }
  await captureStep(
    page,
    testInfo,
    `${testInfo.project.name}-operator-role-options`,
  );

  for (const target of ROLE_SECURITY_USERS.targets) {
    const roleResponsePromise = page.waitForResponse(
      (response) => response.url().includes('/admin/manage-user')
        && response.request().method() === 'POST',
    );
    await page.locator(`select#${target.username}`).evaluate((select) => {
      const administratorOption = document.createElement('option');
      administratorOption.value = 'Administrator';
      administratorOption.textContent = 'Administrator';
      select.append(administratorOption);
      select.value = 'Administrator';
      select.dispatchEvent(new Event('change', { bubbles: true }));
    });

    const roleResponse = await roleResponsePromise;
    expect(roleResponse.status()).toBe(400);
    await expect(page.locator('#modal_error')).toBeVisible();
    await expect(page.locator('#modal_error .modal-body')).toContainText(
      'promote a user to Administrator',
    );
    await captureStep(
      page,
      testInfo,
      `${testInfo.project.name}-${target.roleName.toLowerCase()}-promotion-blocked`,
    );
    await page.locator('#modal_error .modal-footer .btn-secondary').click();
    await expect(page.locator('#modal_error')).toBeHidden();

    await assertApiRole(
      operatorApi, target.username, target.roleName, operatorHeaders,
    );
    await page.reload({ waitUntil: 'networkidle' });
  }

  await operatorApi.dispose();
  await operatorContext.close();
  expect(failures, failures.join('\n')).toEqual([]);
});
