const express = require('express');
const crypto = require('crypto');
const dotenv = require('dotenv');
const fetch = require('node-fetch');

const { createPKCECodes } = require('./pkce');
const { renderTemplate } = require('./templates');

dotenv.config();

const REQUIRED_VARS = ['CLIENT_ID', 'REDIRECT_URI'];
REQUIRED_VARS.forEach((name) => {
  if (!process.env[name]) {
    throw new Error(`Missing required environment variable: ${name}`);
  }
});

const config = {
  clientId: process.env.CLIENT_ID,
  clientSecret: process.env.CLIENT_SECRET || '',
  redirectUri: process.env.REDIRECT_URI,
  baseUrl: process.env.NAQOOD_BASE_URL || 'https://app.naqood.ae',
  port: Number(process.env.PORT || 4001),
};

const ROLE_OPTIONS = [
  {
    value: 'admin',
    label: 'Administrator',
    description: 'Full access to organization resources.',
  },
  {
    value: 'member',
    label: 'Member',
    description: 'Basic organization member access and ability to create purchases.',
  },
  {
    value: 'accountant',
    label: 'Accountant',
    description: 'View financial reports and create journal entries.',
  },
  {
    value: 'billing',
    label: 'Billing Admin',
    description: 'Manage billing settings and subscription.',
  },
  {
    value: 'sales',
    label: 'Sales Person',
    description: 'View invoices and create sales orders.',
  },
];

const ROLE_LOOKUP = new Map(ROLE_OPTIONS.map((role) => [role.value, role]));

const PURCHASE_ACCOUNT_CODES = [1310, 1320];
const STATE_TTL_MS = 10 * 60 * 1000; // 10 minutes
const pendingStates = new Map();
let latestCredential = null;
let lastRequestedRole = ROLE_OPTIONS[0].value;

function resolveRole(value) {
  if (!value) {
    return ROLE_OPTIONS[0].value;
  }
  const normalized = String(value).trim().toLowerCase();
  return ROLE_LOOKUP.has(normalized) ? normalized : ROLE_OPTIONS[0].value;
}

function getRoleMeta(value) {
  return ROLE_LOOKUP.get(value) || ROLE_LOOKUP.get(ROLE_OPTIONS[0].value);
}

function getActiveRole() {
  return latestCredential?.requestedRole || lastRequestedRole || ROLE_OPTIONS[0].value;
}

function saveState(state, verifier, requestedRole) {
  pendingStates.set(state, { verifier, requestedRole, createdAt: Date.now() });
}

function consumeState(state) {
  const entry = pendingStates.get(state);
  pendingStates.delete(state);
  if (!entry) return null;
  if (Date.now() - entry.createdAt > STATE_TTL_MS) {
    return null;
  }
  return entry;
}

function buildAuthorizeUrl(state, challenge, role) {
  const authorizeUrl = new URL('/oauth/authorize', config.baseUrl);
  authorizeUrl.searchParams.set('client_id', config.clientId);
  authorizeUrl.searchParams.set('redirect_uri', config.redirectUri);
  authorizeUrl.searchParams.set('role', role);
  authorizeUrl.searchParams.set('code_challenge', challenge);
  authorizeUrl.searchParams.set('code_challenge_method', 'S256');
  authorizeUrl.searchParams.set('state', state);
  return authorizeUrl.toString();
}

async function exchangeAuthorizationCode(code, verifier) {
  const tokenUrl = new URL('/api/oauth/token', config.baseUrl);
  const response = await fetch(tokenUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      grantType: 'authorization_code',
      code,
      clientId: config.clientId,
      clientSecret: config.clientSecret || undefined,
      redirectUri: config.redirectUri,
      codeVerifier: verifier,
    }),
  });

  const payload = await response.json();
  if (!response.ok) {
    const error =
      payload?.error_description || payload?.error || 'token_exchange_failed';
    throw new Error(`Token exchange failed: ${error}`);
  }
  if (!payload.secretKey) {
    throw new Error('Token response did not include secretKey');
  }
  return {
    secretKey: payload.secretKey,
    organizationSlug: payload.organizationSlug || null,
    tokenType: payload.tokenType || 'Bearer',
  };
}

async function fetchOrganization(secretKey, organizationSlug) {
  if (!organizationSlug) {
    return null;
  }

  const graphqlUrl = new URL('/graphql', config.baseUrl);
  const query = `
    query GetOrganization($slug: Slug!) {
      organization(slug: $slug) {
        id
        slug
        name
        plan
        createdAt
      }
    }
  `;

  const response = await fetch(graphqlUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${secretKey}`,
    },
    body: JSON.stringify({
      query,
      variables: { slug: organizationSlug },
    }),
  });

  const payload = await response.json();
  if (!response.ok || payload.errors) {
    const errorMessage =
      payload?.errors?.[0]?.message || 'GraphQL query failed';
    throw new Error(errorMessage);
  }
  return payload.data.organization;
}

function maskSecret(secret) {
  if (!secret) return 'n/a';
  if (secret.length <= 12) return secret;
  return `${secret.slice(0, 6)}…${secret.slice(-4)}`;
}

function escapeHtml(value) {
  if (value === undefined || value === null) {
    return '';
  }
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function buildRoleCards(activeRole) {
  return ROLE_OPTIONS.map((role) => {
    const isActive = role.value === activeRole;
    const selectedTag = isActive
      ? '<span class="role-card__tag">Selected</span>'
      : '';
    const startLink = `/auth/start?role=${encodeURIComponent(role.value)}`;
    return `
      <li class="role-card${isActive ? ' role-card--active' : ''}">
        <div class="role-card__header">
          <div>
            <strong>${escapeHtml(role.label)}</strong>
            <span class="role-card__slug">${escapeHtml(role.value)}</span>
          </div>
          ${selectedTag}
        </div>
        <p>${escapeHtml(role.description)}</p>
        <a class="btn secondary" href="${escapeHtml(startLink)}">Use ${escapeHtml(role.label)}</a>
      </li>
    `;
  }).join('');
}

async function createBankIngestTransactions(secretKey, slug, transactions) {
  const graphqlUrl = new URL('/graphql', config.baseUrl);
  const mutation = `
    mutation CreateBankIngests($input: CreateBankIngestBulkInput!) {
      createBankIngestBulk(input: $input) {
        bankIngests {
          id
          amount
          currency
          description
          transactionDate
          reconciled
          matchType
          note
          bankAccount {
            id
            name
          }
        }
      }
    }
  `;

  const response = await fetch(graphqlUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${secretKey}`,
    },
    body: JSON.stringify({
      query: mutation,
      variables: {
        input: {
          slug,
          transactions,
        },
      },
    }),
  });

  const payload = await response.json();
  if (!response.ok || payload.errors) {
    const message = payload?.errors?.[0]?.message || 'Bank ingest mutation failed';
    throw new Error(message);
  }

  return payload.data.createBankIngestBulk.bankIngests;
}

function renderBankIngestPage({
  slug,
  formValues = {},
  result,
  errorMessage,
  roleValue,
} = {}) {
  const defaults = {
    currency: 'AED',
    accountCode: String(PURCHASE_ACCOUNT_CODES[0]),
    transactionDate: new Date().toISOString().slice(0, 10),
  };
  const values = { ...defaults, ...formValues };
  const disabled = !slug;
  const activeRole = roleValue || getActiveRole();
  const roleStartLink = `/auth/start?role=${encodeURIComponent(activeRole)}`;
  const escapedRoleLink = escapeHtml(roleStartLink);
  const activeRoleMeta = getRoleMeta(activeRole);
  const escapedRoleLabel = escapeHtml(activeRoleMeta.label);
  const statusBlock = disabled
    ? `<div class="callout warning"><p>Run the OAuth flow to capture a secret and organization slug before creating bank ingests.</p><div class="mini-nav"><a href="${escapedRoleLink}">Start OAuth with ${escapedRoleLabel} →</a><a href="/">Back to overview →</a></div></div>`
    : `<div class="callout success"><strong>Using organization slug</strong> <code>${escapeHtml(slug)}</code>. Secrets stay in memory until you restart this server.</div>`;
  const errorBlock = errorMessage
    ? `<div class="callout danger"><strong>Request failed:</strong> ${escapeHtml(errorMessage)}</div>`
    : '';
  const resultBlock = result
    ? `<section class="result-panel"><header>Latest ingest response</header><pre class="code-block">${escapeHtml(JSON.stringify(result, null, 2))}</pre><div class="mini-nav"><a href="/bank-ingest">Create another ingest →</a><a href="/">Back to overview →</a></div></section>`
    : '';
  const accountOptions = PURCHASE_ACCOUNT_CODES.map((code) => {
    const selected = String(values.accountCode) === String(code) ? ' selected' : '';
    return `<option value="${code}"${selected}>Purchase account ${code}</option>`;
  }).join('');

  return renderTemplate('bank-ingest', {
    statusBlock,
    errorBlock,
    resultBlock,
    fieldsetDisabled: disabled ? 'disabled' : '',
    bankAccountId: escapeHtml(values.bankAccountId || ''),
    amount: escapeHtml(values.amount || ''),
    currency: escapeHtml(values.currency || ''),
    description: escapeHtml(values.description || ''),
    foreignId: escapeHtml(values.foreignId || ''),
    transactionDate: escapeHtml(values.transactionDate || ''),
    note: escapeHtml(values.note || ''),
    accountOptions,
    roleStartLink: escapedRoleLink,
  });
}

const app = express();
app.use(express.urlencoded({ extended: false }));

app.get('/', (req, res) => {
  const issuedAt = latestCredential ? latestCredential.issuedAt : null;
  const issuedText = issuedAt
    ? ` (issued ${new Date(issuedAt).toLocaleTimeString()})`
    : '';
  const secretSummary = latestCredential
    ? `${maskSecret(latestCredential.secretKey)}${issuedText}`
    : 'none yet';
  const slugSummary =
    latestCredential && latestCredential.organizationSlug
      ? latestCredential.organizationSlug
      : 'not set yet';
  const currentRoleValue = getActiveRole();
  const currentRoleMeta = getRoleMeta(currentRoleValue);
  const roleSummary = `${currentRoleMeta.label} (${currentRoleMeta.value})`;
  const roleCards = buildRoleCards(currentRoleValue);
  const roleStartLink = `/auth/start?role=${encodeURIComponent(currentRoleValue)}`;

  res
    .type('html')
    .send(
      renderTemplate('home', {
        roleSummary: escapeHtml(roleSummary),
        slugSummary: escapeHtml(slugSummary),
        secretSummary: escapeHtml(secretSummary),
        roleCards,
        roleStartLink: escapeHtml(roleStartLink),
      }),
    );
});

app.get('/auth/start', (req, res) => {
  const requestedRole = resolveRole(req.query.role);
  const { verifier, challenge } = createPKCECodes();
  const state = crypto.randomBytes(16).toString('hex');
  lastRequestedRole = requestedRole;
  saveState(state, verifier, requestedRole);
  const redirectUrl = buildAuthorizeUrl(state, challenge, requestedRole);
  res.redirect(302, redirectUrl);
});

app.get('/auth/callback', async (req, res) => {
  const { code, state, error, error_description: errorDescription } = req.query;
  if (error) {
    return res
      .status(400)
      .send(`Authorization failed: ${errorDescription || error}`);
  }
  if (!code || !state) {
    return res.status(400).send('Missing code or state');
  }

  const stateEntry = consumeState(state);
  if (!stateEntry) {
    return res
      .status(400)
      .send('Unknown or expired state parameter. Restart the flow.');
  }

  const { verifier, requestedRole } = stateEntry;

  try {
    const tokenResult = await exchangeAuthorizationCode(code, verifier);
    latestCredential = {
      secretKey: tokenResult.secretKey,
      organizationSlug: tokenResult.organizationSlug,
      tokenType: tokenResult.tokenType,
      issuedAt: Date.now(),
      requestedRole: requestedRole || ROLE_OPTIONS[0].value,
    };

    let orgPayload = null;
    if (latestCredential.organizationSlug) {
      try {
        orgPayload = await fetchOrganization(
          latestCredential.secretKey,
          latestCredential.organizationSlug,
        );
      } catch (orgError) {
        orgPayload = { error: orgError.message };
      }
    } else {
      orgPayload = {
        note: 'Token response did not include organizationSlug. Update the Naqood server before retrying.',
      };
    }

    const roleStartLink = `/auth/start?role=${encodeURIComponent(getActiveRole())}`;
    res
      .type('html')
      .send(
        renderTemplate('callback', {
          maskedSecret: escapeHtml(maskSecret(latestCredential.secretKey)),
          organizationSlug: escapeHtml(
            latestCredential.organizationSlug || 'not provided',
          ),
          organizationPayload: escapeHtml(JSON.stringify(orgPayload, null, 2)),
          roleStartLink: escapeHtml(roleStartLink),
        }),
      );
  } catch (tokenError) {
    res.status(500).send(`Token exchange failed: ${tokenError.message}`);
  }
});

app.get('/org', async (req, res) => {
  if (!latestCredential) {
    return res.status(400).send('Run the OAuth flow first to obtain a secret.');
  }
  if (!latestCredential.organizationSlug) {
    return res
      .status(400)
      .send('No organization slug available yet. Re-run the OAuth flow.');
  }
  try {
    const organization = await fetchOrganization(
      latestCredential.secretKey,
      latestCredential.organizationSlug,
    );
    res.json({ organization });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/bank-ingest', (req, res) => {
  const slug = latestCredential?.organizationSlug || null;
  res.type('html').send(
    renderBankIngestPage({
      slug,
      roleValue: getActiveRole(),
    }),
  );
});

app.post('/bank-ingest', async (req, res) => {
  const slug = latestCredential?.organizationSlug;
  if (!latestCredential || !slug) {
    return res
      .status(400)
      .type('html')
      .send(
        renderBankIngestPage({
          slug: null,
          formValues: req.body,
          errorMessage: 'Run the OAuth flow first so we have a secret and organization.',
          roleValue: getActiveRole(),
        }),
      );
  }

  const secretKey = latestCredential.secretKey;
  const {
    bankAccountId,
    amount,
    currency,
    description,
    foreignId,
    transactionDate,
    note,
    accountCode,
  } = req.body;

  if (!bankAccountId || !amount || !currency) {
    return res
      .status(400)
      .type('html')
      .send(
        renderBankIngestPage({
          slug,
          formValues: req.body,
          errorMessage: 'bankAccountId, amount, and currency are required.',
          roleValue: getActiveRole(),
        }),
      );
  }

  const parsedAccountCode = Number(accountCode);
  if (!PURCHASE_ACCOUNT_CODES.includes(parsedAccountCode)) {
    return res
      .status(400)
      .type('html')
      .send(
        renderBankIngestPage({
          slug,
          formValues: req.body,
          errorMessage: 'Account code must be 1310 or 1320 for purchases.',
          roleValue: getActiveRole(),
        }),
      );
  }

  const transaction = {
    bankAccountId: bankAccountId.trim(),
    amount: amount.trim(),
    currency: currency.trim().toUpperCase(),
    description: description?.trim() || undefined,
    foreignId: foreignId?.trim() || undefined,
    transactionDate: transactionDate?.trim() || undefined,
    note: note?.trim() || undefined,
    accountCode: parsedAccountCode,
  };

  try {
    const result = await createBankIngestTransactions(secretKey, slug, [transaction]);
    res.type('html').send(
      renderBankIngestPage({
        slug,
        formValues: {
          currency: transaction.currency,
          accountCode: transaction.accountCode,
          transactionDate: transaction.transactionDate,
        },
        result,
        roleValue: getActiveRole(),
      }),
    );
  } catch (error) {
    res.status(500).type('html').send(
      renderBankIngestPage({
        slug,
        formValues: req.body,
        errorMessage: error.message,
        roleValue: getActiveRole(),
      }),
    );
  }
});

app.listen(config.port, () => {
  /* eslint-disable no-console */
  console.log(`Naqood OAuth demo listening on http://localhost:${config.port}`);
});
