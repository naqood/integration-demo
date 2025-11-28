# Naqood OAuth Demo App

A minimal Express application that demonstrates how to complete the Naqood OAuth 2.0 Authorization Code flow with PKCE, exchange the authorization code for an organization API secret, and call the GraphQL API using that secret.

> **Note:** This project is meant for manual testing in local or staging environments. Do not deploy it as-is to production.

## Prerequisites

- Node.js 18+
- A registered OAuth application in Naqood with a redirect URI pointing to `http://localhost:4001/auth/callback` (or whatever port you use locally).
- Access to at least one organization you can authorize during consent.

## Setup

1. Install dependencies:

```bash
cd www/oauth-demo
npm install
```

2. Copy the example environment file and fill in your credentials:

```bash
cp .env.example .env
```

Required variables:

| Variable          | Description                                                                                       |
| ----------------- | ------------------------------------------------------------------------------------------------- |
| `CLIENT_ID`       | Your OAuth client ID.                                                                             |
| `CLIENT_SECRET`   | The client secret (if issued). Leave blank only if the app truly has no secret.                   |
| `REDIRECT_URI`    | Must match one of the registered redirect URIs. Default is `http://localhost:4001/auth/callback`. |
| `NAQOOD_BASE_URL` | Base URL of the Naqood app (defaults to `https://app.naqood.ae`).                                 |
| `PORT`            | Local port for the Express server (default `4001`).                                               |

The demo includes a role picker on the home page so you can start the OAuth flow as any of the following:

- `admin` – Administrator (full organization access)
- `member` – Member (basic access + purchase creation)
- `accountant` – Accountant (reporting + journals)
- `billing` – Billing Admin (subscription and billing settings)
- `sales` – Sales Person (invoices + sales orders)

During the token exchange the server now responds with the `organizationSlug` associated with the issued secret, so you no longer need to hard-code it in the demo.

## Running the demo

```bash
npm start
```

Visit `http://localhost:4001`, pick one of the available roles, and click **Start OAuth Flow** on either the hero button or the corresponding role card. After approving the request in Naqood, you will land on `/auth/callback`, which exchanges the code for an API secret, stores it (plus the returned `organizationSlug`) in memory, and immediately fetches the organization details for you. Use the **Call GraphQL** link to re-run the sample `organization` query with the stored secret at any time.

The console logs will show helpful debug messages, but the secret itself is only kept in memory so you can manually inspect or reuse it during the session.

## Bank ingest demo

Once you have completed the OAuth flow (so the app has both a secret and an organization slug) you can click **Create purchase bank ingest (1310/1320)** on the home page. That link loads a simple form backed by the `createBankIngestBulk` mutation and includes a dropdown that locks the chart-of-accounts code to Naqood's purchase accounts **1310** and **1320**.

Steps:

1. Paste a valid `bankAccountId` that belongs to the selected organization.
2. Enter the signed amount (negative for vendor payments, positive for customer receipts) and currency.
3. Optionally add description, foreign ID (for idempotency), note, and transaction date.
4. Choose either account code 1310 or 1320 to control which purchase account the ingest pre-matches against, then submit the form.

The server will display the resulting bank ingest payload (or any API errors) inline so you can iterate quickly.

## HTML templates

All demo pages now live under `src/views` and are rendered via the lightweight helper in `src/templates.js`. Updating the HTML no longer requires touching the Express routes—just edit the corresponding template file.

## What it demonstrates

- PKCE verifier/challenge generation entirely in the client app.
- State parameter tracking to prevent replay.
- Token exchange via `POST /api/oauth/token`.
- Using the returned secret and organization slug as a Bearer token source for GraphQL queries.
- Basic error handling and cleanup of pending authorization requests.

## Cleanup

The demo stores secrets and state in memory only. Restarting the process clears all pending data. Revoke secrets directly inside Naqood when you are done testing.
