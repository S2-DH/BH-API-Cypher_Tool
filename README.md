# BHE API Console v1.1

A PowerShell tool for testing BloodHound Enterprise HMAC authentication and running API calls and Cypher queries — from the command line or an interactive console.

---

## Quick Start

1. Place `.env` file in the same directory as the script (see [Credentials](#credentials) below)
2. Run:

```powershell
# Auth test only
.\BHE-API-Console.ps1

# Interactive console
.\BHE-API-Console.ps1 -Interactive

# Direct API call
.\BHE-API-Console.ps1 -API "/api/v2/available-domains"

# Direct Cypher query
.\BHE-API-Console.ps1 -Cypher 'MATCH (u:User {enabled:true, hasspn:true}) RETURN u'
```

---

## Credentials

The script loads credentials from a `.env` file in the script directory. Rename `sample.env` to `.env` and fill in your values:

```
BHE_API_ID="your-token-id"
BHE_API_KEY="your-token-key"
BHE_URL="https://<TENANT_NAME>.bloodhoundenterprise.io"
```

These values come from your BloodHound Enterprise `auth.json` file (Settings > API Tokens).

You can also specify a custom `.env` location:

```powershell
.\BHE-API-Console.ps1 -EnvFile "C:\secure\bhe-creds.env" -Interactive
```

Or pass credentials directly as parameters (overrides `.env`):

```powershell
.\BHE-API-Console.ps1 -RestEndpoint "tenant.bloodhoundenterprise.io" -TokenID "abc123" -Token "xyz789"
```

The `-RestEndpoint` parameter accepts the tenant address with or without `https://` — the script normalizes it automatically.

---

## Modes

### 1. Auth Test Only (default)

Tests connectivity and HMAC authentication against the BHE API. Useful for validating credentials are working before running queries.

```powershell
.\BHE-API-Console.ps1
```

Output:

```
  [1/2] Testing connectivity...
        [PASS] API reachable - Version: v2
  [2/2] Testing authentication...
        [PASS] Authenticated as: John Doe (john@company.com)
```

### 2. Direct API Call (`-API`)

Run a single API endpoint call and return the results.

```powershell
# GET request (default)
.\BHE-API-Console.ps1 -API "/api/v2/available-domains"

# POST request with JSON body
.\BHE-API-Console.ps1 -API "/api/v2/saved-queries" -Method "POST" -Body '{"name":"test","query":"MATCH (n) RETURN n LIMIT 1"}'

# PUT request
.\BHE-API-Console.ps1 -API "/api/v2/asset-groups/1/selectors" -Method "PUT" -Body '{"selectors":[]}'

# DELETE request
.\BHE-API-Console.ps1 -API "/api/v2/tokens/some-id" -Method "DELETE"

# With CSV export
.\BHE-API-Console.ps1 -API "/api/v2/clients" -ExportCSV "collectors.csv"
```

Supported methods: `GET`, `POST`, `PUT`, `PATCH`, `DELETE`

### 3. Direct Cypher Query (`-Cypher`)

Run a single Cypher query against the BHE graph database.

```powershell
# Simple query
.\BHE-API-Console.ps1 -Cypher 'MATCH (u:User {enabled:true}) RETURN u LIMIT 10'

# With CSV export
.\BHE-API-Console.ps1 -Cypher 'MATCH (u:User {enabled:true, hasspn:true}) RETURN u' -ExportCSV "kerberoastable.csv"
```

#### Handling Quotes in Cypher Queries

When running Cypher from the command line, use **single quotes** to wrap the query so inner double quotes are treated literally:

```powershell
.\BHE-API-Console.ps1 -Cypher 'MATCH (u:User) WHERE u.name ENDS WITH "CORP.LOCAL" RETURN u'
```

If the query contains both quote types, use backtick escaping:

```powershell
.\BHE-API-Console.ps1 -Cypher "MATCH (u:User {name:`"ADMIN@CORP.LOCAL`"}) RETURN u"
```

For long or complex queries, use **Interactive mode** instead — the `CYPHER>` prompt has no shell quoting layer so you can paste queries raw.

### 4. Interactive Mode (`-Interactive`)

Drops into a menu-driven console after authentication. Best for exploratory work, complex queries, and avoiding quoting issues.

```powershell
.\BHE-API-Console.ps1 -Interactive
```

Menu options:

| Option | Description |
|--------|-------------|
| **1** | Freeform Cypher query — paste any query at the `CYPHER>` prompt, no quoting needed |
| **2** | Freeform API call — enter endpoint, method, and body at prompts |
| **3** | Query Library — browse and run 20+ pre-built queries by number |
| **4** | Quick Info — shows API version, authenticated user, and available domains |
| **Q** | Quit |

Every result offers an optional CSV export prompt.

---

## Query Library

The built-in query library (Interactive mode, option 3) includes pre-built queries organized by category:

### Tier Zero
| # | Query | Description |
|---|-------|-------------|
| 1 | All Tier Zero Objects | List all T0 / High Value assets |
| 2 | Tier Zero Users | T0 user accounts |
| 3 | Tier Zero Groups | T0 groups |
| 4 | Tier Zero Computers | T0 computers (DCs, etc.) |

### Users
| # | Query | Description |
|---|-------|-------------|
| 5 | Enabled Users (Sample) | First 25 enabled users |
| 6 | Kerberoastable Users | Users with SPNs set |
| 7 | AS-REP Roastable Users | Users without Kerberos preauth |
| 8 | Unconstrained Delegation Users | Users trusted for unconstrained delegation |

### Computers
| # | Query | Description |
|---|-------|-------------|
| 9 | Unconstrained Delegation Computers | Non-DC computers with unconstrained delegation |
| 10 | Domain Controllers | All DC computers |

### Attack Paths
| # | Query | Description |
|---|-------|-------------|
| 11 | Shortest Path to Domain Admins | Paths from non-T0 users to DA |
| 12 | Users with DCSync Rights | Non-T0 principals with DCSync |

### Sessions
| # | Query | Description |
|---|-------|-------------|
| 13 | Active Sessions (Sample) | Recent session relationships |

### API Endpoints
| # | Endpoint | Description |
|---|----------|-------------|
| 14 | Available Domains | Domains collected in BHE |
| 15 | API Version | BHE API version |
| 16 | Self (Whoami) | Current authenticated user |
| 17 | Asset Groups | All asset groups |
| 18 | Audit Logs | Recent audit entries |
| 19 | Data Posture Stats | Posture statistics |
| 20 | List Clients | Registered SharpHound/AzureHound collectors |
| 21 | File Upload Jobs | Recent upload jobs |

---

## Parameters Reference

| Parameter | Required | Description |
|-----------|----------|-------------|
| `-EnvFile` | No | Path to `.env` credentials file (default: `.env` in script directory) |
| `-RestEndpoint` | No* | BHE tenant URL — overrides `BHE_URL` from `.env` |
| `-TokenID` | No* | API Token ID — overrides `BHE_API_ID` from `.env` |
| `-Token` | No* | API Token Key — overrides `BHE_API_KEY` from `.env` |
| `-API` | No | API endpoint path for direct call (e.g., `/api/v2/available-domains`) |
| `-Method` | No | HTTP method for `-API` calls: GET, POST, PUT, PATCH, DELETE (default: GET) |
| `-Body` | No | JSON request body for POST/PUT/PATCH calls |
| `-Cypher` | No | Cypher query string for direct execution |
| `-Interactive` | No | Launch the interactive console |
| `-ExportCSV` | No | Export results to CSV file path |

*\*Required either via `.env` file or parameters. Parameters override `.env` values.*

---

## CSV Export

Export is available in all modes:

```powershell
# Command line
.\BHE-API-Console.ps1 -API "/api/v2/available-domains" -ExportCSV "domains.csv"
.\BHE-API-Console.ps1 -Cypher 'MATCH (u:User {hasspn:true}) RETURN u' -ExportCSV "kerberoastable.csv"

# Interactive mode — prompted after each query result
Export to CSV? (enter file path or press Enter to skip): C:\reports\t0-users.csv
```

---

## Authentication

The script uses **3-step chained HMAC-SHA256** authentication matching the BHE API specification:

1. `HMAC(token_key, METHOD + ENDPOINT)` → hash1
2. `HMAC(hash1, DateKey)` → hash2 (DateKey = first 13 chars of timestamp)
3. `HMAC(hash2, Body)` → signature (Base64 encoded)

Headers sent with every request:

```
Authorization: bhesignature <token_id>
RequestDate:   <RFC3339 timestamp>
Signature:     <base64 HMAC signature>
Content-Type:  application/json
```

The signature includes the request body in Step 3, so POST/PUT requests are signed correctly.

---

## Troubleshooting

### Authentication Fails

- **Verify credentials** — Check `BHE_API_ID` and `BHE_API_KEY` in your `.env` match `auth.json`
- **Token expired** — Generate a new API token in BHE (Settings > API Tokens)
- **Clock skew** — HMAC is time-sensitive. Ensure system clock is accurate (`w32tm /query /status`)
- **URL format** — The script accepts `tenant.bloodhoundenterprise.io` or `https://tenant.bloodhoundenterprise.io`

### Connectivity Fails

- **DNS resolution** — Verify `nslookup tenant.bloodhoundenterprise.io` resolves
- **Firewall/Proxy** — Ensure HTTPS (443) is open to `*.bloodhoundenterprise.io`
- **TLS** — BHE requires TLS 1.2+. Check: `[Net.ServicePointManager]::SecurityProtocol`

### Cypher Query Errors

- **Quoting at command line** — Use single quotes to wrap queries, or use Interactive mode
- **Empty results** — Verify data has been collected for the target domain
- **Syntax errors** — Test queries in the BHE UI first, then paste into the console

---

## Files

| File | Description |
|------|-------------|
| `BHE-API-Console.ps1` | Main script |
| `.env` | Credentials file (create from `sample.env`) |
| `sample.env` | Template credentials file |
| `README.md` | This file |

---

## Requirements

- PowerShell 5.1+ (Windows) or PowerShell 7+ (cross-platform)
- Network access to your BHE tenant
- BHE API token (Token ID + Token Key)
