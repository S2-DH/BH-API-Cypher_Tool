[README.md](https://github.com/user-attachments/files/25375967/README.md)
# BHE-API-Console.ps1

A PowerShell interactive console for BloodHound Enterprise, providing HMAC-authenticated API access, a Cypher query engine, and pre-built query libraries.

## Requirements

- PowerShell 5.1+ (Windows) or PowerShell 7+ (Cross-platform)
- BloodHound Enterprise API credentials (Token ID + Token Key)
- Network access to your BHE tenant URL

## Setup

1. Create a `.env` file in the same directory as the script:

```
BHE_URL=https://yourtenant.bloodhoundenterprise.io
BHE_API_ID=your-token-id
BHE_API_KEY=your-token-key
```

2. Run the script:

```powershell
.\BHE-API-Console.ps1 -Interactive
```

## Authentication

Uses HMAC-SHA256 signed requests with the `bhesignature` header format. The 3-step signature chain covers the HTTP method, request timestamp, and body content to prevent replay attacks.

## Menu

```
======================================================
             BHE Interactive Console
======================================================

[0]  Quick Info (version, self, domains)

CYPHER
[1]  Run a Cypher Query (from cypher.txt or manual)
[2]  Cypher Query Library (pre-built queries)

API
[3]  Run an API Call (freeform)
[4]  API Endpoint Library (pre-built GET calls)

[Q]  Quit
```

## Usage Modes

### Quick Info [0]

Runs three checks in sequence: API version, authenticated user identity, and available domains/tenants.

### Freeform Cypher [1]

Two input methods:

- **cypher.txt** — Place a file called `cypher.txt` in the script directory. The script auto-loads it, strips comment lines (`//` or `#`), and shows a preview before executing. Recommended for complex queries to avoid PowerShell quoting issues.
- **Manual input** — Type or paste a query at the `CYPHER>` prompt.

### Freeform API [3]

Manually specify an HTTP method and endpoint path. Supports GET, POST, PUT, PATCH, and DELETE. POST/PUT/PATCH will prompt for a JSON request body.

---

## Cypher Queries

Pre-built Cypher queries sourced from the [SpecterOps Query Library](https://queries.specterops.io/). All queries use simple `RETURN n` or `RETURN p` patterns compatible with the BHE graph API endpoint.

> **Note:** BHE's `/api/v2/graphs/cypher` returns graph data (nodes/edges). Queries using `RETURN u.name AS ...` or aggregation functions like `COUNT()` are not supported via this endpoint.

**Categories:** Tier Zero, Shortest Paths, Dangerous Privileges, AD Hygiene, ADCS, NTLM Relay, Cross Platform, Domain Info, Azure

### Test Queries

The library includes 20 test queries designed to always return data if BHE has any collected information. Use these to validate your connection and confirm data is present before running more targeted queries.

---

## API GET Queries

Pre-built GET endpoints from the [BHE API Reference](https://bloodhound.specterops.io/reference/overview). All non-deprecated GET endpoints across 37 API sections. Endpoints containing `{param}` placeholders (marked with `*`) will prompt for the required value before executing.

**Categories:** Auth, Permissions, Roles, API Tokens, BloodHound Users, Collectors, Collection Uploads, API Info, Search, Audit, Config, Asset Isolation, Graph, Cypher, Azure Entities, AD Base Entities, Computers, Containers, Domains, GPOs, AIA CAs, Root CAs, Enterprise CAs, NT Auth Stores, Cert Templates, OUs, AD Users, Groups, Data Quality, Datapipe, Analysis, Clients, Jobs, Events, Attack Paths, Risk Posture, Meta Entities

---

## Export

All query results can be exported to CSV or JSON. After any query runs, you are prompted with an export option.

## Error Handling

- **HTTP 404 on Cypher queries** — Treated as "no results" rather than an error. BHE returns 404 when a valid Cypher query matches zero nodes/edges in your environment.
- **Authentication failures** — The script validates connectivity and auth on startup and provides troubleshooting guidance.
- **Unicode escaping** — PowerShell's `ConvertTo-Json` Unicode-escapes characters like `'` `>` `<` which BHE rejects. The script automatically fixes these before sending.

## Files

| File | Purpose |
|------|---------|
| `BHE-API-Console.ps1` | Main script |
| `.env` | API credentials (create this) |
| `cypher.txt` | Optional Cypher query file for freeform input |
| `sample.env` | Credential template |
