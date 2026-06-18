[README.md](https://github.com/user-attachments/files/25482897/README.md)
# BHE-API-Console.ps1

PowerShell interactive console for BloodHound Enterprise. HMAC-authenticated API access, Cypher query engine, and pre-built query libraries.

## Requirements

- PowerShell 5.1+ (Windows) or PowerShell 7+ (Cross-platform)
- BloodHound Enterprise API credentials (Token ID + Token Key)
- Network access to your BHE tenant URL

## Setup

Create a `.env` file in the same directory as the script:

```
BHE_URL=https://yourtenant.bloodhoundenterprise.io
BHE_API_ID=your-token-id
BHE_API_KEY=your-token-key
```

## Usage

```powershell
# Auth test only (default)
.\BHE-API-Console.ps1

# Interactive console
.\BHE-API-Console.ps1 -Interactive

# Interactive with debug output
.\BHE-API-Console.ps1 -Interactive -DebugMode

# Direct API call
.\BHE-API-Console.ps1 -API "/api/v2/available-domains"

# Direct Cypher query
.\BHE-API-Console.ps1 -Cypher "MATCH (n:User {enabled:true}) RETURN n LIMIT 10"

# With CSV export
.\BHE-API-Console.ps1 -API "/api/v2/clients" -ExportCSV "clients.csv"

# Custom .env location
.\BHE-API-Console.ps1 -EnvFile "C:\creds\bhe.env" -Interactive

# Override credentials via parameters
.\BHE-API-Console.ps1 -RestEndpoint "tenant.bloodhoundenterprise.io" -TokenID "abc" -Token "xyz" -Interactive
```

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

## Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `-EnvFile` | string | Path to `.env` file (default: `.env` in script directory) |
| `-RestEndpoint` | string | BHE tenant URL (overrides `.env`) |
| `-TokenID` | string | API Token ID (overrides `.env`) |
| `-Token` | string | API Token Key (overrides `.env`) |
| `-API` | string | Run a direct API endpoint call |
| `-Method` | string | HTTP method for `-API` calls (default: GET) |
| `-Body` | string | Request body JSON for POST/PUT calls |
| `-Cypher` | string | Run a direct Cypher query |
| `-Interactive` | switch | Launch the interactive console |
| `-DebugMode` | switch | Enable verbose debug output |
| `-ExportCSV` | string | Export results to CSV file |

## Debug Mode

Run with `-DebugMode` to see detailed request/response information:

```powershell
.\BHE-API-Console.ps1 -Interactive -DebugMode
```

Debug output includes:
- Full request URLs
- Request body content and size
- Cypher query JSON body (post Unicode-fix)
- `[DEBUG MODE ENABLED]` banner indicator

Debug output is suppressed by default for clean operation.

---

## API GET Queries

167 pre-built GET endpoints across 37 categories from the [BHE API Reference](https://bloodhound.specterops.io/reference/overview). Endpoints with `{param}` placeholders prompt for input at runtime.

<img width="1279" height="1173" alt="image" src="https://github.com/user-attachments/assets/9fe20e79-1e43-4324-adf6-f64d8313b79d" />
<img width="1015" height="1293" alt="image" src="https://github.com/user-attachments/assets/d49136a0-fbaf-4b06-8617-a03eee209fb2" />
<img width="1509" height="1159" alt="image" src="https://github.com/user-attachments/assets/c450a778-c906-4842-bc5c-84b39167134a" />
<img width="1245" height="1057" alt="image" src="https://github.com/user-attachments/assets/f94006bd-0554-4375-9431-682ccf85e735" />

---

## Cypher Queries

68 pre-built Cypher queries sourced from the [SpecterOps Query Library](https://queries.specterops.io/) across 10 categories: Tier Zero, Shortest Paths, Dangerous Privileges, AD Hygiene, ADCS, NTLM Relay, Cross Platform, Domain Info, and Azure.

All queries use `RETURN n` or `RETURN p` patterns compatible with BHE's graph API endpoint.

<img width="898" height="995" alt="image" src="https://github.com/user-attachments/assets/1943bedd-474b-48a5-b449-77579edd3a30" />
<img width="925" height="724" alt="image" src="https://github.com/user-attachments/assets/85ceaa23-e3d5-481b-976a-9120b8c20455" />



### Test Queries

20 additional queries guaranteed to return results if BHE has any collected data. Use these to validate connectivity and confirm data is present before running targeted queries.

---

## Cypher Query Input

Two methods for freeform Cypher queries (option [1]):

- **cypher.txt** — Place a file in the script directory. Auto-loaded with comment stripping (`//` and `#` lines) and preview before execution. Recommended for complex queries.
- **Manual input** — Type or paste at the `CYPHER>` prompt.

## Error Handling

| Scenario | Behaviour |
|----------|-----------|
| HTTP 404 on Cypher | Treated as "no results" — BHE returns 404 when a query matches zero data |
| Auth failures | Validates connectivity and auth on startup with troubleshooting guidance |
| Unicode escaping | Auto-fixes PowerShell's `ConvertTo-Json` escaping of `'` `>` `<` `&` `+` characters |

## Files

| File | Purpose |
|------|---------|
| `BHE-API-Console.ps1` | Main script |
| `.env` | API credentials (create this) |
| `cypher.txt` | Optional Cypher query file for freeform input |
| `sample.env` | Credential template |
