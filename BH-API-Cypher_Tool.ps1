#!/usr/bin/env pwsh
<#
.SYNOPSIS
    BHE API Console - Authentication Test + Interactive Query Console

.DESCRIPTION
    Tests BHE HMAC authentication and provides an interactive console for running
    API calls and Cypher queries against BloodHound Enterprise.

    Credentials are loaded from a .env file (default: .env in script directory) OR
    can be provided via parameters.

    .env file format:
        BHE_API_ID="your-token-id"
        BHE_API_KEY="your-token-key"
        BHE_URL="https://tenant.bloodhoundenterprise.io"

    Modes:
    1. Auth Test Only  (default)      - Tests HMAC authentication
    2. Direct API Call  (-API)        - Runs a single API endpoint call
    3. Direct Cypher    (-Cypher)     - Runs a single Cypher query
    4. Interactive Mode (-Interactive) - Drops into a menu-driven console

.PARAMETER EnvFile
    Path to .env file containing credentials (default: .env in script directory)

.PARAMETER RestEndpoint
    The BHE tenant URL. Overrides BHE_URL from .env file.
    Can be entered with or without https:// prefix.

.PARAMETER TokenID
    The API Token ID. Overrides BHE_API_ID from .env file.

.PARAMETER Token
    The API Token Key. Overrides BHE_API_KEY from .env file.

.PARAMETER API
    Run a direct API call. Provide the endpoint path.
    Example: -API "/api/v2/available-domains"

.PARAMETER Method
    HTTP method for -API calls (default: GET)

.PARAMETER Body
    Request body for POST/PUT API calls (JSON string)

.PARAMETER Cypher
    Run a direct Cypher query.
    Example: -Cypher "MATCH (n:User {enabled:true}) RETURN n.name LIMIT 10"

.PARAMETER Interactive
    Launch the interactive query console after auth test.

.PARAMETER DebugMode
    Enable verbose debug output showing full URLs, request bodies, and response structure.

.PARAMETER ExportCSV
    Export results to CSV file (provide file path)

.EXAMPLE
    # Using .env file (simplest - just place .env in same folder)
    .\BHE-API-Console.ps1

.EXAMPLE
    # Using .env file with interactive mode
    .\BHE-API-Console.ps1 -Interactive

.EXAMPLE
    # Using .env file with direct API call
    .\BHE-API-Console.ps1 -API "/api/v2/available-domains"

.EXAMPLE
    # Using .env file with Cypher query
    .\BHE-API-Console.ps1 -Cypher "MATCH (n:User {enabled:true}) RETURN n.name LIMIT 10"

.EXAMPLE
    # Custom .env file location
    .\BHE-API-Console.ps1 -EnvFile "C:\creds\bhe.env" -Interactive

.EXAMPLE
    # Override with parameters (no .env needed)
    .\BHE-API-Console.ps1 -RestEndpoint "tenant.bloodhoundenterprise.io" -TokenID "abc" -Token "xyz" -Interactive

.EXAMPLE
    # API call with CSV export
    .\BHE-API-Console.ps1 -API "/api/v2/available-domains" -ExportCSV "domains.csv"

.EXAMPLE
    # Interactive mode with debug output
    .\BHE-API-Console.ps1 -Interactive -DebugMode
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$EnvFile,

    [Parameter()]
    [string]$RestEndpoint,

    [Parameter()]
    [string]$TokenID,

    [Parameter()]
    [string]$Token,

    [Parameter()]
    [string]$API,

    [Parameter()]
    [ValidateSet("GET","POST","PUT","PATCH","DELETE")]
    [string]$Method = "GET",

    [Parameter()]
    [string]$Body,

    [Parameter()]
    [string]$Cypher,

    [Parameter()]
    [switch]$Interactive,

    [Parameter()]
    [switch]$DebugMode,

    [Parameter()]
    [string]$ExportCSV
)

# Script-scoped debug flag accessible from all functions
$script:BHEDebug = $DebugMode.IsPresent

# ============================================================================
# BANNER
# ============================================================================
function Show-Banner {
    Write-Host ""
    Write-Host "  ======================================================" -ForegroundColor Cyan
    Write-Host "                                                        " -ForegroundColor Cyan
    Write-Host "           BHE API Console v1.3                         " -ForegroundColor Cyan
    Write-Host "           Authentication + Query Engine                 " -ForegroundColor Cyan
    Write-Host "                                                        " -ForegroundColor Cyan
    Write-Host "  ======================================================" -ForegroundColor Cyan
    if ($script:BHEDebug) {
        Write-Host "  [DEBUG MODE ENABLED]" -ForegroundColor Yellow
    }
    Write-Host ""
}

# ============================================================================
# .ENV FILE LOADER
# ============================================================================
function Import-EnvFile {
    param([string]$Path)

    $envVars = @{}

    if (-not (Test-Path $Path)) {
        return $envVars
    }

    Write-Host "  [*] Loading credentials from: $Path" -ForegroundColor Gray

    $lines = Get-Content $Path -ErrorAction SilentlyContinue
    foreach ($line in $lines) {
        # Skip comments and empty lines
        $trimmed = $line.Trim()
        if ([string]::IsNullOrWhiteSpace($trimmed) -or $trimmed.StartsWith('#')) { continue }

        # Parse KEY="VALUE" or KEY=VALUE
        if ($trimmed -match '^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"?([^"]*)"?\s*$') {
            $envVars[$Matches[1]] = $Matches[2]
        }
    }

    $loaded = @()
    if ($envVars.ContainsKey('BHE_URL'))     { $loaded += 'BHE_URL' }
    if ($envVars.ContainsKey('BHE_API_ID'))  { $loaded += 'BHE_API_ID' }
    if ($envVars.ContainsKey('BHE_API_KEY')) { $loaded += 'BHE_API_KEY' }

    if ($loaded.Count -gt 0) {
        $loadedStr = $loaded -join ', '
        Write-Host "  [+] Loaded: $loadedStr" -ForegroundColor Green
    }
    else {
        Write-Host "  [!] No BHE variables found in .env file" -ForegroundColor Yellow
    }

    return $envVars
}

# ============================================================================
# URL NORMALIZATION
# ============================================================================
function Normalize-Url {
    param([string]$Url)

    if (-not $Url.StartsWith("http://") -and -not $Url.StartsWith("https://")) {
        Write-Host "  [*] Auto-adding https:// to tenant address..." -ForegroundColor Gray
        $Url = "https://$Url"
    }
    $Url = $Url.TrimEnd('/')
    Write-Host "  [+] Target: $Url" -ForegroundColor Green
    Write-Host ""
    return $Url
}

# ============================================================================
# HMAC SIGNATURE GENERATION (3-Step Chained HMAC-SHA256)
# ============================================================================
function Get-BHESignature {
    param(
        [string]$TokenId,
        [string]$TokenKey,
        [string]$RequestMethod,
        [string]$Uri,
        [string]$RequestBody = ""
    )

    try {
        $uriObj = [System.Uri]$Uri
        $endpoint = $uriObj.PathAndQuery

        # Timestamp format: 2026-02-04T17:30:00+00:00
        $timestamp = [DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ss+00:00")
        $dateKey = $timestamp.Substring(0, 13)

        # Step 1: HMAC(token_key, METHOD+ENDPOINT)
        $hmac1 = New-Object System.Security.Cryptography.HMACSHA256
        $hmac1.Key = [System.Text.Encoding]::UTF8.GetBytes($TokenKey)
        $step1Input = "$RequestMethod$endpoint"
        $hash1 = $hmac1.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($step1Input))

        # Step 2: HMAC(hash1, DateKey)
        $hmac2 = New-Object System.Security.Cryptography.HMACSHA256
        $hmac2.Key = $hash1
        $hash2 = $hmac2.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($dateKey))

        # Step 3: HMAC(hash2, Body)
        $hmac3 = New-Object System.Security.Cryptography.HMACSHA256
        $hmac3.Key = $hash2
        if ($RequestBody) {
            $hash3 = $hmac3.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($RequestBody))
        }
        else {
            $hash3 = $hmac3.ComputeHash([System.Text.Encoding]::UTF8.GetBytes(""))
        }

        $signature = [System.Convert]::ToBase64String($hash3)

        return @{
            Headers = @{
                "Authorization" = "bhesignature $TokenId"
                "RequestDate"   = $timestamp
                "Signature"     = $signature
                "Content-Type"  = "application/json"
            }
            Success = $true
        }
    }
    catch {
        Write-Host "  [!] HMAC signature generation failed: $_" -ForegroundColor Red
        return @{ Success = $false }
    }
}

# ============================================================================
# CORE API REQUEST FUNCTION
# ============================================================================
function Invoke-BHERequest {
    param(
        [string]$BaseUrl,
        [string]$Endpoint,
        [string]$RequestMethod = "GET",
        [string]$RequestBody = "",
        [string]$TokenId,
        [string]$TokenKey,
        [switch]$Silent
    )

    # Ensure endpoint starts with /
    if (-not $Endpoint.StartsWith("/")) { $Endpoint = "/$Endpoint" }

    $fullUrl = "$BaseUrl$Endpoint"

    if (-not $Silent) {
        Write-Host "  [>] $RequestMethod $Endpoint" -ForegroundColor Yellow
        if ($script:BHEDebug) {
            Write-Host "  [DEBUG] Full URL: $fullUrl" -ForegroundColor DarkGray
            if ($RequestBody) {
                $bodyPreview = if ($RequestBody.Length -gt 200) { $RequestBody.Substring(0, 200) + '...' } else { $RequestBody }
                Write-Host "  [DEBUG] Has Body: YES ($($RequestBody.Length) chars)" -ForegroundColor DarkGray
                Write-Host "  [DEBUG] Body: $bodyPreview" -ForegroundColor DarkGray
            }
            else {
                Write-Host "  [DEBUG] Has Body: NO" -ForegroundColor DarkGray
            }
        }
    }

    # Generate HMAC signature
    $sig = Get-BHESignature -TokenId $TokenId -TokenKey $TokenKey `
        -RequestMethod $RequestMethod -Uri $fullUrl -RequestBody $RequestBody

    if (-not $sig.Success) {
        return @{ Success = $false; Error = "HMAC signature generation failed" }
    }

    try {
        $invokeParams = @{
            Uri     = $fullUrl
            Method  = $RequestMethod
            Headers = $sig.Headers
        }

        if ($RequestBody -and $RequestMethod -in @("POST","PUT","PATCH")) {
            $invokeParams.Body = $RequestBody
        }

        $response = Invoke-RestMethod @invokeParams -ErrorAction Stop

        if (-not $Silent) {
            Write-Host "  [+] Success" -ForegroundColor Green
        }

        return @{
            Success  = $true
            Data     = $response
            Endpoint = $Endpoint
        }
    }
    catch {
        $statusCode = "Unknown"
        $errorDetail = $_.Exception.Message

        if ($_.Exception.Response) {
            $statusCode = [int]$_.Exception.Response.StatusCode
            try {
                $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
                $errorDetail = $reader.ReadToEnd()
                $reader.Close()
            }
            catch { }
        }

        # BHE returns 404 for Cypher queries that match zero results
        $isCypherEndpoint = $Endpoint -match '/graphs/cypher'
        if ($statusCode -eq 404 -and $isCypherEndpoint) {
            if (-not $Silent) {
                Write-Host "  [*] No results - the query returned zero matches." -ForegroundColor DarkYellow
                Write-Host "      (BHE returns HTTP 404 when a Cypher query matches no data)" -ForegroundColor DarkGray
            }
            return @{
                Success    = $true
                Data       = @{ nodes = @{}; edges = @{} }
                Endpoint   = $Endpoint
                NoResults  = $true
            }
        }

        if (-not $Silent) {
            Write-Host "  [!] Failed - HTTP $statusCode" -ForegroundColor Red
            Write-Host "      $errorDetail" -ForegroundColor DarkRed
        }

        return @{
            Success    = $false
            StatusCode = $statusCode
            Error      = $errorDetail
        }
    }
}

# ============================================================================
# CYPHER QUERY FUNCTION
# ============================================================================
function Invoke-BHECypher {
    param(
        [string]$BaseUrl,
        [string]$Query,
        [string]$TokenId,
        [string]$TokenKey,
        [switch]$Silent
    )

    if (-not $Silent) {
        Write-Host ""
        Write-Host "  [>] Cypher Query:" -ForegroundColor Yellow
        Write-Host "      $Query" -ForegroundColor DarkYellow
    }

    # Build the JSON body
    $bodyObj = @{
        query              = $Query
        include_properties = $true
    }
    $bodyJson = $bodyObj | ConvertTo-Json -Compress
    # Fix PowerShell Unicode-escaping characters that BHE rejects in Cypher
    $bodyJson = $bodyJson.Replace('\u0027', "'")    # single quote
    $bodyJson = $bodyJson.Replace('\u0026', '&')    # ampersand
    $bodyJson = $bodyJson.Replace('\u003c', '<')    # less-than
    $bodyJson = $bodyJson.Replace('\u003e', '>')    # greater-than
    $bodyJson = $bodyJson.Replace('\u002b', '+')    # plus
    $bodyJson = $bodyJson.Replace('\u0060', '`')    # backtick

    if (-not $Silent -and $script:BHEDebug) {
        Write-Host "  [DEBUG] Cypher Body: $bodyJson" -ForegroundColor DarkGray
    }

    $result = Invoke-BHERequest -BaseUrl $BaseUrl -Endpoint "/api/v2/graphs/cypher" `
        -RequestMethod "POST" -RequestBody $bodyJson -TokenId $TokenId -TokenKey $TokenKey -Silent:$Silent

    # Tag as Cypher so Format-APIResult knows how to display it
    if ($result) { $result.IsCypher = $true }

    return $result
}

# ============================================================================
# RESULT FORMATTING
# ============================================================================
function Format-APIResult {
    param(
        [object]$Result,
        [string]$ExportPath
    )

    if (-not $Result.Success) {
        Write-Host ""
        Write-Host "  [!] Request failed." -ForegroundColor Red
        if ($Result.Error) {
            Write-Host "      Error: $($Result.Error)" -ForegroundColor DarkRed
        }
        return
    }

    # Handle Cypher queries that returned zero matches
    if ($Result.NoResults) {
        Write-Host ""
        Write-Host "  -------------------------------------------------" -ForegroundColor DarkCyan
        Write-Host "    Cypher Results: 0 nodes, 0 edges" -ForegroundColor DarkYellow
        Write-Host "    No results match this query in your environment" -ForegroundColor DarkGray
        Write-Host "  -------------------------------------------------" -ForegroundColor DarkCyan
        return
    }

    $data = $Result.Data
    Write-Host ""

    # ── CYPHER RESULTS (nodes/edges graph data) ──
    if ($Result.IsCypher) {
        # Unwrap nested 'data' envelope: { "data": { "nodes": {...}, "edges": {...} } }
        if ($data.data -and $data.data.PSObject -and $data.data.PSObject.Properties) {
            $dataKeys = @($data.data.PSObject.Properties | ForEach-Object { $_.Name })
            if ($dataKeys -contains 'nodes' -or $dataKeys -contains 'edges') {
                $data = $data.data
            }
        }

        $nodeCount = 0
        $edgeCount = 0

        if ($data.nodes) {
            $nodeHash = $data.nodes
            if ($nodeHash -is [System.Collections.IDictionary]) {
                $nodeCount = $nodeHash.Count
            }
            elseif ($nodeHash.PSObject.Properties) {
                $nodeCount = @($nodeHash.PSObject.Properties).Count
            }
        }
        if ($data.edges) {
            $edgeHash = $data.edges
            if ($edgeHash -is [System.Collections.IDictionary]) {
                $edgeCount = $edgeHash.Count
            }
            elseif ($edgeHash.PSObject.Properties) {
                $edgeCount = @($edgeHash.PSObject.Properties).Count
            }
        }

        Write-Host "  -------------------------------------------------" -ForegroundColor DarkCyan
        Write-Host "    Cypher Results: $nodeCount nodes, $edgeCount edges" -ForegroundColor Cyan
        Write-Host "  -------------------------------------------------" -ForegroundColor DarkCyan

        # Display nodes
        if ($nodeCount -gt 0) {
            Write-Host ""
            Write-Host "  NODES:" -ForegroundColor White

            $displayObjects = @()
            if ($nodeHash -is [System.Collections.IDictionary]) {
                $nodeItems = $nodeHash.GetEnumerator()
            }
            else {
                $nodeItems = $nodeHash.PSObject.Properties
            }

            $counter = 0
            foreach ($item in $nodeItems) {
                $counter++
                if ($counter -gt 50) {
                    $truncMsg = '  ... {0} total, showing first 50' -f $nodeCount
                    Write-Host $truncMsg -ForegroundColor DarkGray
                    break
                }

                if ($item.Value) { $node = $item.Value } else { $node = $item }

                # Get label
                if ($node.label) { $nodeLabel = $node.label }
                elseif ($node.kind) { $nodeLabel = $node.kind }
                else { $nodeLabel = "Node" }

                # Get name
                $nodeName = ""
                if ($node.properties) {
                    $p = $node.properties
                    if ($p.name) { $nodeName = $p.name }
                    elseif ($p.system_tags) { $nodeName = $p.system_tags }
                }
                if (-not $nodeName -and $node.name) { $nodeName = $node.name }

                # Get ID
                if ($node.object_id) { $nodeId = $node.object_id }
                elseif ($item.Key) { $nodeId = $item.Key }
                elseif ($item.Name) { $nodeId = $item.Name }
                else { $nodeId = "N/A" }

                $obj = [PSCustomObject]@{
                    '#'    = $counter
                    Label  = $nodeLabel
                    Name   = $nodeName
                    NodeID = $nodeId
                }
                $displayObjects += $obj

                # Console output
                Write-Host "  [$counter] " -ForegroundColor DarkGray -NoNewline
                Write-Host "$nodeLabel" -ForegroundColor Magenta -NoNewline
                Write-Host " : " -NoNewline
                Write-Host "$nodeName" -ForegroundColor White
            }

            # Export if requested
            if ($ExportPath -and $displayObjects.Count -gt 0) {
                Export-Results -Objects $displayObjects -Path $ExportPath
            }
        }

        # Display edges
        if ($edgeCount -gt 0) {
            Write-Host ""
            Write-Host "  EDGES:" -ForegroundColor White

            if ($edgeHash -is [System.Collections.IDictionary]) {
                $edgeItems = $edgeHash.GetEnumerator()
            }
            else {
                $edgeItems = $edgeHash.PSObject.Properties
            }

            $counter = 0
            foreach ($item in $edgeItems) {
                $counter++
                if ($counter -gt 25) {
                    $truncMsg = '  ... {0} total, showing first 25' -f $edgeCount
                    Write-Host $truncMsg -ForegroundColor DarkGray
                    break
                }

                if ($item.Value) { $edge = $item.Value } else { $edge = $item }

                if ($edge.label) { $edgeLabel = $edge.label }
                elseif ($edge.kind) { $edgeLabel = $edge.kind }
                else { $edgeLabel = "Edge" }

                if ($edge.source) { $edgeSource = $edge.source } else { $edgeSource = "?" }
                if ($edge.target) { $edgeTarget = $edge.target } else { $edgeTarget = "?" }

                Write-Host "  [$counter] " -ForegroundColor DarkGray -NoNewline
                Write-Host "$edgeSource" -ForegroundColor Yellow -NoNewline
                Write-Host " --[$edgeLabel]--> " -ForegroundColor DarkGray -NoNewline
                Write-Host "$edgeTarget" -ForegroundColor Yellow
            }
        }
    }
    # ── API RESULTS (standard JSON responses) ──
    else {
        # Unwrap data envelope if present
        $items = $null
        $rawData = $data

        # Many BHE API responses wrap arrays in { "data": [...], "count": N }
        if ($data.PSObject -and $data.PSObject.Properties) {
            $propNames = @($data.PSObject.Properties | ForEach-Object { $_.Name })
            if ($propNames -contains 'data') {
                $inner = $data.data
                if ($inner -is [System.Array]) {
                    $items = $inner
                    $totalCount = if ($data.count) { $data.count } else { $items.Count }
                }
                elseif ($inner -is [PSCustomObject] -or $inner -is [System.Management.Automation.PSCustomObject]) {
                    # Single object wrapped in data envelope
                    $rawData = $inner
                }
            }
        }

        # Direct array response (no envelope)
        if (-not $items -and $data -is [System.Array]) {
            $items = $data
            $totalCount = $items.Count
        }

        # ── Array of items: display as table ──
        if ($items -and $items.Count -gt 0) {
            Write-Host "  -------------------------------------------------" -ForegroundColor DarkCyan
            Write-Host "    API Results: $($items.Count) items" -ForegroundColor Cyan
            if ($totalCount -and $totalCount -gt $items.Count) {
                Write-Host "    (Total: $totalCount - showing returned page)" -ForegroundColor DarkGray
            }
            Write-Host "  -------------------------------------------------" -ForegroundColor DarkCyan
            Write-Host ""

            # Auto-detect columns from first item (max 8 columns)
            $sampleProps = @($items[0].PSObject.Properties | Where-Object {
                # Skip nested objects/arrays for table display
                $val = $_.Value
                -not ($val -is [PSCustomObject] -or $val -is [System.Management.Automation.PSCustomObject])
            } | Select-Object -First 8)

            $displayObjects = @()

            $counter = 0
            foreach ($item in $items) {
                $counter++
                if ($counter -gt 100) {
                    Write-Host "  ... $($items.Count) total, showing first 100" -ForegroundColor DarkGray
                    break
                }

                $obj = [ordered]@{ '#' = $counter }
                foreach ($prop in $sampleProps) {
                    $val = $item.($prop.Name)
                    if ($null -eq $val) { $val = "" }
                    elseif ($val -is [System.Array]) {
                        $val = ($val | ForEach-Object { $_.ToString() }) -join ", "
                    }
                    elseif ($val -is [PSCustomObject]) {
                        $val = "(object)"
                    }
                    # Truncate long strings for table display
                    $valStr = $val.ToString()
                    if ($valStr.Length -gt 60) { $valStr = $valStr.Substring(0, 57) + "..." }
                    $obj[$prop.Name] = $valStr
                }
                $displayObjects += [PSCustomObject]$obj
            }

            # Table display
            $displayObjects | Format-Table -AutoSize -Wrap | Out-String | Write-Host

            if ($ExportPath) {
                Export-Results -Objects $displayObjects -Path $ExportPath
            }
        }
        # ── Single object or non-array: display as formatted JSON ──
        else {
            Write-Host "  -------------------------------------------------" -ForegroundColor DarkCyan
            Write-Host "    API Response" -ForegroundColor Cyan
            Write-Host "  -------------------------------------------------" -ForegroundColor DarkCyan
            Write-Host ""

            # Pretty-print the object properties
            if ($rawData.PSObject -and $rawData.PSObject.Properties) {
                foreach ($prop in $rawData.PSObject.Properties) {
                    $val = $prop.Value
                    if ($val -is [PSCustomObject] -or $val -is [System.Array]) {
                        $val = $val | ConvertTo-Json -Depth 3 -Compress
                        if ($val.Length -gt 120) { $val = $val.Substring(0, 117) + "..." }
                    }
                    $namePad = $prop.Name.PadRight(25)
                    Write-Host "    $namePad" -ForegroundColor White -NoNewline
                    Write-Host "$val" -ForegroundColor Green
                }
            }
            else {
                $jsonOut = $rawData | ConvertTo-Json -Depth 10
                Write-Host $jsonOut -ForegroundColor White
            }

            if ($ExportPath) {
                $jsonOut = $rawData | ConvertTo-Json -Depth 10
                $jsonOut | Out-File -FilePath $ExportPath -Encoding UTF8
                Write-Host ""
                Write-Host "  [+] JSON exported to: $ExportPath" -ForegroundColor Green
            }
        }
    }
}

# ============================================================================
# CSV EXPORT
# ============================================================================
function Export-Results {
    param(
        [object[]]$Objects,
        [string]$Path
    )
    try {
        $Objects | Export-Csv -Path $Path -NoTypeInformation -Encoding UTF8
        $rowCount = $Objects.Count
        Write-Host ""
        Write-Host "  [+] Exported $rowCount rows to: $Path" -ForegroundColor Green
    }
    catch {
        Write-Host "  [!] Export failed: $_" -ForegroundColor Red
    }
}

# ============================================================================
# CYPHER QUERY LIBRARY (from queries.specterops.io)
# ============================================================================
function Get-CypherLibrary {
    # Queries sourced from the official BloodHound Query Library
    # https://queries.specterops.io/
    # https://github.com/SpecterOps/BloodHoundQueryLibrary
    #
    # NOTE: BHE /api/v2/graphs/cypher returns graph data (nodes/edges).
    # All queries use simple RETURN n/p patterns. Complex RETURN with
    # property aliases (AS) and aggregation (COUNT) are not supported.
    return @(
        # ── Tier Zero ──
        @{
            Category    = "Tier Zero"
            Name        = "Kerberoastable Tier Zero Members"
            Description = "Kerberoastable members of Tier Zero / High Value groups"
            Query       = "MATCH (u:User) WHERE ((u:Tag_Tier_Zero) OR COALESCE(u.system_tags, '') CONTAINS 'admin_tier_0') AND u.hasspn=true AND u.enabled = true AND NOT u.objectid ENDS WITH '-502' AND NOT COALESCE(u.gmsa, false) = true AND NOT COALESCE(u.msa, false) = true RETURN u LIMIT 100"
        },
        @{
            Category    = "Tier Zero"
            Name        = "Tier Zero Users with Email"
            Description = "Tier Zero accounts with email access"
            Query       = "MATCH (n) WHERE ((n:Tag_Tier_Zero) OR COALESCE(n.system_tags, '') CONTAINS 'admin_tier_0') AND n.email <> '' AND n.enabled = true AND NOT toUpper(n.email) ENDS WITH '.ONMICROSOFT.COM' RETURN n"
        },
        @{
            Category    = "Tier Zero"
            Name        = "Foreign Principals in Tier Zero"
            Description = "Foreign service principals in T0 targets"
            Query       = "MATCH (n:AZServicePrincipal) WHERE ((n:Tag_Tier_Zero) OR COALESCE(n.system_tags, '') CONTAINS 'admin_tier_0') AND NOT toUpper(n.appownerorganizationid) = toUpper(n.tenantid) AND n.appownerorganizationid CONTAINS '-' RETURN n LIMIT 100"
        },
        @{
            Category    = "Tier Zero"
            Name        = "All Tier Zero Assets"
            Description = "All assets tagged as Tier Zero"
            Query       = "MATCH (n:Tag_Tier_Zero) RETURN n LIMIT 200"
        },
        @{
            Category    = "Tier Zero"
            Name        = "Constrained Delegation to Tier Zero"
            Description = "Non-T0 with constrained delegation to T0"
            Query       = "MATCH p=(n)-[:AllowedToDelegate]->(t:Tag_Tier_Zero) WHERE NOT ((n:Tag_Tier_Zero) OR COALESCE(n.system_tags, '') CONTAINS 'admin_tier_0') RETURN p LIMIT 100"
        },

        # ── Shortest Paths ──
        @{
            Category    = "Shortest Paths"
            Name        = "Domain Users to Tier Zero"
            Description = "Shortest path from Domain Users to any T0 asset"
            Query       = "MATCH p=shortestPath((g:Group)-[:Owns|GenericAll|GenericWrite|WriteOwner|WriteDacl|MemberOf|ForceChangePassword|AllExtendedRights|AddMember|HasSession|GPLink|AllowedToDelegate|CoerceToTGT|AllowedToAct|AdminTo|CanPSRemote|CanRDP|ExecuteDCOM|HasSIDHistory|AddSelf|DCSync|ReadLAPSPassword|ReadGMSAPassword|DumpSMSAPassword|SQLAdmin|AddAllowedToAct|WriteSPN|AddKeyCredentialLink|SyncLAPSPassword|WriteAccountRestrictions|WriteGPLink|GoldenCert|ADCSESC1|ADCSESC3|ADCSESC4|ADCSESC6a|ADCSESC6b|ADCSESC9a|ADCSESC9b|ADCSESC10a|ADCSESC10b|ADCSESC13|SyncedToEntraUser|CoerceAndRelayNTLMToSMB|CoerceAndRelayNTLMToADCS*1..]->(t:Tag_Tier_Zero)) WHERE g.objectid ENDS WITH '-513' AND g<>t RETURN p LIMIT 50"
        },
        @{
            Category    = "Shortest Paths"
            Name        = "Owned Principals to Any Target"
            Description = "Attack paths from owned/compromised principals"
            Query       = "MATCH p=shortestPath((n {owned:true})-[*1..]->(t)) WHERE n<>t AND NOT t:Tag_Tier_Zero RETURN p LIMIT 50"
        },
        @{
            Category    = "Shortest Paths"
            Name        = "Owned Principals to Tier Zero"
            Description = "Attack paths from owned principals to T0"
            Query       = "MATCH p=shortestPath((n {owned:true})-[*1..]->(t:Tag_Tier_Zero)) WHERE n<>t RETURN p LIMIT 50"
        },

        # ── Dangerous Privileges ──
        @{
            Category    = "Dangerous Privileges"
            Name        = "Unconstrained Delegation Computers"
            Description = "Computers with unconstrained delegation (excl DCs)"
            Query       = "MATCH (c:Computer {unconstraineddelegation:true}) WHERE NOT c.objectid ENDS WITH '-502' AND NOT c.distinguishedname CONTAINS 'OU=Domain Controllers' RETURN c"
        },
        @{
            Category    = "Dangerous Privileges"
            Name        = "DA Sessions on Non-DC Computers"
            Description = "Non-DC systems where DAs have sessions"
            Query       = "MATCH p=(c:Computer)-[:HasSession]->(u:User)-[:MemberOf*1..]->(g:Group) WHERE g.objectid ENDS WITH '-512' AND NOT c.distinguishedname CONTAINS 'OU=Domain Controllers' RETURN p LIMIT 100"
        },
        @{
            Category    = "Dangerous Privileges"
            Name        = "Foreign Group Membership"
            Description = "Users in groups from other domains"
            Query       = "MATCH p=(u:User)-[:MemberOf]->(g:Group) WHERE u.domainsid <> g.domainsid RETURN p LIMIT 100"
        },
        @{
            Category    = "Dangerous Privileges"
            Name        = "Exchange Privilege Escalation"
            Description = "WriteDACL on domains via Exchange groups"
            Query       = "MATCH p=(g:Group)-[:WriteDacl]->(d:Domain) WHERE g.name CONTAINS 'EXCHANGE' RETURN p"
        },
        @{
            Category    = "Dangerous Privileges"
            Name        = "SID History Abuse"
            Description = "Objects with SID History set"
            Query       = "MATCH (n) WHERE n.sidhistory IS NOT NULL AND SIZE(n.sidhistory) > 0 RETURN n LIMIT 100"
        },
        @{
            Category    = "Dangerous Privileges"
            Name        = "OU Controllers"
            Description = "Non-admin principals controlling OUs"
            Query       = "MATCH p=(n)-[:Owns|GenericAll|GenericWrite|WriteOwner|WriteDacl]->(ou:OU) WHERE NOT ((n:Tag_Tier_Zero) OR COALESCE(n.system_tags, '') CONTAINS 'admin_tier_0') RETURN p LIMIT 100"
        },
        @{
            Category    = "Dangerous Privileges"
            Name        = "LAPS Password Readers"
            Description = "Non-admin principals reading LAPS passwords"
            Query       = "MATCH p=(n)-[:ReadLAPSPassword]->(c:Computer) WHERE NOT ((n:Tag_Tier_Zero) OR COALESCE(n.system_tags, '') CONTAINS 'admin_tier_0') RETURN p LIMIT 100"
        },
        @{
            Category    = "Dangerous Privileges"
            Name        = "GPO Control Over T0 Assets"
            Description = "Non-admin GPO control over T0 assets"
            Query       = "MATCH p=(n)-[:GenericAll|GenericWrite|WriteOwner|WriteDacl|Owns]->(g:GPO)-[:GPLink]->(ou:OU)-[:Contains*1..]->(t:Tag_Tier_Zero) WHERE NOT ((n:Tag_Tier_Zero) OR COALESCE(n.system_tags, '') CONTAINS 'admin_tier_0') RETURN p LIMIT 100"
        },
        @{
            Category    = "Dangerous Privileges"
            Name        = "BadSuccessor Principals"
            Description = "Principals with dangerous successor relationships"
            Query       = "MATCH p=(n)-[:BadSuccessor]->(m) RETURN p LIMIT 100"
        },

        # ── AD Hygiene ──
        @{
            Category    = "AD Hygiene"
            Name        = "Reversible Encryption Users"
            Description = "Users with reversible encryption"
            Query       = "MATCH (u:User {enabled:true}) WHERE u.useraccountcontrol IS NOT NULL AND (toInteger(u.useraccountcontrol) % 256) >= 128 RETURN u LIMIT 100"
        },
        @{
            Category    = "AD Hygiene"
            Name        = "PASSWD_NOTREQD Users"
            Description = "Active users with PASSWD_NOTREQD flag"
            Query       = "MATCH (u:User {enabled:true, passwordnotreqd:true}) RETURN u LIMIT 100"
        },
        @{
            Category    = "AD Hygiene"
            Name        = "DES-Only Encryption Users"
            Description = "Users configured for DES-only encryption"
            Query       = "MATCH (u:User {enabled:true}) WHERE u.useraccountcontrol IS NOT NULL AND toInteger(u.useraccountcontrol) >= 2097152 RETURN u LIMIT 100"
        },
        @{
            Category    = "AD Hygiene"
            Name        = "AdminCount Orphans"
            Description = "adminCount=1 but not in privileged groups"
            Query       = "MATCH (u:User {admincount:true, enabled:true}) WHERE NOT ((u:Tag_Tier_Zero) OR COALESCE(u.system_tags, '') CONTAINS 'admin_tier_0') AND NOT (u)-[:MemberOf*1..]->(:Group:Tag_Tier_Zero) RETURN u LIMIT 100"
        },
        @{
            Category    = "AD Hygiene"
            Name        = "Computers Without LAPS"
            Description = "Active computers missing LAPS"
            Query       = "MATCH (c:Computer {enabled:true}) WHERE c.haslaps = false RETURN c LIMIT 200"
        },
        @{
            Category    = "AD Hygiene"
            Name        = "Enabled Guest Accounts"
            Description = "Guest accounts that are enabled"
            Query       = "MATCH (u:User {enabled:true}) WHERE u.objectid ENDS WITH '-501' RETURN u"
        },
        @{
            Category    = "AD Hygiene"
            Name        = "Active Built-in Admin (RID-500)"
            Description = "Enabled built-in Administrator accounts"
            Query       = "MATCH (u:User {enabled:true}) WHERE u.objectid ENDS WITH '-500' RETURN u"
        },
        @{
            Category    = "AD Hygiene"
            Name        = "Pre-Windows 2000 Group Members"
            Description = "Pre-Windows 2000 Compatible Access membership"
            Query       = "MATCH p=(m)-[:MemberOf*1..]->(g:Group) WHERE g.objectid ENDS WITH '-554' RETURN p LIMIT 100"
        },
        @{
            Category    = "AD Hygiene"
            Name        = "Circular Group Memberships"
            Description = "Groups with circular nesting"
            Query       = "MATCH p=(g:Group)-[:MemberOf*2..]->(g2:Group) WHERE g.objectid = g2.objectid RETURN p LIMIT 50"
        },
        @{
            Category    = "AD Hygiene"
            Name        = "Orphaned SID in ACLs"
            Description = "ACEs referencing deleted/orphaned SIDs"
            Query       = "MATCH p=()-[r:Owns|GenericAll|GenericWrite|WriteOwner|WriteDacl]->() WHERE NOT EXISTS(startNode(r).name) RETURN p LIMIT 50"
        },

        # ── ADCS ──
        @{
            Category    = "ADCS"
            Name        = "CA Admins (Non-T0)"
            Description = "Non-T0 principals managing CAs"
            Query       = "MATCH p=(n)-[:ManageCA|ManageCertificates]->(ca) WHERE NOT ((n:Tag_Tier_Zero) OR COALESCE(n.system_tags, '') CONTAINS 'admin_tier_0') RETURN p LIMIT 100"
        },
        @{
            Category    = "ADCS"
            Name        = "ESC1 Vulnerable Templates"
            Description = "Templates vulnerable to ESC1"
            Query       = "MATCH p=()-[:ADCSESC1]->() RETURN p LIMIT 100"
        },
        @{
            Category    = "ADCS"
            Name        = "ESC8 (HTTP Enrollment)"
            Description = "CAs with HTTP enrollment (NTLM relay)"
            Query       = "MATCH p=()-[:CoerceAndRelayNTLMToADCS]->() RETURN p LIMIT 100"
        },
        @{
            Category    = "ADCS"
            Name        = "Weak Certificate Binding"
            Description = "Templates with weak cert binding"
            Query       = "MATCH (ct:CertTemplate) WHERE ct.strongcertificatebindingenforcementraw IS NOT NULL AND ct.strongcertificatebindingenforcementraw < 2 RETURN ct"
        },
        @{
            Category    = "ADCS"
            Name        = "Templates Missing Security Extension"
            Description = "No szOID_NTDS_CA_SECURITY_EXT"
            Query       = "MATCH (ct:CertTemplate) WHERE ct.nosecurityextension = true RETURN ct"
        },
        @{
            Category    = "ADCS"
            Name        = "Enrollment Agent Templates"
            Description = "Templates with enrollment agent capability"
            Query       = "MATCH (ct:CertTemplate) WHERE ct.enrollmentagent = true RETURN ct"
        },

        # ── NTLM Relay ──
        @{
            Category    = "NTLM Relay"
            Name        = "All Coerce/Relay Edges"
            Description = "All NTLM coercion/relay attack paths"
            Query       = "MATCH p=()-[:CoerceAndRelayNTLMToSMB|CoerceAndRelayNTLMToADCS|CoerceAndRelayNTLMToLDAP|CoerceAndRelayNTLMToLDAPS]->() RETURN p LIMIT 100"
        },
        @{
            Category    = "NTLM Relay"
            Name        = "T0 Users NOT in Protected Users"
            Description = "T0 users missing Protected Users group"
            Query       = "MATCH (u:User) WHERE ((u:Tag_Tier_Zero) OR COALESCE(u.system_tags, '') CONTAINS 'admin_tier_0') AND u.enabled = true AND NOT (u)-[:MemberOf*1..]->(:Group {name:'PROTECTED USERS@' + toUpper(SPLIT(u.name, '@')[1])}) RETURN u LIMIT 100"
        },

        # ── Cross Platform ──
        @{
            Category    = "Cross Platform"
            Name        = "Synced User Ownership"
            Description = "On-prem synced to Entra with ownership"
            Query       = "MATCH p=(u:User)-[:SyncedToEntraUser]->(au:AZUser)-[:Owns|GenericAll|GenericWrite]->(t) RETURN p LIMIT 100"
        },
        @{
            Category    = "Cross Platform"
            Name        = "Entra ID Role Assignments"
            Description = "Principals with Entra directory roles"
            Query       = "MATCH p=(n)-[:AZHasRole|AZMemberOf*1..]->(r:AZRole) RETURN p LIMIT 100"
        },
        @{
            Category    = "Cross Platform"
            Name        = "Azure RM Permissions"
            Description = "Principals with Azure RM role assignments"
            Query       = "MATCH p=(n)-[:AZOwner|AZContributor|AZUserAccessAdministrator]->(t) RETURN p LIMIT 100"
        },
        @{
            Category    = "Cross Platform"
            Name        = "SSO Key Rotation Check"
            Description = "Domains with SSO key rotation data"
            Query       = "MATCH (d:Domain) WHERE d.lastssokeyrotation IS NOT NULL RETURN d"
        },

        # ── Domain Info ──
        @{
            Category    = "Domain Info"
            Name        = "Domain Trusts"
            Description = "All trust relationships"
            Query       = "MATCH p=(d1:Domain)-[:TrustedBy|SameForestTrust]->(d2:Domain) RETURN p"
        },
        @{
            Category    = "Domain Info"
            Name        = "All OUs"
            Description = "All Organizational Units"
            Query       = "MATCH (ou:OU) RETURN ou LIMIT 200"
        },
        @{
            Category    = "Domain Info"
            Name        = "Schema Admins"
            Description = "Members of Schema Admins"
            Query       = "MATCH p=(u)-[:MemberOf*1..]->(g:Group) WHERE g.objectid ENDS WITH '-518' RETURN p"
        },
        @{
            Category    = "Domain Info"
            Name        = "Account/Server Operators"
            Description = "Members of operator groups"
            Query       = "MATCH p=(u)-[:MemberOf*1..]->(g:Group) WHERE g.objectid ENDS WITH '-548' OR g.objectid ENDS WITH '-549' RETURN p LIMIT 100"
        },
        @{
            Category    = "Domain Info"
            Name        = "Cross-Trust ACE Grants"
            Description = "ACE access across trust boundaries"
            Query       = "MATCH p=(n)-[:Owns|GenericAll|GenericWrite|WriteOwner|WriteDacl]->(t) WHERE n.domainsid <> t.domainsid RETURN p LIMIT 100"
        },
        @{
            Category    = "Domain Info"
            Name        = "Computers Without LAPS (All)"
            Description = "All enabled computers missing LAPS"
            Query       = "MATCH (c:Computer {enabled:true}) WHERE c.haslaps = false RETURN c LIMIT 200"
        },

        # ── Azure ──
        @{
            Category    = "Azure"
            Name        = "Foreign Service Principals"
            Description = "Service principals from external tenants"
            Query       = "MATCH (sp:AZServicePrincipal) WHERE NOT toUpper(sp.appownerorganizationid) = toUpper(sp.tenantid) AND sp.appownerorganizationid CONTAINS '-' RETURN sp LIMIT 100"
        },
        @{
            Category    = "Azure"
            Name        = "MS Graph Role Assignments"
            Description = "SPs with dangerous MS Graph roles"
            Query       = "MATCH p=(sp:AZServicePrincipal)-[:AZMGAppRoleAssignment_ReadWrite_All|AZMGApplication_ReadWrite_All|AZMGDirectory_ReadWrite_All|AZMGRoleManagement_ReadWrite_Directory|AZMGServicePrincipalEndpoint_ReadWrite_All]->(t) RETURN p LIMIT 100"
        },
        @{
            Category    = "Azure"
            Name        = "Circular AZ Group Memberships"
            Description = "Circular group nesting in Entra ID"
            Query       = "MATCH p=(x:AZGroup)-[:AZMemberOf*2..]->(y:AZGroup) WHERE x.objectid=y.objectid RETURN p LIMIT 100"
        },

        # ── Test Queries (Should Always Return Results) ──
        @{
            Category    = "Test Queries"
            Name        = "Any 5 Nodes"
            Description = "Return any 5 nodes (basic connectivity test)"
            Query       = "MATCH (n) RETURN n LIMIT 5"
        },
        @{
            Category    = "Test Queries"
            Name        = "All Domains"
            Description = "All domain objects in the database"
            Query       = "MATCH (d:Domain) RETURN d"
        },
        @{
            Category    = "Test Queries"
            Name        = "All Domain Controllers"
            Description = "All DC computers and their domains"
            Query       = "MATCH p=(c:Computer)-[:DCFor]->(d:Domain) RETURN p"
        },
        @{
            Category    = "Test Queries"
            Name        = "First 10 Enabled Users"
            Description = "Sample of enabled user accounts"
            Query       = "MATCH (u:User {enabled:true}) RETURN u LIMIT 10"
        },
        @{
            Category    = "Test Queries"
            Name        = "First 10 Computers"
            Description = "Sample of computer objects"
            Query       = "MATCH (c:Computer) RETURN c LIMIT 10"
        },
        @{
            Category    = "Test Queries"
            Name        = "First 10 Groups"
            Description = "Sample of group objects"
            Query       = "MATCH (g:Group) RETURN g LIMIT 10"
        },
        @{
            Category    = "Test Queries"
            Name        = "Domain Admins Members"
            Description = "Direct and nested Domain Admins members"
            Query       = "MATCH p=(u)-[:MemberOf*1..]->(g:Group) WHERE g.objectid ENDS WITH '-512' RETURN p"
        },
        @{
            Category    = "Test Queries"
            Name        = "Enterprise Admins Members"
            Description = "Direct and nested Enterprise Admins members"
            Query       = "MATCH p=(u)-[:MemberOf*1..]->(g:Group) WHERE g.objectid ENDS WITH '-519' RETURN p"
        },
        @{
            Category    = "Test Queries"
            Name        = "All GPOs"
            Description = "All Group Policy Objects"
            Query       = "MATCH (g:GPO) RETURN g LIMIT 50"
        },
        @{
            Category    = "Test Queries"
            Name        = "Kerberoastable Users"
            Description = "All users with SPN set"
            Query       = "MATCH (u:User {hasspn:true, enabled:true}) RETURN u LIMIT 50"
        },
        @{
            Category    = "Test Queries"
            Name        = "Computers with Sessions"
            Description = "Computers that have active sessions"
            Query       = "MATCH p=(c:Computer)-[:HasSession]->(u:User) RETURN p LIMIT 20"
        },
        @{
            Category    = "Test Queries"
            Name        = "All OUs"
            Description = "All Organizational Units"
            Query       = "MATCH (ou:OU) RETURN ou LIMIT 50"
        },
        @{
            Category    = "Test Queries"
            Name        = "All Domain Trusts"
            Description = "All trust relationships (any type)"
            Query       = "MATCH p=(d1:Domain)-[r]->(d2:Domain) RETURN p"
        },
        @{
            Category    = "Test Queries"
            Name        = "AdminTo Relationships"
            Description = "All local admin rights"
            Query       = "MATCH p=(n)-[:AdminTo]->(c:Computer) RETURN p LIMIT 30"
        },
        @{
            Category    = "Test Queries"
            Name        = "Users with Local Admin"
            Description = "Users with direct local admin rights"
            Query       = "MATCH p=(u:User)-[:AdminTo]->(c:Computer) RETURN p LIMIT 30"
        },
        @{
            Category    = "Test Queries"
            Name        = "All Certificate Authorities"
            Description = "Enterprise, Root, and AIA CAs"
            Query       = "MATCH (ca) WHERE ca:EnterpriseCA OR ca:RootCA OR ca:AIACA RETURN ca"
        },
        @{
            Category    = "Test Queries"
            Name        = "All Tier Zero Assets"
            Description = "Everything tagged as Tier Zero"
            Query       = "MATCH (n:Tag_Tier_Zero) RETURN n LIMIT 100"
        },
        @{
            Category    = "Test Queries"
            Name        = "All Cert Templates"
            Description = "All certificate templates"
            Query       = "MATCH (ct:CertTemplate) RETURN ct LIMIT 50"
        },
        @{
            Category    = "Test Queries"
            Name        = "MemberOf Edges (Sample)"
            Description = "Sample of group membership relationships"
            Query       = "MATCH p=(n)-[:MemberOf]->(g:Group) RETURN p LIMIT 20"
        },
        @{
            Category    = "Test Queries"
            Name        = "HasSession Edges (Sample)"
            Description = "Sample of session relationships"
            Query       = "MATCH p=(c:Computer)-[:HasSession]->(u:User) RETURN p LIMIT 20"
        }
    )
}

function Get-APILibrary {
    # All non-deprecated GET endpoints from the BloodHound API Reference
    # https://bloodhound.specterops.io/reference/overview
    # Endpoints with {param} will prompt for input at runtime
    return @(
        # ── Auth ──
        @{ Category = "Auth"; Name = "Self (Whoami)"; Description = "Current authenticated user"; Endpoint = "/api/v2/self" },
        @{ Category = "Auth"; Name = "SAML Providers"; Description = "Configured SAML providers"; Endpoint = "/api/v2/saml" },
        @{ Category = "Auth"; Name = "All SAML Sign-On Endpoints"; Description = "SAML SSO endpoint URLs"; Endpoint = "/api/v2/saml/sso" },
        @{ Category = "Auth"; Name = "SAML Provider"; Description = "Specific SAML provider details"; Endpoint = "/api/v2/saml/providers/{saml_provider_id}" },
        @{ Category = "Auth"; Name = "SSO Providers"; Description = "All SSO providers"; Endpoint = "/api/v2/sso/providers" },
        @{ Category = "Auth"; Name = "SAML Signing Certificate"; Description = "SAML signing certificate"; Endpoint = "/api/v2/saml/providers/{saml_provider_id}/signing-certificate" },

        # ── Permissions ──
        @{ Category = "Permissions"; Name = "Permissions"; Description = "All BHE permissions"; Endpoint = "/api/v2/permissions" },
        @{ Category = "Permissions"; Name = "Permission"; Description = "Specific permission details"; Endpoint = "/api/v2/permissions/{permission_id}" },

        # ── Roles ──
        @{ Category = "Roles"; Name = "Roles"; Description = "All BHE user roles"; Endpoint = "/api/v2/roles" },
        @{ Category = "Roles"; Name = "Role"; Description = "Specific role details"; Endpoint = "/api/v2/roles/{role_id}" },

        # ── API Tokens ──
        @{ Category = "API Tokens"; Name = "Auth Tokens"; Description = "All API tokens"; Endpoint = "/api/v2/tokens" },

        # ── BloodHound Users ──
        @{ Category = "BloodHound Users"; Name = "Users"; Description = "All BHE user accounts"; Endpoint = "/api/v2/bloodhound-users" },
        @{ Category = "BloodHound Users"; Name = "User"; Description = "Specific BHE user details"; Endpoint = "/api/v2/bloodhound-users/{user_id}" },
        @{ Category = "BloodHound Users"; Name = "User MFA Status"; Description = "MFA activation status"; Endpoint = "/api/v2/bloodhound-users/{user_id}/mfa-activation" },

        # ── Collectors ──
        @{ Category = "Collectors"; Name = "SharpHound Manifest"; Description = "SharpHound version manifest"; Endpoint = "/api/v2/collectors/sharphound" },
        @{ Category = "Collectors"; Name = "AzureHound Manifest"; Description = "AzureHound version manifest"; Endpoint = "/api/v2/collectors/azurehound" },
        @{ Category = "Collectors"; Name = "Kennel Enterprise Manifest"; Description = "Kennel Enterprise agent manifest"; Endpoint = "/api/v2/collectors/kennel-enterprise" },
        @{ Category = "Collectors"; Name = "Kennel Manifest"; Description = "Kennel agent manifest"; Endpoint = "/api/v2/collectors/kennel" },

        # ── Collection Uploads ──
        @{ Category = "Collection Uploads"; Name = "File Upload Jobs"; Description = "File upload job history"; Endpoint = "/api/v2/file-upload" },
        @{ Category = "Collection Uploads"; Name = "Accepted Upload Types"; Description = "Accepted file types for upload"; Endpoint = "/api/v2/file-upload/accepted-types" },

        # ── API Info ──
        @{ Category = "API Info"; Name = "API Version"; Description = "BHE API version"; Endpoint = "/api/version" },
        @{ Category = "API Info"; Name = "OpenAPI Spec"; Description = "Full OpenAPI 3.0 spec (YAML)"; Endpoint = "/api/v2/spec/openapi.yaml" },

        # ── Search ──
        @{ Category = "Search"; Name = "Search for Objects"; Description = "Search nodes by name"; Endpoint = "/api/v2/search?q={search_query}" },
        @{ Category = "Search"; Name = "Available Domains"; Description = "All domains/tenants collected"; Endpoint = "/api/v2/available-domains" },

        # ── Audit ──
        @{ Category = "Audit"; Name = "Audit Logs"; Description = "Recent audit log entries"; Endpoint = "/api/v2/audit" },

        # ── Config ──
        @{ Category = "Config"; Name = "App Config"; Description = "Application configuration"; Endpoint = "/api/v2/config" },
        @{ Category = "Config"; Name = "Feature Flags"; Description = "Feature flags and status"; Endpoint = "/api/v2/features" },

        # ── Asset Isolation ──
        @{ Category = "Asset Isolation"; Name = "All Asset Groups"; Description = "All asset isolation groups"; Endpoint = "/api/v2/asset-groups" },
        @{ Category = "Asset Isolation"; Name = "Asset Group by ID"; Description = "Specific asset group details"; Endpoint = "/api/v2/asset-groups/{asset_group_id}" },
        @{ Category = "Asset Isolation"; Name = "Asset Group Members"; Description = "Members of an asset group"; Endpoint = "/api/v2/asset-groups/{asset_group_id}/members" },
        @{ Category = "Asset Isolation"; Name = "Asset Group Member Count"; Description = "Members count by kind"; Endpoint = "/api/v2/asset-groups/{asset_group_id}/members/counts" },
        @{ Category = "Asset Isolation"; Name = "Asset Group Custom Member Count"; Description = "Custom-added member count"; Endpoint = "/api/v2/asset-groups/{asset_group_id}/custom-members/count" },
        @{ Category = "Asset Isolation"; Name = "Asset Group Tags"; Description = "Tags on an asset group"; Endpoint = "/api/v2/asset-groups/{asset_group_id}/tags" },
        @{ Category = "Asset Isolation"; Name = "Asset Group Collections"; Description = "Collection history"; Endpoint = "/api/v2/asset-groups/{asset_group_id}/collections" },
        @{ Category = "Asset Isolation"; Name = "Asset Group History"; Description = "Historical records"; Endpoint = "/api/v2/asset-groups/{asset_group_id}/history" },
        @{ Category = "Asset Isolation"; Name = "Privilege Zone Certifications"; Description = "Certifications for privilege zones"; Endpoint = "/api/v2/asset-groups/{asset_group_id}/certifications" },

        # ── Graph ──
        @{ Category = "Graph"; Name = "Graph Kinds"; Description = "All node and edge types"; Endpoint = "/api/v2/graphs/kinds" },
        @{ Category = "Graph"; Name = "Pathfinding"; Description = "Find paths between two nodes"; Endpoint = "/api/v2/pathfinding?start_node={start_object_id}&end_node={end_object_id}" },
        @{ Category = "Graph"; Name = "Graph Search"; Description = "Graph search by node"; Endpoint = "/api/v2/graphs/search?query={search_query}" },
        @{ Category = "Graph"; Name = "Shortest Path"; Description = "Shortest path between nodes"; Endpoint = "/api/v2/graphs/shortest-path?start_node={start_object_id}&end_node={end_object_id}" },
        @{ Category = "Graph"; Name = "Path Composition"; Description = "Decompose edge into components"; Endpoint = "/api/v2/graphs/edge-composition?source_node={source_object_id}&target_node={target_object_id}&edge_type={edge_type}" },
        @{ Category = "Graph"; Name = "Relay Targets"; Description = "NTLM relay targets for a source"; Endpoint = "/api/v2/graphs/relay-targets?source_node={source_object_id}" },
        @{ Category = "Graph"; Name = "ACL Inheritance Path"; Description = "ACL inheritance chain"; Endpoint = "/api/v2/graphs/acl-inheritance?object_id={object_id}" },

        # ── Cypher (Saved Queries) ──
        @{ Category = "Cypher"; Name = "Saved Queries"; Description = "All saved Cypher queries"; Endpoint = "/api/v2/saved-queries" },
        @{ Category = "Cypher"; Name = "Export Saved Query"; Description = "Export a specific saved query"; Endpoint = "/api/v2/saved-queries/{saved_query_id}/export" },
        @{ Category = "Cypher"; Name = "Export All Saved Queries"; Description = "Export all saved queries"; Endpoint = "/api/v2/saved-queries/export" },

        # ── Azure Entities ──
        @{ Category = "Azure Entities"; Name = "Azure Entity"; Description = "Azure/Entra entity info"; Endpoint = "/api/v2/azure/{entity_type}" },

        # ── AD Base Entities ──
        @{ Category = "AD Base Entities"; Name = "Entity Info"; Description = "Any AD entity by object ID"; Endpoint = "/api/v2/base/{object_id}" },
        @{ Category = "AD Base Entities"; Name = "Entity Controllables"; Description = "Objects this entity can control"; Endpoint = "/api/v2/base/{object_id}/controllables" },
        @{ Category = "AD Base Entities"; Name = "Entity Controllers"; Description = "Objects that control this entity"; Endpoint = "/api/v2/base/{object_id}/controllers" },

        # ── Computers ──
        @{ Category = "Computers"; Name = "Computer Info"; Description = "Computer entity details"; Endpoint = "/api/v2/computers/{object_id}" },
        @{ Category = "Computers"; Name = "Computer Admin Rights"; Description = "Systems this computer admins"; Endpoint = "/api/v2/computers/{object_id}/admin-rights" },
        @{ Category = "Computers"; Name = "Computer Admins"; Description = "Admins on this computer"; Endpoint = "/api/v2/computers/{object_id}/admins" },
        @{ Category = "Computers"; Name = "Computer Constrained Delegation"; Description = "Constrained delegation targets"; Endpoint = "/api/v2/computers/{object_id}/constrained-delegation-rights" },
        @{ Category = "Computers"; Name = "Computer Constrained Users"; Description = "Constrained-delegated principals"; Endpoint = "/api/v2/computers/{object_id}/constrained-users" },
        @{ Category = "Computers"; Name = "Computer Controllables"; Description = "Objects this computer controls"; Endpoint = "/api/v2/computers/{object_id}/controllables" },
        @{ Category = "Computers"; Name = "Computer Controllers"; Description = "Objects controlling this computer"; Endpoint = "/api/v2/computers/{object_id}/controllers" },
        @{ Category = "Computers"; Name = "Computer DCOM Rights"; Description = "DCOM rights from this computer"; Endpoint = "/api/v2/computers/{object_id}/dcom-rights" },
        @{ Category = "Computers"; Name = "Computer DCOM Users"; Description = "DCOM users on this computer"; Endpoint = "/api/v2/computers/{object_id}/dcom-users" },
        @{ Category = "Computers"; Name = "Computer Group Membership"; Description = "Groups this computer is in"; Endpoint = "/api/v2/computers/{object_id}/group-membership" },
        @{ Category = "Computers"; Name = "Computer PS Remote Rights"; Description = "PSRemote from this computer"; Endpoint = "/api/v2/computers/{object_id}/ps-remote-rights" },
        @{ Category = "Computers"; Name = "Computer PS Remote Users"; Description = "PSRemote users on this computer"; Endpoint = "/api/v2/computers/{object_id}/ps-remote-users" },
        @{ Category = "Computers"; Name = "Computer RDP Rights"; Description = "RDP from this computer"; Endpoint = "/api/v2/computers/{object_id}/rdp-rights" },
        @{ Category = "Computers"; Name = "Computer RDP Users"; Description = "RDP users on this computer"; Endpoint = "/api/v2/computers/{object_id}/rdp-users" },
        @{ Category = "Computers"; Name = "Computer Sessions"; Description = "Sessions on this computer"; Endpoint = "/api/v2/computers/{object_id}/sessions" },
        @{ Category = "Computers"; Name = "Computer SQL Admins"; Description = "SQL admins on this computer"; Endpoint = "/api/v2/computers/{object_id}/sql-admins" },

        # ── Containers ──
        @{ Category = "Containers"; Name = "Container Info"; Description = "Container entity details"; Endpoint = "/api/v2/containers/{object_id}" },
        @{ Category = "Containers"; Name = "Container Controllers"; Description = "Controllers of this container"; Endpoint = "/api/v2/containers/{object_id}/controllers" },

        # ── Domains ──
        @{ Category = "Domains"; Name = "Domain Info"; Description = "Domain entity details"; Endpoint = "/api/v2/domains/{object_id}" },
        @{ Category = "Domains"; Name = "Domain Computers"; Description = "Computers in domain"; Endpoint = "/api/v2/domains/{object_id}/computers" },
        @{ Category = "Domains"; Name = "Domain Controllers"; Description = "Principals controlling domain"; Endpoint = "/api/v2/domains/{object_id}/controllers" },
        @{ Category = "Domains"; Name = "Domain DC Syncers"; Description = "Principals with DCSync"; Endpoint = "/api/v2/domains/{object_id}/dc-syncers" },
        @{ Category = "Domains"; Name = "Domain Foreign Admins"; Description = "Foreign principals with admin"; Endpoint = "/api/v2/domains/{object_id}/foreign-admins" },
        @{ Category = "Domains"; Name = "Domain Foreign GPO Controllers"; Description = "Foreign GPO controllers"; Endpoint = "/api/v2/domains/{object_id}/foreign-gpo-controllers" },
        @{ Category = "Domains"; Name = "Domain Foreign Groups"; Description = "Foreign group memberships"; Endpoint = "/api/v2/domains/{object_id}/foreign-groups" },
        @{ Category = "Domains"; Name = "Domain Foreign Users"; Description = "Foreign users"; Endpoint = "/api/v2/domains/{object_id}/foreign-users" },
        @{ Category = "Domains"; Name = "Domain GPOs"; Description = "GPOs in domain"; Endpoint = "/api/v2/domains/{object_id}/gpos" },
        @{ Category = "Domains"; Name = "Domain Groups"; Description = "Groups in domain"; Endpoint = "/api/v2/domains/{object_id}/groups" },
        @{ Category = "Domains"; Name = "Domain Inbound Trusts"; Description = "Inbound trust relationships"; Endpoint = "/api/v2/domains/{object_id}/inbound-trusts" },
        @{ Category = "Domains"; Name = "Domain Linked GPOs"; Description = "GPOs linked to domain"; Endpoint = "/api/v2/domains/{object_id}/linked-gpos" },
        @{ Category = "Domains"; Name = "Domain OUs"; Description = "OUs in domain"; Endpoint = "/api/v2/domains/{object_id}/ous" },
        @{ Category = "Domains"; Name = "Domain Outbound Trusts"; Description = "Outbound trust relationships"; Endpoint = "/api/v2/domains/{object_id}/outbound-trusts" },
        @{ Category = "Domains"; Name = "Domain Users"; Description = "Users in domain"; Endpoint = "/api/v2/domains/{object_id}/users" },
        @{ Category = "Domains"; Name = "Domain ADCS Escalations"; Description = "ADCS escalation paths"; Endpoint = "/api/v2/domains/{object_id}/adcs" },

        # ── GPOs ──
        @{ Category = "GPOs"; Name = "GPO Info"; Description = "GPO entity details"; Endpoint = "/api/v2/gpos/{object_id}" },
        @{ Category = "GPOs"; Name = "GPO Computers"; Description = "Computers affected by GPO"; Endpoint = "/api/v2/gpos/{object_id}/computers" },
        @{ Category = "GPOs"; Name = "GPO Controllers"; Description = "Principals controlling GPO"; Endpoint = "/api/v2/gpos/{object_id}/controllers" },
        @{ Category = "GPOs"; Name = "GPO OUs"; Description = "OUs linked to GPO"; Endpoint = "/api/v2/gpos/{object_id}/ous" },
        @{ Category = "GPOs"; Name = "GPO Tier Zero"; Description = "T0 assets affected by GPO"; Endpoint = "/api/v2/gpos/{object_id}/tier-zero" },
        @{ Category = "GPOs"; Name = "GPO Users"; Description = "Users affected by GPO"; Endpoint = "/api/v2/gpos/{object_id}/users" },

        # ── AIA CAs ──
        @{ Category = "AIA CAs"; Name = "AIA CA Info"; Description = "AIA CA entity details"; Endpoint = "/api/v2/aia-cas/{object_id}" },
        @{ Category = "AIA CAs"; Name = "AIA CA Controllers"; Description = "Controllers of this AIA CA"; Endpoint = "/api/v2/aia-cas/{object_id}/controllers" },
        @{ Category = "AIA CAs"; Name = "AIA CA PKI Hierarchy"; Description = "PKI hierarchy"; Endpoint = "/api/v2/aia-cas/{object_id}/pki-hierarchy" },

        # ── Root CAs ──
        @{ Category = "Root CAs"; Name = "Root CA Info"; Description = "Root CA entity details"; Endpoint = "/api/v2/root-cas/{object_id}" },
        @{ Category = "Root CAs"; Name = "Root CA Controllers"; Description = "Controllers of Root CA"; Endpoint = "/api/v2/root-cas/{object_id}/controllers" },
        @{ Category = "Root CAs"; Name = "Root CA PKI Hierarchy"; Description = "PKI hierarchy"; Endpoint = "/api/v2/root-cas/{object_id}/pki-hierarchy" },

        # ── Enterprise CAs ──
        @{ Category = "Enterprise CAs"; Name = "Enterprise CA Info"; Description = "Enterprise CA details"; Endpoint = "/api/v2/enterprise-cas/{object_id}" },
        @{ Category = "Enterprise CAs"; Name = "Enterprise CA Controllers"; Description = "Controllers of Enterprise CA"; Endpoint = "/api/v2/enterprise-cas/{object_id}/controllers" },
        @{ Category = "Enterprise CAs"; Name = "Enterprise CA PKI Hierarchy"; Description = "PKI hierarchy"; Endpoint = "/api/v2/enterprise-cas/{object_id}/pki-hierarchy" },
        @{ Category = "Enterprise CAs"; Name = "Enterprise CA Published Templates"; Description = "Published cert templates"; Endpoint = "/api/v2/enterprise-cas/{object_id}/published-certificate-templates" },

        # ── NT Auth Stores ──
        @{ Category = "NT Auth Stores"; Name = "NT Auth Store Info"; Description = "NT Auth Store details"; Endpoint = "/api/v2/nt-auth-stores/{object_id}" },
        @{ Category = "NT Auth Stores"; Name = "NT Auth Store Controllers"; Description = "Controllers"; Endpoint = "/api/v2/nt-auth-stores/{object_id}/controllers" },
        @{ Category = "NT Auth Stores"; Name = "NT Auth Store Trusted CAs"; Description = "Trusted Enterprise CAs"; Endpoint = "/api/v2/nt-auth-stores/{object_id}/trusted-enterprise-cas" },

        # ── Cert Templates ──
        @{ Category = "Cert Templates"; Name = "Cert Template Info"; Description = "Cert template details"; Endpoint = "/api/v2/cert-templates/{object_id}" },
        @{ Category = "Cert Templates"; Name = "Cert Template Controllers"; Description = "Controllers"; Endpoint = "/api/v2/cert-templates/{object_id}/controllers" },
        @{ Category = "Cert Templates"; Name = "Cert Template Publishing CAs"; Description = "CAs publishing this template"; Endpoint = "/api/v2/cert-templates/{object_id}/enterprise-cas" },

        # ── OUs ──
        @{ Category = "OUs"; Name = "OU Info"; Description = "OU entity details"; Endpoint = "/api/v2/ous/{object_id}" },
        @{ Category = "OUs"; Name = "OU Computers"; Description = "Computers in OU"; Endpoint = "/api/v2/ous/{object_id}/computers" },
        @{ Category = "OUs"; Name = "OU GPOs"; Description = "GPOs linked to OU"; Endpoint = "/api/v2/ous/{object_id}/gpos" },
        @{ Category = "OUs"; Name = "OU Groups"; Description = "Groups in OU"; Endpoint = "/api/v2/ous/{object_id}/groups" },
        @{ Category = "OUs"; Name = "OU Users"; Description = "Users in OU"; Endpoint = "/api/v2/ous/{object_id}/users" },

        # ── AD Users ──
        @{ Category = "AD Users"; Name = "User Info"; Description = "AD User details"; Endpoint = "/api/v2/users/{object_id}" },
        @{ Category = "AD Users"; Name = "User Admin Rights"; Description = "Systems user admins"; Endpoint = "/api/v2/users/{object_id}/admin-rights" },
        @{ Category = "AD Users"; Name = "User Constrained Delegation"; Description = "Constrained delegation"; Endpoint = "/api/v2/users/{object_id}/constrained-delegation-rights" },
        @{ Category = "AD Users"; Name = "User Controllables"; Description = "Objects user controls"; Endpoint = "/api/v2/users/{object_id}/controllables" },
        @{ Category = "AD Users"; Name = "User Controllers"; Description = "Objects controlling user"; Endpoint = "/api/v2/users/{object_id}/controllers" },
        @{ Category = "AD Users"; Name = "User DCOM Rights"; Description = "DCOM rights"; Endpoint = "/api/v2/users/{object_id}/dcom-rights" },
        @{ Category = "AD Users"; Name = "User Group Membership"; Description = "Group memberships"; Endpoint = "/api/v2/users/{object_id}/membership" },
        @{ Category = "AD Users"; Name = "User PS Remote Rights"; Description = "PSRemote rights"; Endpoint = "/api/v2/users/{object_id}/ps-remote-rights" },
        @{ Category = "AD Users"; Name = "User RDP Rights"; Description = "RDP rights"; Endpoint = "/api/v2/users/{object_id}/rdp-rights" },
        @{ Category = "AD Users"; Name = "User Sessions"; Description = "Active sessions"; Endpoint = "/api/v2/users/{object_id}/sessions" },
        @{ Category = "AD Users"; Name = "User SQL Admin Rights"; Description = "SQL admin rights"; Endpoint = "/api/v2/users/{object_id}/sql-admin-rights" },

        # ── Groups ──
        @{ Category = "Groups"; Name = "Group Info"; Description = "AD Group details"; Endpoint = "/api/v2/groups/{object_id}" },
        @{ Category = "Groups"; Name = "Group Admin Rights"; Description = "Systems group admins"; Endpoint = "/api/v2/groups/{object_id}/admin-rights" },
        @{ Category = "Groups"; Name = "Group Controllables"; Description = "Objects group controls"; Endpoint = "/api/v2/groups/{object_id}/controllables" },
        @{ Category = "Groups"; Name = "Group Controllers"; Description = "Objects controlling group"; Endpoint = "/api/v2/groups/{object_id}/controllers" },
        @{ Category = "Groups"; Name = "Group DCOM Rights"; Description = "DCOM rights"; Endpoint = "/api/v2/groups/{object_id}/dcom-rights" },
        @{ Category = "Groups"; Name = "Group Members"; Description = "Direct members"; Endpoint = "/api/v2/groups/{object_id}/members" },
        @{ Category = "Groups"; Name = "Group Memberships"; Description = "Parent groups"; Endpoint = "/api/v2/groups/{object_id}/memberships" },
        @{ Category = "Groups"; Name = "Group PS Remote Rights"; Description = "PSRemote rights"; Endpoint = "/api/v2/groups/{object_id}/ps-remote-rights" },
        @{ Category = "Groups"; Name = "Group RDP Rights"; Description = "RDP rights"; Endpoint = "/api/v2/groups/{object_id}/rdp-rights" },
        @{ Category = "Groups"; Name = "Group Sessions"; Description = "Member sessions"; Endpoint = "/api/v2/groups/{object_id}/sessions" },

        # ── Data Quality ──
        @{ Category = "Data Quality"; Name = "Database Completeness Stats"; Description = "Overall completeness"; Endpoint = "/api/v2/completeness" },
        @{ Category = "Data Quality"; Name = "AD Domain Data Quality"; Description = "Domain data quality stats"; Endpoint = "/api/v2/ad-domains/{domain_id}/data-quality-stats" },
        @{ Category = "Data Quality"; Name = "Azure Tenant Data Quality"; Description = "Tenant data quality stats"; Endpoint = "/api/v2/azure-tenants/{tenant_id}/data-quality-stats" },
        @{ Category = "Data Quality"; Name = "Platform Data Quality"; Description = "Aggregate quality stats"; Endpoint = "/api/v2/platform/{platform_id}/data-quality-stats" },

        # ── Datapipe ──
        @{ Category = "Datapipe"; Name = "Datapipe Status"; Description = "Analysis pipeline status"; Endpoint = "/api/v2/datapipe/status" },

        # ── Analysis ──
        @{ Category = "Analysis"; Name = "Tier Zero Combo Node"; Description = "Latest T0 composite node"; Endpoint = "/api/v2/meta-nodes/{domain_id}" },
        @{ Category = "Analysis"; Name = "Meta Tree Graph"; Description = "Meta tree visualization"; Endpoint = "/api/v2/meta-trees/{domain_id}" },
        @{ Category = "Analysis"; Name = "Asset Group Combo Tree"; Description = "Combo tree for asset group"; Endpoint = "/api/v2/asset-groups/{asset_group_id}/combo-node" },

        # ── Clients ──
        @{ Category = "Clients"; Name = "Clients"; Description = "Registered collectors"; Endpoint = "/api/v2/clients" },
        @{ Category = "Clients"; Name = "Client"; Description = "Specific client details"; Endpoint = "/api/v2/clients/{client_id}" },
        @{ Category = "Clients"; Name = "Client Completed Tasks"; Description = "Completed tasks for client"; Endpoint = "/api/v2/clients/{client_id}/completed-tasks" },
        @{ Category = "Clients"; Name = "Client Completed Jobs"; Description = "Completed jobs for client"; Endpoint = "/api/v2/clients/{client_id}/completed-jobs" },

        # ── Jobs ──
        @{ Category = "Jobs"; Name = "Available Jobs"; Description = "Available client jobs"; Endpoint = "/api/v2/jobs/available" },
        @{ Category = "Jobs"; Name = "Finished Jobs"; Description = "Completed job history"; Endpoint = "/api/v2/jobs/finished" },
        @{ Category = "Jobs"; Name = "Jobs"; Description = "All jobs with status"; Endpoint = "/api/v2/jobs" },
        @{ Category = "Jobs"; Name = "Client Current Job"; Description = "Running job for a client"; Endpoint = "/api/v2/jobs/current/{client_id}" },
        @{ Category = "Jobs"; Name = "Job Details"; Description = "Specific job details"; Endpoint = "/api/v2/jobs/{job_id}" },
        @{ Category = "Jobs"; Name = "Job Log File"; Description = "Log for a specific job"; Endpoint = "/api/v2/jobs/{job_id}/log" },

        # ── Events (Schedules) ──
        @{ Category = "Events"; Name = "Events"; Description = "Scheduled collection events"; Endpoint = "/api/v2/events" },
        @{ Category = "Events"; Name = "Event"; Description = "Specific event details"; Endpoint = "/api/v2/events/{event_id}" },

        # ── Attack Paths ──
        @{ Category = "Attack Paths"; Name = "Export All Findings"; Description = "Export all attack path findings"; Endpoint = "/api/v2/attack-paths/details" },
        @{ Category = "Attack Paths"; Name = "All Findings"; Description = "All findings summary"; Endpoint = "/api/v2/attack-paths" },
        @{ Category = "Attack Paths"; Name = "Attack Path Types"; Description = "Available attack path types"; Endpoint = "/api/v2/attack-path-types" },
        @{ Category = "Attack Paths"; Name = "Domain Available Paths"; Description = "Available paths for domain"; Endpoint = "/api/v2/domains/{domain_id}/available-attack-paths" },
        @{ Category = "Attack Paths"; Name = "Domain Path Details"; Description = "Path details for domain"; Endpoint = "/api/v2/domains/{domain_id}/attack-path-findings" },
        @{ Category = "Attack Paths"; Name = "Attack Path Sparklines"; Description = "Trend sparkline data"; Endpoint = "/api/v2/domains/{domain_id}/sparkline" },
        @{ Category = "Attack Paths"; Name = "Finding Trends"; Description = "Historical finding trends"; Endpoint = "/api/v2/attack-paths/finding-trends" },

        # ── Risk Posture ──
        @{ Category = "Risk Posture"; Name = "Posture Statistics"; Description = "Overall risk posture"; Endpoint = "/api/v2/posture-stats" },
        @{ Category = "Risk Posture"; Name = "Posture History"; Description = "Historical posture data"; Endpoint = "/api/v2/posture-history" },

        # ── Meta Entities ──
        @{ Category = "Meta Entities"; Name = "Meta Entity Info"; Description = "Meta entity details"; Endpoint = "/api/v2/meta/{object_id}" }
    )
}

# ============================================================================
# CYPHER LIBRARY BROWSER
# ============================================================================
function Show-CypherLibrary {
    param(
        [array]$Library,
        [string]$BaseUrl,
        [string]$TokenId,
        [string]$TokenKey
    )

    while ($true) {
        $categories = $Library | Group-Object { $_.Category } | Sort-Object Name

        Write-Host ""
        Write-Host "  -- Cypher Query Library ------------------------------------" -ForegroundColor DarkCyan
        Write-Host "     Source: https://queries.specterops.io/" -ForegroundColor DarkGray
        Write-Host ""

        $index = 1
        $queryMap = @{}
        foreach ($cat in $categories) {
            Write-Host "  [$($cat.Name)]" -ForegroundColor Magenta
            foreach ($q in $cat.Group) {
                $queryMap[$index] = $q
                $paddedIndex = $index.ToString().PadLeft(3)
                Write-Host "   $paddedIndex. " -ForegroundColor DarkGray -NoNewline
                Write-Host "$($q.Name)" -ForegroundColor White -NoNewline
                Write-Host " - $($q.Description)" -ForegroundColor DarkGray
                $index++
            }
            Write-Host ""
        }

        Write-Host "  Enter query number to run (or 'back'):" -ForegroundColor Yellow
        $pick = Read-Host "  CYPHER-LIB>"

        if ($pick -eq 'back' -or [string]::IsNullOrWhiteSpace($pick)) { return }

        $pickNum = 0
        if ([int]::TryParse($pick, [ref]$pickNum) -and $queryMap.ContainsKey($pickNum)) {
            $selected = $queryMap[$pickNum]

            Write-Host ""
            Write-Host "  Running: $($selected.Name)" -ForegroundColor Cyan
            Write-Host "  Query: $($selected.Query)" -ForegroundColor DarkYellow

            $result = Invoke-BHECypher -BaseUrl $BaseUrl -Query $selected.Query `
                -TokenId $TokenId -TokenKey $TokenKey
            Format-APIResult -Result $result

            Write-Host ""
            $exportChoice = Read-Host "  Export to CSV? (enter file path or press Enter to skip)"
            if (-not [string]::IsNullOrWhiteSpace($exportChoice)) {
                Format-APIResult -Result $result -ExportPath $exportChoice
            }

            Write-Host ""
            Write-Host "  Press Enter to return to library..." -ForegroundColor DarkGray
            Read-Host | Out-Null
        }
        else {
            Write-Host "  [!] Invalid selection." -ForegroundColor Red
        }
    }
}

# ============================================================================
# API LIBRARY BROWSER
# ============================================================================
function Show-APILibrary {
    param(
        [array]$Library,
        [string]$BaseUrl,
        [string]$TokenId,
        [string]$TokenKey
    )

    while ($true) {
        $categories = $Library | Group-Object { $_.Category } | Sort-Object Name

        Write-Host ""
        Write-Host "  -- API Endpoint Library ------------------------------------" -ForegroundColor DarkCyan
        Write-Host "     Source: bloodhound.specterops.io/reference" -ForegroundColor DarkGray
        Write-Host "     Endpoints with {param} will prompt for input" -ForegroundColor DarkGray
        Write-Host ""

        $index = 1
        $queryMap = @{}
        foreach ($cat in $categories) {
            Write-Host "  [$($cat.Name)]" -ForegroundColor Magenta
            foreach ($q in $cat.Group) {
                $queryMap[$index] = $q
                $paddedIndex = $index.ToString().PadLeft(3)
                $hasParams = $q.Endpoint -match '\{[^}]+\}'
                if ($hasParams) { $paramTag = "*" } else { $paramTag = " " }
                $method = if ($q.HttpMethod) { $q.HttpMethod } else { "GET" }

                # Strip redundant Get/List from display name since method shown
                $displayName = $q.Name -replace '^Get ', '' -replace '^List ', ''
                $col1 = "$($method.PadRight(6))$($displayName)".PadRight(42)

                Write-Host "   $paddedIndex.$paramTag" -ForegroundColor DarkGray -NoNewline
                Write-Host "$($method.PadRight(6))" -ForegroundColor Green -NoNewline
                Write-Host "$($displayName.PadRight(36))" -ForegroundColor White -NoNewline
                Write-Host "$($q.Endpoint)" -ForegroundColor DarkCyan
                $index++
            }
            Write-Host ""
        }

        Write-Host "  (* = requires parameter input)" -ForegroundColor DarkGray
        Write-Host ""
        Write-Host "  Enter endpoint number to run (or 'back'):" -ForegroundColor Yellow
        $pick = Read-Host "  API-LIB>"

        if ($pick -eq 'back' -or [string]::IsNullOrWhiteSpace($pick)) { return }

        $pickNum = 0
        if ([int]::TryParse($pick, [ref]$pickNum) -and $queryMap.ContainsKey($pickNum)) {
            $selected = $queryMap[$pickNum]
            $endpoint = $selected.Endpoint

            # Check for {param} placeholders and prompt
            $paramMatches = [regex]::Matches($endpoint, '\{([^}]+)\}')
            if ($paramMatches.Count -gt 0) {
                Write-Host ""
                Write-Host "  This endpoint requires parameters:" -ForegroundColor Yellow
                foreach ($m in $paramMatches) {
                    $paramName = $m.Groups[1].Value
                    $paramValue = Read-Host "  Enter $paramName"
                    if ([string]::IsNullOrWhiteSpace($paramValue)) {
                        Write-Host "  [!] Cancelled - parameter required." -ForegroundColor Red
                        $endpoint = $null
                        break
                    }
                    $endpoint = $endpoint.Replace($m.Value, $paramValue)
                }
            }

            if ($endpoint) {
                Write-Host ""
                Write-Host "  Running: $($selected.Name)" -ForegroundColor Cyan

                $result = Invoke-BHERequest -BaseUrl $BaseUrl -Endpoint $endpoint `
                    -RequestMethod "GET" -TokenId $TokenId -TokenKey $TokenKey
                Format-APIResult -Result $result

                Write-Host ""
                $exportChoice = Read-Host "  Export to CSV? (enter file path or press Enter to skip)"
                if (-not [string]::IsNullOrWhiteSpace($exportChoice)) {
                    Format-APIResult -Result $result -ExportPath $exportChoice
                }

                Write-Host ""
                Write-Host "  Press Enter to return to library..." -ForegroundColor DarkGray
                Read-Host | Out-Null
            }
        }
        else {
            Write-Host "  [!] Invalid selection." -ForegroundColor Red
        }
    }
}

# ============================================================================
# INTERACTIVE CONSOLE
# ============================================================================
function Start-InteractiveConsole {
    param(
        [string]$BaseUrl,
        [string]$TokenId,
        [string]$TokenKey
    )

    $cypherLib = Get-CypherLibrary
    $apiLib = Get-APILibrary

    while ($true) {
        Write-Host ""
        Write-Host "  ======================================================" -ForegroundColor Cyan
        Write-Host "               BHE Interactive Console                   " -ForegroundColor Cyan
        Write-Host "  ======================================================" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "   [0]  Quick Info (version, self, domains)             " -ForegroundColor White
        Write-Host ""
        Write-Host "   CYPHER" -ForegroundColor Yellow
        Write-Host "   [1]  Run a Cypher Query (from cypher.txt or manual) " -ForegroundColor White
        Write-Host "   [2]  Cypher Query Library (pre-built queries)       " -ForegroundColor White
        Write-Host ""
        Write-Host "   API" -ForegroundColor Green
        Write-Host "   [3]  Run an API Call (freeform)                     " -ForegroundColor White
        Write-Host "   [4]  API Endpoint Library (pre-built GET calls)     " -ForegroundColor White
        Write-Host ""
        Write-Host "   [Q]  Quit                                           " -ForegroundColor White
        Write-Host ""
        $choice = Read-Host "  Select option"

        switch ($choice.ToUpper()) {
            "0" {
                # Quick Info
                Write-Host ""
                Write-Host "  -- Quick Info -----------------------------------------------" -ForegroundColor DarkCyan
                Write-Host ""

                Write-Host "  [1/3] API Version" -ForegroundColor White
                $r = Invoke-BHERequest -BaseUrl $BaseUrl -Endpoint "/api/version" `
                    -TokenId $TokenId -TokenKey $TokenKey -Silent
                if ($r.Success) {
                    $ver = $r.Data
                    if ($ver.data.API.current_version) {
                        Write-Host "        API Version: $($ver.data.API.current_version)" -ForegroundColor Green
                    }
                    if ($ver.data.server_version) {
                        Write-Host "        Server Version: $($ver.data.server_version)" -ForegroundColor Green
                    }
                    else {
                        $ver | ConvertTo-Json -Depth 3 -Compress | Write-Host -ForegroundColor Green
                    }
                }
                else {
                    Write-Host "        [FAIL] Could not retrieve version" -ForegroundColor Red
                }

                Write-Host ""
                Write-Host "  [2/3] Authenticated User" -ForegroundColor White
                $r = Invoke-BHERequest -BaseUrl $BaseUrl -Endpoint "/api/v2/self" `
                    -TokenId $TokenId -TokenKey $TokenKey -Silent
                if ($r.Success) {
                    if ($r.Data.data) { $selfData = $r.Data.data } else { $selfData = $r.Data }
                    $displayName = "$($selfData.first_name) $($selfData.last_name)".Trim()
                    Write-Host "        Name: $displayName" -ForegroundColor Green
                    Write-Host "        Email: $($selfData.email_address)" -ForegroundColor Green
                    if ($selfData.roles) {
                        $roleList = $selfData.roles -join ', '
                        Write-Host "        Role: $roleList" -ForegroundColor Green
                    }
                }
                else {
                    Write-Host "        [FAIL] Could not retrieve user info" -ForegroundColor Red
                }

                Write-Host ""
                Write-Host "  [3/3] Available Domains" -ForegroundColor White
                $r = Invoke-BHERequest -BaseUrl $BaseUrl -Endpoint "/api/v2/available-domains" `
                    -TokenId $TokenId -TokenKey $TokenKey -Silent
                if ($r.Success) {
                    if ($r.Data.data) { $domains = $r.Data.data } else { $domains = $r.Data }
                    if ($domains -is [System.Array]) {
                        foreach ($d in $domains) {
                            if ($d.name) { $dName = $d.name }
                            elseif ($d.id) { $dName = $d.id }
                            else { $dName = $d.ToString() }
                            $dExtra = ""
                            if ($d.type) { $dExtra += " [$($d.type)]" }
                            if ($d.collected) { $dExtra += " Last: $($d.collected)" }
                            Write-Host "        - $dName$dExtra" -ForegroundColor Green
                        }
                    }
                    else {
                        $domains | ConvertTo-Json -Depth 3 | Write-Host -ForegroundColor Green
                    }
                }
                else {
                    Write-Host "        [FAIL] Could not retrieve domains" -ForegroundColor Red
                }

                Write-Host ""
                Write-Host "  ---------------------------------------------------------------" -ForegroundColor DarkCyan
            }

            "1" {
                # Freeform Cypher
                Write-Host ""

                # Check for cypher.txt in script directory
                $cypherFile = Join-Path $scriptDir "cypher.txt"
                if (-not $scriptDir) {
                    $cypherFile = Join-Path (Get-Location) "cypher.txt"
                }

                $query = $null

                if (Test-Path $cypherFile) {
                    $fileContent = (Get-Content $cypherFile -Raw -ErrorAction SilentlyContinue).Trim()
                    if (-not [string]::IsNullOrWhiteSpace($fileContent)) {
                        # Remove comment lines (starting with // or #)
                        $cleanLines = $fileContent -split "`n" | Where-Object {
                            $trimLine = $_.Trim()
                            -not $trimLine.StartsWith('//') -and -not $trimLine.StartsWith('#') -and -not [string]::IsNullOrWhiteSpace($trimLine)
                        }
                        $query = ($cleanLines -join "`n").Trim()

                        Write-Host "  [+] Loaded query from: $cypherFile" -ForegroundColor Green
                        # Show preview
                        $preview = if ($query.Length -gt 120) { $query.Substring(0, 120) + '...' } else { $query }
                        Write-Host "      $preview" -ForegroundColor DarkYellow
                        Write-Host ""
                        $confirm = Read-Host "  Run this query? [Y/n]"
                        if ($confirm -eq 'n' -or $confirm -eq 'N') {
                            Write-Host "  Skipped. You can also type a query manually:" -ForegroundColor DarkGray
                            $query = $null
                        }
                    }
                    else {
                        Write-Host "  [*] cypher.txt found but empty" -ForegroundColor DarkGray
                    }
                }
                else {
                    Write-Host "  [*] No cypher.txt found in: $cypherFile" -ForegroundColor DarkGray
                    Write-Host "      Tip: Paste your query into cypher.txt to avoid quoting issues" -ForegroundColor DarkGray
                }

                # Fall back to manual input if no file query
                if ([string]::IsNullOrWhiteSpace($query)) {
                    Write-Host ""
                    Write-Host "  Enter Cypher query (or 'back' to return):" -ForegroundColor Yellow
                    $query = Read-Host "  CYPHER>"
                }

                if ($query -eq 'back' -or [string]::IsNullOrWhiteSpace($query)) { continue }

                $result = Invoke-BHECypher -BaseUrl $BaseUrl -Query $query -TokenId $TokenId -TokenKey $TokenKey
                Format-APIResult -Result $result

                Write-Host ""
                $exportChoice = Read-Host "  Export to CSV? (enter file path or press Enter to skip)"
                if (-not [string]::IsNullOrWhiteSpace($exportChoice)) {
                    Format-APIResult -Result $result -ExportPath $exportChoice
                }
            }

            "2" {
                # Cypher Query Library
                Show-CypherLibrary -Library $cypherLib -BaseUrl $BaseUrl -TokenId $TokenId -TokenKey $TokenKey
            }

            "3" {
                # Freeform API
                Write-Host ""
                Write-Host "  HTTP Method [GET/POST/PUT/DELETE] (default: GET):" -ForegroundColor Yellow
                $apiMethod = Read-Host "  METHOD>"
                if ([string]::IsNullOrWhiteSpace($apiMethod)) { $apiMethod = "GET" }

                Write-Host "  Enter API endpoint (e.g., /api/v2/available-domains):" -ForegroundColor Yellow
                $endpoint = Read-Host "  API>"

                if ($endpoint -eq 'back' -or [string]::IsNullOrWhiteSpace($endpoint)) { continue }

                # Validate endpoint looks like an API path
                if ($endpoint -notmatch '^/') {
                    Write-Host "  [!] Endpoint must start with / (e.g., /api/v2/available-domains)" -ForegroundColor Red
                    Write-Host "      You entered: $endpoint" -ForegroundColor DarkRed
                    continue
                }

                $apiBody = ""
                if ($apiMethod.ToUpper() -in @("POST","PUT","PATCH")) {
                    Write-Host "  Request body (JSON):" -ForegroundColor Yellow
                    $apiBody = Read-Host "  BODY>"
                }

                $result = Invoke-BHERequest -BaseUrl $BaseUrl -Endpoint $endpoint `
                    -RequestMethod $apiMethod.ToUpper() -RequestBody $apiBody `
                    -TokenId $TokenId -TokenKey $TokenKey
                Format-APIResult -Result $result

                Write-Host ""
                $exportChoice = Read-Host "  Export to CSV? (enter file path or press Enter to skip)"
                if (-not [string]::IsNullOrWhiteSpace($exportChoice)) {
                    Format-APIResult -Result $result -ExportPath $exportChoice
                }
            }

            "4" {
                # API Endpoint Library
                Show-APILibrary -Library $apiLib -BaseUrl $BaseUrl -TokenId $TokenId -TokenKey $TokenKey
            }

            "Q" {
                Write-Host ""
                Write-Host "  [*] Exiting console. Goodbye!" -ForegroundColor Cyan
                Write-Host ""
                return
            }

            default {
                Write-Host "  [!] Invalid option. Try 0-4 or Q." -ForegroundColor Red
            }
        }
    }
}


# ============================================================================
# AUTHENTICATION TEST
# ============================================================================
function Test-Authentication {
    param(
        [string]$BaseUrl,
        [string]$TokenId,
        [string]$TokenKey
    )

    Write-Host "  -- Authentication Test -------------------------------------" -ForegroundColor DarkCyan
    Write-Host ""

    # Test 1: API Version (connectivity)
    Write-Host "  [1/2] Testing connectivity..." -ForegroundColor White
    $versionResult = Invoke-BHERequest -BaseUrl $BaseUrl -Endpoint "/api/version" `
        -TokenId $TokenId -TokenKey $TokenKey -Silent

    if ($versionResult.Success) {
        $ver = $versionResult.Data
        $apiVer = "OK"
        if ($ver.data.API.current_version) { $apiVer = $ver.data.API.current_version }
        Write-Host "        [PASS] API reachable - Version: $apiVer" -ForegroundColor Green
    }
    else {
        Write-Host "        [FAIL] Cannot reach API" -ForegroundColor Red
        Write-Host "        $($versionResult.Error)" -ForegroundColor DarkRed
        Write-Host ""
        Write-Host "  [!] Authentication test aborted - fix connectivity first." -ForegroundColor Red
        return $false
    }

    # Test 2: Self endpoint (auth validation)
    Write-Host "  [2/2] Testing authentication..." -ForegroundColor White
    $selfResult = Invoke-BHERequest -BaseUrl $BaseUrl -Endpoint "/api/v2/self" `
        -TokenId $TokenId -TokenKey $TokenKey -Silent

    if ($selfResult.Success) {
        if ($selfResult.Data.data) { $selfData = $selfResult.Data.data } else { $selfData = $selfResult.Data }
        $userName = "$($selfData.first_name) $($selfData.last_name)".Trim()
        $userEmail = $selfData.email_address
        Write-Host "        [PASS] Authenticated as: $userName ($userEmail)" -ForegroundColor Green
    }
    else {
        Write-Host "        [FAIL] Authentication failed" -ForegroundColor Red
        Write-Host "        $($selfResult.Error)" -ForegroundColor DarkRed
        Write-Host ""
        Write-Host "  Troubleshooting:" -ForegroundColor Yellow
        Write-Host "    1. Verify BHE_API_ID and BHE_API_KEY in your .env file" -ForegroundColor Yellow
        Write-Host "    2. Check if the API token has expired" -ForegroundColor Yellow
        Write-Host "    3. Ensure system clock is accurate - HMAC is time-sensitive" -ForegroundColor Yellow
        Write-Host "    4. Verify the tenant URL is correct" -ForegroundColor Yellow
        return $false
    }

    Write-Host ""
    Write-Host "  -- Authentication: SUCCESS ---------------------------------" -ForegroundColor Green
    Write-Host ""
    return $true
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

Show-Banner

# ── Load .env file ──
$envVars = @{}

if ($EnvFile) {
    # Explicit .env path provided
    if (Test-Path $EnvFile) {
        $envVars = Import-EnvFile -Path $EnvFile
    }
    else {
        Write-Host "  [!] Specified .env file not found: $EnvFile" -ForegroundColor Red
        exit 1
    }
}
else {
    # Auto-detect .env in script directory
    $scriptDir = $PSScriptRoot
    if (-not $scriptDir) { $scriptDir = Get-Location }
    $defaultEnv = Join-Path $scriptDir ".env"

    if (Test-Path $defaultEnv) {
        $envVars = Import-EnvFile -Path $defaultEnv
    }
    else {
        Write-Host "  [*] No .env file found in script directory" -ForegroundColor DarkGray
        Write-Host "      Expected: $defaultEnv" -ForegroundColor DarkGray
        Write-Host "      You can also pass credentials via -RestEndpoint, -TokenID, -Token" -ForegroundColor DarkGray
        Write-Host ""
    }
}

# ── Resolve credentials (params override .env) ──
if (-not $RestEndpoint -and $envVars.ContainsKey('BHE_URL')) {
    $RestEndpoint = $envVars['BHE_URL']
}
if (-not $TokenID -and $envVars.ContainsKey('BHE_API_ID')) {
    $TokenID = $envVars['BHE_API_ID']
}
if (-not $Token -and $envVars.ContainsKey('BHE_API_KEY')) {
    $Token = $envVars['BHE_API_KEY']
}

# ── Validate we have all required credentials ──
$missing = @()
if ([string]::IsNullOrWhiteSpace($RestEndpoint)) { $missing += 'BHE_URL / -RestEndpoint' }
if ([string]::IsNullOrWhiteSpace($TokenID))      { $missing += 'BHE_API_ID / -TokenID' }
if ([string]::IsNullOrWhiteSpace($Token))         { $missing += 'BHE_API_KEY / -Token' }

if ($missing.Count -gt 0) {
    Write-Host "  [!] Missing required credentials:" -ForegroundColor Red
    foreach ($m in $missing) {
        Write-Host "      - $m" -ForegroundColor Red
    }
    Write-Host ""
    Write-Host "  Create a .env file in the script directory with:" -ForegroundColor Yellow
    Write-Host '      BHE_API_ID="your-token-id"' -ForegroundColor Yellow
    Write-Host '      BHE_API_KEY="your-token-key"' -ForegroundColor Yellow
    Write-Host '      BHE_URL="https://tenant.bloodhoundenterprise.io"' -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Or pass credentials as parameters:" -ForegroundColor Yellow
    Write-Host '      .\BHE-API-Console.ps1 -RestEndpoint "tenant.bhe.io" -TokenID "abc" -Token "xyz"' -ForegroundColor Yellow
    Write-Host ""
    exit 1
}

$BaseUrl = Normalize-Url -Url $RestEndpoint

# ── Always run auth test first ──
$authSuccess = Test-Authentication -BaseUrl $BaseUrl -TokenId $TokenID -TokenKey $Token

if (-not $authSuccess) {
    Write-Host ""
    Write-Host "  [!] Exiting due to authentication failure." -ForegroundColor Red
    Write-Host ""
    exit 1
}

# ── Route based on mode ──
if ($API) {
    # Direct API Call
    Write-Host "  -- Direct API Call -----------------------------------------" -ForegroundColor DarkCyan
    Write-Host ""

    $result = Invoke-BHERequest -BaseUrl $BaseUrl -Endpoint $API `
        -RequestMethod $Method -RequestBody $Body `
        -TokenId $TokenID -TokenKey $Token

    Format-APIResult -Result $result -ExportPath $ExportCSV
}
elseif ($Cypher) {
    # Direct Cypher Query
    Write-Host "  -- Direct Cypher Query -------------------------------------" -ForegroundColor DarkCyan

    $result = Invoke-BHECypher -BaseUrl $BaseUrl -Query $Cypher `
        -TokenId $TokenID -TokenKey $Token

    Format-APIResult -Result $result -ExportPath $ExportCSV
}
elseif ($Interactive) {
    # Interactive Console
    Start-InteractiveConsole -BaseUrl $BaseUrl -TokenId $TokenID -TokenKey $Token
}
else {
    # Auth Only (default)
    Write-Host "  Tip: Use -API, -Cypher, or -Interactive for more!" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "  Examples:" -ForegroundColor DarkGray
    Write-Host '    .\BHE-API-Console.ps1 -API "/api/v2/available-domains"' -ForegroundColor DarkGray
    Write-Host '    .\BHE-API-Console.ps1 -Cypher "MATCH (n:User {enabled:true}) RETURN n.name LIMIT 10"' -ForegroundColor DarkGray
    Write-Host '    .\BHE-API-Console.ps1 -Interactive' -ForegroundColor DarkGray
}

Write-Host ""
