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
    [string]$ExportCSV
)

# ============================================================================
# BANNER
# ============================================================================
function Show-Banner {
    Write-Host ""
    Write-Host "  ======================================================" -ForegroundColor Cyan
    Write-Host "                                                        " -ForegroundColor Cyan
    Write-Host "           BHE API Console v1.1                         " -ForegroundColor Cyan
    Write-Host "           Authentication + Query Engine                 " -ForegroundColor Cyan
    Write-Host "                                                        " -ForegroundColor Cyan
    Write-Host "  ======================================================" -ForegroundColor Cyan
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

    $result = Invoke-BHERequest -BaseUrl $BaseUrl -Endpoint "/api/v2/graphs/cypher" `
        -RequestMethod "POST" -RequestBody $bodyJson -TokenId $TokenId -TokenKey $TokenKey -Silent:$Silent

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

    $data = $Result.Data
    Write-Host ""

    # ── Handle Cypher results (nodes/edges) ──
    if ($data.nodes -or $data.edges) {
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
    # ── Handle standard API responses (arrays/objects) ──
    else {
        $items = $null
        if ($data.data) { $items = $data.data }
        elseif ($data -is [System.Array]) { $items = $data }

        if ($items) {
            $itemCount = $items.Count
            Write-Host "  -------------------------------------------------" -ForegroundColor DarkCyan
            Write-Host "    API Results: $itemCount items" -ForegroundColor Cyan
            Write-Host "  -------------------------------------------------" -ForegroundColor DarkCyan
            Write-Host ""

            # Auto-detect columns from first item
            if ($items.Count -gt 0) {
                $sampleProps = @($items[0].PSObject.Properties | Select-Object -First 6)
                $displayObjects = @()

                $counter = 0
                foreach ($item in $items) {
                    $counter++
                    if ($counter -gt 100) {
                        $truncMsg = '  ... {0} total, showing first 100' -f $itemCount
                        Write-Host $truncMsg -ForegroundColor DarkGray
                        break
                    }

                    $obj = [ordered]@{ '#' = $counter }
                    foreach ($prop in $sampleProps) {
                        $val = $item.($prop.Name)
                        if ($val -is [System.Collections.ICollection]) {
                            $val = ($val | ForEach-Object { $_.ToString() }) -join ", "
                        }
                        $obj[$prop.Name] = $val
                    }
                    $displayObjects += [PSCustomObject]$obj
                }

                # Table display
                $displayObjects | Format-Table -AutoSize -Wrap | Out-String | Write-Host

                if ($ExportPath) {
                    Export-Results -Objects $displayObjects -Path $ExportPath
                }
            }
        }
        else {
            # Single object / raw response
            Write-Host "  -------------------------------------------------" -ForegroundColor DarkCyan
            Write-Host "    API Response" -ForegroundColor Cyan
            Write-Host "  -------------------------------------------------" -ForegroundColor DarkCyan
            Write-Host ""
            $data | ConvertTo-Json -Depth 5 | Write-Host -ForegroundColor White

            if ($ExportPath) {
                $data | ConvertTo-Json -Depth 5 | Out-File -FilePath $ExportPath -Encoding UTF8
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
# BUILT-IN QUERY LIBRARY
# ============================================================================
function Get-QueryLibrary {
    return @(
        @{
            Category    = "Tier Zero"
            Name        = "All Tier Zero Objects"
            Description = "List all Tier Zero / High Value assets"
            Type        = "Cypher"
            Query       = "MATCH (n) WHERE n.system_tags CONTAINS 'admin_tier_0' RETURN n"
        },
        @{
            Category    = "Tier Zero"
            Name        = "Tier Zero Users"
            Description = "List Tier Zero user accounts"
            Type        = "Cypher"
            Query       = "MATCH (n:User) WHERE n.system_tags CONTAINS 'admin_tier_0' RETURN n"
        },
        @{
            Category    = "Tier Zero"
            Name        = "Tier Zero Groups"
            Description = "List Tier Zero groups"
            Type        = "Cypher"
            Query       = "MATCH (n:Group) WHERE n.system_tags CONTAINS 'admin_tier_0' RETURN n"
        },
        @{
            Category    = "Tier Zero"
            Name        = "Tier Zero Computers"
            Description = "List Tier Zero computers (DCs, etc.)"
            Type        = "Cypher"
            Query       = "MATCH (n:Computer) WHERE n.system_tags CONTAINS 'admin_tier_0' RETURN n"
        },
        @{
            Category    = "Users"
            Name        = "Enabled Users (Sample)"
            Description = "First 25 enabled user accounts"
            Type        = "Cypher"
            Query       = "MATCH (u:User {enabled:true}) RETURN u LIMIT 25"
        },
        @{
            Category    = "Users"
            Name        = "Kerberoastable Users"
            Description = "Users with SPNs set (Kerberoastable)"
            Type        = "Cypher"
            Query       = "MATCH (u:User {enabled:true, hasspn:true}) RETURN u"
        },
        @{
            Category    = "Users"
            Name        = "AS-REP Roastable Users"
            Description = "Users that don't require Kerberos preauth"
            Type        = "Cypher"
            Query       = "MATCH (u:User {enabled:true, dontreqpreauth:true}) RETURN u"
        },
        @{
            Category    = "Users"
            Name        = "Unconstrained Delegation Users"
            Description = "Users trusted for unconstrained delegation"
            Type        = "Cypher"
            Query       = "MATCH (u:User {enabled:true, unconstraineddelegation:true}) RETURN u"
        },
        @{
            Category    = "Computers"
            Name        = "Unconstrained Delegation Computers"
            Description = "Computers trusted for unconstrained delegation (non-DCs)"
            Type        = "Cypher"
            Query       = "MATCH (c:Computer {unconstraineddelegation:true}) WHERE NOT c.system_tags CONTAINS 'admin_tier_0' RETURN c"
        },
        @{
            Category    = "Computers"
            Name        = "Domain Controllers"
            Description = "All Domain Controller computers"
            Type        = "Cypher"
            Query       = "MATCH (c:Computer) WHERE c.system_tags CONTAINS 'admin_tier_0' AND c.operatingsystem CONTAINS 'Server' RETURN c"
        },
        @{
            Category    = "Attack Paths"
            Name        = "Shortest Path to Domain Admins"
            Description = "Shortest paths from non-T0 to Domain Admins"
            Type        = "Cypher"
            Query       = "MATCH p=shortestPath((u:User {enabled:true})-[*1..]->(g:Group)) WHERE g.name STARTS WITH 'DOMAIN ADMINS@' AND NOT u.system_tags CONTAINS 'admin_tier_0' RETURN p LIMIT 10"
        },
        @{
            Category    = "Attack Paths"
            Name        = "Users with DCSync Rights"
            Description = "Non-T0 principals with DCSync capabilities"
            Type        = "Cypher"
            Query       = "MATCH p=(n)-[:DCSync|GetChanges|GetChangesAll|GetChangesInFilteredSet]->(d:Domain) WHERE NOT n.system_tags CONTAINS 'admin_tier_0' RETURN p"
        },
        @{
            Category    = "Sessions"
            Name        = "Active Sessions (Sample)"
            Description = "Recent session relationships"
            Type        = "Cypher"
            Query       = "MATCH p=(c:Computer)-[:HasSession]->(u:User) RETURN p LIMIT 25"
        },
        @{
            Category    = "API Endpoints"
            Name        = "Available Domains"
            Description = "List all domains collected in BHE"
            Type        = "API"
            Endpoint    = "/api/v2/available-domains"
            HttpMethod  = "GET"
        },
        @{
            Category    = "API Endpoints"
            Name        = "API Version"
            Description = "Check BHE API version"
            Type        = "API"
            Endpoint    = "/api/version"
            HttpMethod  = "GET"
        },
        @{
            Category    = "API Endpoints"
            Name        = "Self (Whoami)"
            Description = "Show current authenticated user info"
            Type        = "API"
            Endpoint    = "/api/v2/self"
            HttpMethod  = "GET"
        },
        @{
            Category    = "API Endpoints"
            Name        = "Asset Groups"
            Description = "List all asset groups"
            Type        = "API"
            Endpoint    = "/api/v2/asset-groups"
            HttpMethod  = "GET"
        },
        @{
            Category    = "API Endpoints"
            Name        = "Audit Logs"
            Description = "View recent audit log entries"
            Type        = "API"
            Endpoint    = "/api/v2/audit"
            HttpMethod  = "GET"
        },
        @{
            Category    = "API Endpoints"
            Name        = "Data Posture Stats"
            Description = "Overall posture statistics"
            Type        = "API"
            Endpoint    = "/api/v2/posture-stats"
            HttpMethod  = "GET"
        },
        @{
            Category    = "API Endpoints"
            Name        = "List Clients (Collectors)"
            Description = "Show registered SharpHound/AzureHound clients"
            Type        = "API"
            Endpoint    = "/api/v2/clients"
            HttpMethod  = "GET"
        },
        @{
            Category    = "API Endpoints"
            Name        = "File Upload Jobs"
            Description = "List recent file upload jobs"
            Type        = "API"
            Endpoint    = "/api/v2/file-upload"
            HttpMethod  = "GET"
        }
    )
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

    $library = Get-QueryLibrary

    while ($true) {
        Write-Host ""
        Write-Host "  ======================================================" -ForegroundColor Cyan
        Write-Host "               BHE Interactive Console                   " -ForegroundColor Cyan
        Write-Host "  ======================================================" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "   [1]  Run a Cypher Query (freeform)                   " -ForegroundColor White
        Write-Host "   [2]  Run an API Call (freeform)                      " -ForegroundColor White
        Write-Host "   [3]  Query Library (pre-built queries)               " -ForegroundColor White
        Write-Host "   [4]  Quick Info (version, self, domains)             " -ForegroundColor White
        Write-Host "   [Q]  Quit                                            " -ForegroundColor White
        Write-Host ""
        $choice = Read-Host "  Select option"

        switch ($choice.ToUpper()) {
            "1" {
                # Freeform Cypher
                Write-Host ""
                Write-Host "  Enter Cypher query (or 'back' to return):" -ForegroundColor Yellow
                Write-Host "  Tip: Enter full query on one line." -ForegroundColor DarkGray
                Write-Host ""
                $query = Read-Host "  CYPHER>"

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
                # Freeform API
                Write-Host ""
                Write-Host "  Enter API endpoint (e.g., /api/v2/available-domains):" -ForegroundColor Yellow
                $endpoint = Read-Host "  API>"

                if ($endpoint -eq 'back' -or [string]::IsNullOrWhiteSpace($endpoint)) { continue }

                Write-Host "  HTTP Method [GET/POST/PUT/DELETE] (default: GET):" -ForegroundColor Yellow
                $apiMethod = Read-Host "  METHOD>"
                if ([string]::IsNullOrWhiteSpace($apiMethod)) { $apiMethod = "GET" }

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

            "3" {
                # Query Library
                Show-QueryLibrary -Library $library -BaseUrl $BaseUrl -TokenId $TokenId -TokenKey $TokenKey
            }

            "4" {
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

            "Q" {
                Write-Host ""
                Write-Host "  [*] Exiting console. Goodbye!" -ForegroundColor Cyan
                Write-Host ""
                return
            }

            default {
                Write-Host "  [!] Invalid option. Try 1-4 or Q." -ForegroundColor Red
            }
        }
    }
}

# ============================================================================
# QUERY LIBRARY BROWSER
# ============================================================================
function Show-QueryLibrary {
    param(
        [array]$Library,
        [string]$BaseUrl,
        [string]$TokenId,
        [string]$TokenKey
    )

    while ($true) {
        # Group by category
        $categories = $Library | Group-Object { $_.Category } | Sort-Object Name

        Write-Host ""
        Write-Host "  -- Query Library -------------------------------------------" -ForegroundColor DarkCyan
        Write-Host ""

        $index = 1
        $queryMap = @{}
        foreach ($cat in $categories) {
            Write-Host "  [$($cat.Name)]" -ForegroundColor Magenta
            foreach ($q in $cat.Group) {
                if ($q.Type -eq "Cypher") { $typeTag = "CYP" } else { $typeTag = "API" }
                if ($q.Type -eq "Cypher") { $tagColor = "Yellow" } else { $tagColor = "Green" }
                $queryMap[$index] = $q

                $paddedIndex = $index.ToString().PadLeft(2)
                Write-Host "    $paddedIndex. " -ForegroundColor DarkGray -NoNewline
                Write-Host "[$typeTag] " -ForegroundColor $tagColor -NoNewline
                Write-Host "$($q.Name)" -ForegroundColor White -NoNewline
                Write-Host " - $($q.Description)" -ForegroundColor DarkGray
                $index++
            }
            Write-Host ""
        }

        Write-Host "  Enter query number to run (or 'back'):" -ForegroundColor Yellow
        $pick = Read-Host "  LIBRARY>"

        if ($pick -eq 'back' -or [string]::IsNullOrWhiteSpace($pick)) { return }

        $pickNum = 0
        if ([int]::TryParse($pick, [ref]$pickNum) -and $queryMap.ContainsKey($pickNum)) {
            $selected = $queryMap[$pickNum]

            Write-Host ""
            Write-Host "  Running: $($selected.Name)" -ForegroundColor Cyan

            if ($selected.Type -eq "Cypher") {
                Write-Host "  Query: $($selected.Query)" -ForegroundColor DarkYellow
                $result = Invoke-BHECypher -BaseUrl $BaseUrl -Query $selected.Query `
                    -TokenId $TokenId -TokenKey $TokenKey
            }
            else {
                $result = Invoke-BHERequest -BaseUrl $BaseUrl -Endpoint $selected.Endpoint `
                    -RequestMethod $selected.HttpMethod -TokenId $TokenId -TokenKey $TokenKey
            }

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
