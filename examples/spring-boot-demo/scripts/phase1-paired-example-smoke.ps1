[CmdletBinding()]
param(
    [string] $IamIssuer = $(if ($env:IAM_ISSUER_URI) { $env:IAM_ISSUER_URI } else { "http://localhost:30001" }),
    [string] $ApiBaseUrl = $(if ($env:API_BASE_URL) { $env:API_BASE_URL } else { "http://localhost:8080" }),
    [string] $Token = $env:TOKEN
)

$ErrorActionPreference = "Stop"

function Join-Url {
    param(
        [Parameter(Mandatory = $true)][string] $Base,
        [Parameter(Mandatory = $true)][string] $Path
    )

    return $Base.TrimEnd("/") + "/" + $Path.TrimStart("/")
}

function Invoke-Status {
    param(
        [Parameter(Mandatory = $true)][string] $Name,
        [Parameter(Mandatory = $true)][string] $Uri,
        [string] $Method = "GET",
        [hashtable] $Headers = @{},
        [string] $Body = $null
    )

    try {
        $params = @{
            Uri = $Uri
            Method = $Method
            Headers = $Headers
        }
        if ($Body) {
            $params.ContentType = "application/json"
            $params.Body = $Body
        }
        $response = Invoke-WebRequest @params
        $status = [int] $response.StatusCode
    } catch {
        if ($_.Exception.Response -and $_.Exception.Response.StatusCode) {
            $status = [int] $_.Exception.Response.StatusCode
        } else {
            throw
        }
    }

    Write-Host ("{0}: HTTP {1}" -f $Name, $status)
    return $status
}

function Assert-Status {
    param(
        [Parameter(Mandatory = $true)][string] $Name,
        [Parameter(Mandatory = $true)][int] $Actual,
        [Parameter(Mandatory = $true)][int[]] $Expected
    )

    if ($Expected -notcontains $Actual) {
        throw ("{0} expected HTTP {1}, got {2}" -f $Name, ($Expected -join "/"), $Actual)
    }
}

$discoveryUrl = Join-Url $IamIssuer "/.well-known/openid-configuration"
$jwksUrl = Join-Url $IamIssuer "/oauth2/jwks"
$publicUrl = Join-Url $ApiBaseUrl "/public"
$protectedUrl = Join-Url $ApiBaseUrl "/posts"

Assert-Status "IAM discovery" (Invoke-Status "IAM discovery" $discoveryUrl) @(200)
Assert-Status "IAM JWKS" (Invoke-Status "IAM JWKS" $jwksUrl) @(200)
Assert-Status "Spring public endpoint" (Invoke-Status "Spring public endpoint" $publicUrl) @(200)
Assert-Status "Spring protected endpoint without token" (Invoke-Status "Spring protected endpoint without token" $protectedUrl) @(401, 403)

if ($Token) {
    $headers = @{ Authorization = "Bearer $Token" }
    Assert-Status "Spring protected endpoint with TOKEN" (Invoke-Status "Spring protected endpoint with TOKEN" $protectedUrl "GET" $headers) @(200)
} else {
    Write-Host "TOKEN is not set; skipping bearer-token success check."
}

Write-Host "Phase 1 paired example smoke completed."
