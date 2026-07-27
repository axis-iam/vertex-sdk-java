[CmdletBinding()]
param(
    [string] $IamServer = $(if ($env:IAM_SERVER_URL) { $env:IAM_SERVER_URL } else { "http://localhost:30001" }),
    [string] $IamPortal = $(if ($env:IAM_PORTAL_URL) { $env:IAM_PORTAL_URL } else { "http://localhost:30002" }),
    [string] $PortalClientId = $(if ($env:IAM_PORTAL_CLIENT_ID) { $env:IAM_PORTAL_CLIENT_ID } else { "iam_bBUvJ4IoeQcN9Qg-flyF6sIh" }),
    [string] $AdminEmail = $(if ($env:IAM_E2E_ADMIN_EMAIL) { $env:IAM_E2E_ADMIN_EMAIL } else { "admin@example.com" }),
    [string] $AdminPassword = $env:IAM_E2E_ADMIN_PASSWORD,
    [string] $ApiBaseUrl = $(if ($env:API_BASE_URL) { $env:API_BASE_URL } else { "http://localhost:8080" }),
    [string] $SpaBaseUrl = $(if ($env:VITE_DEV_ORIGIN) { $env:VITE_DEV_ORIGIN } else { "http://localhost:5173" }),
    [string] $ReportDir = $(if ($env:PHASE1_LIVE_E2E_REPORT_DIR) { $env:PHASE1_LIVE_E2E_REPORT_DIR } else { (Join-Path $env:TEMP "phase1-live-paired-example-e2e") }),
    [switch] $SkipReact,
    [switch] $SkipBrowserCheck,
    [switch] $KeepApplication,
    [switch] $KeepProcesses
)

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($AdminPassword)) {
    throw "Set IAM_E2E_ADMIN_PASSWORD to the local Portal developer password before running live provisioning."
}

$RunId = "p1-sdk-live-" + (Get-Date -Format "yyyyMMddHHmmss")
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$SpringDir = Split-Path -Parent $ScriptDir
$SdkJavaDir = (Resolve-Path (Join-Path $SpringDir "..\..")).Path
$SdkRoot = (Resolve-Path (Join-Path $SdkJavaDir "..")).Path
$ReactDir = Join-Path $SdkRoot "sdk-js\examples\react-demo"
$SmokeScript = Join-Path $ScriptDir "phase1-paired-example-smoke.ps1"

$RunReportDir = Join-Path $ReportDir $RunId
New-Item -ItemType Directory -Force -Path $RunReportDir | Out-Null
$ReportPath = Join-Path $RunReportDir "redacted-report.json"
$SpringOut = Join-Path $RunReportDir "spring-boot-demo.out.log"
$SpringErr = Join-Path $RunReportDir "spring-boot-demo.err.log"
$ReactOut = Join-Path $RunReportDir "react-demo.out.log"
$ReactErr = Join-Path $RunReportDir "react-demo.err.log"
$CdpScript = Join-Path $RunReportDir "react-login-cdp.mjs"

function ConvertTo-JsonBody {
    param($Value)
    $Value | ConvertTo-Json -Depth 80 -Compress
}

function Invoke-Api {
    param(
        [Parameter(Mandatory = $true)][string] $Method,
        [Parameter(Mandatory = $true)][string] $Uri,
        $Body = $null,
        [string] $Token = $null,
        [hashtable] $Headers = @{},
        [string] $ContentType = "application/json"
    )

    $allHeaders = @{}
    foreach ($key in $Headers.Keys) {
        $allHeaders[$key] = $Headers[$key]
    }
    if ($Token) {
        $allHeaders["Authorization"] = "Bearer $Token"
    }

    $params = @{
        Method = $Method
        Uri = $Uri
        Headers = $allHeaders
        TimeoutSec = 45
        SkipHttpErrorCheck = $true
    }
    if ($null -ne $Body) {
        $params["Body"] = if ($Body -is [string]) { $Body } else { ConvertTo-JsonBody $Body }
        if ($ContentType) {
            $params["ContentType"] = $ContentType
        }
    }

    $response = Invoke-WebRequest @params
    $content = if ($response.Content -is [byte[]]) {
        [Text.Encoding]::UTF8.GetString($response.Content)
    } else {
        [string] $response.Content
    }
    $parsed = $null
    if (-not [string]::IsNullOrWhiteSpace($content)) {
        try {
            $parsed = $content | ConvertFrom-Json
        } catch {
            $parsed = $content
        }
    }

    [pscustomobject]@{
        status = [int] $response.StatusCode
        body = $parsed
        text = $content
        headers = $response.Headers
        responseUri = $response.BaseResponse.ResponseUri.AbsoluteUri
    }
}

function Assert-Status {
    param($Response, [int[]] $Expected, [string] $Name)
    if ($Expected -notcontains [int] $Response.status) {
        throw "$Name expected HTTP $($Expected -join '/') but got $($Response.status): $($Response.text)"
    }
}

function Assert-Check {
    param([bool] $Condition, [string] $Message)
    if (-not $Condition) {
        throw "ASSERT failed: $Message"
    }
}

function Get-ClientResponseBody {
    param($ResponseBody)
    if ($ResponseBody -and $ResponseBody.PSObject.Properties.Name -contains "client") {
        return $ResponseBody.client
    }
    return $ResponseBody
}

function Get-ClientSecret {
    param($ResponseBody)
    if ($ResponseBody -and $ResponseBody.PSObject.Properties.Name -contains "clientSecret") {
        return [string] $ResponseBody.clientSecret
    }
    return $null
}

function Get-PagedItems {
    param($ResponseBody)
    if ($ResponseBody -and $ResponseBody.PSObject.Properties.Name -contains "content") {
        return @($ResponseBody.content)
    }
    return @($ResponseBody)
}

function New-QueryString {
    param([hashtable] $Params)
    ($Params.GetEnumerator() | ForEach-Object {
        [uri]::EscapeDataString([string] $_.Key) + "=" + [uri]::EscapeDataString([string] $_.Value)
    }) -join "&"
}

function Decode-JwtPart {
    param([string] $Jwt, [int] $Index)
    if ([string]::IsNullOrWhiteSpace($Jwt)) {
        return $null
    }
    $parts = $Jwt.Split(".")
    if ($parts.Count -le $Index) {
        return $null
    }
    $encoded = $parts[$Index].Replace("-", "+").Replace("_", "/")
    switch ($encoded.Length % 4) {
        2 { $encoded += "==" }
        3 { $encoded += "=" }
    }
    [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($encoded)) | ConvertFrom-Json
}

function Wait-HttpStatus {
    param(
        [Parameter(Mandatory = $true)][string] $Uri,
        [Parameter(Mandatory = $true)][int[]] $Expected,
        [Parameter(Mandatory = $true)][int] $TimeoutSeconds,
        [Parameter(Mandatory = $true)][string] $Name
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $last = $null
    while ((Get-Date) -lt $deadline) {
        try {
            $response = Invoke-Api -Method Get -Uri $Uri
            $last = $response.status
            if ($Expected -contains $response.status) {
                return $response
            }
        } catch {
            $last = $_.Exception.Message
        }
        Start-Sleep -Seconds 2
    }
    throw "$Name did not reach HTTP $($Expected -join '/') within ${TimeoutSeconds}s; last=$last"
}

function Get-HeaderValue {
    param($Headers, [string] $Name)
    return (@($Headers[$Name]) -join ",")
}

function Wait-IamDiscoveryCors {
    param(
        [Parameter(Mandatory = $true)][string] $Origin,
        [int] $TimeoutSeconds = 90
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $attempts = 0
    $last = $null
    while ((Get-Date) -lt $deadline) {
        $attempts++
        $response = Invoke-WebRequest -Uri "$IamServer/.well-known/openid-configuration" -Headers @{
            Origin = $Origin
        } -SkipHttpErrorCheck -TimeoutSec 20
        $allowOrigin = Get-HeaderValue $response.Headers "Access-Control-Allow-Origin"
        $allowed = -not [string]::IsNullOrWhiteSpace($allowOrigin) -and ($allowOrigin -eq "*" -or $allowOrigin -eq $Origin)
        $last = [ordered]@{
            status = [int] $response.StatusCode
            origin = $Origin
            accessControlAllowOrigin = if ([string]::IsNullOrWhiteSpace($allowOrigin)) { $null } else { $allowOrigin }
            allowed = $allowed
            attempts = $attempts
        }
        if ($allowed) {
            return $last
        }
        Start-Sleep -Seconds 3
    }

    return $last
}

function Stop-ProcessTree {
    param([int] $RootPid)
    if ($RootPid -le 0) {
        return
    }
    $children = @(Get-CimInstance Win32_Process -Filter "ParentProcessId=$RootPid" -ErrorAction SilentlyContinue)
    foreach ($child in $children) {
        Stop-ProcessTree -RootPid ([int] $child.ProcessId)
    }
    Stop-Process -Id $RootPid -Force -ErrorAction SilentlyContinue
}

function Test-PortFree {
    param([int] $Port, [string] $Name)
    $listeners = @(Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue)
    if ($listeners.Count -gt 0) {
        $owners = $listeners | ForEach-Object { $_.OwningProcess } | Sort-Object -Unique
        throw "$Name port $Port is already in use by pid(s): $($owners -join ', ')"
    }
}

function Poll-PostPermissions {
    param([string] $AppId, [string] $PortalToken)
    $deadline = (Get-Date).AddSeconds(80)
    while ((Get-Date) -lt $deadline) {
        $list = Invoke-Api -Method Get -Uri "$IamPortal/portal/v1/apps/$AppId/permissions?size=100" -Token $PortalToken
        if ($list.status -eq 200) {
            $items = Get-PagedItems $list.body
            $posts = @($items | Where-Object { $_.resource -eq "posts" -and ($_.action -eq "read" -or $_.action -eq "write") })
            if (@($posts | Where-Object { $_.action -eq "read" }).Count -gt 0 -and @($posts | Where-Object { $_.action -eq "write" }).Count -gt 0) {
                return $posts
            }
        }
        Start-Sleep -Seconds 2
    }
    throw "posts:read/posts:write permissions were not visible through Portal after Spring startup"
}

function Invoke-DirectLogin {
    param([string] $ClientId, [string] $Email, [string] $Password)
    Invoke-Api -Method Post -Uri "$IamServer/api/v1/auth/login" -Body @{
        identifier = $Email
        password = $Password
        client_id = $ClientId
    }
}

function Invoke-PhaseSmoke {
    param([string] $Token = $null)
    $oldToken = $env:TOKEN
    try {
        if ($Token) {
            $env:TOKEN = $Token
        } else {
            Remove-Item Env:\TOKEN -ErrorAction SilentlyContinue
        }
        $output = & pwsh -NoProfile -ExecutionPolicy Bypass -File $SmokeScript -IamIssuer $IamServer -ApiBaseUrl $ApiBaseUrl 2>&1
        if ($LASTEXITCODE -ne 0) {
            throw "phase1-paired-example-smoke.ps1 failed: $($output -join "`n")"
        }
        return ($output -join "`n")
    } finally {
        if ($null -ne $oldToken) {
            $env:TOKEN = $oldToken
        } else {
            Remove-Item Env:\TOKEN -ErrorAction SilentlyContinue
        }
    }
}

function Invoke-ReactBrowserCheck {
    param([string] $UserEmail, [string] $UserPassword)

    $chrome = "C:\Program Files\Google\Chrome\Application\chrome.exe"
    if (-not (Test-Path -LiteralPath $chrome)) {
        $chrome = "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
    }
    if (-not (Test-Path -LiteralPath $chrome)) {
        return @{
            skipped = $true
            reason = "Chrome or Edge executable was not found"
        }
    }

    $cdpPort = 9333
    Test-PortFree -Port $cdpPort -Name "Chrome DevTools"
    $profile = Join-Path $RunReportDir "chrome-profile"
    New-Item -ItemType Directory -Force -Path $profile | Out-Null
    $chromeProcess = $null
    try {
        $chromeProcess = Start-Process -FilePath $chrome -ArgumentList @(
            "--headless=new",
            "--remote-debugging-port=$cdpPort",
            "--user-data-dir=$profile",
            "--disable-gpu",
            "--disable-extensions",
            "about:blank"
        ) -WindowStyle Hidden -PassThru
        Start-Sleep -Seconds 2

        @'
const port = Number(process.env.CDP_PORT || "9333");
const targetUrl = process.env.REACT_TARGET_URL || "http://localhost:5173";
const targetOrigin = new URL(targetUrl).origin;
const iamOrigin = process.env.REACT_IAM_ORIGIN || "http://localhost:30001";
const loginEmail = process.env.REACT_LOGIN_EMAIL || "";
const loginPassword = process.env.REACT_LOGIN_PASSWORD || "";

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function callJson(url, init) {
  const response = await fetch(url, init);
  if (!response.ok) throw new Error(`${url} -> ${response.status}`);
  return response.json();
}

const tab = await callJson(`http://127.0.0.1:${port}/json/new?${encodeURIComponent(targetUrl)}`, { method: "PUT" });
const ws = new WebSocket(tab.webSocketDebuggerUrl);
const pending = new Map();
const consoleMessages = [];
const exceptions = [];
const logEntries = [];
let id = 0;

ws.onmessage = (event) => {
  const message = JSON.parse(event.data);
  if (message.method === "Runtime.consoleAPICalled") {
    consoleMessages.push({
      type: message.params.type,
      text: message.params.args.map((arg) => arg.value ?? arg.description ?? "").join(" "),
    });
  }
  if (message.method === "Runtime.exceptionThrown") {
    exceptions.push({
      text: message.params.exceptionDetails.text,
      description: message.params.exceptionDetails.exception?.description ?? "",
    });
  }
  if (message.method === "Log.entryAdded") {
    logEntries.push(message.params.entry);
  }
  if (message.id && pending.has(message.id)) {
    const { resolve, reject } = pending.get(message.id);
    pending.delete(message.id);
    if (message.error) reject(new Error(JSON.stringify(message.error)));
    else resolve(message);
  }
};

await new Promise((resolve, reject) => {
  ws.onopen = resolve;
  ws.onerror = reject;
});

function send(method, params = {}) {
  return new Promise((resolve, reject) => {
    const next = ++id;
    pending.set(next, { resolve, reject });
    ws.send(JSON.stringify({ id: next, method, params }));
  });
}

async function evalValue(expression) {
  const message = await send("Runtime.evaluate", {
    expression,
    returnByValue: true,
    awaitPromise: true,
  });
  return message.result.result.value;
}

async function waitFor(expression, timeoutMs, label) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      if (await evalValue(expression)) return true;
    } catch {}
    await sleep(500);
  }
  const href = await evalValue("location.href").catch(() => "");
  const text = await evalValue("document.body ? document.body.innerText : ''").catch(() => "");
  throw new Error(`Timed out waiting for ${label}; href=${href}; text=${text.slice(0, 200)}`);
}

await send("Page.enable");
await send("Runtime.enable");
await send("Log.enable");
await waitFor(
  "document.body && document.body.innerText.includes('My App') && document.body.innerText.includes('Sign in')",
  20000,
  "React sign-in screen"
);
const initialText = await evalValue("document.body.innerText");
await evalValue("Array.from(document.querySelectorAll('button')).find((b) => b.textContent.trim() === 'Sign in')?.click(); true");
let redirectError = null;
let loginPageHref = null;
let loginPageText = "";
try {
  await waitFor(
    `location.href.startsWith(${JSON.stringify(iamOrigin)}) && document.body && /Sign in|登录|password|client_id/i.test(document.body.innerText + document.body.innerHTML)`,
    25000,
    "IAM login redirect"
  );
  loginPageHref = await evalValue("location.href");
  loginPageText = await evalValue("document.body.innerText");
} catch (error) {
  redirectError = error.message;
}

let consentApproved = false;
let callbackError = null;
let dashboardHref = null;
let dashboardHasDashboard = false;
let apiSmoke = { passed: false, publicStatus: null, postsStatus: null, error: null };

if (redirectError === null) {
  try {
    await waitFor("document.querySelector('#username') && document.querySelector('#password')", 10000, "IAM password form");
    await evalValue(`(() => {
      const username = document.querySelector("#username");
      const password = document.querySelector("#password");
      username.value = ${JSON.stringify(loginEmail)};
      password.value = ${JSON.stringify(loginPassword)};
      username.dispatchEvent(new Event("input", { bubbles: true }));
      password.dispatchEvent(new Event("input", { bubbles: true }));
      const form = document.querySelector("#form-password");
      if (form?.requestSubmit) form.requestSubmit();
      else document.querySelector("#btn-password-submit")?.click();
      return true;
    })()`);
    await waitFor(
      `location.origin === ${JSON.stringify(targetOrigin)} || (document.body && document.body.innerText.includes("Authorize access"))`,
      45000,
      "React callback or consent"
    );

    const afterPasswordText = await evalValue("document.body ? document.body.innerText : ''");
    if (afterPasswordText.includes("Authorize access")) {
      consentApproved = true;
      await evalValue(`Array.from(document.querySelectorAll('button')).find((button) => button.name === 'consent_action' && button.value === 'approve')?.click(); true`);
    }

    await waitFor(
      `location.origin === ${JSON.stringify(targetOrigin)} && document.body && document.body.innerText.includes("Dashboard")`,
      45000,
      "React dashboard after callback"
    );
    dashboardHref = await evalValue("location.href");
    dashboardHasDashboard = await evalValue("document.body.innerText.includes('Dashboard')");
  } catch (error) {
    callbackError = error.message;
  }
}

if (redirectError === null && callbackError === null) {
  try {
    await waitFor("!!document.querySelector('[data-testid=\"api-smoke-panel\"]')", 10000, "React API smoke panel");
    await evalValue("document.querySelector('[data-testid=\"fetch-public\"]')?.click(); true");
    await waitFor("document.querySelector('[data-testid=\"api-public-status\"]')?.textContent.includes('200')", 20000, "React /public fetch 200");
    const publicStatus = await evalValue("document.querySelector('[data-testid=\"api-public-status\"]')?.textContent || ''");

    await evalValue("document.querySelector('[data-testid=\"fetch-posts\"]')?.click(); true");
    await waitFor("document.querySelector('[data-testid=\"api-posts-status\"]')?.textContent.includes('200')", 20000, "React /posts fetch 200");
    const postsStatus = await evalValue("document.querySelector('[data-testid=\"api-posts-status\"]')?.textContent || ''");

    apiSmoke = {
      passed: true,
      publicStatus,
      postsStatus,
      error: null,
    };
  } catch (error) {
    apiSmoke = {
      passed: false,
      publicStatus: await evalValue("document.querySelector('[data-testid=\"api-public-status\"]')?.textContent || ''").catch(() => ""),
      postsStatus: await evalValue("document.querySelector('[data-testid=\"api-posts-status\"]')?.textContent || ''").catch(() => ""),
      error: error.message,
    };
  }
}

console.log(JSON.stringify({
  passed: redirectError === null && callbackError === null && apiSmoke.passed,
  initialHasMyApp: initialText.includes("My App"),
  initialHasSignIn: initialText.includes("Sign in"),
  loginPageHref,
  loginPageHasMarker: /Sign in|登录|password|client_id/i.test(loginPageText),
  consentApproved,
  dashboardHref,
  dashboardHasDashboard,
  apiSmoke,
  redirectError,
  callbackError,
  consoleMessages,
  exceptions,
  logEntries,
}, null, 2));
ws.close();
'@ | Set-Content -LiteralPath $CdpScript -Encoding UTF8

        $oldPort = $env:CDP_PORT
        $oldTarget = $env:REACT_TARGET_URL
        $oldIamOrigin = $env:REACT_IAM_ORIGIN
        $oldLoginEmail = $env:REACT_LOGIN_EMAIL
        $oldLoginPassword = $env:REACT_LOGIN_PASSWORD
        try {
            $env:CDP_PORT = [string] $cdpPort
            $env:REACT_TARGET_URL = $SpaBaseUrl
            $env:REACT_IAM_ORIGIN = ([uri] $IamServer).GetLeftPart([System.UriPartial]::Authority)
            $env:REACT_LOGIN_EMAIL = $UserEmail
            $env:REACT_LOGIN_PASSWORD = $UserPassword
            $raw = node $CdpScript 2>&1
            if ($LASTEXITCODE -ne 0) {
                throw ($raw -join "`n")
            }
            return ($raw -join "`n") | ConvertFrom-Json
        } finally {
            if ($null -ne $oldPort) { $env:CDP_PORT = $oldPort } else { Remove-Item Env:\CDP_PORT -ErrorAction SilentlyContinue }
            if ($null -ne $oldTarget) { $env:REACT_TARGET_URL = $oldTarget } else { Remove-Item Env:\REACT_TARGET_URL -ErrorAction SilentlyContinue }
            if ($null -ne $oldIamOrigin) { $env:REACT_IAM_ORIGIN = $oldIamOrigin } else { Remove-Item Env:\REACT_IAM_ORIGIN -ErrorAction SilentlyContinue }
            if ($null -ne $oldLoginEmail) { $env:REACT_LOGIN_EMAIL = $oldLoginEmail } else { Remove-Item Env:\REACT_LOGIN_EMAIL -ErrorAction SilentlyContinue }
            if ($null -ne $oldLoginPassword) { $env:REACT_LOGIN_PASSWORD = $oldLoginPassword } else { Remove-Item Env:\REACT_LOGIN_PASSWORD -ErrorAction SilentlyContinue }
        }
    } finally {
        if ($chromeProcess) {
            Stop-ProcessTree -RootPid $chromeProcess.Id
        }
    }
}

function Save-Report {
    $Report.finishedAt = (Get-Date).ToString("o")
    $Report | ConvertTo-Json -Depth 100 | Set-Content -LiteralPath $ReportPath -Encoding UTF8
}

$Report = [ordered]@{
    runId = $RunId
    startedAt = (Get-Date).ToString("o")
    inputs = [ordered]@{
        iamServer = $IamServer
        iamPortal = $IamPortal
        apiBaseUrl = $ApiBaseUrl
        spaBaseUrl = $SpaBaseUrl
        adminEmail = $AdminEmail
        adminPassword = "<redacted>"
    }
    branch = [ordered]@{
        sdkJava = (git -C $SdkJavaDir branch --show-current)
        sdkJs = (git -C (Join-Path $SdkRoot "sdk-js") branch --show-current)
    }
    checks = [ordered]@{}
    provisioning = [ordered]@{}
    spring = [ordered]@{}
    smoke = [ordered]@{}
    react = [ordered]@{}
    cleanup = [ordered]@{}
    logs = [ordered]@{
        springOut = $SpringOut
        springErr = $SpringErr
        reactOut = $ReactOut
        reactErr = $ReactErr
    }
    blockers = @()
}

$appId = $null
$portalToken = $null
$springProcess = $null
$reactProcess = $null
$webClientSecret = $null
$oldEnv = @{
    IAM_ENDPOINT = $env:IAM_ENDPOINT
    IAM_CLIENT_ID = $env:IAM_CLIENT_ID
    IAM_CLIENT_SECRET = $env:IAM_CLIENT_SECRET
    SERVER_PORT = $env:SERVER_PORT
    VITE_IAM_CLIENT_ID = $env:VITE_IAM_CLIENT_ID
    VITE_IAM_ISSUER_URI = $env:VITE_IAM_ISSUER_URI
    VITE_IAM_REDIRECT_URI = $env:VITE_IAM_REDIRECT_URI
    VITE_API_BASE_URL = $env:VITE_API_BASE_URL
}

try {
    Test-PortFree -Port 8080 -Name "Spring Boot demo"
    if (-not $SkipReact) {
        Test-PortFree -Port 5173 -Name "React demo"
    }

    foreach ($item in @(
        @{ name = "iam-server health"; uri = "$IamServer/actuator/health" },
        @{ name = "iam-portal health"; uri = "$IamPortal/actuator/health" },
        @{ name = "OIDC discovery"; uri = "$IamServer/.well-known/openid-configuration" },
        @{ name = "JWKS"; uri = "$IamServer/oauth2/jwks" }
    )) {
        $response = Invoke-Api -Method Get -Uri $item.uri
        Assert-Status $response @(200) $item.name
        $Report.checks[$item.name] = @{ status = $response.status }
    }

    $portalLogin = Invoke-Api -Method Post -Uri "$IamServer/api/v1/auth/login" -Body @{
        identifier = $AdminEmail
        password = $AdminPassword
        client_id = $PortalClientId
    }
    Assert-Status $portalLogin @(200) "Portal login"
    $portalToken = $portalLogin.body.access_token
    $Report.checks.portalLogin = @{ status = 200; token = "<redacted>" }

    $app = Invoke-Api -Method Post -Uri "$IamPortal/portal/v1/apps" -Token $portalToken -Body @{
        name = "phase1-live-paired-example-e2e-$RunId"
        description = "Temporary SDK paired example live E2E application"
        frontendOrigins = @($SpaBaseUrl)
    }
    Assert-Status $app @(201) "Application create"
    $appId = $app.body.id

    $spaRedirectUri = "$SpaBaseUrl/callback"
    $spa = Invoke-Api -Method Post -Uri "$IamPortal/portal/v1/apps/$appId/clients" -Token $portalToken -Body @{
        name = "Phase1 Live React SPA"
        clientType = "SPA"
        grantTypes = @("authorization_code", "refresh_token")
        redirectUris = @($spaRedirectUri)
        allowedOrigins = @($SpaBaseUrl)
        postLogoutRedirectUris = @("$SpaBaseUrl/")
    }
    Assert-Status $spa @(201) "SPA client create"
    $spaClient = Get-ClientResponseBody $spa.body

    $web = Invoke-Api -Method Post -Uri "$IamPortal/portal/v1/apps/$appId/clients" -Token $portalToken -Body @{
        name = "Phase1 Live Spring API"
        clientType = "WEB"
        grantTypes = @("authorization_code", "refresh_token")
        redirectUris = @("$ApiBaseUrl/callback")
        allowedOrigins = @($ApiBaseUrl)
        postLogoutRedirectUris = @("$ApiBaseUrl/")
    }
    Assert-Status $web @(201) "WEB client create"
    $webClient = Get-ClientResponseBody $web.body
    $webClientSecret = Get-ClientSecret $web.body
    Assert-Check ($webClientSecret -and $webClientSecret.Length -gt 10) "WEB client did not return one-time secret"

    $userEmail = "phase1-live-user-$RunId@example.com"
    $userPassword = "Tmp-$([Guid]::NewGuid().ToString("N"))!A1"
    $user = Invoke-Api -Method Post -Uri "$IamPortal/portal/v1/apps/$appId/users" -Token $portalToken -Body @{
        email = $userEmail
        username = "phase1-live-$RunId"
        password = $userPassword
    }
    Assert-Status $user @(201) "App user create"
    $userId = $user.body.id

    $Report.provisioning = [ordered]@{
        applicationId = $appId
        spaClientRecordId = $spaClient.id
        spaClientId = $spaClient.clientId
        webClientRecordId = $webClient.id
        webClientId = $webClient.clientId
        webClientSecret = "<redacted>"
        appUserId = $userId
        appUserEmail = $userEmail
        appUserPassword = "<redacted>"
        redirectUri = $spaRedirectUri
        allowedOrigin = $SpaBaseUrl
    }

    $env:IAM_ENDPOINT = $IamServer
    $env:IAM_CLIENT_ID = $webClient.clientId
    $env:IAM_CLIENT_SECRET = $webClientSecret
    $env:SERVER_PORT = "8080"
    $springProcess = Start-Process -FilePath "cmd.exe" -ArgumentList @("/c", "..\..\gradlew.bat", "bootRun") -WorkingDirectory $SpringDir -RedirectStandardOutput $SpringOut -RedirectStandardError $SpringErr -WindowStyle Hidden -PassThru
    $Report.spring.processId = $springProcess.Id
    Wait-HttpStatus -Uri "$ApiBaseUrl/public" -Expected @(200) -TimeoutSeconds 140 -Name "Spring public endpoint" | Out-Null
    $Report.spring.publicEndpoint = 200

    $postPermissions = Poll-PostPermissions -AppId $appId -PortalToken $portalToken
    $readPermission = @($postPermissions | Where-Object { $_.action -eq "read" } | Select-Object -First 1)[0]
    $writePermission = @($postPermissions | Where-Object { $_.action -eq "write" } | Select-Object -First 1)[0]
    $role = Invoke-Api -Method Post -Uri "$IamPortal/portal/v1/apps/$appId/roles" -Token $portalToken -Body @{
        key = "posts-reader-$RunId"
        name = "Posts Reader $RunId"
        description = "Temporary role for live SDK smoke"
    }
    Assert-Status $role @(201) "Role create"
    $roleId = $role.body.id
    $rolePermissions = Invoke-Api -Method Put -Uri "$IamPortal/portal/v1/apps/$appId/roles/$roleId/permissions" -Token $portalToken -Body @{
        permissionIds = @($readPermission.id)
    }
    Assert-Status $rolePermissions @(200) "Role permission assignment"
    $assignment = Invoke-Api -Method Post -Uri "$IamPortal/portal/v1/apps/$appId/user-roles" -Token $portalToken -Body @{
        userId = $userId
        roleId = $roleId
    }
    Assert-Status $assignment @(201) "User role assignment"
    $Report.spring.permissions = [ordered]@{
        upsertedBySpring = $true
        postsReadPermissionId = $readPermission.id
        postsWritePermissionId = $writePermission.id
        roleId = $roleId
        userRoleAssigned = $true
    }

    $Report.smoke.withoutToken = Invoke-PhaseSmoke

    $login = Invoke-DirectLogin -ClientId $spaClient.clientId -Email $userEmail -Password $userPassword
    if ($login.status -ne 200) {
        $Report.smoke.spaDirectLoginStatus = $login.status
        $login = Invoke-DirectLogin -ClientId $webClient.clientId -Email $userEmail -Password $userPassword
    }
    Assert-Status $login @(200) "Direct login for bearer smoke"
    $accessToken = $login.body.access_token
    Assert-Check ($accessToken -and $accessToken.Split(".").Count -eq 3) "Direct login did not return a JWT access token"
    $tokenHeader = Decode-JwtPart -Jwt $accessToken -Index 0
    $tokenClaims = Decode-JwtPart -Jwt $accessToken -Index 1
    $permissionsCheck = Invoke-Api -Method Get -Uri "$IamServer/api/v1/auth/me/permissions" -Headers @{
        Authorization = "Bearer $accessToken"
    }
    Assert-Status $permissionsCheck @(200) "Canonical current-user permission summary"
    Assert-Check ($permissionsCheck.body -and
        $permissionsCheck.body.applicationId -and
        $permissionsCheck.body.roles -is [System.Array] -and
        $permissionsCheck.body.permissions -is [System.Array]) "Canonical current-user permission summary is malformed"
    $Report.smoke.tokenDiagnostics = [ordered]@{
        header = $tokenHeader
        claims = [ordered]@{
            iss = $tokenClaims.iss
            sub = $tokenClaims.sub
            aud = $tokenClaims.aud
            app_id = $tokenClaims.app_id
            roles = $tokenClaims.roles
            iat = $tokenClaims.iat
            exp = $tokenClaims.exp
        }
        authPermissionsStatus = $permissionsCheck.status
        authPermissions = if ($permissionsCheck.body -and $permissionsCheck.body.PSObject.Properties.Name -contains "permissions") { @($permissionsCheck.body.permissions) } else { @() }
    }
    try {
        $Report.smoke.withToken = Invoke-PhaseSmoke -Token $accessToken
    } catch {
        $manualPosts = Invoke-Api -Method Get -Uri "$ApiBaseUrl/posts" -Headers @{
            Authorization = "Bearer $accessToken"
        }
        $wwwAuthenticate = $manualPosts.headers["WWW-Authenticate"]
        $Report.smoke.withTokenFailure = [ordered]@{
            smokeError = $_.Exception.Message
            postsStatus = $manualPosts.status
            wwwAuthenticate = $wwwAuthenticate
            responseBody = $manualPosts.text
        }
        throw
    }
    $Report.smoke.token = "<redacted>"
    $Report.smoke.directLoginClient = if ($Report.smoke.spaDirectLoginStatus) { "WEB fallback" } else { "SPA" }

    if (-not $SkipReact) {
        $env:VITE_IAM_CLIENT_ID = $spaClient.clientId
        $env:VITE_IAM_ISSUER_URI = $IamServer
        $env:VITE_IAM_REDIRECT_URI = $spaRedirectUri
        $env:VITE_API_BASE_URL = $ApiBaseUrl
        $reactProcess = Start-Process -FilePath "cmd.exe" -ArgumentList @("/c", "pnpm", "dev", "--host", "localhost", "--port", "5173", "--strictPort") -WorkingDirectory $ReactDir -RedirectStandardOutput $ReactOut -RedirectStandardError $ReactErr -WindowStyle Hidden -PassThru
        $Report.react.processId = $reactProcess.Id
        Wait-HttpStatus -Uri $SpaBaseUrl -Expected @(200) -TimeoutSeconds 80 -Name "React Vite dev server" | Out-Null
        $Report.react.devServer = 200

        $authQuery = New-QueryString @{
            response_type = "code"
            client_id = $spaClient.clientId
            redirect_uri = $spaRedirectUri
            scope = "openid profile email"
            state = "phase1-live-state"
            code_challenge = "0123456789012345678901234567890123456789012"
            code_challenge_method = "S256"
        }
        $authPage = Invoke-WebRequest -Uri "$IamServer/oauth2/authorize?$authQuery" -MaximumRedirection 5 -SkipHttpErrorCheck -TimeoutSec 20
        $authText = if ($authPage.Content -is [byte[]]) { [Text.Encoding]::UTF8.GetString($authPage.Content) } else { [string] $authPage.Content }
        Assert-Check ([int] $authPage.StatusCode -eq 200) "Authorization URL did not return login page HTTP 200"
        Assert-Check ($authText -match "Sign in|登录|password|client_id") "Authorization URL response did not look like login page"
        $Report.react.oauthAuthorizeLoginPage = [ordered]@{
            status = [int] $authPage.StatusCode
            finalUri = $authPage.BaseResponse.ResponseUri.AbsoluteUri
            containsLoginMarker = $true
        }

        if (-not $SkipBrowserCheck) {
            $Report.react.discoveryCors = Wait-IamDiscoveryCors -Origin $SpaBaseUrl
            if (-not $Report.react.discoveryCors.allowed) {
                $Report.blockers += "React SDK browser discovery is blocked by IAM CORS: GET $IamServer/.well-known/openid-configuration from Origin $SpaBaseUrl did not return an allowed Access-Control-Allow-Origin after dynamic CORS cache wait. Last status=$($Report.react.discoveryCors.status), allowOrigin=$($Report.react.discoveryCors.accessControlAllowOrigin)."
                $Report.react.browserLogin = [ordered]@{
                    skipped = $true
                    reason = "OIDC discovery CORS header missing or not allowed"
                }
            } else {
                $Report.react.browserLogin = Invoke-ReactBrowserCheck -UserEmail $userEmail -UserPassword $userPassword
                if (-not $Report.react.browserLogin.passed) {
                    $Report.blockers += "React browser login/API check failed: redirect=$($Report.react.browserLogin.redirectError); callback=$($Report.react.browserLogin.callbackError); api=$($Report.react.browserLogin.apiSmoke.error)"
                }
            }
        }
    }

    if ($Report.blockers.Count -gt 0) {
        throw ($Report.blockers -join "`n")
    }
} catch {
    if ($Report.blockers -notcontains $_.Exception.Message) {
        $Report.blockers += $_.Exception.Message
    }
    throw
} finally {
    foreach ($key in $oldEnv.Keys) {
        if ($null -ne $oldEnv[$key]) {
            Set-Item -Path "Env:\$key" -Value $oldEnv[$key]
        } else {
            Remove-Item -Path "Env:\$key" -ErrorAction SilentlyContinue
        }
    }

    if (-not $KeepProcesses) {
        if ($reactProcess) {
            Stop-ProcessTree -RootPid $reactProcess.Id
            $Report.cleanup.reactProcessStopped = $true
        }
        if ($springProcess) {
            Stop-ProcessTree -RootPid $springProcess.Id
            $Report.cleanup.springProcessStopped = $true
        }
    }

    if ($portalToken -and $appId -and -not $KeepApplication) {
        try {
            $delete = Invoke-Api -Method Delete -Uri "$IamPortal/portal/v1/apps/$appId" -Token $portalToken
            $Report.cleanup.applicationDeleteStatus = $delete.status
        } catch {
            $Report.cleanup.applicationDeleteError = $_.Exception.Message
        }
    }

    Save-Report
}

Write-Host "REPORT=$ReportPath"
Write-Host "RUN_ID=$RunId"
Write-Host "APP_ID=$appId"
Write-Host "SPA_CLIENT_ID=$($Report.provisioning.spaClientId)"
Write-Host "WEB_CLIENT_ID=$($Report.provisioning.webClientId)"
Write-Host "WEB_CLIENT_SECRET=<redacted>"
Write-Host "TOKEN=<redacted>"
$Report | ConvertTo-Json -Depth 100
