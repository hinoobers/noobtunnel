param(
  [string]$Server,
  [string]$Token,
  [string]$Fingerprint,
  [string]$Pin,
  [string]$Name,
  [switch]$Uninstall,
  [uint32]$AgentId
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  function PSQuote([string]$Value) { return "'" + $Value.Replace("'", "''") + "'" }
  if ($Uninstall) {
    $reentry = '& ' + (PSQuote $PSCommandPath) + ' -Uninstall -Server ' + (PSQuote $Server) +
      ' -Pin ' + (PSQuote $Pin) + ' -AgentId ' + $AgentId
  } else {
    $reentry = '& ' + (PSQuote $PSCommandPath) + ' -Server ' + (PSQuote $Server) +
      ' -Token ' + (PSQuote $Token) + ' -Fingerprint ' + (PSQuote $Fingerprint) +
      ' -Pin ' + (PSQuote $Pin) + ' -Name ' + (PSQuote $Name)
  }
  $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($reentry))
  Write-Host 'Requesting administrator access to manage the tunnel service...'
  Start-Process -FilePath powershell.exe -Verb RunAs -ArgumentList @('-NoExit', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', $encoded)
  exit 0
}
if ($Server -notmatch '^[A-Za-z0-9.\-]+:\d+$') { throw 'Invalid control server address.' }
if ($Pin -notmatch '^[A-Za-z0-9+/]{43}=$') { throw 'Invalid certificate pin.' }
$root = Join-Path $env:ProgramFiles 'noobtunnel'
$state = Join-Path $env:ProgramData 'noobtunnel'
$binary = Join-Path $root 'noobtunnel.exe'
$dll = Join-Path $root 'wintun.dll'
$tokenFile = Join-Path $state 'token'

if ($Uninstall) {
  if ($AgentId -eq 0) { throw 'Invalid agent ID.' }
  if (-not (Test-Path -LiteralPath $tokenFile)) { throw 'No local agent token found. Use control node only removal.' }
  $localToken = (Get-Content -LiteralPath $tokenFile -Raw).Trim()
  if (-not $localToken) { throw 'The local agent token is empty.' }
  ('header = "Authorization: Bearer ' + $localToken + '"') | & curl.exe --fail --silent --show-error `
    --insecure --pinnedpubkey "sha256//$Pin" --config - --request POST `
    "https://$Server/api/agent-uninstall/$AgentId" --output NUL
  if ($LASTEXITCODE -ne 0) { throw 'Control node removal failed. The local agent was kept so you can retry.' }
  $service = Get-Service -Name 'noobtunnel-agent' -ErrorAction SilentlyContinue
  if ($service) {
    if ($service.Status -ne 'Stopped') {
      Stop-Service -Name 'noobtunnel-agent' -Force
      (Get-Service -Name 'noobtunnel-agent').WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
    }
    & sc.exe delete noobtunnel-agent | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Could not remove the Windows service.' }
  }
  Get-NetFirewallRule -Name 'noobtunnel-mesh' -ErrorAction SilentlyContinue | Remove-NetFirewallRule
  if (Test-Path -LiteralPath $root) { Remove-Item -LiteralPath $root -Recurse -Force }
  if (Test-Path -LiteralPath $state) { Remove-Item -LiteralPath $state -Recurse -Force }
  Write-Host 'Agent removed from the control node and this machine.'
  exit 0
}

if (-not [Environment]::Is64BitOperatingSystem) { throw 'This installer currently supports 64-bit Windows only.' }
if (-not $Token -or -not $Name) { throw 'Token and name are required.' }
# The control node formats SHA-256 fingerprints as colon-separated hex.
if ($Fingerprint -notmatch '^(?:[a-fA-F0-9]{2}:){31}[a-fA-F0-9]{2}$' -and
    $Fingerprint -notmatch '^[a-fA-F0-9]{64}$') { throw 'Invalid certificate fingerprint.' }

New-Item -ItemType Directory -Force -Path $root, $state | Out-Null

function Fetch-Pinned([string]$Url, [string]$Target) {
  & curl.exe --fail --silent --show-error --location --insecure --pinnedpubkey "sha256//$Pin" $Url --output $Target
  if ($LASTEXITCODE -ne 0) { throw "Download failed: $Url" }
}

Write-Host 'Downloading noobtunnel agent...'
$manifestFile = Join-Path $env:TEMP 'noobtunnel-manifest.json'
Fetch-Pinned "https://$Server/download/manifest.json" $manifestFile
$manifest = Get-Content -LiteralPath $manifestFile -Raw | ConvertFrom-Json
$artifact = @($manifest.binaries | Where-Object { $_.name -eq 'noobtunnel_windows_amd64.exe' }) | Select-Object -First 1
if (-not $artifact) { throw 'The control node has no Windows agent binary. Ask the operator to publish it.' }
$download = Join-Path $env:TEMP 'noobtunnel-agent-new.exe'
Fetch-Pinned "https://$Server/download/noobtunnel_windows_amd64.exe" $download
$actual = (Get-FileHash -LiteralPath $download -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actual -ne $artifact.sha256.ToLowerInvariant()) { throw 'Agent binary checksum mismatch.' }

if (-not (Test-Path -LiteralPath $dll)) {
  Write-Host 'Downloading signed Wintun driver...'
  $zip = Join-Path $env:TEMP 'noobtunnel-wintun.zip'
  Invoke-WebRequest -Uri 'https://www.wintun.net/builds/wintun-0.14.1.zip' -OutFile $zip -UseBasicParsing
  $expected = '07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51'
  if ((Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expected) {
    throw 'Wintun driver checksum mismatch.'
  }
  $expanded = Join-Path $env:TEMP 'noobtunnel-wintun'
  Expand-Archive -LiteralPath $zip -DestinationPath $expanded -Force
  $source = Get-ChildItem -LiteralPath $expanded -Recurse -Filter wintun.dll | Where-Object { $_.FullName -match 'amd64' } | Select-Object -First 1
  if (-not $source) { throw 'Wintun archive has no 64-bit DLL.' }
  Copy-Item -LiteralPath $source.FullName -Destination $dll -Force
}

$service = Get-Service -Name 'noobtunnel-agent' -ErrorAction SilentlyContinue
if ($service -and $service.Status -ne 'Stopped') {
  Stop-Service -Name 'noobtunnel-agent' -Force
  (Get-Service -Name 'noobtunnel-agent').WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
}
$runtimePath = Join-Path $state 'runtime.json'
if (Test-Path -LiteralPath $runtimePath) { Remove-Item -LiteralPath $runtimePath -Force }
Copy-Item -LiteralPath $download -Destination $binary -Force
& icacls.exe $state /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not secure the agent state directory.' }
Set-Content -LiteralPath $tokenFile -Value $Token -NoNewline -Encoding Ascii
& icacls.exe $tokenFile /inheritance:r /grant:r 'SYSTEM:F' 'Administrators:F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not secure the enrollment token.' }
& icacls.exe $root /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F' | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not secure the agent program directory.' }

$agentArgs = @('agent', '--server', $Server, '--token-file', $tokenFile, '--fingerprint', $Fingerprint, '--name', $Name, '--state-dir', $state)
$quoted = @($agentArgs | ForEach-Object { '"' + $_.Replace('"','\"') + '"' }) -join ' '
$command = '"' + $binary + '" ' + $quoted
if ($service) {
  $existing = Get-CimInstance Win32_Service -Filter "Name='noobtunnel-agent'"
  $compatible = $existing.PathName.Contains('"' + $binary + '"') -and
    $existing.PathName.Contains('"' + $Server + '"') -and
    $existing.PathName.Contains('"' + $tokenFile + '"') -and
    $existing.PathName.Contains('"' + $Fingerprint + '"') -and
    $existing.PathName.Contains('"' + $state + '"')
  if (-not $compatible) {
    $change = Invoke-CimMethod -InputObject $existing -MethodName Change -Arguments @{PathName=$command;StartMode='Automatic'}
    if ($change.ReturnValue -ne 0) { throw "Could not update the Windows service (Windows error $($change.ReturnValue))." }
  }
} else {
  New-Service -Name 'noobtunnel-agent' -BinaryPathName $command -DisplayName 'noobtunnel agent' -StartupType Automatic | Out-Null
}
Start-Service -Name 'noobtunnel-agent'
Write-Host 'Waiting for agent to connect...'
$failureSeen = 0
$lastFailure = ''
for ($n = 0; $n -lt 60; $n++) {
  Start-Sleep -Seconds 2
  if (Test-Path -LiteralPath $runtimePath) {
    $runtime = $null
    try { $runtime = Get-Content -LiteralPath $runtimePath -Raw | ConvertFrom-Json } catch { }
    if ($runtime) {
      if ($runtime.connected -and $runtime.address -and -not $runtime.lastError) {
        Write-Host "Agent connected. Mesh address: $($runtime.address)"
        exit 0
      }
      if ($runtime.lastError) {
        if ($runtime.lastError -ne $lastFailure) { Write-Warning "Agent setup: $($runtime.lastError)" }
        $lastFailure = $runtime.lastError
        $failureSeen++
        if ($failureSeen -ge 5) { throw "Agent could not connect: $lastFailure" }
      }
    }
  }
  if ((Get-Service -Name 'noobtunnel-agent').Status -eq 'Stopped') {
    if ($lastFailure) { throw "Agent service stopped: $lastFailure" }
    throw 'Agent service stopped before writing runtime status.'
  }
}
throw 'The agent did not connect within two minutes. Run "C:\Program Files\noobtunnel\noobtunnel.exe" status for details.'
