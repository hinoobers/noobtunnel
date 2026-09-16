# Cross compile noobtunnel release binaries into dist/ (Windows friendly).
#
#   .\scripts\build.ps1
[CmdletBinding()]
param(
    [string]$Version = "0.1.0",
    [string[]]$Targets = @("linux/amd64", "linux/arm64", "linux/arm/7", "linux/386", "windows/amd64")
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$out = Join-Path $root "dist"
New-Item -ItemType Directory -Force -Path $out | Out-Null
# Drop leftovers from interrupted builds (a locked binary gets renamed on Windows).
Get-ChildItem -Path $out -Filter "noobtunnel_*~" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue

$commit = "unknown"
if (Get-Command git -ErrorAction SilentlyContinue) {
    # The tree may not be a git checkout; that is not an error for a build.
    $previous = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    $try = & git -C $root rev-parse --short HEAD 2>&1
    $code = $LASTEXITCODE
    $ErrorActionPreference = $previous
    if ($code -eq 0 -and $try) { $commit = ($try | Select-Object -First 1).ToString().Trim() }
}
$buildDate = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$ldflags = "-s -w -X github.com/noobtunnel/noobtunnel/internal/version.Version=$Version " +
           "-X github.com/noobtunnel/noobtunnel/internal/version.Commit=$commit " +
           "-X github.com/noobtunnel/noobtunnel/internal/version.BuildDate=$buildDate"

Push-Location $root
try {
    foreach ($target in $Targets) {
        $parts = $target.Split("/")
        $os = $parts[0]
        $arch = $parts[1]
        $arm = if ($parts.Length -gt 2) { $parts[2] } else { "" }
        $name = "noobtunnel_${os}_${arch}"
        if ($arm -ne "") { $name = "${name}v$arm" }
        if ($os -eq "windows") { $name = "$name.exe" }

        Write-Host ("building {0,-30}" -f $name) -NoNewline
        $env:GOOS = $os
        $env:GOARCH = $arch
        $env:GOARM = $arm
        $env:CGO_ENABLED = "0"
        go build -trimpath -ldflags $ldflags -o (Join-Path $out $name) ./cmd/noobtunnel
        if ($LASTEXITCODE -ne 0) { throw "build failed for $target" }
        Write-Host "ok"
    }
} finally {
    Remove-Item Env:\GOOS, Env:\GOARCH, Env:\GOARM, Env:\CGO_ENABLED -ErrorAction SilentlyContinue
    Pop-Location
}

# Windows can leave a "~" copy behind when it swaps a binary that was recently
# executed; clean those up so dist/ only ever holds real artifacts.
Get-ChildItem -Path $out -Filter "noobtunnel_*~" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue

$sums = Get-ChildItem -Path $out -Filter "noobtunnel_*" | Where-Object { $_.Name -notlike "*~" } | ForEach-Object {
    $hash = (Get-FileHash -Algorithm SHA256 $_.FullName).Hash.ToLower()
    "$hash  $($_.Name)"
}
$sums | Set-Content -Path (Join-Path $out "SHA256SUMS")

Write-Host ""
Write-Host "artifacts in $out"
# Windows can leave a "~" copy behind when a binary is swapped while in use.
Get-ChildItem -Path $out -Filter "noobtunnel_*~" -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
Get-ChildItem $out | Select-Object Name, Length | Format-Table
