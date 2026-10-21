<#
.SYNOPSIS
    Valtrivo LogSeal - Native Endpoint Agent Installer for Windows
    Platforms: Windows 10, Windows 11, Windows Server 2016, 2019, 2022, 2025 (x64 / ARM64)
.DESCRIPTION
    Downloads the native logger-agent.exe binary, configures authentication tokens,
    creates the Windows Service 'LoggerAgent', and starts automatic monitoring.
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File install-agent.ps1 -Server "http://logger.lan:8080" -Token "lp_ea_xxx"
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$Server = "http://localhost:8080",

    [Parameter(Mandatory=$false)]
    [string]$Token = "",

    [Parameter(Mandatory=$false)]
    [switch]$Insecure = $false
)

$ErrorActionPreference = "Stop"

# Ensure Run as Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "This installer must be run as Administrator. Please reopen PowerShell with 'Run as administrator'."
    exit 1
}

Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host "      VALTRIVO LOGSEAL - WINDOWS ENDPOINT AGENT INSTALLER         " -ForegroundColor Cyan
Write-Host "==================================================================" -ForegroundColor Cyan

# Prompt for Token if empty
if ([string]::IsNullOrWhiteSpace($Token)) {
    $Token = Read-Host "Enter LogSeal Enrollment Token (lp_ea_...)"
}
if ([string]::IsNullOrWhiteSpace($Token)) {
    Write-Error "Enrollment token is required. Generate one from LogSeal Endpoint > Tokens."
    exit 1
}

$Server = $Server.TrimEnd('/')
$InstallDir = "C:\Program Files\LOGGER Agent"
$DataDir = "$InstallDir\data"
$ConfigFile = "$InstallDir\config.json"
$BinaryPath = "$InstallDir\logger-agent.exe"
$ServiceName = "LoggerAgent"

# Create installation directory
if (-not (Test-Path -Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}
if (-not (Test-Path -Path $DataDir)) {
    New-Item -ItemType Directory -Path $DataDir -Force | Out-Null
}

# Determine architecture
$arch = if ([System.Environment]::Is64BitOperatingSystem) { "amd64" } else { "386" }
$downloadUrl = "$Server/static/bin/logger-agent-windows-$arch.exe"

Write-Host "[*] Target Server : $Server" -ForegroundColor Blue
Write-Host "[*] Architecture  : $arch" -ForegroundColor Blue
Write-Host "[*] Install Path  : $InstallDir" -ForegroundColor Blue

# Download or place binary
if ($Insecure) {
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
}

Write-Host "[*] Fetching logger-agent.exe..." -ForegroundColor Blue
try {
    Invoke-WebRequest -Uri $downloadUrl -OutFile $BinaryPath -UseBasicParsing -TimeoutSec 30
    Write-Host "[✓] Downloaded logger-agent.exe successfully." -ForegroundColor Green
} catch {
    Write-Warning "Could not download remote binary from $downloadUrl ($($_.Exception.Message))."
    if (Test-Path -Path ".\logger-agent.exe") {
        Copy-Item -Path ".\logger-agent.exe" -Destination $BinaryPath -Force
        Write-Host "[✓] Copied local logger-agent.exe." -ForegroundColor Green
    } elseif (Test-Path -Path $BinaryPath) {
        Write-Host "[✓] Using existing logger-agent.exe at destination." -ForegroundColor Green
    } else {
        Write-Error "Cannot locate logger-agent.exe binary. Please host the binary or place it in the current directory."
        exit 1
    }
}

# Write Config
Write-Host "[*] Writing configuration..." -ForegroundColor Blue
$config = @{
    server_url = $Server
    enrollment_token = $Token
    insecure_tls = [bool]$Insecure
    log_level = "info"
    data_dir = $DataDir
    heartbeat_interval_sec = 30
    identity_file = "$InstallDir\identity.json"
}
$config | ConvertTo-Json -Depth 4 | Set-Content -Path $ConfigFile -Encoding UTF8

# Setup Windows Service
Write-Host "[*] Configuring Windows Service '$ServiceName'..." -ForegroundColor Blue
$existingService = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existingService) {
    Write-Host "[*] Stopping existing service..." -ForegroundColor Yellow
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    & sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 2
}

# Create new Windows Service
$binPathArg = "`"$BinaryPath`" -config `"$ConfigFile`""
$createResult = & sc.exe create $ServiceName binPath= $binPathArg start= auto DisplayName= "LogSeal Endpoint Security Agent"
Write-Host "[*] sc.exe result: $createResult"

& sc.exe description $ServiceName "Valtrivo LogSeal cross-platform endpoint telemetry, asset inventory, and vulnerability agent." | Out-Null
& sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/10000/restart/60000 | Out-Null

# Start Service
Write-Host "[*] Starting $ServiceName..." -ForegroundColor Blue
Start-Service -Name $ServiceName
Start-Sleep -Seconds 2

$status = Get-Service -Name $ServiceName
Write-Host "==================================================================" -ForegroundColor Green
Write-Host "      LOGGER AGENT INSTALLED AND STARTED SUCCESSFULLY!            " -ForegroundColor Green
Write-Host "==================================================================" -ForegroundColor Green
Write-Host "Service Name   : $($status.Name) ($($status.DisplayName))"
Write-Host "Service Status : $($status.Status)"
Write-Host "Configuration  : $ConfigFile"
Write-Host "Check Status   : Get-Service LoggerAgent"
