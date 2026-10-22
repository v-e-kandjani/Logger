<#
.SYNOPSIS
    Valtrivo LogSeal - Native Endpoint Agent Uninstaller for Windows
.DESCRIPTION
    Stops and removes the LoggerAgent Windows Service, deletes registry entries,
    and cleanly removes C:\Program Files\LOGGER Agent.
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File uninstall-agent.ps1
    # Or via remote one-liner:
    iwr -useb "http://10.34.33.40:8080/static/scripts/uninstall-agent.ps1" | iex
#>

[CmdletBinding()]
param(
    [switch]$KeepData = $false
)

$ErrorActionPreference = "SilentlyContinue"

# Check Administrator privileges
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "Please run this uninstaller as Administrator. (Right-click PowerShell -> Run as Administrator)"
    exit 1
}

Write-Host "==================================================================" -ForegroundColor Yellow
Write-Host "      VALTRIVO LOGSEAL - WINDOWS ENDPOINT AGENT UNINSTALLER       " -ForegroundColor Yellow
Write-Host "==================================================================" -ForegroundColor Yellow

$ServiceName = "LoggerAgent"
$InstallDir = "C:\Program Files\LOGGER Agent"

# 1. Stop service
Write-Host "[*] Stopping $ServiceName service..." -ForegroundColor Cyan
Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
& sc.exe stop $ServiceName | Out-Null
Start-Sleep -Seconds 1

# Kill any remaining process if running
Get-Process -Name "logger-agent" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

# 2. Delete service
Write-Host "[*] Deleting $ServiceName service..." -ForegroundColor Cyan
& sc.exe delete $ServiceName | Out-Null
Start-Sleep -Seconds 1

# 3. Clean registry
Write-Host "[*] Removing Windows Add/Remove programs registry entries..." -ForegroundColor Cyan
$regBase = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\$ServiceName"
if (Test-Path $regBase) {
    Remove-Item -Path $regBase -Recurse -Force -ErrorAction SilentlyContinue
}

# 4. Remove installation directory
if (-not $KeepData) {
    Write-Host "[*] Removing files from $InstallDir..." -ForegroundColor Cyan
    if (Test-Path $InstallDir) {
        Remove-Item -Path $InstallDir -Recurse -Force -ErrorAction SilentlyContinue
    }
} else {
    Write-Host "[*] Preserved data and config at: $InstallDir" -ForegroundColor Yellow
}

Write-Host "==================================================================" -ForegroundColor Green
Write-Host " [✓] VALTRIVO LOGSEAL AGENT HAS BEEN COMPLETELY UNINSTALLED!      " -ForegroundColor Green
Write-Host "==================================================================" -ForegroundColor Green
