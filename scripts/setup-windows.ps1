param(
  [switch]$Force
)

# NetGuardian Windows setup script
# - Installs dependencies (Npcap, Nmap) via winget or Chocolatey if available
# - Creates and populates a Python virtual environment
# - Verifies environment prerequisites

$ErrorActionPreference = 'Stop'

function Assert-Admin {
  $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
  $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
  if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Warning 'It is recommended to run this script in an elevated PowerShell (Run as Administrator), especially for packet capture.'
  }
}

function Has-Command($name) {
  try { $null = Get-Command $name -ErrorAction Stop; return $true } catch { return $false }
}

function Install-With-Winget($id) {
  if (Has-Command 'winget') {
    Write-Host "Installing $id via winget..."
    winget install --id $id -e --silent --accept-source-agreements --accept-package-agreements | Out-Null
    return $true
  }
  return $false
}

function Install-With-Choco($pkg) {
  if (Has-Command 'choco') {
    Write-Host "Installing $pkg via Chocolatey..."
    choco install $pkg -y --no-progress | Out-Null
    return $true
  }
  return $false
}

function Ensure-Npcap {
  Write-Host 'Ensuring Npcap (WinPcap-compatible packet capture driver) is installed...'
  $installed = $false
  # Try winget first (common IDs: Nmap.Npcap or Npcap.Npcap)
  $installed = (Install-With-Winget 'Nmap.Npcap') -or (Install-With-Winget 'Npcap.Npcap') -or $installed
  # Fallback to Chocolatey
  $installed = (Install-With-Choco 'npcap') -or $installed
  if (-not $installed) {
    Write-Warning 'Npcap could not be installed automatically. Please install it manually from https://npcap.com (enable WinPcap API compatibility during setup).'
  } else {
    Write-Host 'Npcap installation attempted (verify if prompted).'
  }
}

function Ensure-Nmap {
  Write-Host 'Ensuring Nmap is installed...'
  $installed = $false
  $installed = (Install-With-Winget 'Insecure.Nmap') -or $installed
  $installed = (Install-With-Choco 'nmap') -or $installed
  if (-not $installed) {
    Write-Warning 'Nmap could not be installed automatically. Please install it manually from https://nmap.org/download.html and ensure nmap.exe is on PATH.'
  } else {
    Write-Host 'Nmap installation attempted.'
  }
}

function Ensure-Python {
  if (-not (Has-Command 'python')) {
    Write-Error 'Python is not available on PATH. Install Python 3.10+ and re-run.'
  }
}

function Setup-Venv {
  param([string]$ReqPath = 'requirements.txt')
  Write-Host 'Creating Python virtual environment (.venv-win)...'
  python -m venv .venv-win
  $venvActivate = Join-Path (Resolve-Path '.venv-win').Path 'Scripts\Activate.ps1'
  if (-not (Test-Path $venvActivate)) { Write-Error 'Virtual environment creation failed.' }
  Write-Host 'Activating virtual environment and installing requirements...'
  & $venvActivate
  python -m pip install --upgrade pip
  if (Test-Path $ReqPath) {
    pip install -r $ReqPath
  } else {
    Write-Warning "$ReqPath not found; installing core packages individually."
    pip install scapy python-nmap PyQt6 zeroconf bleak psutil manuf networkx matplotlib dnspython requests
  }
  Write-Host 'Python dependencies installed.'
}

function Verify-Env {
  Write-Host 'Verifying environment...'
  # Check nmap
  try { nmap --version | Out-Null; Write-Host 'Nmap detected.' }
  catch { Write-Warning 'Nmap not detected on PATH.' }
  # Check scapy
  try { python -c "import scapy.all as s; print('scapy OK')" | Out-Null; Write-Host 'Scapy import OK.' }
  catch { Write-Warning 'Scapy import failed in venv.' }
}

Assert-Admin
Ensure-Python
Ensure-Npcap
Ensure-Nmap
Setup-Venv -ReqPath 'requirements.txt'
Verify-Env

Write-Host "\nSetup complete. Notes:"
Write-Host "- For packet capture, run PowerShell and NetGuardian as Administrator."
Write-Host "- Ensure Npcap was installed with WinPcap API compatibility."
Write-Host "- Activate venv for usage: `.& .venv-win\Scripts\Activate.ps1`"
Write-Host "- To run the GUI directly during development:"
Write-Host "    python .\gui\netguardian_gui.py"
Write-Host "- Or build the standalone EXE:"
Write-Host "    scripts\\build-windows.ps1"

