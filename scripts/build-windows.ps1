param(
  [switch]$Clean
)

# Build Windows EXE for NetGuardian GUI using PyInstaller
# Output: dist/NetGuardianGUI.exe

$ErrorActionPreference = 'Stop'

function Has-Command($name) {
  try { $null = Get-Command $name -ErrorAction Stop; return $true } catch { return $false }
}

# Ensure Python and pip
if (-not (Has-Command 'python')) { Write-Error 'Python is not on PATH. Install Python 3.10+.' }

# Optionally clean previous builds
if ($Clean) {
  Write-Host 'Cleaning build and dist folders...'
  Remove-Item -Recurse -Force -ErrorAction SilentlyContinue build, dist
  Get-ChildItem -Recurse -Filter *.spec | Remove-Item -Force -ErrorAction SilentlyContinue
}

# Create venv if missing
if (-not (Test-Path '.venv-win')) {
  Write-Host 'Creating venv (.venv-win)'
  python -m venv .venv-win
}

$activate = Join-Path (Resolve-Path '.venv-win').Path 'Scripts\Activate.ps1'
. $activate

# Upgrade pip and install build deps
python -m pip install --upgrade pip
pip install -r requirements.txt
pip install pyinstaller

# Common PyInstaller options
$common = @('--noconfirm', '--clean', '--collect-all','scapy','--collect-all','dns','--collect-all','zeroconf')

# Build GUI (windowed)
Write-Host 'Building NetGuardianGUI.exe (gui/netguardian_gui.py)'
pyinstaller @common --name NetGuardianGUI --windowed --onefile gui/netguardian_gui.py

Write-Host "Build complete. EXE is in the 'dist' folder:"
Write-Host ' - dist\NetGuardianGUI.exe'

