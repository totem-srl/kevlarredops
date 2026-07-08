# PentestCode installer for Windows
# Usage: irm https://raw.githubusercontent.com/s0ld13rr/pentestcode/main/install.ps1 | iex
#
# Options (env vars):
#   $env:PENTESTCODE_VERSION   — specific version (default: latest)
#   $env:PENTESTCODE_INSTALL   — install directory (default: $HOME\.local\bin)
#   $env:PENTESTCODE_REPO      — GitHub repo (default: s0ld13rr/pentestcode)

$ErrorActionPreference = "Stop"

$Repo = if ($env:PENTESTCODE_REPO) { $env:PENTESTCODE_REPO } else { "s0ld13rr/pentestcode" }
$InstallDir = if ($env:PENTESTCODE_INSTALL) { $env:PENTESTCODE_INSTALL } else { "$HOME\.local\bin" }
$Version = if ($env:PENTESTCODE_VERSION) { $env:PENTESTCODE_VERSION } else { "latest" }
$BinName = "pentestcode"

function Info($msg) { Write-Host "→ $msg" -ForegroundColor Cyan }
function Ok($msg) { Write-Host "✓ $msg" -ForegroundColor Green }
function Err($msg) { Write-Host "✗ $msg" -ForegroundColor Red; exit 1 }

# detect arch
$Arch = switch ([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture) {
    "X64"   { "x64" }
    "Arm64" { "arm64" }
    default { Err "Unsupported architecture: $_" }
}

# check AVX2
$Avx2 = ""
if ($Arch -eq "x64") {
    try {
        $cpuInfo = Get-CimInstance Win32_Processor -ErrorAction SilentlyContinue
        # conservative: assume baseline if we can't detect
        $Avx2 = ""
    } catch {
        $Avx2 = "-baseline"
    }
}

$AssetName = "$BinName-windows-$Arch$Avx2"

Info "Installing PentestCode..."
Info "Platform: windows/$Arch$Avx2"

# resolve version
if ($Version -eq "latest") {
    Info "Fetching latest release..."
    try {
        $release = Invoke-RestMethod "https://api.github.com/repos/$Repo/releases/latest"
        $Version = $release.tag_name -replace '^v', ''
    } catch {
        Err "Could not determine latest version. Set `$env:PENTESTCODE_VERSION manually."
    }
}

Info "Version: v$Version"

$DownloadUrl = "https://github.com/$Repo/releases/download/v$Version/$AssetName.zip"

# download
$TmpDir = Join-Path ([System.IO.Path]::GetTempPath()) "pentestcode-install-$(Get-Random)"
New-Item -ItemType Directory -Path $TmpDir -Force | Out-Null

try {
    Info "Downloading $DownloadUrl..."
    Invoke-WebRequest -Uri $DownloadUrl -OutFile "$TmpDir\archive.zip" -UseBasicParsing

    Info "Extracting..."
    Expand-Archive -Path "$TmpDir\archive.zip" -DestinationPath $TmpDir -Force

    # install
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null

    $Binary = Join-Path $TmpDir "$BinName.exe"
    if (-not (Test-Path $Binary)) {
        Err "Binary not found in archive. Contents: $(Get-ChildItem $TmpDir | Select-Object -ExpandProperty Name)"
    }

    Copy-Item $Binary "$InstallDir\$BinName.exe" -Force

    Ok "Installed $BinName v$Version to $InstallDir\$BinName.exe"

    # check PATH
    $UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if ($UserPath -notlike "*$InstallDir*") {
        Write-Host ""
        Info "Add to your PATH (run once):"
        Write-Host ""
        Write-Host "  `$env:Path = `"$InstallDir;`$env:Path`""
        Write-Host "  [Environment]::SetEnvironmentVariable('Path', `"$InstallDir;`" + [Environment]::GetEnvironmentVariable('Path', 'User'), 'User')"
        Write-Host ""
    }

    Ok "Run 'pentestcode' to start"
} finally {
    Remove-Item -Recurse -Force $TmpDir -ErrorAction SilentlyContinue
}
