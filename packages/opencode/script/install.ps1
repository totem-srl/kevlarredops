#!/usr/bin/env pwsh
#Requires -Version 5.1
param(
    [string]$Version,
    [string]$InstallDir
)

$ErrorActionPreference = "Stop"

$Repo = "s0ld13rr/pentestcode"
$Binary = "pentestcode"

if (-not $InstallDir) {
    $InstallDir = Join-Path $env:USERPROFILE ".pentestcode\bin"
}

function Detect-Arch {
    $arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture
    switch ($arch) {
        "X64"   { return "x64" }
        "Arm64" { return "arm64" }
        default { throw "Unsupported architecture: $arch" }
    }
}

function Resolve-Version {
    if ($Version) { return $Version }
    $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" -UseBasicParsing
    return $release.tag_name -replace '^v', ''
}

function Main {
    $arch = Detect-Arch
    $ver = Resolve-Version
    $artifact = "$Binary-windows-$arch"
    $url = "https://github.com/$Repo/releases/download/v$ver/$artifact.zip"

    Write-Host "  Installing $Binary v$ver ($artifact)"
    Write-Host "  From: $url"

    $tmpDir = Join-Path ([System.IO.Path]::GetTempPath()) "pentestcode-install-$([System.Guid]::NewGuid().ToString('N').Substring(0,8))"
    New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null

    try {
        $zipPath = Join-Path $tmpDir "archive.zip"
        Write-Host "  Downloading..."
        Invoke-WebRequest -Uri $url -OutFile $zipPath -UseBasicParsing

        Write-Host "  Extracting..."
        Expand-Archive -Path $zipPath -DestinationPath $tmpDir -Force

        if (-not (Test-Path $InstallDir)) {
            New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
        }

        $src = Join-Path $tmpDir "$Binary.exe"
        if (-not (Test-Path $src)) {
            $src = Get-ChildItem -Path $tmpDir -Filter "$Binary.exe" -Recurse | Select-Object -First 1 -ExpandProperty FullName
        }
        if (-not $src) { throw "Binary not found in archive" }

        $dest = Join-Path $InstallDir "$Binary.exe"
        Copy-Item -Path $src -Destination $dest -Force
        Write-Host "  Installed to $dest"

        $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
        if ($userPath -notlike "*$InstallDir*") {
            [Environment]::SetEnvironmentVariable("Path", "$InstallDir;$userPath", "User")
            $env:Path = "$InstallDir;$env:Path"
            Write-Host "  Added $InstallDir to user PATH"
        }

        Write-Host ""
        Write-Host "  Run '$Binary --help' to get started."
        Write-Host "  You may need to restart your terminal for PATH changes."
    }
    finally {
        Remove-Item -Path $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

Main
