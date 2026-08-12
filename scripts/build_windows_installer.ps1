param(
    [Parameter(Mandatory = $true)]
    [string]$DesktopExecutable,
    [string]$OutputDirectory = "dist\installer",
    [string]$Iscc = "",
    [string]$Python = "python"
)

$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo

$exe = [System.IO.Path]::GetFullPath($DesktopExecutable)
if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) {
    throw "Desktop executable does not exist: $exe"
}

$version = (& $Python -c "from dwi.version import __version__; print(__version__)").Trim()
if (-not $version) { throw "Could not determine DWI version." }
$output = [System.IO.Path]::GetFullPath($OutputDirectory)
New-Item -ItemType Directory -Force -Path $output | Out-Null

if (-not $Iscc) {
    $command = Get-Command iscc.exe -ErrorAction SilentlyContinue
    if ($command) {
        $Iscc = $command.Source
    } else {
        $known = @(
            "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe",
            "$env:ProgramFiles\Inno Setup 6\ISCC.exe"
        ) | Where-Object { $_ -and (Test-Path -LiteralPath $_) }
        if ($known.Count -gt 0) { $Iscc = $known[0] }
    }
}
if (-not $Iscc -or -not (Test-Path -LiteralPath $Iscc -PathType Leaf)) {
    throw "Inno Setup ISCC.exe is required to produce a Windows installer; no supported installation was found."
}

$fileVersion = "1.0.0.1"
& $Iscc "/DDWI_VERSION=$version" "/DDWI_FILE_VERSION=$fileVersion" "/DDWI_EXE=$exe" "/O$output" "packaging\dwi_installer.iss"
if ($LASTEXITCODE -ne 0) { throw "Inno Setup installer build failed." }

$installer = Join-Path $output ("DWI-{0}-Setup.exe" -f $version)
if (-not (Test-Path -LiteralPath $installer -PathType Leaf)) {
    throw "Expected installer was not produced: $installer"
}
Write-Output "Installer: $installer"
