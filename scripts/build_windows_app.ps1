param(
    [string]$OutputDirectory = "dist\windows",
    [string]$Python = "python"
)

$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo

$architecture = (& $Python -c "import platform; print(platform.machine())").Trim()
if ($architecture -notmatch "^(AMD64|x86_64)$") {
    throw "The Windows Desktop artifact is named windows-x64 only when the build host reports AMD64/x86_64; got '$architecture'."
}
$version = (& $Python -c "from dwi.version import __version__; print(__version__)").Trim()
$null = & $Python -m PyInstaller --version
if ($LASTEXITCODE -ne 0) {
    throw "PyInstaller is required in the isolated build environment."
}

$output = [System.IO.Path]::GetFullPath($OutputDirectory)
$work = Join-Path $env:TEMP ("dwi-pyinstaller-" + $version)
$versionFile = Join-Path $env:TEMP ("dwi-version-" + $version + ".txt")
$appName = "DWI-$version-Desktop"
New-Item -ItemType Directory -Force -Path $output | Out-Null
& $Python scripts\create_windows_version_file.py $versionFile
if ($LASTEXITCODE -ne 0) { throw "Could not create the Windows version resource." }

& $Python -m PyInstaller --noconfirm --clean --onefile --windowed `
    --name $appName --distpath $output --workpath $work `
    --specpath (Join-Path $env:TEMP "dwi-pyinstaller-spec") `
    --hidden-import dwi.desktop.resources --collect-data dwi.desktop.resources `
    --version-file $versionFile packaging\desktop_entry.py
if ($LASTEXITCODE -ne 0) { throw "PyInstaller Desktop build failed." }

$exe = Join-Path $output ($appName + ".exe")
if (-not (Test-Path -LiteralPath $exe)) { throw "Expected Desktop executable was not produced: $exe" }
$zip = Join-Path $output ("DWI-$version-windows-x64.zip")
$portable = Join-Path ([System.IO.Path]::GetTempPath()) ("dwi-portable-" + [System.Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Force -Path $portable | Out-Null
try {
    Copy-Item -LiteralPath $exe -Destination (Join-Path $portable (Split-Path -Leaf $exe))
    Copy-Item -LiteralPath (Join-Path $repo "LICENSE") -Destination (Join-Path $portable "LICENSE")
    Copy-Item -LiteralPath (Join-Path $repo "docs\DEPENDENCY_LICENSES.md") -Destination (Join-Path $portable "THIRD-PARTY-NOTICES.md")
    @"
DWI $version Desktop (portable archive)

Run DWI-$version-Desktop.exe. The executable is unsigned; Windows SmartScreen
may display a warning. This archive is a release candidate and is not the final
1.0.0 release. LICENSE and THIRD-PARTY-NOTICES.md accompany the executable.
"@ | Set-Content -LiteralPath (Join-Path $portable "README.txt") -Encoding UTF8
    Compress-Archive -Path (Join-Path $portable "*") -DestinationPath $zip -Force
} finally {
    if (Test-Path -LiteralPath $portable) {
        Remove-Item -LiteralPath $portable -Recurse -Force
    }
}
Add-Type -AssemblyName System.IO.Compression.FileSystem
$archive = [System.IO.Compression.ZipFile]::OpenRead($zip)
try {
    $required = @("$appName.exe", "LICENSE", "THIRD-PARTY-NOTICES.md", "README.txt")
    $actual = @($archive.Entries | ForEach-Object { $_.Name })
    foreach ($name in $required) {
        if ($actual -notcontains $name) { throw "Portable archive is missing required entry: $name" }
    }
} finally {
    $archive.Dispose()
}
Write-Output "Desktop executable: $exe"
Write-Output "Portable archive: $zip"
