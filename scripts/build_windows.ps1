param(
    [string]$OutputDirectory = "dist",
    [string]$Python = "python"
)

$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo

& $Python -m compileall -q dwi
$saved_error_action = $ErrorActionPreference
$ErrorActionPreference = "Continue"
& $Python -c "import build, setuptools; print('build tooling available')" 2>$null
$build_exit = $LASTEXITCODE
$ErrorActionPreference = $saved_error_action
if ($build_exit -ne 0) {
    throw "The isolated Python must provide 'build' and 'setuptools'. Install build tooling in the build environment only."
}

New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
& $Python -m build --wheel --sdist --no-isolation --outdir $OutputDirectory
if ($LASTEXITCODE -ne 0) {
    throw "Python package artifact build failed."
}
Write-Output "DWI package artifacts written to $OutputDirectory"
