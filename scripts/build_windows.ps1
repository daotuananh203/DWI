param(
    [string]$OutputDirectory = "dist"
)

$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot
Set-Location $repo

python -m compileall -q dwi
$saved_error_action = $ErrorActionPreference
$ErrorActionPreference = "Continue"
python -c "import build" 2>$null
$build_exit = $LASTEXITCODE
$ErrorActionPreference = $saved_error_action
if ($build_exit -ne 0) {
    throw "The optional 'build' package is required for this local packaging smoke. Install it in the build environment only."
}

New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
python -m build --wheel --sdist --no-isolation --outdir $OutputDirectory
Write-Output "DWI package artifacts written to $OutputDirectory"
