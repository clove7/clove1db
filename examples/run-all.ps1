# Builds the seven examples into ONE build folder (their dependencies are compiled once, not seven times) and runs each one.
# Usage:  powershell -File run-all.ps1 [-Target <build folder>]
# The default build folder is clove1db-examples-target under the system's temporary folder. The examples themselves are not changed.
# Cost: clove1db is compiled once for each set of its features that the examples use (none: 01, 04, 05; derive: 02, 03; encryption: 06, 07),
# 30 to 45 s each, so a first run takes about 2 minutes. The features are the examples' own and are not changed to avoid this.
param([string]$Target = (Join-Path ([IO.Path]::GetTempPath()) 'clove1db-examples-target'))
$ErrorActionPreference = 'Continue'
$env:CARGO_TARGET_DIR = $Target
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
# the examples are separate workspaces, so the library's own profile line does not reach them: the same line is given on the command line
$optimised = Join-Path $Target 'optimised-dependencies.toml'
New-Item -ItemType Directory -Force $Target | Out-Null
Set-Content -LiteralPath $optimised -Value '[profile.dev.package."*"]', 'opt-level = 3'
$started = Get-Date
$rows = foreach ($dir in Get-ChildItem $here -Directory | Sort-Object Name) {
    $manifest = Join-Path $dir.FullName 'Cargo.toml'
    $t0 = Get-Date
    cargo build --quiet --config $optimised --manifest-path $manifest 2>&1 | Out-Null
    $built = $LASTEXITCODE -eq 0
    $buildSeconds = [math]::Round(((Get-Date) - $t0).TotalSeconds, 1)
    $crate = (Select-String -LiteralPath $manifest -Pattern '^name\s*=\s*"(.+)"' | Select-Object -First 1).Matches[0].Groups[1].Value
    $exit = $null; $runSeconds = $null
    if ($built) {
        $t1 = Get-Date
        & (Join-Path $Target "debug\$crate.exe") *> $null
        $exit = $LASTEXITCODE
        $runSeconds = [math]::Round(((Get-Date) - $t1).TotalSeconds, 1)
    }
    [pscustomobject]@{ example = $dir.Name; built = $built; build_s = $buildSeconds; exit = $exit; run_s = $runSeconds }
}
$rows | Format-Table -AutoSize | Out-String
"all: {0} s; built {1}/{2}; exit 0: {3}/{2}" -f [int]((Get-Date) - $started).TotalSeconds, @($rows | Where-Object built).Count, @($rows).Count, @($rows | Where-Object { $_.exit -eq 0 }).Count
if (@($rows | Where-Object { $_.exit -ne 0 }).Count -gt 0) { exit 1 }
