$ErrorActionPreference = 'Stop'

$dossierDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$workspace = Split-Path -Parent $dossierDir
$source = Join-Path $dossierDir 'HX-1977-final-dossier.html'
$output = Join-Path $dossierDir 'HX-1977-final-dossier.pdf'
$profile = Join-Path $workspace '.tools\dossier-chrome-profile'

$chromeCandidates = @(
    'C:\Program Files\Google\Chrome\Application\chrome.exe',
    'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe',
    'C:\Program Files\Microsoft\Edge\Application\msedge.exe'
)

$browser = $chromeCandidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
if (-not $browser) {
    throw 'Chrome or Edge was not found. Install one of them or update render-dossier.ps1.'
}

New-Item -ItemType Directory -Force -Path $profile | Out-Null
$sourceUri = [System.Uri]::new($source).AbsoluteUri

$arguments = @(
    '--headless=new',
    '--disable-gpu',
    '--no-first-run',
    '--disable-default-apps',
    '--disable-extensions',
    '--allow-file-access-from-files',
    "--user-data-dir=$profile",
    "--print-to-pdf=$output",
    '--no-pdf-header-footer',
    $sourceUri
)

# Chromium is a GUI-subsystem executable on Windows, so direct PowerShell
# invocation can return before the PDF writer exits. Start-Process -Wait keeps
# the rendering step deterministic.
$process = Start-Process -FilePath $browser -ArgumentList $arguments -Wait -PassThru -WindowStyle Hidden

if ($process.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $output)) {
    throw "PDF rendering failed with exit code $($process.ExitCode)"
}

$hash = Get-FileHash -Algorithm SHA256 -LiteralPath $output
$item = Get-Item -LiteralPath $output
Write-Output "PDF: $($item.FullName)"
Write-Output "Bytes: $($item.Length)"
Write-Output "SHA256: $($hash.Hash.ToLowerInvariant())"
