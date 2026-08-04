# raptor-win launcher (Windows) — garante o semgrep no PATH e chama o scanner.
# Uso:  .\raptor-win.ps1 <pasta> [--md report.md] [--fail-on HIGH] ...
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path

# pip instala o semgrep.exe na pasta Scripts do Python, que nem sempre está no PATH.
try {
  $scripts = & python -c "import sysconfig; print(sysconfig.get_path('scripts'))" 2>$null
  if ($scripts -and (Test-Path $scripts)) { $env:Path = "$scripts;$env:Path" }
} catch { }

python "$here\raptor_win.py" @args
exit $LASTEXITCODE
