# scan-all.ps1 - roda o raptor-win (SAST + SCA) em CADA subpasta de um diretorio
# base, gerando um relatorio por projeto + um RESUMO combinado. Feito para
# agendamento recorrente (Tarefa Agendada). So VERIFICA e RELATA - nunca altera
# codigo nem faz push (isso e decisao humana, revisando o relatorio).
#
# ASCII-only de proposito: o Windows PowerShell 5.1 le .ps1 como ANSI e quebra
# com UTF-8 sem BOM.
#
# Uso:  .\scan-all.ps1 -Base C:\DEV
#       .\scan-all.ps1 -Base C:\repos -Out C:\repos\_seg -Skip @('venv','tmp')
param(
  [Parameter(Mandatory = $true)][string]$Base,
  [string]$Out,
  [string[]]$Skip = @('.git', 'node_modules', 'raptor', 'raptor-win', 'Backup')
)
$ErrorActionPreference = 'Continue'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
if (-not $Out) { $Out = Join-Path $Base '_raptor-reports' }

# Garante o semgrep no PATH (pip instala em Scripts, nem sempre no PATH).
try {
  $s = & python -c "import sysconfig; print(sysconfig.get_path('scripts'))" 2>$null
  if ($s -and (Test-Path $s)) { $env:Path = "$s;$env:Path" }
} catch { }

$stamp = Get-Date -Format 'yyyy-MM-dd_HHmm'
$dir = Join-Path $Out $stamp
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$resumo = Join-Path $dir 'RESUMO.md'
$lines = New-Object System.Collections.Generic.List[string]
$lines.Add("# raptor-win - varredura de $Base")
$lines.Add("_$stamp_")
$lines.Add("")
$lines.Add("| Projeto | SAST (exigem atencao) | SCA (pacotes c/ CVE) |")
$lines.Add("|---------|-----------------------|----------------------|")

$projs = Get-ChildItem $Base -Directory -ErrorAction SilentlyContinue | Where-Object { $Skip -notcontains $_.Name }
foreach ($p in $projs) {
  $hasCode = Get-ChildItem $p.FullName -Recurse -Include *.py, *.ts, *.tsx, *.js, *.jsx -File -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -notmatch '\\(node_modules|\.venv|venv|site-packages)\\' } | Select-Object -First 1
  if (-not $hasCode) { continue }
  Write-Host "==> $($p.Name)"
  $log = Join-Path $dir "$($p.Name).log.txt"
  $res = & python "$here\raptor_win.py" $p.FullName --md (Join-Path $dir "$($p.Name).sast.md") --sca 2>&1 | Out-String
  $res | Set-Content $log -Encoding utf8
  $m = [regex]::Match($res, 'total:\s*\d+.*?exigem aten\S+o:\s*(\d+)')
  $sastTxt = if ($m.Success) { $m.Groups[1].Value } else { '-' }
  $scaHits = ([regex]::Matches($res, "\u2014\s+\d+\s+vuln")).Count
  $scaTxt = if ($res -match 'Nenhuma depend') { '0' } elseif ($scaHits -gt 0) { "$scaHits" } else { '-' }
  $lines.Add("| $($p.Name) | $sastTxt | $scaTxt |")
}
$lines.Add("")
$lines.Add("> SAST = achados do Semgrep que exigem atencao (exclui taint em codigo proprio e")
$lines.Add("> fixture com falha plantada; achado em codigo de teste CONTA). SCA = CVE via OSV.")
$lines.Add("> Detalhes por projeto: arquivos *.sast.md e *.log.txt nesta pasta.")
$lines.Add("> Esta varredura NAO altera codigo nem faz push - revise e trate manualmente.")
$lines | Set-Content $resumo -Encoding utf8
Write-Host ""
Write-Host "Relatorio: $resumo"
