# Repo stats helper
$exts = @('*.go','*.md','*.sh','*.ps1','*.json','*.yaml','*.yml','*.txt','*.py','*.js','*.ts')
$files = Get-ChildItem -Recurse -File -Include $exts -ErrorAction SilentlyContinue
$totalFiles = $files.Count
$totalLines = 0
$byExt = @()
foreach ($ext in $exts) {
    $extName = $ext -replace '\*',''
    $extFiles = $files | Where-Object { $_.Extension -ieq $extName }
    $lineCount = 0
    foreach ($f in $extFiles) {
        try { $lineCount += (Get-Content $f.FullName -ErrorAction SilentlyContinue | Measure-Object -Line).Lines } catch { }
    }
    $byExt += [PSCustomObject]@{ext=$extName; files=$extFiles.Count; lines=$lineCount}
    $totalLines += $lineCount
}
$goFiles = $files | Where-Object { $_.Extension -ieq '.go' }
$goFilePaths = $goFiles | ForEach-Object { $_.FullName }
$funcMatches = 0
if ($goFilePaths.Count -gt 0) {
    $funcMatches = (Select-String -Path $goFilePaths -Pattern '^[\s]*func[\s]+' -AllMatches -ErrorAction SilentlyContinue | Measure-Object).Count
}
$avgLinesPerFile = if ($totalFiles -gt 0) { [math]::Round($totalLines / $totalFiles,2) } else { 0 }
$goLines = ($byExt | Where-Object { $_.ext -ieq '.go' } | Select-Object -ExpandProperty lines)
$avgLinesPerGoFile = if ($goFiles.Count -gt 0) { [math]::Round($goLines / $goFiles.Count,2) } else { 0 }
Write-Host "Repository scan summary:"
Write-Host "  Files scanned: $totalFiles"
Write-Host "  Total lines: $totalLines"
Write-Host "  Avg lines/file: $avgLinesPerFile"
Write-Host ""
Write-Host "Lines by extension:"
$byExt | Sort-Object -Property lines -Descending | ForEach-Object { Write-Host "  $($_.ext) : $($_.files) files, $($_.lines) lines" }
Write-Host ""
Write-Host "Go specifics:"
Write-Host "  Go files: $($goFiles.Count)"
Write-Host "  Go lines: $goLines"
Write-Host "  Func count (lines starting with 'func'): $funcMatches"
Write-Host "  Avg lines/go file: $avgLinesPerGoFile"
if ($funcMatches -gt 0) { $avgLinesPerFunc = [math]::Round($goLines / $funcMatches,2); Write-Host "  Avg lines/func: $avgLinesPerFunc" }
