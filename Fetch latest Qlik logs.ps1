<#
  Copies the newest Qlik Sense logs from the ArchivedLogs share to a local folder, so the Qlik Server Event Manager
  can read them quickly (and so you have a snapshot to keep or send).

  For each log type the app uses it copies the files archived in the last -Days (newest first, up to -MaxMBPerType),
  or the single newest file if none are that recent. It also writes:
    audit_files_per_hour.txt   engine audit files per hour, from the folder listing (whole archive, no files opened)
    audit_sample.txt           (with -Sample) which app/user filled the engine audit log, one file per day
    Script\                    the apps' reload logs (ArchivedLogs\<host>\Script) from the last -ScriptDays days

  Examples
    .\Fetch latest Qlik logs.ps1
    .\Fetch latest Qlik logs.ps1 -Days 7 -MaxMBPerType 128 -Sample
    .\Fetch latest Qlik logs.ps1 -Root '\\server\QlikShare$\ArchivedLogs\server'

  The ArchivedLogs folder comes from -Root, the QLIK_ARCHIVE_ROOT environment variable, or ARCHIVE_ROOT in site_config.py.
#>
param(
    [string]$Root = '',
    [double]$Days = 2,
    [int]$MaxMBPerType = 64,
    [string]$Dest = (Join-Path $env:USERPROFILE 'QlikLogs\latest'),
    [switch]$Sample,
    [int]$SampleDays = 90,
    [int]$ScriptDays = 14
)

$ErrorActionPreference = 'Stop'

# The ArchivedLogs folder: -Root, else the QLIK_ARCHIVE_ROOT environment variable, else ARCHIVE_ROOT in site_config.py
if (-not $Root) { $Root = $env:QLIK_ARCHIVE_ROOT }
if (-not $Root) {
    $cfg = Join-Path $PSScriptRoot 'site_config.py'
    if (Test-Path -LiteralPath $cfg) {
        $m = Select-String -LiteralPath $cfg -Pattern '^ARCHIVE_ROOT\s*=\s*r?["''](.*)["'']' | Select-Object -First 1
        if ($m) { $Root = $m.Matches[0].Groups[1].Value }
    }
}
if (-not $Root) { $Root = Read-Host 'ArchivedLogs folder for the Qlik node (e.g. \\server\QlikShare$\ArchivedLogs\server)' }
$used = @('Performance_Engine', 'Session_Engine', 'System_Engine', 'AuditActivity_Engine', 'Service_Engine',
          'Performance_Repository', 'AuditActivity_Repository', 'Performance_Proxy', 'Audit_Proxy',
          'TaskExecution_Scheduler', 'Service_Scheduler', 'System_Scheduler', 'System_Proxy')
$rx = '^[^_]+_(?<t>.+?)(?:_\d{8})?_\d{4}-\d{2}-\d{2}T[\d.]+Z?\.(log|txt)$'

if (-not (Test-Path -LiteralPath $Root)) {
    Write-Host "Can't reach $Root - check you're on the network and have access to the share." -ForegroundColor Red
    exit 1
}

Write-Host "Listing $Root (this reads names and dates only)..."
$all = @(Get-ChildItem -LiteralPath $Root -Recurse -File -ErrorAction SilentlyContinue | ForEach-Object {
    if ($_.Name -match $rx) { [pscustomobject]@{ File = $_; Type = $Matches['t'] } }
})
if ($all.Count -eq 0) { Write-Host 'No Qlik log files found.' -ForegroundColor Red; exit 1 }
Write-Host ("Found {0:N0} log files." -f $all.Count)

# fresh destination: remove only log/txt files we may have copied before
if (Test-Path -LiteralPath $Dest) {
    Get-ChildItem -LiteralPath $Dest -File | Where-Object { $_.Extension -in '.log', '.txt' } | Remove-Item -Force
} else {
    New-Item -ItemType Directory -Path $Dest -Force | Out-Null
}

$newest = ($all | ForEach-Object { $_.File.LastWriteTime } | Measure-Object -Maximum).Maximum
$cut = $newest.AddDays(-$Days)
$totalMB = 0; $totalFiles = 0

foreach ($t in $used) {
    $g = @($all | Where-Object { $_.Type -eq $t } | Sort-Object { $_.File.LastWriteTime } -Descending)
    if ($g.Count -eq 0) { Write-Host ("  {0,-26} not found" -f $t) -ForegroundColor DarkYellow; continue }
    if (($newest - $g[0].File.LastWriteTime).TotalDays -gt 45) {
        Write-Host ("  {0,-26} newest is {1:dd MMM yyyy} - skipped (too old)" -f $t, $g[0].File.LastWriteTime) -ForegroundColor DarkYellow
        continue
    }
    $recent = @($g | Where-Object { $_.File.LastWriteTime -ge $cut })
    if ($recent.Count -eq 0) { $recent = @($g[0]) }
    $mb = 0; $n = 0
    foreach ($x in $recent) {
        if ($n -gt 0 -and $mb -ge $MaxMBPerType) { break }
        $target = Join-Path $Dest $x.File.Name
        Copy-Item -LiteralPath $x.File.FullName -Destination $target -Force
        (Get-Item -LiteralPath $target).LastWriteTime = $x.File.LastWriteTime
        $mb += $x.File.Length / 1MB; $n++
    }
    $totalMB += $mb; $totalFiles += $n
    Write-Host ("  {0,-26} {1,3} file(s) {2,7:N1} MB  newest {3:ddd dd MMM HH:mm}" -f $t, $n, $mb, $g[0].File.LastWriteTime)
}

# the apps' own reload logs (used for reload failures)
$scriptSrc = Join-Path $Root 'Script'
if (Test-Path -LiteralPath $scriptSrc) {
    $scriptDest = Join-Path $Dest 'Script'
    if (Test-Path -LiteralPath $scriptDest) { Get-ChildItem -LiteralPath $scriptDest -File | Remove-Item -Force }
    else { New-Item -ItemType Directory -Path $scriptDest -Force | Out-Null }
    $since = $newest.AddDays(-$ScriptDays)
    $sl = @(Get-ChildItem -LiteralPath $scriptSrc -File -Filter '*.log' | Where-Object { $_.LastWriteTime -ge $since })
    foreach ($f in $sl) {
        $target = Join-Path $scriptDest $f.Name
        Copy-Item -LiteralPath $f.FullName -Destination $target -Force
        (Get-Item -LiteralPath $target).LastWriteTime = $f.LastWriteTime
    }
    Write-Host ("  Script\                    {0} reload log(s) from the last {1} days" -f $sl.Count, $ScriptDays)
}

# engine request history from the listing alone
$aud = @($all | Where-Object { $_.Type -eq 'AuditActivity_Engine' })
if ($aud.Count) {
    $aud | Group-Object { $_.File.LastWriteTime.ToString('yyyy-MM-dd HH:00') } | Sort-Object Name |
        ForEach-Object { '{0}  {1}' -f $_.Name, $_.Count } |
        Set-Content -LiteralPath (Join-Path $Dest 'audit_files_per_hour.txt') -Encoding UTF8
    Write-Host ("  audit_files_per_hour.txt   {0:N0} audit files summarised by hour" -f $aud.Count)
}

if ($Sample -and $aud.Count) {
    Write-Host "Sampling one engine audit file per day for the last $SampleDays days (reads ~8 MB a day)..."
    $from = $newest.Date.AddDays(-($SampleDays - 1))
    $days = @($aud | Where-Object { $_.File.LastWriteTime -ge $from } |
              Group-Object { $_.File.LastWriteTime.ToString('yyyy-MM-dd') } | Sort-Object Name)
    $i = 0
    $rows = foreach ($d in $days) {
        $i++
        Write-Progress -Activity 'Sampling engine audit files' -Status $d.Name -PercentComplete (100 * $i / $days.Count)
        $files = @($d.Group | Sort-Object { $_.File.LastWriteTime })
        $f = $files[[int][math]::Floor($files.Count / 2)].File
        $data = @(Import-Csv -LiteralPath $f.FullName -Delimiter "`t")
        if ($data.Count -eq 0) { continue }
        $top = $data | Group-Object ObjectName, UserId | Sort-Object Count -Descending | Select-Object -First 1
        [pscustomobject]@{
            Day        = $d.Name
            Files      = $files.Count
            Sampled    = $f.LastWriteTime.ToString('HH:mm')
            TopAppUser = $top.Name
            SharePct   = [math]::Round(100 * $top.Count / $data.Count)
        }
    }
    Write-Progress -Activity 'Sampling engine audit files' -Completed
    $rows | Format-Table -AutoSize | Out-String -Width 220 |
        Set-Content -LiteralPath (Join-Path $Dest 'audit_sample.txt') -Encoding UTF8
    Write-Host ("  audit_sample.txt           {0} days sampled" -f @($rows).Count)
}

Write-Host ''
Write-Host ("Copied {0} files ({1:N0} MB) to {2}" -f $totalFiles, $totalMB, $Dest) -ForegroundColor Green
Write-Host 'In the app, paste that folder into "...or read every log in a local folder" (and clear the ArchivedLogs box if you like).'
