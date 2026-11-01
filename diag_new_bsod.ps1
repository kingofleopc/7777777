$out = @()
$ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$out += "===== DIAG TIME: $ts ====="

try {
  $bt = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
  $out += ("[1] LAST BOOT: " + $bt.ToString("yyyy-MM-dd HH:mm:ss"))
  $up = (Get-Date) - $bt
  $out += ("    UPTIME: {0}d {1}h {2}m" -f $up.Days,$up.Hours,$up.Minutes)
} catch { $out += ("[1] BOOT TIME FAIL: " + $_.Exception.Message) }

$out += ""
$out += "===== [2] MINIDUMP LATEST ====="
$dir = "C:\Windows\Minidump"
if (Test-Path $dir) {
  $dumps = Get-ChildItem $dir -Filter "*.dmp" | Sort-Object LastWriteTime -Descending
  $out += ("  TOTAL " + $dumps.Count + " dumps. TOP 5:")
  foreach ($d in ($dumps | Select-Object -First 5)) {
    $out += ("  " + $d.Name + " | size " + $d.Length + " | written " + $d.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss"))
  }
} else { $out += "  Minidump dir missing" }

$out += ""
$out += "===== [3] SYSTEM LOG BUGCHECK (EventID 1001, 7d) ====="
try {
  $evts = Get-WinEvent -FilterHashtable @{LogName='System'; Id=1001; StartTime=(Get-Date).AddDays(-7)} -ErrorAction SilentlyContinue
  if ($evts) {
    $out += ("  TOTAL " + $evts.Count + " events. TOP 3:")
    foreach ($e in ($evts | Sort-Object TimeCreated -Descending | Select-Object -First 3)) {
      $out += ("  ---- " + $e.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss") + " | src: " + $e.ProviderName)
      $lines = ($e.Message -split "`n" | Where-Object { $_.Trim() -ne "" } | Select-Object -First 8)
      foreach ($l in $lines) { $out += ("    " + $l.Trim()) }
    }
  } else { $out += "  NO EventID 1001 in 7d" }
} catch { $out += ("  EventID1001 FAIL: " + $_.Exception.Message) }

$out += ""
$out += "===== [4] WER SYSTEM ERROR REPORT (7d) ====="
try {
  $wer = Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Microsoft-Windows-WER-SystemErrorReporting'; StartTime=(Get-Date).AddDays(-7)} -ErrorAction SilentlyContinue
  if ($wer) {
    $out += ("  TOTAL " + $wer.Count + " events. TOP 3:")
    foreach ($e in ($wer | Sort-Object TimeCreated -Descending | Select-Object -First 3)) {
      $out += ("  ---- " + $e.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss"))
      $lines = ($e.Message -split "`n" | Where-Object { $_.Trim() -ne "" } | Select-Object -First 5)
      foreach ($l in $lines) { $out += ("    " + $l.Trim()) }
    }
  } else { $out += "  NO WER reports" }
} catch { $out += ("  WER FAIL: " + $_.Exception.Message) }

$out += ""
$out += "===== [5] CURRENT DISPLAY DRIVERS ====="
try {
  $vcs = Get-CimInstance Win32_VideoController
  foreach ($c in $vcs) {
    $out += ("  " + $c.Name + " | ver: " + $c.DriverVersion + " | status: " + $c.Status)
  }
} catch { $out += ("  VIDEO QUERY FAIL: " + $_.Exception.Message) }

$out += ""
$out += "===== [6] PENDING FILE RENAME (reboot-pending) ====="
try {
  $pfr = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name PendingFileRenameOperations -ErrorAction SilentlyContinue
  if ($pfr -and $pfr.PendingFileRenameOperations) {
    $out += ("  FOUND " + $pfr.PendingFileRenameOperations.Count + " pending:")
    foreach ($p in $pfr.PendingFileRenameOperations) { $out += ("    " + $p) }
  } else { $out += "  NONE pending" }
} catch { $out += ("  READ FAIL: " + $_.Exception.Message) }

$out | Set-Content -Encoding UTF8 "D:\kingofleo\2026-10-29-20-08-09\diag_new_bsod.txt"
Write-Output "DIAG_DONE"
