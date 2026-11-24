# IBRA ANTIVIRUS — installs the behaviour guard as a SYSTEM task (runs at boot, restarts itself, normal programs cannot stop it)
param([Parameter(Mandatory = $true)][string]$Exe, [switch]$Remove)
$ErrorActionPreference = 'SilentlyContinue'
$name = 'IBRA ANTIVIRUS Guard'
Stop-ScheduledTask -TaskName $name
Unregister-ScheduledTask -TaskName $name -Confirm:$false
Get-Process ibra-guard | Stop-Process -Force
if ($Remove) { exit 0 }
$ErrorActionPreference = 'Stop'
$a = New-ScheduledTaskAction -Execute $Exe -Argument '--service'
$t1 = New-ScheduledTaskTrigger -AtStartup
$t2 = New-ScheduledTaskTrigger -AtLogOn
$t3 = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 5)
$p = New-ScheduledTaskPrincipal -UserId 'S-1-5-18' -LogonType ServiceAccount -RunLevel Highest
$s = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew -StartWhenAvailable -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -Priority 4
Register-ScheduledTask -TaskName $name -Action $a -Trigger @($t1, $t2, $t3) -Principal $p -Settings $s -Description 'IBRA ANTIVIRUS behaviour guard' -Force | Out-Null
Start-ScheduledTask -TaskName $name
'ok'
