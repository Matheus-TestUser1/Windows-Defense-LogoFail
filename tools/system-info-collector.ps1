#Requires -Version 5.1

<#
.SYNOPSIS
    System Information Collector - Coleta Informações Detalhadas do Sistema
    
.DESCRIPTION
    Ferramenta para coleta abrangente de informações do sistema Windows,
    incluindo hardware, software, configurações de segurança e status
    de proteção contra LogoFAIL. Útil para análise forense e troubleshooting.
    
.PARAMETER OutputPath
    Caminho para salvar o relatório de informações
    
.PARAMETER IncludeHardware
    Inclui informações detalhadas de hardware
    
.PARAMETER IncludeSoftware
    Inclui lista de software instalado
    
.PARAMETER IncludeNetwork
    Inclui configurações e status de rede
    
.PARAMETER IncludeSecurity
    Inclui configurações de segurança detalhadas
    
.PARAMETER Format
    Formato de saída: JSON, HTML, CSV
    
.EXAMPLE
    .\system-info-collector.ps1 -IncludeHardware -IncludeSecurity -Format HTML
    
.NOTES
    Author: Matheus-TestUser1
    Version: 1.0.0
    Requires: PowerShell 5.1+
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = ".\SystemInfo",
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeHardware,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeSoftware,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeNetwork,
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeSecurity,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("JSON", "HTML", "CSV")]
    [string]$Format = "JSON"
)

# ============================================================================
# CONFIGURAÇÕES GLOBAIS
# ============================================================================

$Script:CollectorConfig = @{
    Version = "1.0.0"
    StartTime = Get-Date
    OutputPath = $OutputPath
    Format = $Format
    SystemInfo = @{}
}

# ============================================================================
# FUNÇÕES DE LOGGING
# ============================================================================

function Write-CollectorLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("Info", "Warning", "Error", "Success")]
        [string]$Level = "Info"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    
    $color = switch ($Level) {
        "Info" { "Cyan" }
        "Warning" { "Yellow" }
        "Error" { "Red" }
        "Success" { "Green" }
    }
    
    Write-Host "[$timestamp] $Message" -ForegroundColor $color
}

# ============================================================================
# COLETA DE INFORMAÇÕES BÁSICAS
# ============================================================================

function Get-BasicSystemInfo {
    Write-CollectorLog "Coletando informações básicas do sistema..." -Level "Info"
    
    try {
        $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
        $computerInfo = Get-CimInstance -ClassName Win32_ComputerSystem
        $biosInfo = Get-CimInstance -ClassName Win32_BIOS
        
        return @{
            OperatingSystem = @{
                Name = $osInfo.Caption
                Version = $osInfo.Version
                BuildNumber = $osInfo.BuildNumber
                Architecture = $osInfo.OSArchitecture
                InstallDate = $osInfo.InstallDate
                LastBootUpTime = $osInfo.LastBootUpTime
                SystemDirectory = $osInfo.SystemDirectory
                WindowsDirectory = $osInfo.WindowsDirectory
                TotalVisibleMemorySize = $osInfo.TotalVisibleMemorySize
                FreePhysicalMemory = $osInfo.FreePhysicalMemory
                TotalVirtualMemorySize = $osInfo.TotalVirtualMemorySize
                FreeVirtualMemory = $osInfo.FreeVirtualMemory
            }
            Computer = @{
                Name = $computerInfo.Name
                Domain = $computerInfo.Domain
                Workgroup = $computerInfo.Workgroup
                Manufacturer = $computerInfo.Manufacturer
                Model = $computerInfo.Model
                SystemType = $computerInfo.SystemType
                TotalPhysicalMemory = $computerInfo.TotalPhysicalMemory
                NumberOfProcessors = $computerInfo.NumberOfProcessors
                NumberOfLogicalProcessors = $computerInfo.NumberOfLogicalProcessors
            }
            BIOS = @{
                Manufacturer = $biosInfo.Manufacturer
                Name = $biosInfo.Name
                Version = $biosInfo.Version
                SerialNumber = $biosInfo.SerialNumber
                ReleaseDate = $biosInfo.ReleaseDate
                SMBIOSBIOSVersion = $biosInfo.SMBIOSBIOSVersion
                SMBIOSMajorVersion = $biosInfo.SMBIOSMajorVersion
                SMBIOSMinorVersion = $biosInfo.SMBIOSMinorVersion
            }
            Environment = @{
                ComputerName = $env:COMPUTERNAME
                UserName = $env:USERNAME
                UserDomain = $env:USERDOMAIN
                PowerShellVersion = $PSVersionTable.PSVersion.ToString()
                CLRVersion = $PSVersionTable.CLRVersion.ToString()
            }
        }
    }
    catch {
        Write-CollectorLog "Erro ao coletar informações básicas: $_" -Level "Error"
        return @{}
    }
}

# ============================================================================
# COLETA DE INFORMAÇÕES DE HARDWARE
# ============================================================================

function Get-HardwareInfo {
    if (-not $IncludeHardware) {
        return @{}
    }
    
    Write-CollectorLog "Coletando informações de hardware..." -Level "Info"
    
    try {
        $hardware = @{
            Processors = @()
            Memory = @()
            Disks = @()
            NetworkAdapters = @()
            VideoControllers = @()
        }
        
        # Processadores
        $processors = Get-CimInstance -ClassName Win32_Processor
        foreach ($proc in $processors) {
            $hardware.Processors += @{
                Name = $proc.Name
                Manufacturer = $proc.Manufacturer
                MaxClockSpeed = $proc.MaxClockSpeed
                NumberOfCores = $proc.NumberOfCores
                NumberOfLogicalProcessors = $proc.NumberOfLogicalProcessors
                Architecture = $proc.Architecture
                Family = $proc.Family
                Model = $proc.Model
                Stepping = $proc.Stepping
            }
        }
        
        # Memória
        $memory = Get-CimInstance -ClassName Win32_PhysicalMemory
        foreach ($mem in $memory) {
            $hardware.Memory += @{
                Capacity = $mem.Capacity
                Speed = $mem.Speed
                Manufacturer = $mem.Manufacturer
                PartNumber = $mem.PartNumber
                SerialNumber = $mem.SerialNumber
                BankLabel = $mem.BankLabel
                DeviceLocator = $mem.DeviceLocator
            }
        }
        
        # Discos
        $disks = Get-CimInstance -ClassName Win32_DiskDrive
        foreach ($disk in $disks) {
            $hardware.Disks += @{
                Model = $disk.Model
                Size = $disk.Size
                InterfaceType = $disk.InterfaceType
                MediaType = $disk.MediaType
                SerialNumber = $disk.SerialNumber
                FirmwareRevision = $disk.FirmwareRevision
                Partitions = $disk.Partitions
            }
        }
        
        # Adaptadores de rede
        $netAdapters = Get-CimInstance -ClassName Win32_NetworkAdapter | Where-Object { $_.PhysicalAdapter -eq $true }
        foreach ($adapter in $netAdapters) {
            $hardware.NetworkAdapters += @{
                Name = $adapter.Name
                Manufacturer = $adapter.Manufacturer
                MACAddress = $adapter.MACAddress
                AdapterType = $adapter.AdapterType
                Speed = $adapter.Speed
                NetConnectionStatus = $adapter.NetConnectionStatus
            }
        }
        
        # Controladores de vídeo
        $videoControllers = Get-CimInstance -ClassName Win32_VideoController
        foreach ($video in $videoControllers) {
            $hardware.VideoControllers += @{
                Name = $video.Name
                AdapterRAM = $video.AdapterRAM
                DriverVersion = $video.DriverVersion
                DriverDate = $video.DriverDate
                VideoProcessor = $video.VideoProcessor
                CurrentHorizontalResolution = $video.CurrentHorizontalResolution
                CurrentVerticalResolution = $video.CurrentVerticalResolution
            }
        }
        
        return $hardware
    }
    catch {
        Write-CollectorLog "Erro ao coletar informações de hardware: $_" -Level "Error"
        return @{}
    }
}

# ============================================================================
# COLETA DE INFORMAÇÕES DE SOFTWARE
# ============================================================================

function Get-SoftwareInfo {
    if (-not $IncludeSoftware) {
        return @{}
    }
    
    Write-CollectorLog "Coletando informações de software..." -Level "Info"
    
    try {
        $software = @{
            InstalledPrograms = @()
            Services = @()
            StartupPrograms = @()
            WindowsFeatures = @()
        }
        
        # Programas instalados (32-bit e 64-bit)
        $uninstallPaths = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
        )
        
        foreach ($path in $uninstallPaths) {
            $programs = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName }
            foreach ($program in $programs) {
                $software.InstalledPrograms += @{
                    DisplayName = $program.DisplayName
                    DisplayVersion = $program.DisplayVersion
                    Publisher = $program.Publisher
                    InstallDate = $program.InstallDate
                    EstimatedSize = $program.EstimatedSize
                    InstallLocation = $program.InstallLocation
                }
            }
        }
        
        # Serviços
        $services = Get-Service | Select-Object -First 50  # Limitar para não sobrecarregar
        foreach ($service in $services) {
            $software.Services += @{
                Name = $service.Name
                DisplayName = $service.DisplayName
                Status = $service.Status.ToString()
                StartType = $service.StartType.ToString()
            }
        }
        
        # Programas de inicialização
        $startupLocations = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
        )
        
        foreach ($location in $startupLocations) {
            try {
                $startupItems = Get-ItemProperty -Path $location -ErrorAction SilentlyContinue
                if ($startupItems) {
                    $startupItems.PSObject.Properties | Where-Object { $_.Name -notmatch "^PS" } | ForEach-Object {
                        $software.StartupPrograms += @{
                            Name = $_.Name
                            Command = $_.Value
                            Location = $location
                        }
                    }
                }
            }
            catch { }
        }
        
        return $software
    }
    catch {
        Write-CollectorLog "Erro ao coletar informações de software: $_" -Level "Error"
        return @{}
    }
}

# ============================================================================
# COLETA DE INFORMAÇÕES DE REDE
# ============================================================================

function Get-NetworkInfo {
    if (-not $IncludeNetwork) {
        return @{}
    }
    
    Write-CollectorLog "Coletando informações de rede..." -Level "Info"
    
    try {
        $network = @{
            IPConfiguration = @()
            NetworkConnections = @()
            FirewallStatus = @{}
            DNSConfiguration = @{}
        }
        
        # Configuração IP
        $ipConfigs = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true }
        foreach ($config in $ipConfigs) {
            $network.IPConfiguration += @{
                Description = $config.Description
                IPAddress = $config.IPAddress
                SubnetMask = $config.IPSubnet
                DefaultGateway = $config.DefaultIPGateway
                DNSServerSearchOrder = $config.DNSServerSearchOrder
                DHCPEnabled = $config.DHCPEnabled
                MACAddress = $config.MACAddress
            }
        }
        
        # Conexões de rede ativas (limitadas)
        $connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | Select-Object -First 20
        foreach ($conn in $connections) {
            $network.NetworkConnections += @{
                LocalAddress = $conn.LocalAddress
                LocalPort = $conn.LocalPort
                RemoteAddress = $conn.RemoteAddress
                RemotePort = $conn.RemotePort
                State = $conn.State.ToString()
                OwningProcess = $conn.OwningProcess
            }
        }
        
        # Status do Firewall
        try {
            $firewallProfiles = Get-NetFirewallProfile
            foreach ($profile in $firewallProfiles) {
                $network.FirewallStatus[$profile.Name] = @{
                    Enabled = $profile.Enabled
                    DefaultInboundAction = $profile.DefaultInboundAction.ToString()
                    DefaultOutboundAction = $profile.DefaultOutboundAction.ToString()
                }
            }
        }
        catch { }
        
        return $network
    }
    catch {
        Write-CollectorLog "Erro ao coletar informações de rede: $_" -Level "Error"
        return @{}
    }
}

# ============================================================================
# COLETA DE INFORMAÇÕES DE SEGURANÇA
# ============================================================================

function Get-SecurityInfo {
    if (-not $IncludeSecurity) {
        return @{}
    }
    
    Write-CollectorLog "Coletando informações de segurança..." -Level "Info"
    
    try {
        $security = @{
            SecureBoot = @{}
            TPM = @{}
            WindowsDefender = @{}
            BitLocker = @{}
            UAC = @{}
            WindowsUpdate = @{}
            LogoFAILProtection = @{}
        }
        
        # Secure Boot
        try {
            $secureBootState = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
            $security.SecureBoot = @{
                Enabled = $secureBootState
                Supported = $true
            }
        }
        catch {
            $security.SecureBoot = @{
                Enabled = $false
                Supported = $false
                Error = $_.Exception.Message
            }
        }
        
        # TPM
        try {
            $tpm = Get-Tpm -ErrorAction SilentlyContinue
            $security.TPM = @{
                TpmPresent = $tpm.TpmPresent
                TpmReady = $tpm.TpmReady
                TpmEnabled = $tpm.TpmEnabled
                TpmActivated = $tpm.TpmActivated
                TpmOwned = $tpm.TpmOwned
                RestartPending = $tpm.RestartPending
                ManufacturerVersion = $tpm.ManufacturerVersion
                ManufacturerVersionFull20 = $tmp.ManufacturerVersionFull20
                ManagedAuthLevel = $tpm.ManagedAuthLevel
            }
        }
        catch {
            $security.TPM = @{
                Available = $false
                Error = $_.Exception.Message
            }
        }
        
        # Windows Defender
        try {
            $defenderStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
            $security.WindowsDefender = @{
                AntivirusEnabled = $defenderStatus.AntivirusEnabled
                AntispywareEnabled = $defenderStatus.AntispywareEnabled
                RealTimeProtectionEnabled = $defenderStatus.RealTimeProtectionEnabled
                OnAccessProtectionEnabled = $defenderStatus.OnAccessProtectionEnabled
                BehaviorMonitorEnabled = $defenderStatus.BehaviorMonitorEnabled
                IoavProtectionEnabled = $defenderStatus.IoavProtectionEnabled
                NISEnabled = $defenderStatus.NISEnabled
                AntivirusSignatureLastUpdated = $defenderStatus.AntivirusSignatureLastUpdated
                AntispywareSignatureLastUpdated = $defenderStatus.AntispywareSignatureLastUpdated
            }
        }
        catch {
            $security.WindowsDefender = @{
                Available = $false
                Error = $_.Exception.Message
            }
        }
        
        # BitLocker
        try {
            $bitlockerVolumes = Get-BitLockerVolume -ErrorAction SilentlyContinue
            $security.BitLocker = @{
                Volumes = @()
            }
            
            foreach ($volume in $bitlockerVolumes) {
                $security.BitLocker.Volumes += @{
                    MountPoint = $volume.MountPoint
                    EncryptionMethod = $volume.EncryptionMethod.ToString()
                    VolumeStatus = $volume.VolumeStatus.ToString()
                    ProtectionStatus = $volume.ProtectionStatus.ToString()
                    LockStatus = $volume.LockStatus.ToString()
                    EncryptionPercentage = $volume.EncryptionPercentage
                }
            }
        }
        catch {
            $security.BitLocker = @{
                Available = $false
                Error = $_.Exception.Message
            }
        }
        
        # Verificar proteção LogoFAIL
        $logoFailPath = "$env:ProgramData\WindowsDefenseLogoFAIL"
        if (Test-Path $logoFailPath) {
            $security.LogoFAILProtection = @{
                Installed = $true
                InstallPath = $logoFailPath
                ConfigExists = Test-Path "$logoFailPath\Config"
                LogsExist = Test-Path "$logoFailPath\Logs"
                BaselinesExist = Test-Path "$logoFailPath\Baselines"
            }
            
            # Verificar tarefa agendada
            $task = Get-ScheduledTask -TaskName "LogoFAIL-ContinuousMonitor" -ErrorAction SilentlyContinue
            $security.LogoFAILProtection.ScheduledTaskExists = $task -ne $null
            if ($task) {
                $security.LogoFAILProtection.ScheduledTaskState = $task.State.ToString()
            }
        } else {
            $security.LogoFAILProtection = @{
                Installed = $false
            }
        }
        
        return $security
    }
    catch {
        Write-CollectorLog "Erro ao coletar informações de segurança: $_" -Level "Error"
        return @{}
    }
}

# ============================================================================
# GERAÇÃO DE RELATÓRIO
# ============================================================================

function Export-SystemInfo {
    param([hashtable]$SystemInfo)
    
    try {
        if (-not (Test-Path $Script:CollectorConfig.OutputPath)) {
            New-Item -Path $Script:CollectorConfig.OutputPath -ItemType Directory -Force | Out-Null
        }
        
        $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
        $fileName = "system-info-$timestamp"
        
        switch ($Script:CollectorConfig.Format) {
            "JSON" {
                $outputFile = Join-Path $Script:CollectorConfig.OutputPath "$fileName.json"
                $SystemInfo | ConvertTo-Json -Depth 6 | Set-Content -Path $outputFile -Encoding UTF8
            }
            
            "HTML" {
                $outputFile = Join-Path $Script:CollectorConfig.OutputPath "$fileName.html"
                $htmlContent = Generate-HTMLReport -SystemInfo $SystemInfo
                $htmlContent | Set-Content -Path $outputFile -Encoding UTF8
            }
            
            "CSV" {
                $outputFile = Join-Path $Script:CollectorConfig.OutputPath "$fileName.csv"
                # Para CSV, achatar os dados principais
                $flatData = Flatten-SystemInfo -SystemInfo $SystemInfo
                $flatData | Export-Csv -Path $outputFile -NoTypeInformation -Encoding UTF8
            }
        }
        
        Write-CollectorLog "Relatório de sistema salvo em: $outputFile" -Level "Success"
        return $outputFile
    }
    catch {
        Write-CollectorLog "Erro ao exportar relatório: $_" -Level "Error"
        return $null
    }
}

function Generate-HTMLReport {
    param([hashtable]$SystemInfo)
    
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>System Information Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }
        .section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background: #f5f5f5; }
        .metric { display: inline-block; margin: 10px; padding: 15px; background: #f8f9fa; border-radius: 5px; }
    </style>
</head>
<body>
    <div class="header">
        <h1>System Information Report</h1>
        <p>Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
        <p>Computer: $($SystemInfo.Basic.Computer.Name)</p>
    </div>
"@
    
    # Adicionar seções baseadas nos dados coletados
    foreach ($section in $SystemInfo.Keys) {
        if ($SystemInfo[$section] -and $SystemInfo[$section].Count -gt 0) {
            $html += "<div class='section'><h2>$section</h2>"
            $html += "<pre>$(($SystemInfo[$section] | ConvertTo-Json -Depth 3) -replace '<', '&lt;' -replace '>', '&gt;')</pre>"
            $html += "</div>"
        }
    }
    
    $html += "</body></html>"
    return $html
}

function Flatten-SystemInfo {
    param([hashtable]$SystemInfo)
    
    $flatData = @()
    
    # Converter dados hierárquicos em linhas planas para CSV
    foreach ($category in $SystemInfo.Keys) {
        if ($SystemInfo[$category] -is [hashtable]) {
            foreach ($item in $SystemInfo[$category].Keys) {
                $flatData += [PSCustomObject]@{
                    Category = $category
                    Item = $item
                    Value = $SystemInfo[$category][$item]
                }
            }
        }
    }
    
    return $flatData
}

# ============================================================================
# FUNÇÃO PRINCIPAL
# ============================================================================

function Start-SystemInfoCollection {
    Write-Host "======================================================================" -ForegroundColor Cyan
    Write-Host "    System Information Collector" -ForegroundColor Cyan
    Write-Host "    Versão: $($Script:CollectorConfig.Version)" -ForegroundColor Cyan
    Write-Host "======================================================================" -ForegroundColor Cyan
    Write-Host ""
    
    try {
        $systemInfo = @{}
        
        # Coletar informações básicas
        $systemInfo.Basic = Get-BasicSystemInfo
        
        # Coletar informações opcionais baseadas nos parâmetros
        if ($IncludeHardware) {
            $systemInfo.Hardware = Get-HardwareInfo
        }
        
        if ($IncludeSoftware) {
            $systemInfo.Software = Get-SoftwareInfo
        }
        
        if ($IncludeNetwork) {
            $systemInfo.Network = Get-NetworkInfo
        }
        
        if ($IncludeSecurity) {
            $systemInfo.Security = Get-SecurityInfo
        }
        
        # Adicionar metadados da coleta
        $systemInfo.CollectionMetadata = @{
            Version = $Script:CollectorConfig.Version
            StartTime = $Script:CollectorConfig.StartTime.ToString("yyyy-MM-dd HH:mm:ss")
            EndTime = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            Duration = ((Get-Date) - $Script:CollectorConfig.StartTime).TotalSeconds
            IncludedSections = @()
        }
        
        # Registrar seções incluídas
        if ($IncludeHardware) { $systemInfo.CollectionMetadata.IncludedSections += "Hardware" }
        if ($IncludeSoftware) { $systemInfo.CollectionMetadata.IncludedSections += "Software" }
        if ($IncludeNetwork) { $systemInfo.CollectionMetadata.IncludedSections += "Network" }
        if ($IncludeSecurity) { $systemInfo.CollectionMetadata.IncludedSections += "Security" }
        
        $Script:CollectorConfig.SystemInfo = $systemInfo
        
        # Exportar relatório
        $reportFile = Export-SystemInfo -SystemInfo $systemInfo
        
        Write-Host ""
        Write-Host "======================================================================" -ForegroundColor Green
        Write-Host "    Coleta de Informações Concluída!" -ForegroundColor Green
        Write-Host "======================================================================" -ForegroundColor Green
        Write-Host ""
        
        # Exibir resumo
        Write-Host "RESUMO DA COLETA:" -ForegroundColor Yellow
        Write-Host "- Sistema: $($systemInfo.Basic.Computer.Name)" -ForegroundColor White
        Write-Host "- OS: $($systemInfo.Basic.OperatingSystem.Name)" -ForegroundColor White
        Write-Host "- Formato: $($Script:CollectorConfig.Format)" -ForegroundColor White
        Write-Host "- Seções coletadas: $($systemInfo.CollectionMetadata.IncludedSections.Count)" -ForegroundColor White
        Write-Host "- Duração: $([math]::Round($systemInfo.CollectionMetadata.Duration, 2)) segundos" -ForegroundColor White
        
        if ($reportFile) {
            Write-Host "- Relatório: $reportFile" -ForegroundColor White
        }
        
        return $true
    }
    catch {
        Write-CollectorLog "Erro durante coleta de informações: $_" -Level "Error"
        return $false
    }
}

# ============================================================================
# EXECUÇÃO PRINCIPAL
# ============================================================================

try {
    $result = Start-SystemInfoCollection
    if ($result) {
        exit 0
    } else {
        exit 1
    }
}
catch {
    Write-Host "Erro fatal: $_" -ForegroundColor Red
    exit 1
}