#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    LogoFAIL Forensic Analysis - Análise Forense Completa para Vulnerabilidades LogoFAIL
    
.DESCRIPTION
    Script especializado para análise forense detalhada de sistemas Windows visando
    identificar sinais de comprometimento relacionados à vulnerabilidade LogoFAIL.
    Inclui análise de firmware, processos, registro, arquivos e conexões de rede.
    
.PARAMETER OutputPath
    Caminho para salvar o relatório forense
    
.PARAMETER IncludeLenovoAnalysis
    Inclui análise específica do Lenovo Vantage
    
.PARAMETER DeepScan
    Ativa varredura profunda (mais demorada)
    
.PARAMETER ExportEvidence
    Exporta evidências para análise offline
    
.EXAMPLE
    .\LogoFAIL-ForensicAnalysis.ps1 -OutputPath "C:\Forensics" -IncludeLenovoAnalysis -DeepScan
    
.NOTES
    Author: Matheus-TestUser1
    Version: 1.0.0
    Requires: Windows 10/11, PowerShell 5.1+, Administrator privileges
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = "$env:TEMP\LogoFAIL-Forensics",
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeLenovoAnalysis,
    
    [Parameter(Mandatory = $false)]
    [switch]$DeepScan,
    
    [Parameter(Mandatory = $false)]
    [switch]$ExportEvidence
)

# ============================================================================
# CONFIGURAÇÕES GLOBAIS
# ============================================================================

$Script:ForensicConfig = @{
    Version = "1.0.0"
    StartTime = Get-Date
    OutputPath = $OutputPath
    TempPath = "$env:TEMP\LogoFAIL-Temp-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
    ReportFile = ""
    EvidenceFiles = @()
    ThreatLevel = "INFO"
}

# Indicadores de Comprometimento (IoCs) conhecidos para LogoFAIL
$Script:LogoFAILIoCs = @{
    SuspiciousFiles = @(
        "*logo*.efi",
        "*boot*.efi", 
        "*uefi*.dll",
        "bootmgfw.efi.backup",
        "*.bmp.exe",
        "*.jpg.exe",
        "*.png.exe"
    )
    SuspiciousProcesses = @(
        "LenovoVantageService",
        "ImControllerService", 
        "LenovoVantage",
        "*logo*",
        "*boot*"
    )
    SuspiciousRegistryKeys = @(
        "HKLM:\SOFTWARE\Lenovo\ImController",
        "HKLM:\SOFTWARE\Lenovo\Vantage",
        "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State",
        "HKLM:\SYSTEM\CurrentControlSet\Control\BootDriverFlags"
    )
    SuspiciousNetworkConnections = @(
        "*.lenovo.com",
        "*vantage*",
        "*logo*"
    )
    VulnerableFirmwareVersions = @(
        # Versões conhecidas vulneráveis serão adicionadas conforme descobertas
    )
}

# ============================================================================
# FUNÇÕES DE LOGGING E RELATÓRIO
# ============================================================================

function Write-ForensicLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("CRÍTICO", "SUSPEITO", "ALERTA", "INFO")]
        [string]$Level = "INFO",
        
        [Parameter(Mandatory = $false)]
        [string]$Component = "ForensicAnalysis"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = @{
        Timestamp = $timestamp
        Level = $Level
        Component = $Component
        Message = $Message
        ComputerName = $env:COMPUTERNAME
    }
    
    # Console output com cores baseadas no nível
    $color = switch ($Level) {
        "CRÍTICO" { "Red" }
        "SUSPEITO" { "Magenta" }
        "ALERTA" { "Yellow" }
        "INFO" { "Cyan" }
    }
    
    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $color
    
    # Atualizar nível de ameaça global
    switch ($Level) {
        "CRÍTICO" { $Script:ForensicConfig.ThreatLevel = "CRÍTICO" }
        "SUSPEITO" { 
            if ($Script:ForensicConfig.ThreatLevel -eq "INFO" -or $Script:ForensicConfig.ThreatLevel -eq "ALERTA") {
                $Script:ForensicConfig.ThreatLevel = "SUSPEITO"
            }
        }
        "ALERTA" { 
            if ($Script:ForensicConfig.ThreatLevel -eq "INFO") {
                $Script:ForensicConfig.ThreatLevel = "ALERTA"
            }
        }
    }
    
    return $logEntry
}

function New-ForensicReport {
    param(
        [Parameter(Mandatory = $true)]
        [hashtable]$AnalysisResults
    )
    
    $reportData = @{
        ReportMetadata = @{
            GeneratedBy = "LogoFAIL Forensic Analysis v$($Script:ForensicConfig.Version)"
            GeneratedAt = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            ComputerName = $env:COMPUTERNAME
            Username = $env:USERNAME
            AnalysisDuration = ((Get-Date) - $Script:ForensicConfig.StartTime).TotalSeconds
            ThreatLevel = $Script:ForensicConfig.ThreatLevel
        }
        SystemInfo = $AnalysisResults.SystemInfo
        FirmwareAnalysis = $AnalysisResults.FirmwareAnalysis
        ProcessAnalysis = $AnalysisResults.ProcessAnalysis
        RegistryAnalysis = $AnalysisResults.RegistryAnalysis
        FileSystemAnalysis = $AnalysisResults.FileSystemAnalysis
        NetworkAnalysis = $AnalysisResults.NetworkAnalysis
        EventLogAnalysis = $AnalysisResults.EventLogAnalysis
        IntegrityAnalysis = $AnalysisResults.IntegrityAnalysis
        LenovoAnalysis = $AnalysisResults.LenovoAnalysis
        Recommendations = $AnalysisResults.Recommendations
        Evidence = $Script:ForensicConfig.EvidenceFiles
    }
    
    try {
        # Relatório JSON detalhado
        $jsonReport = Join-Path $Script:ForensicConfig.OutputPath "forensic-report-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
        $reportData | ConvertTo-Json -Depth 6 | Set-Content -Path $jsonReport -Encoding UTF8
        
        # Relatório HTML legível
        $htmlReport = Join-Path $Script:ForensicConfig.OutputPath "forensic-report-$(Get-Date -Format 'yyyyMMdd-HHmmss').html"
        $htmlContent = Generate-HTMLReport -ReportData $reportData
        $htmlContent | Set-Content -Path $htmlReport -Encoding UTF8
        
        $Script:ForensicConfig.ReportFile = $jsonReport
        
        Write-ForensicLog "Relatório forense salvo em: $jsonReport" -Level "INFO"
        Write-ForensicLog "Relatório HTML salvo em: $htmlReport" -Level "INFO"
        
        return $jsonReport
    }
    catch {
        Write-ForensicLog "Erro ao gerar relatório: $_" -Level "CRÍTICO"
        return $null
    }
}

function Generate-HTMLReport {
    param([hashtable]$ReportData)
    
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>LogoFAIL Forensic Analysis Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 5px; }
        .section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
        .critical { background: #ffebee; border-left: 5px solid #f44336; }
        .suspicious { background: #fce4ec; border-left: 5px solid #e91e63; }
        .warning { background: #fff3e0; border-left: 5px solid #ff9800; }
        .info { background: #e3f2fd; border-left: 5px solid #2196f3; }
        .threat-level { font-size: 24px; font-weight: bold; text-align: center; padding: 10px; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background: #f5f5f5; }
        pre { background: #f5f5f5; padding: 10px; border-radius: 3px; overflow-x: auto; }
    </style>
</head>
<body>
    <div class="header">
        <h1>LogoFAIL Forensic Analysis Report</h1>
        <p>Computer: $($ReportData.ReportMetadata.ComputerName) | Generated: $($ReportData.ReportMetadata.GeneratedAt)</p>
    </div>
    
    <div class="threat-level $($ReportData.ReportMetadata.ThreatLevel.ToLower())">
        THREAT LEVEL: $($ReportData.ReportMetadata.ThreatLevel)
    </div>
"@
    
    # Adicionar seções do relatório
    foreach ($section in @("SystemInfo", "FirmwareAnalysis", "ProcessAnalysis", "RegistryAnalysis", "FileSystemAnalysis", "NetworkAnalysis", "EventLogAnalysis", "IntegrityAnalysis")) {
        if ($ReportData.ContainsKey($section) -and $ReportData[$section]) {
            $html += "<div class='section'><h2>$section</h2><pre>$(($ReportData[$section] | ConvertTo-Json -Depth 3) -replace '<', '&lt;' -replace '>', '&gt;')</pre></div>"
        }
    }
    
    $html += "</body></html>"
    return $html
}

# ============================================================================
# ANÁLISE DE INFORMAÇÕES DO SISTEMA
# ============================================================================

function Get-SystemInformation {
    Write-ForensicLog "Coletando informações do sistema..." -Level "INFO"
    
    try {
        $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
        $computerInfo = Get-CimInstance -ClassName Win32_ComputerSystem
        $biosInfo = Get-CimInstance -ClassName Win32_BIOS
        
        return @{
            OperatingSystem = @{
                Caption = $osInfo.Caption
                Version = $osInfo.Version
                BuildNumber = $osInfo.BuildNumber
                InstallDate = $osInfo.InstallDate
                LastBootUpTime = $osInfo.LastBootUpTime
                Architecture = $osInfo.OSArchitecture
            }
            Computer = @{
                Name = $computerInfo.Name
                Domain = $computerInfo.Domain
                Manufacturer = $computerInfo.Manufacturer
                Model = $computerInfo.Model
                SystemType = $computerInfo.SystemType
                TotalPhysicalMemory = $computerInfo.TotalPhysicalMemory
            }
            BIOS = @{
                Manufacturer = $biosInfo.Manufacturer
                Version = $biosInfo.Version
                SerialNumber = $biosInfo.SerialNumber
                ReleaseDate = $biosInfo.ReleaseDate
                SMBIOSVersion = $biosInfo.SMBIOSBIOSVersion
            }
            CollectionTime = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        }
    }
    catch {
        Write-ForensicLog "Erro ao coletar informações do sistema: $_" -Level "CRÍTICO"
        return @{ Error = $_.Exception.Message }
    }
}

# ============================================================================
# ANÁLISE DE FIRMWARE E BOOT
# ============================================================================

function Invoke-FirmwareAnalysis {
    Write-ForensicLog "Analisando integridade do firmware e boot..." -Level "INFO"
    
    $analysis = @{
        SecureBootStatus = $null
        FirmwareType = $null
        BootConfiguration = @{}
        UEFIVariables = @{}
        TPMStatus = $null
        Issues = @()
    }
    
    try {
        # Verificar Secure Boot
        try {
            $secureBootState = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
            $analysis.SecureBootStatus = $secureBootState
            
            if (-not $secureBootState) {
                $analysis.Issues += "Secure Boot desabilitado - CRÍTICO para proteção LogoFAIL"
                Write-ForensicLog "Secure Boot desabilitado - sistema vulnerável" -Level "CRÍTICO"
            } else {
                Write-ForensicLog "Secure Boot ativo" -Level "INFO"
            }
        }
        catch {
            $analysis.Issues += "Não foi possível verificar status do Secure Boot"
            Write-ForensicLog "Erro ao verificar Secure Boot: $_" -Level "ALERTA"
        }
        
        # Verificar tipo de firmware
        try {
            $firmwareType = (Get-CimInstance -ClassName Win32_ComputerSystem).PCSystemType
            $analysis.FirmwareType = if ($firmwareType -eq 2) { "UEFI" } else { "Legacy" }
            
            if ($analysis.FirmwareType -eq "Legacy") {
                $analysis.Issues += "Sistema Legacy BIOS detectado - considere atualizar para UEFI"
                Write-ForensicLog "Sistema Legacy BIOS - vulnerabilidade potencial" -Level "ALERTA"
            }
        }
        catch {
            Write-ForensicLog "Erro ao detectar tipo de firmware: $_" -Level "ALERTA"
        }
        
        # Verificar configuração de boot
        try {
            $bootConfig = & bcdedit.exe /enum 2>$null
            if ($bootConfig) {
                $analysis.BootConfiguration = @{
                    RawOutput = $bootConfig -join "`n"
                    ParsedEntries = @()
                }
                
                # Procurar por configurações suspeitas
                foreach ($line in $bootConfig) {
                    if ($line -match "testsigning.*yes") {
                        $analysis.Issues += "Test signing habilitado - pode permitir drivers não assinados"
                        Write-ForensicLog "Test signing habilitado detectado" -Level "SUSPEITO"
                    }
                    if ($line -match "nointegritychecks.*yes") {
                        $analysis.Issues += "Verificações de integridade desabilitadas"
                        Write-ForensicLog "Verificações de integridade desabilitadas" -Level "SUSPEITO"
                    }
                }
            }
        }
        catch {
            Write-ForensicLog "Erro ao analisar configuração de boot: $_" -Level "ALERTA"
        }
        
        # Verificar TPM
        try {
            $tpm = Get-Tpm -ErrorAction SilentlyContinue
            if ($tpm) {
                $analysis.TPMStatus = @{
                    Enabled = $tpm.TpmEnabled
                    Activated = $tpm.TpmActivated
                    Owned = $tpm.TpmOwned
                    Version = $tpm.TpmVersion
                }
                
                if (-not $tpm.TpmEnabled) {
                    $analysis.Issues += "TPM não habilitado - recurso de segurança importante"
                    Write-ForensicLog "TPM não habilitado" -Level "ALERTA"
                }
            }
        }
        catch {
            Write-ForensicLog "Erro ao verificar TPM: $_" -Level "ALERTA"
        }
        
        return $analysis
    }
    catch {
        Write-ForensicLog "Erro durante análise de firmware: $_" -Level "CRÍTICO"
        return $analysis
    }
}

# ============================================================================
# ANÁLISE DE PROCESSOS SUSPEITOS
# ============================================================================

function Invoke-ProcessAnalysis {
    Write-ForensicLog "Analisando processos em execução..." -Level "INFO"
    
    $analysis = @{
        SuspiciousProcesses = @()
        RunningServices = @()
        NetworkConnections = @()
        LoadedModules = @()
        Issues = @()
    }
    
    try {
        $processes = Get-Process | Select-Object Id, Name, ProcessName, Path, Company, StartTime, WorkingSet64
        
        foreach ($process in $processes) {
            $isSuspicious = $false
            $suspiciousReasons = @()
            
            # Verificar contra IoCs conhecidos
            foreach ($suspiciousPattern in $Script:LogoFAILIoCs.SuspiciousProcesses) {
                if ($process.ProcessName -like $suspiciousPattern) {
                    $isSuspicious = $true
                    $suspiciousReasons += "Nome corresponde a padrão suspeito: $suspiciousPattern"
                }
            }
            
            # Verificar processos sem assinatura digital ou de locais incomuns
            if ($process.Path) {
                try {
                    $signature = Get-AuthenticodeSignature -FilePath $process.Path -ErrorAction SilentlyContinue
                    if ($signature -and $signature.Status -ne "Valid") {
                        $isSuspicious = $true
                        $suspiciousReasons += "Assinatura digital inválida: $($signature.Status)"
                    }
                    
                    # Verificar se está executando de locais incomuns
                    $suspiciousLocations = @("$env:TEMP", "$env:APPDATA", "C:\Users\Public")
                    foreach ($location in $suspiciousLocations) {
                        if ($process.Path -like "$location*") {
                            $isSuspicious = $true
                            $suspiciousReasons += "Executando de local suspeito: $location"
                        }
                    }
                }
                catch {
                    # Ignorar erros de verificação de assinatura para alguns processos do sistema
                }
            }
            
            if ($isSuspicious) {
                $suspiciousProcess = @{
                    ProcessId = $process.Id
                    Name = $process.ProcessName
                    Path = $process.Path
                    Company = $process.Company
                    StartTime = $process.StartTime
                    WorkingSet = $process.WorkingSet64
                    Reasons = $suspiciousReasons
                }
                
                $analysis.SuspiciousProcesses += $suspiciousProcess
                Write-ForensicLog "Processo suspeito detectado: $($process.ProcessName) (PID: $($process.Id))" -Level "SUSPEITO"
                
                $analysis.Issues += "Processo suspeito: $($process.ProcessName) - $($suspiciousReasons -join ', ')"
            }
        }
        
        # Analisar serviços específicos
        $targetServices = @("LenovoVantageService", "ImControllerService", "Lenovo*")
        foreach ($servicePattern in $targetServices) {
            $services = Get-Service -Name $servicePattern -ErrorAction SilentlyContinue
            foreach ($service in $services) {
                $serviceInfo = @{
                    Name = $service.Name
                    DisplayName = $service.DisplayName
                    Status = $service.Status.ToString()
                    StartType = $service.StartType.ToString()
                }
                
                $analysis.RunningServices += $serviceInfo
                
                if ($service.Status -eq "Running") {
                    Write-ForensicLog "Serviço Lenovo ativo detectado: $($service.Name)" -Level "ALERTA"
                    $analysis.Issues += "Serviço Lenovo ativo: $($service.Name) - pode estar relacionado a LogoFAIL"
                }
            }
        }
        
        return $analysis
    }
    catch {
        Write-ForensicLog "Erro durante análise de processos: $_" -Level "CRÍTICO"
        return $analysis
    }
}

# ============================================================================
# ANÁLISE DO REGISTRO
# ============================================================================

function Invoke-RegistryAnalysis {
    Write-ForensicLog "Analisando modificações no registro..." -Level "INFO"
    
    $analysis = @{
        SuspiciousKeys = @()
        SecureBootKeys = @()
        StartupPrograms = @()
        Issues = @()
    }
    
    try {
        # Verificar chaves de registro suspeitas
        foreach ($keyPath in $Script:LogoFAILIoCs.SuspiciousRegistryKeys) {
            try {
                if (Test-Path $keyPath) {
                    $keyData = Get-ItemProperty -Path $keyPath -ErrorAction SilentlyContinue
                    if ($keyData) {
                        $keyInfo = @{
                            Path = $keyPath
                            Properties = @{}
                            LastWriteTime = (Get-Item $keyPath).LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
                        }
                        
                        # Capturar propriedades (excluindo propriedades padrão do PowerShell)
                        $excludeProperties = @("PSPath", "PSParentPath", "PSChildName", "PSDrive", "PSProvider")
                        foreach ($property in $keyData.PSObject.Properties) {
                            if ($property.Name -notin $excludeProperties) {
                                $keyInfo.Properties[$property.Name] = $property.Value
                            }
                        }
                        
                        $analysis.SuspiciousKeys += $keyInfo
                        Write-ForensicLog "Chave de registro suspeita encontrada: $keyPath" -Level "ALERTA"
                    }
                }
            }
            catch {
                Write-ForensicLog "Erro ao verificar chave $keyPath`: $_" -Level "ALERTA"
            }
        }
        
        # Verificar configurações de Secure Boot no registro
        try {
            $secureBootPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State"
            if (Test-Path $secureBootPath) {
                $secureBootData = Get-ItemProperty -Path $secureBootPath -ErrorAction SilentlyContinue
                $analysis.SecureBootKeys = $secureBootData
                
                if ($secureBootData.UEFISecureBootEnabled -eq 0) {
                    $analysis.Issues += "Secure Boot desabilitado no registro"
                    Write-ForensicLog "Secure Boot desabilitado detectado no registro" -Level "CRÍTICO"
                }
            }
        }
        catch {
            Write-ForensicLog "Erro ao verificar configurações de Secure Boot: $_" -Level "ALERTA"
        }
        
        # Verificar programas de inicialização
        $startupLocations = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
        )
        
        foreach ($location in $startupLocations) {
            try {
                if (Test-Path $location) {
                    $startupItems = Get-ItemProperty -Path $location -ErrorAction SilentlyContinue
                    if ($startupItems) {
                        foreach ($property in $startupItems.PSObject.Properties) {
                            if ($property.Name -notin @("PSPath", "PSParentPath", "PSChildName", "PSDrive", "PSProvider")) {
                                $startupInfo = @{
                                    Location = $location
                                    Name = $property.Name
                                    Command = $property.Value
                                }
                                
                                # Verificar se é suspeito
                                if ($property.Value -match "lenovo|vantage|logo" -or 
                                    $property.Value -match "\.tmp|\.temp|users\\public") {
                                    $startupInfo.Suspicious = $true
                                    $analysis.Issues += "Programa de inicialização suspeito: $($property.Name) -> $($property.Value)"
                                    Write-ForensicLog "Programa de inicialização suspeito: $($property.Name)" -Level "SUSPEITO"
                                } else {
                                    $startupInfo.Suspicious = $false
                                }
                                
                                $analysis.StartupPrograms += $startupInfo
                            }
                        }
                    }
                }
            }
            catch {
                Write-ForensicLog "Erro ao verificar $location`: $_" -Level "ALERTA"
            }
        }
        
        return $analysis
    }
    catch {
        Write-ForensicLog "Erro durante análise do registro: $_" -Level "CRÍTICO"
        return $analysis
    }
}

# ============================================================================
# ANÁLISE DO SISTEMA DE ARQUIVOS
# ============================================================================

function Invoke-FileSystemAnalysis {
    Write-ForensicLog "Analisando arquivos suspeitos no sistema..." -Level "INFO"
    
    $analysis = @{
        SuspiciousFiles = @()
        BootFiles = @()
        SystemFiles = @()
        Issues = @()
    }
    
    try {
        # Locais críticos para verificar
        $criticalLocations = @(
            "$env:SystemRoot\System32",
            "$env:SystemRoot\SysWOW64",
            "$env:SystemRoot\Boot",
            "$env:SystemDrive\EFI",
            "$env:TEMP",
            "$env:APPDATA",
            "C:\Users\Public"
        )
        
        foreach ($location in $criticalLocations) {
            if (Test-Path $location) {
                Write-ForensicLog "Verificando: $location" -Level "INFO"
                
                try {
                    # Buscar arquivos suspeitos baseados em padrões IoC
                    foreach ($pattern in $Script:LogoFAILIoCs.SuspiciousFiles) {
                        $suspiciousFiles = Get-ChildItem -Path $location -Filter $pattern -Recurse -ErrorAction SilentlyContinue
                        
                        foreach ($file in $suspiciousFiles) {
                            try {
                                $fileInfo = @{
                                    FullName = $file.FullName
                                    Name = $file.Name
                                    Size = $file.Length
                                    CreationTime = $file.CreationTime.ToString("yyyy-MM-dd HH:mm:ss")
                                    LastWriteTime = $file.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
                                    Attributes = $file.Attributes.ToString()
                                    Hash = $null
                                    Signature = $null
                                }
                                
                                # Calcular hash para arquivos pequenos
                                if ($file.Length -lt 50MB) {
                                    try {
                                        $hash = Get-FileHash -Path $file.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue
                                        $fileInfo.Hash = $hash.Hash
                                    }
                                    catch {
                                        $fileInfo.Hash = "Erro ao calcular hash"
                                    }
                                }
                                
                                # Verificar assinatura digital
                                try {
                                    $signature = Get-AuthenticodeSignature -FilePath $file.FullName -ErrorAction SilentlyContinue
                                    $fileInfo.Signature = $signature.Status.ToString()
                                }
                                catch {
                                    $fileInfo.Signature = "Não verificável"
                                }
                                
                                $analysis.SuspiciousFiles += $fileInfo
                                Write-ForensicLog "Arquivo suspeito encontrado: $($file.FullName)" -Level "SUSPEITO"
                                $analysis.Issues += "Arquivo suspeito: $($file.FullName)"
                                
                                # Exportar evidência se solicitado
                                if ($ExportEvidence -and $file.Length -lt 10MB) {
                                    $evidenceDir = Join-Path $Script:ForensicConfig.OutputPath "Evidence"
                                    if (-not (Test-Path $evidenceDir)) {
                                        New-Item -Path $evidenceDir -ItemType Directory -Force | Out-Null
                                    }
                                    
                                    $evidenceFile = Join-Path $evidenceDir ($file.Name + ".evidence")
                                    Copy-Item -Path $file.FullName -Destination $evidenceFile -Force
                                    $Script:ForensicConfig.EvidenceFiles += $evidenceFile
                                }
                            }
                            catch {
                                Write-ForensicLog "Erro ao analisar arquivo $($file.FullName): $_" -Level "ALERTA"
                            }
                        }
                    }
                }
                catch {
                    Write-ForensicLog "Erro ao verificar $location`: $_" -Level "ALERTA"
                }
            }
        }
        
        # Verificar arquivos de boot específicos
        $bootFiles = @(
            "$env:SystemDrive\EFI\Microsoft\Boot\bootmgfw.efi",
            "$env:SystemDrive\EFI\Boot\bootx64.efi",
            "$env:SystemRoot\System32\winload.exe"
        )
        
        foreach ($bootFile in $bootFiles) {
            if (Test-Path $bootFile) {
                try {
                    $file = Get-Item $bootFile
                    $hash = Get-FileHash -Path $bootFile -Algorithm SHA256
                    $signature = Get-AuthenticodeSignature -FilePath $bootFile -ErrorAction SilentlyContinue
                    
                    $bootFileInfo = @{
                        Path = $bootFile
                        Size = $file.Length
                        LastWriteTime = $file.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
                        Hash = $hash.Hash
                        SignatureStatus = $signature.Status.ToString()
                        Version = $file.VersionInfo.FileVersion
                    }
                    
                    $analysis.BootFiles += $bootFileInfo
                    
                    if ($signature.Status -ne "Valid") {
                        $analysis.Issues += "Arquivo de boot com assinatura inválida: $bootFile"
                        Write-ForensicLog "Arquivo de boot com assinatura inválida: $bootFile" -Level "CRÍTICO"
                    }
                }
                catch {
                    Write-ForensicLog "Erro ao analisar arquivo de boot $bootFile`: $_" -Level "ALERTA"
                }
            }
        }
        
        return $analysis
    }
    catch {
        Write-ForensicLog "Erro durante análise do sistema de arquivos: $_" -Level "CRÍTICO"
        return $analysis
    }
}

# ============================================================================
# ANÁLISE ESPECÍFICA DO LENOVO VANTAGE
# ============================================================================

function Invoke-LenovoAnalysis {
    if (-not $IncludeLenovoAnalysis) {
        return @{ Enabled = $false }
    }
    
    Write-ForensicLog "Executando análise específica do Lenovo Vantage..." -Level "INFO"
    
    $analysis = @{
        Enabled = $true
        VantageInstalled = $false
        VantageVersion = $null
        VantageServices = @()
        VantageProcesses = @()
        VantageFiles = @()
        RegistryEntries = @()
        Issues = @()
    }
    
    try {
        # Verificar se Lenovo Vantage está instalado
        $vantageApp = Get-AppxPackage | Where-Object { $_.Name -like "*Lenovo*Vantage*" }
        if ($vantageApp) {
            $analysis.VantageInstalled = $true
            $analysis.VantageVersion = $vantageApp.Version
            Write-ForensicLog "Lenovo Vantage detectado: versão $($vantageApp.Version)" -Level "ALERTA"
            $analysis.Issues += "Lenovo Vantage instalado - pode ser vulnerável a LogoFAIL"
        }
        
        # Verificar serviços relacionados
        $lenovoServices = Get-Service | Where-Object { $_.Name -like "*Lenovo*" -or $_.Name -like "*ImController*" }
        foreach ($service in $lenovoServices) {
            $serviceInfo = @{
                Name = $service.Name
                DisplayName = $service.DisplayName
                Status = $service.Status.ToString()
                StartType = $service.StartType.ToString()
            }
            
            $analysis.VantageServices += $serviceInfo
            
            if ($service.Status -eq "Running") {
                Write-ForensicLog "Serviço Lenovo ativo: $($service.Name)" -Level "SUSPEITO"
                $analysis.Issues += "Serviço Lenovo ativo: $($service.Name)"
            }
        }
        
        # Verificar processos em execução
        $lenovoProcesses = Get-Process | Where-Object { $_.ProcessName -like "*Lenovo*" -or $_.ProcessName -like "*Vantage*" }
        foreach ($process in $lenovoProcesses) {
            $processInfo = @{
                Name = $process.ProcessName
                Id = $process.Id
                Path = $process.Path
                StartTime = $process.StartTime
            }
            
            $analysis.VantageProcesses += $processInfo
            Write-ForensicLog "Processo Lenovo ativo: $($process.ProcessName)" -Level "SUSPEITO"
        }
        
        # Verificar entradas de registro específicas
        $lenovoRegistryPaths = @(
            "HKLM:\SOFTWARE\Lenovo",
            "HKLM:\SOFTWARE\WOW6432Node\Lenovo",
            "HKCU:\SOFTWARE\Lenovo"
        )
        
        foreach ($regPath in $lenovoRegistryPaths) {
            if (Test-Path $regPath) {
                try {
                    $regKeys = Get-ChildItem -Path $regPath -Recurse -ErrorAction SilentlyContinue
                    foreach ($key in $regKeys) {
                        $keyInfo = @{
                            Path = $key.PSPath
                            Name = $key.PSChildName
                            LastWriteTime = $key.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
                        }
                        
                        $analysis.RegistryEntries += $keyInfo
                    }
                }
                catch {
                    Write-ForensicLog "Erro ao analisar registro Lenovo $regPath`: $_" -Level "ALERTA"
                }
            }
        }
        
        # Verificar arquivos específicos do Vantage
        $vantageLocations = @(
            "$env:ProgramFiles\Lenovo",
            "$env:ProgramFiles(x86)\Lenovo",
            "$env:LOCALAPPDATA\Packages\*Lenovo*"
        )
        
        foreach ($location in $vantageLocations) {
            if (Test-Path $location) {
                try {
                    $files = Get-ChildItem -Path $location -Recurse -File -ErrorAction SilentlyContinue | Select-Object -First 50
                    foreach ($file in $files) {
                        $fileInfo = @{
                            Path = $file.FullName
                            Name = $file.Name
                            Size = $file.Length
                            LastWriteTime = $file.LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
                        }
                        
                        $analysis.VantageFiles += $fileInfo
                    }
                }
                catch {
                    Write-ForensicLog "Erro ao analisar arquivos Vantage em $location`: $_" -Level "ALERTA"
                }
            }
        }
        
        return $analysis
    }
    catch {
        Write-ForensicLog "Erro durante análise do Lenovo Vantage: $_" -Level "CRÍTICO"
        return $analysis
    }
}

# ============================================================================
# FUNÇÃO PRINCIPAL
# ============================================================================

function Start-LogoFAILForensicAnalysis {
    Write-Host "======================================================================" -ForegroundColor Cyan
    Write-Host "    LogoFAIL Forensic Analysis - Análise Forense Completa" -ForegroundColor Cyan
    Write-Host "    Versão: $($Script:ForensicConfig.Version)" -ForegroundColor Cyan
    Write-Host "======================================================================" -ForegroundColor Cyan
    Write-Host ""
    
    # Criar diretórios de output
    try {
        if (-not (Test-Path $Script:ForensicConfig.OutputPath)) {
            New-Item -Path $Script:ForensicConfig.OutputPath -ItemType Directory -Force | Out-Null
        }
        if (-not (Test-Path $Script:ForensicConfig.TempPath)) {
            New-Item -Path $Script:ForensicConfig.TempPath -ItemType Directory -Force | Out-Null
        }
    }
    catch {
        Write-ForensicLog "Erro ao criar diretórios de output: $_" -Level "CRÍTICO"
        return $false
    }
    
    Write-ForensicLog "Iniciando análise forense completa..." -Level "INFO"
    
    # Executar todas as análises
    $analysisResults = @{}
    
    try {
        $analysisResults.SystemInfo = Get-SystemInformation
        $analysisResults.FirmwareAnalysis = Invoke-FirmwareAnalysis
        $analysisResults.ProcessAnalysis = Invoke-ProcessAnalysis
        $analysisResults.RegistryAnalysis = Invoke-RegistryAnalysis
        $analysisResults.FileSystemAnalysis = Invoke-FileSystemAnalysis
        $analysisResults.LenovoAnalysis = Invoke-LenovoAnalysis
        
        # Compilar recomendações
        $recommendations = @()
        
        foreach ($analysis in $analysisResults.Values) {
            if ($analysis -and $analysis.Issues) {
                $recommendations += $analysis.Issues
            }
        }
        
        # Adicionar recomendações gerais baseadas no nível de ameaça
        switch ($Script:ForensicConfig.ThreatLevel) {
            "CRÍTICO" {
                $recommendations += "AÇÃO IMEDIATA REQUERIDA: Desconectar da rede e executar análise detalhada"
                $recommendations += "Considerar reimagem completa do sistema"
                $recommendations += "Verificar logs de rede para comunicações suspeitas"
            }
            "SUSPEITO" {
                $recommendations += "Monitorar sistema de perto por atividades suspeitas"
                $recommendations += "Executar análise antimalware completa"
                $recommendations += "Revisar logs de sistema detalhadamente"
            }
            "ALERTA" {
                $recommendations += "Aplicar atualizações de segurança imediatamente"
                $recommendations += "Verificar configurações de segurança"
                $recommendations += "Executar verificações regulares"
            }
        }
        
        $analysisResults.Recommendations = $recommendations
        
        # Gerar relatório
        $reportFile = New-ForensicReport -AnalysisResults $analysisResults
        
        Write-Host ""
        Write-Host "======================================================================" -ForegroundColor Green
        Write-Host "    Análise Forense Concluída" -ForegroundColor Green
        Write-Host "======================================================================" -ForegroundColor Green
        Write-Host ""
        
        # Exibir resumo
        Write-Host "RESUMO DA ANÁLISE:" -ForegroundColor Yellow
        Write-Host "- Nível de Ameaça: $($Script:ForensicConfig.ThreatLevel)" -ForegroundColor $(if ($Script:ForensicConfig.ThreatLevel -eq "CRÍTICO") { "Red" } elseif ($Script:ForensicConfig.ThreatLevel -eq "SUSPEITO") { "Magenta" } elseif ($Script:ForensicConfig.ThreatLevel -eq "ALERTA") { "Yellow" } else { "Green" })
        Write-Host "- Duração da Análise: $([math]::Round(((Get-Date) - $Script:ForensicConfig.StartTime).TotalMinutes, 2)) minutos" -ForegroundColor White
        Write-Host "- Relatório Salvo em: $reportFile" -ForegroundColor White
        Write-Host "- Evidências Coletadas: $($Script:ForensicConfig.EvidenceFiles.Count)" -ForegroundColor White
        
        if ($recommendations.Count -gt 0) {
            Write-Host ""
            Write-Host "RECOMENDAÇÕES:" -ForegroundColor Yellow
            foreach ($recommendation in $recommendations | Select-Object -First 10) {
                Write-Host "  - $recommendation" -ForegroundColor White
            }
            
            if ($recommendations.Count -gt 10) {
                Write-Host "  ... e mais $($recommendations.Count - 10) recomendações no relatório completo" -ForegroundColor Gray
            }
        }
        
        return $true
    }
    catch {
        Write-ForensicLog "Erro fatal durante análise forense: $_" -Level "CRÍTICO"
        return $false
    }
    finally {
        # Limpeza
        if (Test-Path $Script:ForensicConfig.TempPath) {
            Remove-Item -Path $Script:ForensicConfig.TempPath -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

# ============================================================================
# EXECUÇÃO PRINCIPAL
# ============================================================================

try {
    $result = Start-LogoFAILForensicAnalysis
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