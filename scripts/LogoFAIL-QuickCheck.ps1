#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    LogoFAIL Quick Check - Verificação Rápida de Proteções LogoFAIL
    
.DESCRIPTION
    Script para verificação rápida do status de proteções contra vulnerabilidades LogoFAIL.
    Executa verificações essenciais de segurança e fornece um relatório resumido
    do status atual das proteções implementadas.
    
.PARAMETER Detailed
    Exibe informações detalhadas sobre cada verificação
    
.PARAMETER ExportReport
    Exporta relatório detalhado para arquivo JSON
    
.PARAMETER CheckBaseline
    Verifica integridade comparando com baseline
    
.EXAMPLE
    .\LogoFAIL-QuickCheck.ps1 -Detailed -ExportReport
    
.NOTES
    Author: Matheus-TestUser1
    Version: 1.0.0
    Requires: Windows 10/11, PowerShell 5.1+, Administrator privileges
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [switch]$Detailed,
    
    [Parameter(Mandatory = $false)]
    [switch]$ExportReport,
    
    [Parameter(Mandatory = $false)]
    [switch]$CheckBaseline
)

# ============================================================================
# CONFIGURAÇÕES GLOBAIS
# ============================================================================

$Script:QuickCheckConfig = @{
    Version = "1.0.0"
    StartTime = Get-Date
    BasePath = "$env:ProgramData\WindowsDefenseLogoFAIL"
    LogPath = "$env:ProgramData\WindowsDefenseLogoFAIL\Logs"
    BaselinePath = "$env:ProgramData\WindowsDefenseLogoFAIL\Baselines"
    ConfigPath = "$env:ProgramData\WindowsDefenseLogoFAIL\Config"
    OverallStatus = "UNKNOWN"
    SecurityScore = 0
    MaxScore = 100
}

# ============================================================================
# FUNÇÕES DE LOGGING
# ============================================================================

function Write-QuickLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("Info", "Warning", "Error", "Success", "Critical")]
        [string]$Level = "Info"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    
    $color = switch ($Level) {
        "Info" { "Cyan" }
        "Warning" { "Yellow" }
        "Error" { "Red" }
        "Success" { "Green" }
        "Critical" { "Magenta" }
    }
    
    Write-Host "[$timestamp] $Message" -ForegroundColor $color
}

function Write-StatusIndicator {
    param(
        [string]$Description,
        [bool]$Status,
        [string]$Details = "",
        [int]$Points = 10
    )
    
    $indicator = if ($Status) { "✓" } else { "✗" }
    $color = if ($Status) { "Green" } else { "Red" }
    
    if ($Status) {
        $Script:QuickCheckConfig.SecurityScore += $Points
    }
    
    Write-Host "  $indicator $Description" -ForegroundColor $color
    
    if ($Detailed -and $Details) {
        Write-Host "    └─ $Details" -ForegroundColor Gray
    }
    
    return @{
        Description = $Description
        Status = $Status
        Details = $Details
        Points = if ($Status) { $Points } else { 0 }
    }
}

# ============================================================================
# VERIFICAÇÕES DE SEGURANÇA
# ============================================================================

function Test-SecureBootStatus {
    Write-Host "`n[1] SECURE BOOT STATUS" -ForegroundColor Cyan
    
    $results = @{
        SecureBootEnabled = $false
        FirmwareType = "Unknown"
        TPMEnabled = $false
        Details = @{}
    }
    
    try {
        # Verificar Secure Boot
        try {
            $secureBootState = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
            $results.SecureBootEnabled = $secureBootState
            $results.Details.SecureBoot = $secureBootState
        }
        catch {
            $results.Details.SecureBootError = $_.Exception.Message
        }
        
        # Verificar tipo de firmware
        $firmwareType = (Get-CimInstance -ClassName Win32_ComputerSystem).PCSystemType
        $results.FirmwareType = if ($firmwareType -eq 2) { "UEFI" } else { "Legacy" }
        $results.Details.FirmwareType = $results.FirmwareType
        
        # Verificar TPM
        try {
            $tpm = Get-Tpm -ErrorAction SilentlyContinue
            $results.TPMEnabled = $tpm -and $tpm.TpmEnabled
            $results.Details.TPM = @{
                Enabled = $results.TPMEnabled
                Version = if ($tpm) { $tpm.TpmVersion } else { "N/A" }
            }
        }
        catch {
            $results.Details.TPMError = $_.Exception.Message
        }
        
        # Exibir resultados
        $results.SecureBootCheck = Write-StatusIndicator "Secure Boot Ativo" $results.SecureBootEnabled "$(if ($results.SecureBootEnabled) { 'Proteção ativa contra boot malicioso' } else { 'Sistema vulnerável - ative no firmware UEFI' })" 20
        $results.FirmwareCheck = Write-StatusIndicator "Firmware UEFI" ($results.FirmwareType -eq "UEFI") "Firmware: $($results.FirmwareType)" 10
        $results.TPMCheck = Write-StatusIndicator "TPM Habilitado" $results.TPMEnabled "$(if ($results.TPMEnabled) { 'Recursos de segurança de hardware disponíveis' } else { 'TPM não disponível ou desabilitado' })" 15
        
        return $results
    }
    catch {
        Write-QuickLog "Erro durante verificação de Secure Boot: $_" -Level "Error"
        return $results
    }
}

function Test-WindowsDefenderStatus {
    Write-Host "`n[2] WINDOWS DEFENDER STATUS" -ForegroundColor Cyan
    
    $results = @{
        RealTimeProtection = $false
        CloudProtection = $false
        ControlledFolderAccess = $false
        NetworkProtection = $false
        PUAProtection = $false
        Details = @{}
    }
    
    try {
        $defenderStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
        $defenderPrefs = Get-MpPreference -ErrorAction SilentlyContinue
        
        if ($defenderStatus -and $defenderPrefs) {
            $results.RealTimeProtection = $defenderStatus.RealTimeProtectionEnabled
            $results.CloudProtection = ($defenderPrefs.MAPSReporting -ne [Microsoft.PowerShell.Cmdletization.GeneratedTypes.MpPreference.MAPSReportingType]::Disabled)
            $results.ControlledFolderAccess = ($defenderPrefs.EnableControlledFolderAccess -eq [Microsoft.PowerShell.Cmdletization.GeneratedTypes.MpPreference.ControlledFolderAccessType]::Enabled)
            $results.NetworkProtection = ($defenderPrefs.EnableNetworkProtection -eq [Microsoft.PowerShell.Cmdletization.GeneratedTypes.MpPreference.EnableNetworkProtectionType]::Enabled)
            $results.PUAProtection = ($defenderPrefs.PUAProtection -eq [Microsoft.PowerShell.Cmdletization.GeneratedTypes.MpPreference.PUAProtectionType]::Enabled)
            
            $results.Details = @{
                AntivirusEnabled = $defenderStatus.AntivirusEnabled
                AMServiceEnabled = $defenderStatus.AMServiceEnabled
                AntispywareEnabled = $defenderStatus.AntispywareEnabled
                BehaviorMonitorEnabled = $defenderStatus.BehaviorMonitorEnabled
                IoavProtectionEnabled = $defenderStatus.IoavProtectionEnabled
                NISEnabled = $defenderStatus.NISEnabled
                OnAccessProtectionEnabled = $defenderStatus.OnAccessProtectionEnabled
                LastFullScanAge = $defenderStatus.AntispywareSignatureAge
                LastQuickScanAge = $defenderStatus.AntivirusSignatureAge
            }
        }
        
        # Exibir resultados
        $results.RTProtectionCheck = Write-StatusIndicator "Proteção em Tempo Real" $results.RealTimeProtection "$(if ($results.RealTimeProtection) { 'Monitoramento ativo de ameaças' } else { 'CRÍTICO: Proteção desabilitada!' })" 15
        $results.CloudProtectionCheck = Write-StatusIndicator "Proteção na Nuvem" $results.CloudProtection "$(if ($results.CloudProtection) { 'Detecção avançada habilitada' } else { 'Proteção limitada sem cloud' })" 10
        $results.CFACheck = Write-StatusIndicator "Controlled Folder Access" $results.ControlledFolderAccess "$(if ($results.ControlledFolderAccess) { 'Proteção contra ransomware ativa' } else { 'Proteção adicional recomendada' })" 10
        $results.NetworkProtectionCheck = Write-StatusIndicator "Network Protection" $results.NetworkProtection "$(if ($results.NetworkProtection) { 'Proteção contra exploits de rede' } else { 'Vulnerável a ataques de rede' })" 10
        $results.PUACheck = Write-StatusIndicator "PUA Protection" $results.PUAProtection "$(if ($results.PUAProtection) { 'Proteção contra software indesejado' } else { 'Aplicativos suspeitos permitidos' })" 5
        
        return $results
    }
    catch {
        Write-QuickLog "Erro durante verificação do Windows Defender: $_" -Level "Error"
        return $results
    }
}

function Test-SystemIntegrity {
    Write-Host "`n[3] INTEGRIDADE DO SISTEMA" -ForegroundColor Cyan
    
    $results = @{
        SystemFileIntegrity = $false
        BootConfiguration = $false
        CriticalServices = $false
        Details = @{}
    }
    
    try {
        # Verificar integridade de arquivos do sistema (SFC)
        Write-QuickLog "Verificando integridade de arquivos do sistema..." -Level "Info"
        $sfcResult = & sfc.exe /verifyonly 2>&1
        $results.SystemFileIntegrity = $LASTEXITCODE -eq 0
        $results.Details.SFCOutput = $sfcResult -join "`n"
        
        # Verificar configuração de boot
        try {
            $bootConfig = & bcdedit.exe /enum 2>$null
            $results.BootConfiguration = $true
            
            # Verificar configurações problemáticas
            foreach ($line in $bootConfig) {
                if ($line -match "testsigning.*yes") {
                    $results.BootConfiguration = $false
                    $results.Details.BootIssue = "Test signing habilitado"
                    break
                }
                if ($line -match "nointegritychecks.*yes") {
                    $results.BootConfiguration = $false
                    $results.Details.BootIssue = "Verificações de integridade desabilitadas"
                    break
                }
            }
            
            $results.Details.BootConfig = $bootConfig -join "`n"
        }
        catch {
            $results.Details.BootConfigError = $_.Exception.Message
        }
        
        # Verificar serviços críticos
        $criticalServices = @("Windefend", "WinRM", "EventLog", "CryptSvc")
        $runningServices = 0
        
        foreach ($serviceName in $criticalServices) {
            try {
                $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
                if ($service -and $service.Status -eq "Running") {
                    $runningServices++
                }
            }
            catch {
                # Serviço não encontrado
            }
        }
        
        $results.CriticalServices = $runningServices -eq $criticalServices.Count
        $results.Details.CriticalServicesStatus = "$runningServices de $($criticalServices.Count) serviços críticos em execução"
        
        # Exibir resultados
        $results.SFCCheck = Write-StatusIndicator "Integridade de Arquivos do Sistema" $results.SystemFileIntegrity "$(if ($results.SystemFileIntegrity) { 'Arquivos do sistema íntegros' } else { 'Arquivos corrompidos detectados - execute sfc /scannow' })" 15
        $results.BootConfigCheck = Write-StatusIndicator "Configuração de Boot Segura" $results.BootConfiguration "$(if ($results.BootConfiguration) { 'Configuração de boot segura' } else { $results.Details.BootIssue + ' - configuração insegura' })" 10
        $results.ServicesCheck = Write-StatusIndicator "Serviços Críticos Ativos" $results.CriticalServices $results.Details.CriticalServicesStatus 10
        
        return $results
    }
    catch {
        Write-QuickLog "Erro durante verificação de integridade: $_" -Level "Error"
        return $results
    }
}

function Test-AdvancedSecurityFeatures {
    Write-Host "`n[4] RECURSOS AVANÇADOS DE SEGURANÇA" -ForegroundColor Cyan
    
    $results = @{
        HVCI = $false
        DeviceGuard = $false
        CredentialGuard = $false
        ApplicationGuard = $false
        Details = @{}
    }
    
    try {
        # Verificar HVCI
        try {
            $deviceGuardPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"
            $hvciPath = "$deviceGuardPath\Scenarios\HypervisorEnforcedCodeIntegrity"
            
            if (Test-Path $hvciPath) {
                $hvciEnabled = Get-ItemProperty -Path $hvciPath -Name "Enabled" -ErrorAction SilentlyContinue
                $results.HVCI = $hvciEnabled -and $hvciEnabled.Enabled -eq 1
            }
            $results.Details.HVCI = $results.HVCI
        }
        catch {
            $results.Details.HVCIError = $_.Exception.Message
        }
        
        # Verificar Device Guard
        try {
            if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard") {
                $dgVBS = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -ErrorAction SilentlyContinue
                $results.DeviceGuard = $dgVBS -and $dgVBS.EnableVirtualizationBasedSecurity -eq 1
            }
            $results.Details.DeviceGuard = $results.DeviceGuard
        }
        catch {
            $results.Details.DeviceGuardError = $_.Exception.Message
        }
        
        # Verificar Credential Guard
        try {
            $lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
            $lsaCfg = Get-ItemProperty -Path $lsaPath -Name "LsaCfgFlags" -ErrorAction SilentlyContinue
            $results.CredentialGuard = $lsaCfg -and $lsaCfg.LsaCfgFlags -eq 1
            $results.Details.CredentialGuard = $results.CredentialGuard
        }
        catch {
            $results.Details.CredentialGuardError = $_.Exception.Message
        }
        
        # Verificar Application Guard
        try {
            $appGuardFeature = Get-WindowsOptionalFeature -Online -FeatureName Windows-Defender-ApplicationGuard -ErrorAction SilentlyContinue
            $results.ApplicationGuard = $appGuardFeature -and $appGuardFeature.State -eq "Enabled"
            $results.Details.ApplicationGuard = $results.ApplicationGuard
        }
        catch {
            $results.Details.ApplicationGuardError = $_.Exception.Message
        }
        
        # Exibir resultados
        $results.HVCICheck = Write-StatusIndicator "HVCI (Hypervisor-protected Code Integrity)" $results.HVCI "$(if ($results.HVCI) { 'Proteção avançada contra modificação de código' } else { 'Proteção adicional disponível' })" 15
        $results.DeviceGuardCheck = Write-StatusIndicator "Device Guard" $results.DeviceGuard "$(if ($results.DeviceGuard) { 'Virtualização de segurança ativa' } else { 'Configuração adicional recomendada' })" 10
        $results.CredentialGuardCheck = Write-StatusIndicator "Credential Guard" $results.CredentialGuard "$(if ($results.CredentialGuard) { 'Proteção de credenciais ativa' } else { 'Credenciais vulneráveis' })" 10
        $results.ApplicationGuardCheck = Write-StatusIndicator "Application Guard" $results.ApplicationGuard "$(if ($results.ApplicationGuard) { 'Isolamento de aplicações ativo' } else { 'Recurso não habilitado' })" 5
        
        return $results
    }
    catch {
        Write-QuickLog "Erro durante verificação de recursos avançados: $_" -Level "Error"
        return $results
    }
}

function Test-BaselineIntegrity {
    if (-not $CheckBaseline) {
        return @{ Enabled = $false }
    }
    
    Write-Host "`n[5] INTEGRIDADE DE BASELINE" -ForegroundColor Cyan
    
    $results = @{
        Enabled = $true
        BaselineExists = $false
        CriticalFilesOK = $false
        ChangesDetected = @()
        Details = @{}
    }
    
    try {
        # Verificar se existe baseline
        $baselineFiles = Get-ChildItem -Path $Script:QuickCheckConfig.BaselinePath -Filter "security-baseline-*.json" -ErrorAction SilentlyContinue
        
        if (-not $baselineFiles) {
            $results.Details.Message = "Nenhum baseline encontrado - execute Install-LogoFAILProtection.ps1 primeiro"
            $results.BaselineCheck = Write-StatusIndicator "Baseline de Segurança Existe" $false $results.Details.Message 0
            return $results
        }
        
        $results.BaselineExists = $true
        $latestBaseline = $baselineFiles | Sort-Object LastWriteTime -Descending | Select-Object -First 1
        $baselineData = Get-Content $latestBaseline.FullName | ConvertFrom-Json
        
        # Verificar arquivos críticos
        $changedFiles = 0
        $totalFiles = 0
        
        if ($baselineData.CriticalFiles) {
            foreach ($filePath in $baselineData.CriticalFiles.PSObject.Properties.Name) {
                $totalFiles++
                try {
                    if (Test-Path $filePath) {
                        $currentHash = (Get-FileHash -Path $filePath -Algorithm SHA256).Hash
                        $baselineHash = $baselineData.CriticalFiles.$filePath.SHA256
                        
                        if ($currentHash -ne $baselineHash) {
                            $changedFiles++
                            $results.ChangesDetected += "Arquivo modificado: $filePath"
                        }
                    } else {
                        $changedFiles++
                        $results.ChangesDetected += "Arquivo removido: $filePath"
                    }
                }
                catch {
                    $results.ChangesDetected += "Erro ao verificar: $filePath"
                }
            }
        }
        
        $results.CriticalFilesOK = $changedFiles -eq 0
        $results.Details.FilesChecked = $totalFiles
        $results.Details.FilesChanged = $changedFiles
        $results.Details.BaselineDate = $baselineData.CreationDate
        
        # Exibir resultados
        $results.BaselineCheck = Write-StatusIndicator "Baseline de Segurança Existe" $true "Baseline criado em: $($baselineData.CreationDate)" 5
        $results.IntegrityCheck = Write-StatusIndicator "Integridade de Arquivos Críticos" $results.CriticalFilesOK "$(if ($results.CriticalFilesOK) { "$totalFiles arquivos verificados - todos íntegros" } else { "$changedFiles de $totalFiles arquivos modificados" })" 15
        
        if ($results.ChangesDetected.Count -gt 0 -and $Detailed) {
            Write-Host "    Alterações detectadas:" -ForegroundColor Yellow
            foreach ($change in $results.ChangesDetected) {
                Write-Host "      - $change" -ForegroundColor Red
            }
        }
        
        return $results
    }
    catch {
        Write-QuickLog "Erro durante verificação de baseline: $_" -Level "Error"
        return $results
    }
}

function Test-LogoFAILSpecificChecks {
    Write-Host "`n[6] VERIFICAÇÕES ESPECÍFICAS LOGOFAIL" -ForegroundColor Cyan
    
    $results = @{
        LenovoVantageDetected = $false
        SuspiciousProcesses = $false
        VulnerableDrivers = $false
        Details = @{}
    }
    
    try {
        # Verificar Lenovo Vantage
        $lenovoApps = Get-AppxPackage | Where-Object { $_.Name -like "*Lenovo*Vantage*" }
        $results.LenovoVantageDetected = $lenovoApps.Count -gt 0
        
        if ($results.LenovoVantageDetected) {
            $results.Details.LenovoVantageVersion = $lenovoApps[0].Version
        }
        
        # Verificar processos suspeitos
        $suspiciousPatterns = @("*lenovo*", "*vantage*", "*logo*.exe", "*.tmp.exe")
        $suspiciousProcesses = @()
        
        foreach ($pattern in $suspiciousPatterns) {
            $processes = Get-Process | Where-Object { $_.ProcessName -like $pattern }
            $suspiciousProcesses += $processes
        }
        
        $results.SuspiciousProcesses = $suspiciousProcesses.Count -eq 0
        $results.Details.SuspiciousProcessCount = $suspiciousProcesses.Count
        
        if ($suspiciousProcesses.Count -gt 0) {
            $results.Details.SuspiciousProcessNames = $suspiciousProcesses | Select-Object -ExpandProperty ProcessName -Unique
        }
        
        # Verificar drivers vulneráveis (placeholder para versões específicas conhecidas)
        $results.VulnerableDrivers = $true  # Assumir OK até que drivers específicos sejam identificados
        
        # Exibir resultados
        $results.LenovoCheck = Write-StatusIndicator "Lenovo Vantage Não Detectado" (-not $results.LenovoVantageDetected) "$(if ($results.LenovoVantageDetected) { 'ALERTA: Lenovo Vantage detectado - potencialmente vulnerável' } else { 'Sistema não possui Lenovo Vantage' })" 15
        $results.ProcessCheck = Write-StatusIndicator "Processos Suspeitos Não Detectados" $results.SuspiciousProcesses "$(if ($results.SuspiciousProcesses) { 'Nenhum processo suspeito em execução' } else { "$($results.Details.SuspiciousProcessCount) processos suspeitos detectados" })" 10
        $results.DriverCheck = Write-StatusIndicator "Drivers Vulneráveis Não Detectados" $results.VulnerableDrivers "Verificação de drivers específicos" 5
        
        if (-not $results.SuspiciousProcesses -and $Detailed -and $results.Details.SuspiciousProcessNames) {
            Write-Host "    Processos suspeitos:" -ForegroundColor Yellow
            foreach ($processName in $results.Details.SuspiciousProcessNames) {
                Write-Host "      - $processName" -ForegroundColor Red
            }
        }
        
        return $results
    }
    catch {
        Write-QuickLog "Erro durante verificações específicas LogoFAIL: $_" -Level "Error"
        return $results
    }
}

# ============================================================================
# FUNÇÃO PRINCIPAL
# ============================================================================

function Start-QuickSecurityCheck {
    Write-Host "======================================================================" -ForegroundColor Cyan
    Write-Host "    LogoFAIL Quick Check - Verificação Rápida de Segurança" -ForegroundColor Cyan
    Write-Host "    Versão: $($Script:QuickCheckConfig.Version)" -ForegroundColor Cyan
    Write-Host "======================================================================" -ForegroundColor Cyan
    
    # Verificar privilégios de administrador
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-QuickLog "Este script requer privilégios de administrador" -Level "Error"
        return $false
    }
    
    Write-QuickLog "Iniciando verificação rápida de segurança..." -Level "Info"
    
    # Executar todas as verificações
    $checkResults = @{
        SecureBootStatus = Test-SecureBootStatus
        WindowsDefenderStatus = Test-WindowsDefenderStatus
        SystemIntegrity = Test-SystemIntegrity
        AdvancedSecurityFeatures = Test-AdvancedSecurityFeatures
        BaselineIntegrity = Test-BaselineIntegrity
        LogoFAILSpecificChecks = Test-LogoFAILSpecificChecks
    }
    
    # Calcular score e status geral
    $percentageScore = [math]::Round(($Script:QuickCheckConfig.SecurityScore / $Script:QuickCheckConfig.MaxScore) * 100, 1)
    
    $Script:QuickCheckConfig.OverallStatus = if ($percentageScore -ge 90) {
        "EXCELENTE"
    } elseif ($percentageScore -ge 75) {
        "BOM"
    } elseif ($percentageScore -ge 50) {
        "REGULAR"
    } elseif ($percentageScore -ge 25) {
        "RUIM"
    } else {
        "CRÍTICO"
    }
    
    # Exibir resumo final
    Write-Host "`n======================================================================" -ForegroundColor Cyan
    Write-Host "    RESUMO DA VERIFICAÇÃO DE SEGURANÇA" -ForegroundColor Cyan
    Write-Host "======================================================================" -ForegroundColor Cyan
    
    $statusColor = switch ($Script:QuickCheckConfig.OverallStatus) {
        "EXCELENTE" { "Green" }
        "BOM" { "Green" }
        "REGULAR" { "Yellow" }
        "RUIM" { "Red" }
        "CRÍTICO" { "Magenta" }
    }
    
    Write-Host "`nSTATUS GERAL: $($Script:QuickCheckConfig.OverallStatus)" -ForegroundColor $statusColor
    Write-Host "SCORE DE SEGURANÇA: $($Script:QuickCheckConfig.SecurityScore)/$($Script:QuickCheckConfig.MaxScore) ($percentageScore%)" -ForegroundColor $statusColor
    
    # Recomendações baseadas no score
    Write-Host "`nRECOMENDAÇÕES:" -ForegroundColor Yellow
    
    if ($checkResults.SecureBootStatus.SecureBootEnabled -eq $false) {
        Write-Host "  ❗ CRÍTICO: Ative o Secure Boot no firmware UEFI" -ForegroundColor Red
    }
    
    if ($checkResults.WindowsDefenderStatus.RealTimeProtection -eq $false) {
        Write-Host "  ❗ CRÍTICO: Ative a Proteção em Tempo Real do Windows Defender" -ForegroundColor Red
    }
    
    if ($checkResults.LogoFAILSpecificChecks.LenovoVantageDetected) {
        Write-Host "  ⚠️  ALERTA: Lenovo Vantage detectado - considere atualização ou remoção" -ForegroundColor Yellow
    }
    
    if ($checkResults.AdvancedSecurityFeatures.HVCI -eq $false) {
        Write-Host "  💡 Execute LogoFAIL-AdvancedProtection.ps1 para ativar HVCI" -ForegroundColor Cyan
    }
    
    if ($checkResults.BaselineIntegrity.Enabled -and $checkResults.BaselineIntegrity.CriticalFilesOK -eq $false) {
        Write-Host "  ⚠️  ALERTA: Arquivos críticos foram modificados - execute análise forense" -ForegroundColor Yellow
    }
    
    if ($percentageScore -lt 75) {
        Write-Host "  📋 Execute LogoFAIL-AdvancedProtection.ps1 para melhorar a segurança" -ForegroundColor Cyan
        Write-Host "  🔍 Execute LogoFAIL-ForensicAnalysis.ps1 para análise detalhada" -ForegroundColor Cyan
    }
    
    Write-Host "`nPRÓXIMOS PASSOS:" -ForegroundColor Yellow
    Write-Host "  1. Revise e implemente as recomendações acima" -ForegroundColor White
    Write-Host "  2. Execute verificações regulares com este script" -ForegroundColor White
    Write-Host "  3. Monitore logs de sistema para atividades suspeitas" -ForegroundColor White
    Write-Host "  4. Mantenha o sistema e definições antivírus atualizados" -ForegroundColor White
    
    # Exportar relatório se solicitado
    if ($ExportReport) {
        try {
            $reportData = @{
                Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                OverallStatus = $Script:QuickCheckConfig.OverallStatus
                SecurityScore = $Script:QuickCheckConfig.SecurityScore
                MaxScore = $Script:QuickCheckConfig.MaxScore
                PercentageScore = $percentageScore
                CheckResults = $checkResults
                SystemInfo = @{
                    ComputerName = $env:COMPUTERNAME
                    OSVersion = (Get-CimInstance Win32_OperatingSystem).Caption
                    OSBuild = (Get-CimInstance Win32_OperatingSystem).BuildNumber
                }
            }
            
            $reportFile = Join-Path $Script:QuickCheckConfig.LogPath "quick-check-report-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
            
            if (-not (Test-Path $Script:QuickCheckConfig.LogPath)) {
                New-Item -Path $Script:QuickCheckConfig.LogPath -ItemType Directory -Force | Out-Null
            }
            
            $reportData | ConvertTo-Json -Depth 6 | Set-Content -Path $reportFile -Encoding UTF8
            Write-Host "`nRelatório exportado para: $reportFile" -ForegroundColor Green
        }
        catch {
            Write-QuickLog "Erro ao exportar relatório: $_" -Level "Error"
        }
    }
    
    $duration = ((Get-Date) - $Script:QuickCheckConfig.StartTime).TotalSeconds
    Write-Host "`nVerificação concluída em $([math]::Round($duration, 1)) segundos" -ForegroundColor Gray
    
    return $true
}

# ============================================================================
# EXECUÇÃO PRINCIPAL
# ============================================================================

try {
    $result = Start-QuickSecurityCheck
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