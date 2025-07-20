#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    LogoFAIL Advanced Protection - Proteções Avançadas contra Vulnerabilidades LogoFAIL
    
.DESCRIPTION
    Script para implementar proteções avançadas de segurança contra vulnerabilidades LogoFAIL.
    Inclui configurações de firmware UEFI, Secure Boot, Windows Defender avançado,
    HVCI, Device Guard, monitoramento de integridade de boot e políticas de grupo.
    
.PARAMETER EnableHVCI
    Ativa Hypervisor-protected Code Integrity
    
.PARAMETER EnableDeviceGuard
    Ativa Device Guard e Credential Guard
    
.PARAMETER EnableApplicationGuard
    Ativa Application Guard
    
.PARAMETER CreateSystemBackup
    Cria backup completo das configurações do sistema
    
.PARAMETER Force
    Força aplicação de configurações mesmo se detectar conflitos
    
.EXAMPLE
    .\LogoFAIL-AdvancedProtection.ps1 -EnableHVCI -EnableDeviceGuard -CreateSystemBackup
    
.NOTES
    Author: Matheus-TestUser1
    Version: 1.0.0
    Requires: Windows 10/11 Enterprise/Pro, PowerShell 5.1+, Administrator privileges
    Warning: Algumas configurações podem requerer reinicialização
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [switch]$EnableHVCI,
    
    [Parameter(Mandatory = $false)]
    [switch]$EnableDeviceGuard,
    
    [Parameter(Mandatory = $false)]
    [switch]$EnableApplicationGuard,
    
    [Parameter(Mandatory = $false)]
    [switch]$CreateSystemBackup,
    
    [Parameter(Mandatory = $false)]
    [switch]$Force
)

# ============================================================================
# CONFIGURAÇÕES GLOBAIS
# ============================================================================

$Script:AdvancedConfig = @{
    Version = "1.0.0"
    StartTime = Get-Date
    LogPath = "$env:ProgramData\WindowsDefenseLogoFAIL\Logs"
    BackupPath = "$env:ProgramData\WindowsDefenseLogoFAIL\Backups"
    ConfigPath = "$env:ProgramData\WindowsDefenseLogoFAIL\Config"
    RequireReboot = $false
    AppliedConfigurations = @()
    BackupFiles = @()
}

# Configurações de segurança recomendadas
$Script:SecurityPolicies = @{
    RegistrySettings = @{
        # Secure Boot e UEFI
        "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State" = @{
            "UEFISecureBootEnabled" = 1
        }
        
        # Boot Driver Flags
        "HKLM:\SYSTEM\CurrentControlSet\Control\BootDriverFlags" = @{
            "CreationTime" = 1
            "CryptoDriverVerification" = 1
        }
        
        # Kernel DMA Protection
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection" = @{
            "DeviceEnumerationPolicy" = 0
        }
        
        # Windows Defender configurações avançadas
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender" = @{
            "DisableAntiSpyware" = 0
            "DisableAntiVirus" = 0
        }
        
        "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" = @{
            "DisableBehaviorMonitoring" = 0
            "DisableOnAccessProtection" = 0
            "DisableRealtimeMonitoring" = 0
            "DisableIOAVProtection" = 0
            "DisableScriptScanning" = 0
        }
        
        # HVCI
        "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" = @{
            "EnableVirtualizationBasedSecurity" = 1
            "RequirePlatformSecurityFeatures" = 1
            "Locked" = 1
        }
        
        "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" = @{
            "Enabled" = 1
            "Locked" = 1
        }
        
        # LSA Protection
        "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" = @{
            "RunAsPPL" = 1
            "LsaCfgFlags" = 1
        }
        
        # SMB Security
        "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" = @{
            "RequireSecuritySignature" = 1
            "EnableSecuritySignature" = 1
        }
        
        # Network Security
        "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" = @{
            "NTLMMinClientSec" = 0x20080000
            "NTLMMinServerSec" = 0x20080000
        }
    }
    
    GroupPolicySettings = @{
        # Configurações de Política de Grupo Local
        SecurityOptions = @{
            "MACHINE\System\CurrentControlSet\Control\Session Manager\Kernel\ObCaseInsensitive" = "4,1"
            "MACHINE\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers\AddPrinterDrivers" = "4,1"
            "MACHINE\System\CurrentControlSet\Services\LDAP\LDAPClientIntegrity" = "4,1"
        }
    }
}

# ============================================================================
# FUNÇÕES DE LOGGING E UTILITÁRIOS
# ============================================================================

function Write-AdvancedLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("Error", "Warning", "Information", "Verbose", "Success")]
        [string]$Level = "Information",
        
        [Parameter(Mandatory = $false)]
        [string]$Component = "AdvancedProtection"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = @{
        Timestamp = $timestamp
        Level = $Level
        Component = $Component
        Message = $Message
        ComputerName = $env:COMPUTERNAME
        Username = $env:USERNAME
    }
    
    # Console output com cores
    $color = switch ($Level) {
        "Error" { "Red" }
        "Warning" { "Yellow" }
        "Information" { "Cyan" }
        "Verbose" { "Gray" }
        "Success" { "Green" }
    }
    
    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $color
    
    # Log para arquivo JSON
    try {
        if (-not (Test-Path $Script:AdvancedConfig.LogPath)) {
            New-Item -Path $Script:AdvancedConfig.LogPath -ItemType Directory -Force | Out-Null
        }
        
        $logFile = Join-Path $Script:AdvancedConfig.LogPath "advanced-protection-$(Get-Date -Format 'yyyy-MM-dd').json"
        $logEntry | ConvertTo-Json -Compress | Add-Content -Path $logFile -Encoding UTF8
    }
    catch {
        Write-Warning "Falha ao escrever log: $_"
    }
}

function Test-SystemCompatibility {
    Write-AdvancedLog "Verificando compatibilidade do sistema..." -Level "Information"
    
    $compatibility = @{
        WindowsVersion = $false
        Edition = $false
        HyperV = $false
        TPM = $false
        SecureBoot = $false
        UEFI = $false
        BitLocker = $false
        Issues = @()
    }
    
    try {
        # Verificar versão do Windows
        $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
        $buildNumber = [int]$osInfo.BuildNumber
        
        if ($buildNumber -ge 19041) { # Windows 10 2004+
            $compatibility.WindowsVersion = $true
        } else {
            $compatibility.Issues += "Windows 10 versão 2004 ou superior é requerido"
        }
        
        # Verificar edição do Windows
        if ($osInfo.Caption -match "Enterprise|Pro") {
            $compatibility.Edition = $true
        } else {
            $compatibility.Issues += "Windows Pro ou Enterprise é requerido para recursos avançados"
        }
        
        # Verificar suporte a Hyper-V
        $hyperVFeature = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -ErrorAction SilentlyContinue
        if ($hyperVFeature -and $hyperVFeature.State -eq "Enabled") {
            $compatibility.HyperV = $true
        } else {
            $compatibility.Issues += "Hyper-V não está habilitado (necessário para HVCI)"
        }
        
        # Verificar TPM
        try {
            $tpm = Get-Tpm -ErrorAction SilentlyContinue
            if ($tpm -and $tpm.TpmEnabled -and $tpm.TpmVersion -ge "2.0") {
                $compatibility.TPM = $true
            } else {
                $compatibility.Issues += "TPM 2.0 não encontrado ou não habilitado"
            }
        }
        catch {
            $compatibility.Issues += "Erro ao verificar TPM: $_"
        }
        
        # Verificar Secure Boot
        try {
            $secureBootState = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
            if ($secureBootState) {
                $compatibility.SecureBoot = $true
            } else {
                $compatibility.Issues += "Secure Boot não está ativo"
            }
        }
        catch {
            $compatibility.Issues += "Erro ao verificar Secure Boot"
        }
        
        # Verificar UEFI
        $firmwareType = (Get-CimInstance -ClassName Win32_ComputerSystem).PCSystemType
        if ($firmwareType -eq 2) {
            $compatibility.UEFI = $true
        } else {
            $compatibility.Issues += "Sistema Legacy BIOS detectado - UEFI é requerido"
        }
        
        # Verificar BitLocker
        try {
            $bitlockerVolumes = Get-BitLockerVolume -ErrorAction SilentlyContinue
            if ($bitlockerVolumes) {
                $compatibility.BitLocker = $true
            }
        }
        catch {
            # BitLocker pode não estar disponível
        }
        
        return $compatibility
    }
    catch {
        Write-AdvancedLog "Erro durante verificação de compatibilidade: $_" -Level "Error"
        return $compatibility
    }
}

# ============================================================================
# BACKUP DO SISTEMA
# ============================================================================

function New-SystemBackup {
    if (-not $CreateSystemBackup) {
        return $true
    }
    
    Write-AdvancedLog "Criando backup das configurações do sistema..." -Level "Information"
    
    try {
        $backupTimestamp = Get-Date -Format "yyyyMMdd-HHmmss"
        $backupDir = Join-Path $Script:AdvancedConfig.BackupPath $backupTimestamp
        
        if (-not (Test-Path $backupDir)) {
            New-Item -Path $backupDir -ItemType Directory -Force | Out-Null
        }
        
        $backup = @{
            Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            SystemInfo = @{
                ComputerName = $env:COMPUTERNAME
                OSVersion = (Get-CimInstance Win32_OperatingSystem).Caption
                OSBuild = (Get-CimInstance Win32_OperatingSystem).BuildNumber
            }
            RegistryBackup = @{}
            GroupPolicyBackup = @{}
            SecurityConfigBackup = @{}
        }
        
        # Backup de chaves de registro críticas
        $criticalRegistryKeys = @(
            "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot",
            "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard",
            "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa",
            "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
        )
        
        foreach ($keyPath in $criticalRegistryKeys) {
            try {
                if (Test-Path $keyPath) {
                    $keyData = Get-ItemProperty -Path $keyPath -ErrorAction SilentlyContinue
                    if ($keyData) {
                        $backup.RegistryBackup[$keyPath] = $keyData | ConvertTo-Json -Depth 3
                        
                        # Exportar chave de registro
                        $regFileName = ($keyPath -replace "HKLM:\\", "" -replace "\\", "_") + ".reg"
                        $regFilePath = Join-Path $backupDir $regFileName
                        & reg.exe export $keyPath.Replace(":", "") $regFilePath /y 2>$null
                        
                        if (Test-Path $regFilePath) {
                            $Script:AdvancedConfig.BackupFiles += $regFilePath
                        }
                    }
                }
            }
            catch {
                Write-AdvancedLog "Erro ao fazer backup de $keyPath`: $_" -Level "Warning"
            }
        }
        
        # Backup de configurações de segurança local
        try {
            $secdbPath = Join-Path $backupDir "secedit-backup.inf"
            & secedit.exe /export /cfg $secdbPath /quiet
            
            if (Test-Path $secdbPath) {
                $Script:AdvancedConfig.BackupFiles += $secdbPath
                Write-AdvancedLog "Backup de política de segurança criado" -Level "Success"
            }
        }
        catch {
            Write-AdvancedLog "Erro ao fazer backup de políticas de segurança: $_" -Level "Warning"
        }
        
        # Backup de configurações do Windows Defender
        try {
            $defenderConfigPath = Join-Path $backupDir "defender-config.json"
            $defenderConfig = Get-MpPreference -ErrorAction SilentlyContinue
            if ($defenderConfig) {
                $defenderConfig | ConvertTo-Json -Depth 3 | Set-Content -Path $defenderConfigPath -Encoding UTF8
                $Script:AdvancedConfig.BackupFiles += $defenderConfigPath
            }
        }
        catch {
            Write-AdvancedLog "Erro ao fazer backup do Windows Defender: $_" -Level "Warning"
        }
        
        # Salvar metadados do backup
        $backupMetadataPath = Join-Path $backupDir "backup-metadata.json"
        $backup | ConvertTo-Json -Depth 5 | Set-Content -Path $backupMetadataPath -Encoding UTF8
        $Script:AdvancedConfig.BackupFiles += $backupMetadataPath
        
        Write-AdvancedLog "Backup do sistema criado em: $backupDir" -Level "Success"
        return $true
    }
    catch {
        Write-AdvancedLog "Erro ao criar backup do sistema: $_" -Level "Error"
        return $false
    }
}

# ============================================================================
# CONFIGURAÇÃO DE FIRMWARE UEFI E SECURE BOOT
# ============================================================================

function Set-UEFISecuritySettings {
    Write-AdvancedLog "Configurando segurança UEFI e Secure Boot..." -Level "Information"
    
    try {
        $securityApplied = $false
        
        # Verificar se Secure Boot está ativo
        try {
            $secureBootState = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
            if (-not $secureBootState) {
                Write-AdvancedLog "AVISO: Secure Boot não está ativo. Isso deve ser configurado no firmware UEFI." -Level "Warning"
                Write-AdvancedLog "Para ativar Secure Boot:" -Level "Information"
                Write-AdvancedLog "1. Reinicie o computador e entre no setup UEFI (normalmente F2, F12, Del)" -Level "Information"
                Write-AdvancedLog "2. Procure por 'Secure Boot' nas configurações de segurança" -Level "Information"
                Write-AdvancedLog "3. Ative o Secure Boot e salve as configurações" -Level "Information"
            } else {
                Write-AdvancedLog "Secure Boot está ativo" -Level "Success"
                $securityApplied = $true
            }
        }
        catch {
            Write-AdvancedLog "Erro ao verificar Secure Boot: $_" -Level "Warning"
        }
        
        # Configurar registros relacionados ao Secure Boot
        try {
            $secureBootRegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State"
            if (Test-Path $secureBootRegPath) {
                Set-ItemProperty -Path $secureBootRegPath -Name "UEFISecureBootEnabled" -Value 1 -Type DWord -Force
                $securityApplied = $true
                Write-AdvancedLog "Registro Secure Boot configurado" -Level "Success"
                $Script:AdvancedConfig.AppliedConfigurations += "SecureBoot Registry"
            }
        }
        catch {
            Write-AdvancedLog "Erro ao configurar registro Secure Boot: $_" -Level "Warning"
        }
        
        # Configurar Boot Driver Flags
        try {
            $bootDriverPath = "HKLM:\SYSTEM\CurrentControlSet\Control\BootDriverFlags"
            if (-not (Test-Path $bootDriverPath)) {
                New-Item -Path $bootDriverPath -Force | Out-Null
            }
            
            Set-ItemProperty -Path $bootDriverPath -Name "CreationTime" -Value 1 -Type DWord -Force
            Set-ItemProperty -Path $bootDriverPath -Name "CryptoDriverVerification" -Value 1 -Type DWord -Force
            
            $securityApplied = $true
            Write-AdvancedLog "Boot Driver Flags configurados" -Level "Success"
            $Script:AdvancedConfig.AppliedConfigurations += "Boot Driver Flags"
        }
        catch {
            Write-AdvancedLog "Erro ao configurar Boot Driver Flags: $_" -Level "Warning"
        }
        
        return $securityApplied
    }
    catch {
        Write-AdvancedLog "Erro durante configuração UEFI: $_" -Level "Error"
        return $false
    }
}

# ============================================================================
# CONFIGURAÇÃO DO WINDOWS DEFENDER AVANÇADO
# ============================================================================

function Set-AdvancedDefenderConfiguration {
    Write-AdvancedLog "Configurando Windows Defender para proteção avançada..." -Level "Information"
    
    try {
        $defenderConfigured = $false
        
        # Configurações avançadas do Windows Defender
        $defenderSettings = @{
            DisableRealtimeMonitoring = $false
            DisableBehaviorMonitoring = $false
            DisableBlockAtFirstSeen = $false
            DisableIOAVProtection = $false
            DisableScriptScanning = $false
            DisableArchiveScanning = $false
            DisableIntrusionPreventionSystem = $false
            DisableEmailScanning = $false
            MAPSReporting = [Microsoft.PowerShell.Cmdletization.GeneratedTypes.MpPreference.MAPSReportingType]::Advanced
            SubmitSamplesConsent = [Microsoft.PowerShell.Cmdletization.GeneratedTypes.MpPreference.SubmitSamplesConsentType]::SendAllSamples
            EnableControlledFolderAccess = [Microsoft.PowerShell.Cmdletization.GeneratedTypes.MpPreference.ControlledFolderAccessType]::Enabled
            EnableNetworkProtection = [Microsoft.PowerShell.Cmdletization.GeneratedTypes.MpPreference.EnableNetworkProtectionType]::Enabled
            PUAProtection = [Microsoft.PowerShell.Cmdletization.GeneratedTypes.MpPreference.PUAProtectionType]::Enabled
        }
        
        foreach ($setting in $defenderSettings.GetEnumerator()) {
            try {
                Set-MpPreference -$($setting.Key) $setting.Value -Force
                Write-AdvancedLog "Configuração aplicada: $($setting.Key) = $($setting.Value)" -Level "Verbose"
                $defenderConfigured = $true
            }
            catch {
                Write-AdvancedLog "Erro ao aplicar configuração $($setting.Key): $_" -Level "Warning"
            }
        }
        
        # Configurar exclusões específicas para LogoFAIL (se necessário)
        # Normalmente não recomendado, mas pode ser necessário em alguns ambientes
        
        # Configurar políticas de grupo para Windows Defender
        $defenderPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
        $rtProtectionPath = "$defenderPolicyPath\Real-Time Protection"
        
        try {
            if (-not (Test-Path $defenderPolicyPath)) {
                New-Item -Path $defenderPolicyPath -Force | Out-Null
            }
            if (-not (Test-Path $rtProtectionPath)) {
                New-Item -Path $rtProtectionPath -Force | Out-Null
            }
            
            # Configurações de política
            Set-ItemProperty -Path $defenderPolicyPath -Name "DisableAntiSpyware" -Value 0 -Type DWord -Force
            Set-ItemProperty -Path $defenderPolicyPath -Name "DisableAntiVirus" -Value 0 -Type DWord -Force
            
            Set-ItemProperty -Path $rtProtectionPath -Name "DisableBehaviorMonitoring" -Value 0 -Type DWord -Force
            Set-ItemProperty -Path $rtProtectionPath -Name "DisableOnAccessProtection" -Value 0 -Type DWord -Force
            Set-ItemProperty -Path $rtProtectionPath -Name "DisableRealtimeMonitoring" -Value 0 -Type DWord -Force
            Set-ItemProperty -Path $rtProtectionPath -Name "DisableScriptScanning" -Value 0 -Type DWord -Force
            
            Write-AdvancedLog "Políticas de grupo do Windows Defender configuradas" -Level "Success"
            $Script:AdvancedConfig.AppliedConfigurations += "Windows Defender Policies"
        }
        catch {
            Write-AdvancedLog "Erro ao configurar políticas do Windows Defender: $_" -Level "Warning"
        }
        
        # Forçar atualização de definições
        try {
            Update-MpSignature -UpdateSource MicrosoftUpdateServer
            Write-AdvancedLog "Definições do Windows Defender atualizadas" -Level "Success"
        }
        catch {
            Write-AdvancedLog "Erro ao atualizar definições: $_" -Level "Warning"
        }
        
        if ($defenderConfigured) {
            Write-AdvancedLog "Windows Defender configurado para proteção avançada" -Level "Success"
            $Script:AdvancedConfig.AppliedConfigurations += "Advanced Windows Defender"
        }
        
        return $defenderConfigured
    }
    catch {
        Write-AdvancedLog "Erro durante configuração do Windows Defender: $_" -Level "Error"
        return $false
    }
}

# ============================================================================
# CONFIGURAÇÃO DE HVCI (HYPERVISOR-PROTECTED CODE INTEGRITY)
# ============================================================================

function Enable-HVCIProtection {
    if (-not $EnableHVCI) {
        return $true
    }
    
    Write-AdvancedLog "Configurando Hypervisor-protected Code Integrity (HVCI)..." -Level "Information"
    
    try {
        # Verificar pré-requisitos
        $hyperVFeature = Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All -ErrorAction SilentlyContinue
        if (-not $hyperVFeature -or $hyperVFeature.State -ne "Enabled") {
            Write-AdvancedLog "AVISO: Hyper-V não está habilitado. HVCI requer Hyper-V." -Level "Warning"
            Write-AdvancedLog "Para habilitar Hyper-V: Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Hyper-V-All" -Level "Information"
            
            if (-not $Force) {
                return $false
            }
        }
        
        # Configurar registros para HVCI
        $deviceGuardPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"
        $hvciPath = "$deviceGuardPath\Scenarios\HypervisorEnforcedCodeIntegrity"
        
        try {
            if (-not (Test-Path $deviceGuardPath)) {
                New-Item -Path $deviceGuardPath -Force | Out-Null
            }
            if (-not (Test-Path $hvciPath)) {
                New-Item -Path $hvciPath -Force | Out-Null
            }
            
            # Configurações do Device Guard
            Set-ItemProperty -Path $deviceGuardPath -Name "EnableVirtualizationBasedSecurity" -Value 1 -Type DWord -Force
            Set-ItemProperty -Path $deviceGuardPath -Name "RequirePlatformSecurityFeatures" -Value 1 -Type DWord -Force
            Set-ItemProperty -Path $deviceGuardPath -Name "Locked" -Value 1 -Type DWord -Force
            
            # Configurações do HVCI
            Set-ItemProperty -Path $hvciPath -Name "Enabled" -Value 1 -Type DWord -Force
            Set-ItemProperty -Path $hvciPath -Name "Locked" -Value 1 -Type DWord -Force
            
            Write-AdvancedLog "HVCI configurado com sucesso" -Level "Success"
            $Script:AdvancedConfig.AppliedConfigurations += "HVCI"
            $Script:AdvancedConfig.RequireReboot = $true
            
            return $true
        }
        catch {
            Write-AdvancedLog "Erro ao configurar registros HVCI: $_" -Level "Error"
            return $false
        }
    }
    catch {
        Write-AdvancedLog "Erro durante configuração HVCI: $_" -Level "Error"
        return $false
    }
}

# ============================================================================
# CONFIGURAÇÃO DE DEVICE GUARD E CREDENTIAL GUARD
# ============================================================================

function Enable-DeviceGuardProtection {
    if (-not $EnableDeviceGuard) {
        return $true
    }
    
    Write-AdvancedLog "Configurando Device Guard e Credential Guard..." -Level "Information"
    
    try {
        # Configurar LSA Protection
        $lsaPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        
        try {
            Set-ItemProperty -Path $lsaPath -Name "RunAsPPL" -Value 1 -Type DWord -Force
            Set-ItemProperty -Path $lsaPath -Name "LsaCfgFlags" -Value 1 -Type DWord -Force
            
            Write-AdvancedLog "LSA Protection configurado" -Level "Success"
            $Script:AdvancedConfig.AppliedConfigurations += "LSA Protection"
        }
        catch {
            Write-AdvancedLog "Erro ao configurar LSA Protection: $_" -Level "Warning"
        }
        
        # Configurar Credential Guard via registro
        $credGuardPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"
        
        try {
            if (-not (Test-Path $credGuardPath)) {
                New-Item -Path $credGuardPath -Force | Out-Null
            }
            
            Set-ItemProperty -Path $credGuardPath -Name "EnableVirtualizationBasedSecurity" -Value 1 -Type DWord -Force
            Set-ItemProperty -Path $credGuardPath -Name "RequirePlatformSecurityFeatures" -Value 3 -Type DWord -Force
            Set-ItemProperty -Path $credGuardPath -Name "LsaCfgFlags" -Value 1 -Type DWord -Force
            
            Write-AdvancedLog "Device Guard e Credential Guard configurados" -Level "Success"
            $Script:AdvancedConfig.AppliedConfigurations += "Device Guard/Credential Guard"
            $Script:AdvancedConfig.RequireReboot = $true
        }
        catch {
            Write-AdvancedLog "Erro ao configurar Device Guard: $_" -Level "Warning"
        }
        
        # Configurar política de integridade de código
        try {
            $codeIntegrityPath = "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config"
            if (-not (Test-Path $codeIntegrityPath)) {
                New-Item -Path $codeIntegrityPath -Force | Out-Null
            }
            
            Set-ItemProperty -Path $codeIntegrityPath -Name "VulnerableDriverBlocklistEnable" -Value 1 -Type DWord -Force
            
            Write-AdvancedLog "Política de integridade de código configurada" -Level "Success"
            $Script:AdvancedConfig.AppliedConfigurations += "Code Integrity Policy"
        }
        catch {
            Write-AdvancedLog "Erro ao configurar política de integridade: $_" -Level "Warning"
        }
        
        return $true
    }
    catch {
        Write-AdvancedLog "Erro durante configuração Device Guard: $_" -Level "Error"
        return $false
    }
}

# ============================================================================
# CONFIGURAÇÃO DE APPLICATION GUARD
# ============================================================================

function Enable-ApplicationGuardProtection {
    if (-not $EnableApplicationGuard) {
        return $true
    }
    
    Write-AdvancedLog "Configurando Windows Defender Application Guard..." -Level "Information"
    
    try {
        # Verificar se o recurso está disponível
        $appGuardFeature = Get-WindowsOptionalFeature -Online -FeatureName Windows-Defender-ApplicationGuard -ErrorAction SilentlyContinue
        
        if (-not $appGuardFeature) {
            Write-AdvancedLog "Application Guard não está disponível nesta edição do Windows" -Level "Warning"
            return $false
        }
        
        if ($appGuardFeature.State -ne "Enabled") {
            try {
                Enable-WindowsOptionalFeature -Online -FeatureName Windows-Defender-ApplicationGuard -All -NoRestart
                Write-AdvancedLog "Application Guard habilitado" -Level "Success"
                $Script:AdvancedConfig.AppliedConfigurations += "Application Guard"
                $Script:AdvancedConfig.RequireReboot = $true
            }
            catch {
                Write-AdvancedLog "Erro ao habilitar Application Guard: $_" -Level "Warning"
                return $false
            }
        }
        
        # Configurar políticas do Application Guard
        $appGuardPolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\AppHVSI"
        
        try {
            if (-not (Test-Path $appGuardPolicyPath)) {
                New-Item -Path $appGuardPolicyPath -Force | Out-Null
            }
            
            Set-ItemProperty -Path $appGuardPolicyPath -Name "AllowAppHVSI_ProviderSet" -Value 1 -Type DWord -Force
            Set-ItemProperty -Path $appGuardPolicyPath -Name "AppHVSIClipboardSettings" -Value 1 -Type DWord -Force
            Set-ItemProperty -Path $appGuardPolicyPath -Name "AppHVSIPrintingSettings" -Value 1 -Type DWord -Force
            
            Write-AdvancedLog "Políticas do Application Guard configuradas" -Level "Success"
            $Script:AdvancedConfig.AppliedConfigurations += "Application Guard Policies"
        }
        catch {
            Write-AdvancedLog "Erro ao configurar políticas Application Guard: $_" -Level "Warning"
        }
        
        return $true
    }
    catch {
        Write-AdvancedLog "Erro durante configuração Application Guard: $_" -Level "Error"
        return $false
    }
}

# ============================================================================
# CONFIGURAÇÃO DE POLÍTICAS DE SEGURANÇA LOCAIS
# ============================================================================

function Set-LocalSecurityPolicies {
    Write-AdvancedLog "Configurando políticas de segurança locais..." -Level "Information"
    
    try {
        $policiesApplied = $false
        
        # Configurar política de auditoria
        $auditPolicies = @{
            "System\Audit Logon Events" = "Success,Failure"
            "System\Audit Account Logon Events" = "Success,Failure"
            "System\Audit Process Tracking" = "Success,Failure"
            "System\Audit Policy Change" = "Success,Failure"
            "System\Audit Privilege Use" = "Failure"
            "System\Audit System Events" = "Success,Failure"
        }
        
        foreach ($policy in $auditPolicies.GetEnumerator()) {
            try {
                & auditpol.exe /set /subcategory:"$($policy.Key)" /success:enable /failure:enable 2>$null
                Write-AdvancedLog "Política de auditoria configurada: $($policy.Key)" -Level "Verbose"
                $policiesApplied = $true
            }
            catch {
                Write-AdvancedLog "Erro ao configurar política $($policy.Key): $_" -Level "Warning"
            }
        }
        
        # Configurar direitos de usuário
        $userRights = @{
            "SeDenyNetworkLogonRight" = "Guest"
            "SeDenyRemoteInteractiveLogonRight" = "Guest"
            "SeDenyServiceLogonRight" = "Guest"
        }
        
        # Configurar políticas de senha (se aplicável)
        try {
            & net.exe accounts /minpwlen:14 /maxpwage:60 /minpwage:1 /uniquepw:12 2>$null
            Write-AdvancedLog "Políticas de senha configuradas" -Level "Success"
            $policiesApplied = $true
        }
        catch {
            Write-AdvancedLog "Erro ao configurar políticas de senha: $_" -Level "Warning"
        }
        
        if ($policiesApplied) {
            $Script:AdvancedConfig.AppliedConfigurations += "Local Security Policies"
        }
        
        return $policiesApplied
    }
    catch {
        Write-AdvancedLog "Erro durante configuração de políticas locais: $_" -Level "Error"
        return $false
    }
}

# ============================================================================
# CONFIGURAÇÕES DE REDE E SMB
# ============================================================================

function Set-NetworkSecuritySettings {
    Write-AdvancedLog "Configurando segurança de rede..." -Level "Information"
    
    try {
        $networkConfigured = $false
        
        # Configurar SMB
        $smbServerPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
        $smbClientPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
        
        try {
            Set-ItemProperty -Path $smbServerPath -Name "RequireSecuritySignature" -Value 1 -Type DWord -Force
            Set-ItemProperty -Path $smbServerPath -Name "EnableSecuritySignature" -Value 1 -Type DWord -Force
            Set-ItemProperty -Path $smbServerPath -Name "EnableForcedLogoff" -Value 1 -Type DWord -Force
            
            Set-ItemProperty -Path $smbClientPath -Name "RequireSecuritySignature" -Value 1 -Type DWord -Force
            Set-ItemProperty -Path $smbClientPath -Name "EnableSecuritySignature" -Value 1 -Type DWord -Force
            
            Write-AdvancedLog "Configurações SMB de segurança aplicadas" -Level "Success"
            $networkConfigured = $true
        }
        catch {
            Write-AdvancedLog "Erro ao configurar SMB: $_" -Level "Warning"
        }
        
        # Configurar NTLM
        $ntlmPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0"
        
        try {
            if (-not (Test-Path $ntlmPath)) {
                New-Item -Path $ntlmPath -Force | Out-Null
            }
            
            Set-ItemProperty -Path $ntlmPath -Name "NTLMMinClientSec" -Value 0x20080000 -Type DWord -Force
            Set-ItemProperty -Path $ntlmPath -Name "NTLMMinServerSec" -Value 0x20080000 -Type DWord -Force
            
            Write-AdvancedLog "Configurações NTLM de segurança aplicadas" -Level "Success"
            $networkConfigured = $true
        }
        catch {
            Write-AdvancedLog "Erro ao configurar NTLM: $_" -Level "Warning"
        }
        
        # Desabilitar protocolos inseguros
        try {
            # Desabilitar SSLv2 e SSLv3
            $sslPath = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"
            
            $insecureProtocols = @("SSL 2.0", "SSL 3.0")
            
            foreach ($protocol in $insecureProtocols) {
                $protocolPath = "$sslPath\$protocol\Server"
                if (-not (Test-Path $protocolPath)) {
                    New-Item -Path $protocolPath -Force | Out-Null
                }
                Set-ItemProperty -Path $protocolPath -Name "Enabled" -Value 0 -Type DWord -Force
                Set-ItemProperty -Path $protocolPath -Name "DisabledByDefault" -Value 1 -Type DWord -Force
                
                $clientPath = "$sslPath\$protocol\Client"
                if (-not (Test-Path $clientPath)) {
                    New-Item -Path $clientPath -Force | Out-Null
                }
                Set-ItemProperty -Path $clientPath -Name "Enabled" -Value 0 -Type DWord -Force
                Set-ItemProperty -Path $clientPath -Name "DisabledByDefault" -Value 1 -Type DWord -Force
            }
            
            Write-AdvancedLog "Protocolos inseguros desabilitados" -Level "Success"
            $networkConfigured = $true
        }
        catch {
            Write-AdvancedLog "Erro ao desabilitar protocolos inseguros: $_" -Level "Warning"
        }
        
        if ($networkConfigured) {
            $Script:AdvancedConfig.AppliedConfigurations += "Network Security Settings"
        }
        
        return $networkConfigured
    }
    catch {
        Write-AdvancedLog "Erro durante configuração de rede: $_" -Level "Error"
        return $false
    }
}

# ============================================================================
# FUNÇÃO PRINCIPAL
# ============================================================================

function Start-LogoFAILAdvancedProtection {
    Write-Host "======================================================================" -ForegroundColor Cyan
    Write-Host "    LogoFAIL Advanced Protection - Proteções Avançadas de Segurança" -ForegroundColor Cyan
    Write-Host "    Versão: $($Script:AdvancedConfig.Version)" -ForegroundColor Cyan
    Write-Host "======================================================================" -ForegroundColor Cyan
    Write-Host ""
    
    # Verificar privilégios de administrador
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-AdvancedLog "Este script requer privilégios de administrador" -Level "Error"
        return $false
    }
    
    # Criar diretórios necessários
    try {
        $directories = @(
            $Script:AdvancedConfig.LogPath,
            $Script:AdvancedConfig.BackupPath,
            $Script:AdvancedConfig.ConfigPath
        )
        
        foreach ($dir in $directories) {
            if (-not (Test-Path $dir)) {
                New-Item -Path $dir -ItemType Directory -Force | Out-Null
            }
        }
    }
    catch {
        Write-AdvancedLog "Erro ao criar diretórios: $_" -Level "Error"
        return $false
    }
    
    Write-AdvancedLog "Iniciando configuração de proteções avançadas..." -Level "Information"
    
    # Verificar compatibilidade do sistema
    $compatibility = Test-SystemCompatibility
    
    if ($compatibility.Issues.Count -gt 0 -and -not $Force) {
        Write-AdvancedLog "Problemas de compatibilidade encontrados:" -Level "Warning"
        foreach ($issue in $compatibility.Issues) {
            Write-AdvancedLog "  - $issue" -Level "Warning"
        }
        Write-AdvancedLog "Use -Force para ignorar verificações de compatibilidade" -Level "Information"
        return $false
    }
    
    # Criar backup do sistema
    if (-not (New-SystemBackup)) {
        Write-AdvancedLog "Falha ao criar backup - continuando sem backup" -Level "Warning"
    }
    
    # Aplicar configurações de segurança
    $results = @{
        UEFISettings = Set-UEFISecuritySettings
        DefenderConfig = Set-AdvancedDefenderConfiguration
        HVCIConfig = Enable-HVCIProtection
        DeviceGuardConfig = Enable-DeviceGuardProtection
        ApplicationGuardConfig = Enable-ApplicationGuardProtection
        LocalPolicies = Set-LocalSecurityPolicies
        NetworkSecurity = Set-NetworkSecuritySettings
    }
    
    # Compilar resultados
    $successCount = ($results.Values | Where-Object { $_ -eq $true }).Count
    $totalCount = $results.Count
    
    Write-Host ""
    Write-Host "======================================================================" -ForegroundColor Green
    Write-Host "    Configuração de Proteções Avançadas Concluída" -ForegroundColor Green
    Write-Host "======================================================================" -ForegroundColor Green
    Write-Host ""
    
    # Exibir resumo
    Write-Host "RESUMO DAS CONFIGURAÇÕES:" -ForegroundColor Yellow
    Write-Host "- Configurações aplicadas com sucesso: $successCount de $totalCount" -ForegroundColor White
    Write-Host "- Configurações implementadas:" -ForegroundColor White
    
    foreach ($config in $Script:AdvancedConfig.AppliedConfigurations) {
        Write-Host "  ✓ $config" -ForegroundColor Green
    }
    
    if ($Script:AdvancedConfig.BackupFiles.Count -gt 0) {
        Write-Host "- Arquivos de backup criados: $($Script:AdvancedConfig.BackupFiles.Count)" -ForegroundColor White
        Write-Host "  Localização: $($Script:AdvancedConfig.BackupPath)" -ForegroundColor Gray
    }
    
    # Verificar se reinicialização é necessária
    if ($Script:AdvancedConfig.RequireReboot) {
        Write-Host ""
        Write-Host "IMPORTANTE: Reinicialização necessária!" -ForegroundColor Red
        Write-Host "Algumas configurações só terão efeito após reinicializar o sistema." -ForegroundColor Yellow
        Write-Host "Recomenda-se reinicializar o computador agora." -ForegroundColor Yellow
    }
    
    Write-Host ""
    Write-Host "VERIFICAÇÕES RECOMENDADAS APÓS REINICIALIZAÇÃO:" -ForegroundColor Yellow
    Write-Host "1. Execute LogoFAIL-QuickCheck.ps1 para verificar o status das proteções" -ForegroundColor White
    Write-Host "2. Execute LogoFAIL-ForensicAnalysis.ps1 para análise completa" -ForegroundColor White
    Write-Host "3. Verifique os logs em: $($Script:AdvancedConfig.LogPath)" -ForegroundColor White
    
    # Salvar configuração
    try {
        $configSummary = @{
            Version = $Script:AdvancedConfig.Version
            InstallationDate = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            AppliedConfigurations = $Script:AdvancedConfig.AppliedConfigurations
            BackupFiles = $Script:AdvancedConfig.BackupFiles
            RequireReboot = $Script:AdvancedConfig.RequireReboot
            Results = $results
            SystemCompatibility = $compatibility
        }
        
        $configFile = Join-Path $Script:AdvancedConfig.ConfigPath "advanced-protection-config.json"
        $configSummary | ConvertTo-Json -Depth 5 | Set-Content -Path $configFile -Encoding UTF8
        
        Write-AdvancedLog "Configuração salva em: $configFile" -Level "Success"
    }
    catch {
        Write-AdvancedLog "Erro ao salvar configuração: $_" -Level "Warning"
    }
    
    return $true
}

# ============================================================================
# EXECUÇÃO PRINCIPAL
# ============================================================================

try {
    $result = Start-LogoFAILAdvancedProtection
    if ($result) {
        exit 0
    } else {
        exit 1
    }
}
catch {
    Write-AdvancedLog "Erro fatal durante configuração: $_" -Level "Error"
    exit 1
}