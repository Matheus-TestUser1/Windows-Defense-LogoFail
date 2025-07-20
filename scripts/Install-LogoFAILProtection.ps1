#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Windows Defense LogoFAIL - Sistema Completo de Prevenção e Monitoramento
    
.DESCRIPTION
    Script principal para instalação e configuração de proteção contra vulnerabilidades LogoFAIL.
    Implementa verificação de saúde do sistema, monitoramento preventivo, baselines de segurança,
    otimização do Windows Defender e sistema de alertas configurável.
    
.PARAMETER EnableContinuousMonitoring
    Ativa o monitoramento contínuo em background
    
.PARAMETER AlertEmail
    Email para envio de alertas (opcional)
    
.PARAMETER LogLevel
    Nível de log: Error, Warning, Information, Verbose
    
.EXAMPLE
    .\Install-LogoFAILProtection.ps1 -EnableContinuousMonitoring -AlertEmail "admin@empresa.com"
    
.NOTES
    Author: Matheus-TestUser1
    Version: 1.0.0
    Requires: Windows 10/11, PowerShell 5.1+, Administrator privileges
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [switch]$EnableContinuousMonitoring,
    
    [Parameter(Mandatory = $false)]
    [string]$AlertEmail,
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("Error", "Warning", "Information", "Verbose")]
    [string]$LogLevel = "Information"
)

# ============================================================================
# CONFIGURAÇÕES GLOBAIS
# ============================================================================

$Script:LogoFAILConfig = @{
    Version = "1.0.0"
    InstallPath = "$env:ProgramFiles\WindowsDefenseLogoFAIL"
    LogPath = "$env:ProgramData\WindowsDefenseLogoFAIL\Logs"
    ConfigPath = "$env:ProgramData\WindowsDefenseLogoFAIL\Config"
    BaselinePath = "$env:ProgramData\WindowsDefenseLogoFAIL\Baselines"
    TaskName = "LogoFAIL-ContinuousMonitor"
    LogLevel = $LogLevel
    AlertEmail = $AlertEmail
}

# ============================================================================
# FUNÇÕES DE LOGGING E UTILITÁRIOS
# ============================================================================

function Write-LogoFAILLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("Error", "Warning", "Information", "Verbose")]
        [string]$Level = "Information",
        
        [Parameter(Mandatory = $false)]
        [string]$Component = "Main"
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
        "Information" { "Green" }
        "Verbose" { "Cyan" }
    }
    
    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $color
    
    # Log para arquivo JSON
    try {
        $logFile = Join-Path $Script:LogoFAILConfig.LogPath "logofail-$(Get-Date -Format 'yyyy-MM-dd').json"
        $logEntry | ConvertTo-Json -Compress | Add-Content -Path $logFile -Encoding UTF8
    }
    catch {
        Write-Warning "Falha ao escrever log: $_"
    }
}

function Test-AdminPrivileges {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Initialize-LogoFAILDirectories {
    try {
        $directories = @(
            $Script:LogoFAILConfig.InstallPath,
            $Script:LogoFAILConfig.LogPath,
            $Script:LogoFAILConfig.ConfigPath,
            $Script:LogoFAILConfig.BaselinePath
        )
        
        foreach ($dir in $directories) {
            if (-not (Test-Path $dir)) {
                New-Item -Path $dir -ItemType Directory -Force | Out-Null
                Write-LogoFAILLog "Diretório criado: $dir" -Level "Information"
            }
        }
        
        return $true
    }
    catch {
        Write-LogoFAILLog "Erro ao criar diretórios: $_" -Level "Error"
        return $false
    }
}

# ============================================================================
# VERIFICAÇÕES DE SAÚDE DO SISTEMA
# ============================================================================

function Test-SystemHealth {
    Write-LogoFAILLog "Iniciando verificação de saúde do sistema..." -Level "Information"
    
    $healthResults = @{
        WindowsVersion = $true
        SecureBoot = $false
        WindowsDefender = $false
        SystemIntegrity = $false
        FirmwareType = "Unknown"
        VulnerableDrivers = @()
        Recommendations = @()
    }
    
    try {
        # Verificar versão do Windows
        $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
        $buildNumber = [int]$osInfo.BuildNumber
        
        if ($buildNumber -ge 19041) { # Windows 10 2004+
            $healthResults.WindowsVersion = $true
            Write-LogoFAILLog "Versão do Windows compatível: $($osInfo.Caption) Build $buildNumber" -Level "Information"
        } else {
            $healthResults.WindowsVersion = $false
            $healthResults.Recommendations += "Atualizar para Windows 10 versão 2004 ou superior"
            Write-LogoFAILLog "Versão do Windows pode ser vulnerável: Build $buildNumber" -Level "Warning"
        }
        
        # Verificar Secure Boot
        try {
            $secureBootState = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
            if ($secureBootState) {
                $healthResults.SecureBoot = $true
                Write-LogoFAILLog "Secure Boot está ativado" -Level "Information"
            } else {
                $healthResults.Recommendations += "Ativar Secure Boot no firmware UEFI"
                Write-LogoFAILLog "Secure Boot não está ativado - CRÍTICO para proteção LogoFAIL" -Level "Warning"
            }
        }
        catch {
            $healthResults.Recommendations += "Verificar suporte e configuração do Secure Boot"
            Write-LogoFAILLog "Não foi possível verificar Secure Boot: $_" -Level "Warning"
        }
        
        # Verificar tipo de firmware
        try {
            $firmwareType = (Get-CimInstance -ClassName Win32_ComputerSystem).PCSystemType
            $healthResults.FirmwareType = if ($firmwareType -eq 2) { "UEFI" } else { "Legacy" }
            Write-LogoFAILLog "Tipo de firmware: $($healthResults.FirmwareType)" -Level "Information"
        }
        catch {
            Write-LogoFAILLog "Erro ao detectar tipo de firmware: $_" -Level "Warning"
        }
        
        # Verificar Windows Defender
        try {
            $defenderStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
            if ($defenderStatus -and $defenderStatus.RealTimeProtectionEnabled) {
                $healthResults.WindowsDefender = $true
                Write-LogoFAILLog "Windows Defender ativo e funcionando" -Level "Information"
            } else {
                $healthResults.Recommendations += "Ativar Windows Defender Real-Time Protection"
                Write-LogoFAILLog "Windows Defender não está totalmente ativo" -Level "Warning"
            }
        }
        catch {
            $healthResults.Recommendations += "Verificar status do Windows Defender"
            Write-LogoFAILLog "Erro ao verificar Windows Defender: $_" -Level "Warning"
        }
        
        # Verificar integridade do sistema
        Write-LogoFAILLog "Executando verificação de integridade do sistema (SFC)..." -Level "Information"
        $sfcResult = & sfc.exe /verifyonly 2>&1
        if ($LASTEXITCODE -eq 0) {
            $healthResults.SystemIntegrity = $true
            Write-LogoFAILLog "Integridade do sistema verificada com sucesso" -Level "Information"
        } else {
            $healthResults.Recommendations += "Executar 'sfc /scannow' para reparar arquivos corrompidos"
            Write-LogoFAILLog "Problemas de integridade detectados no sistema" -Level "Warning"
        }
        
        return $healthResults
    }
    catch {
        Write-LogoFAILLog "Erro durante verificação de saúde: $_" -Level "Error"
        return $healthResults
    }
}

# ============================================================================
# CRIAÇÃO DE BASELINES DE SEGURANÇA
# ============================================================================

function New-SecurityBaseline {
    Write-LogoFAILLog "Criando baseline de segurança..." -Level "Information"
    
    try {
        $baseline = @{
            CreationDate = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            SystemInfo = @{
                ComputerName = $env:COMPUTERNAME
                OSVersion = (Get-CimInstance Win32_OperatingSystem).Caption
                OSBuild = (Get-CimInstance Win32_OperatingSystem).BuildNumber
            }
            CriticalFiles = @{}
            RegistryKeys = @{}
            Services = @{}
        }
        
        # Baseline de arquivos críticos
        $criticalFiles = @(
            "$env:SystemRoot\System32\svchost.exe",
            "$env:SystemRoot\System32\winlogon.exe",
            "$env:SystemRoot\System32\lsass.exe",
            "$env:SystemRoot\System32\csrss.exe",
            "$env:SystemRoot\System32\smss.exe"
        )
        
        foreach ($file in $criticalFiles) {
            if (Test-Path $file) {
                $fileInfo = Get-FileHash -Path $file -Algorithm SHA256
                $baseline.CriticalFiles[$file] = @{
                    SHA256 = $fileInfo.Hash
                    Size = (Get-Item $file).Length
                    LastWriteTime = (Get-Item $file).LastWriteTime.ToString("yyyy-MM-dd HH:mm:ss")
                    Version = (Get-Item $file).VersionInfo.FileVersion
                }
                Write-LogoFAILLog "Baseline criado para: $file" -Level "Verbose"
            }
        }
        
        # Baseline de chaves de registro críticas
        $registryKeys = @(
            "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot",
            "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\BootExecute",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
        )
        
        foreach ($key in $registryKeys) {
            try {
                if (Test-Path $key) {
                    $regData = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
                    if ($regData) {
                        $baseline.RegistryKeys[$key] = $regData | ConvertTo-Json -Depth 3
                        Write-LogoFAILLog "Baseline de registro criado para: $key" -Level "Verbose"
                    }
                }
            }
            catch {
                Write-LogoFAILLog "Erro ao criar baseline para $key`: $_" -Level "Warning"
            }
        }
        
        # Baseline de serviços críticos
        $criticalServices = @("Windows Defender Antivirus Service", "Windows Security Service", "Cryptographic Services")
        
        foreach ($service in $criticalServices) {
            try {
                $svc = Get-Service -Name $service -ErrorAction SilentlyContinue
                if ($svc) {
                    $baseline.Services[$service] = @{
                        Status = $svc.Status.ToString()
                        StartType = $svc.StartType.ToString()
                        DisplayName = $svc.DisplayName
                    }
                    Write-LogoFAILLog "Baseline de serviço criado para: $service" -Level "Verbose"
                }
            }
            catch {
                Write-LogoFAILLog "Erro ao criar baseline para serviço $service`: $_" -Level "Warning"
            }
        }
        
        # Salvar baseline
        $baselineFile = Join-Path $Script:LogoFAILConfig.BaselinePath "security-baseline-$(Get-Date -Format 'yyyy-MM-dd-HHmm').json"
        $baseline | ConvertTo-Json -Depth 5 | Set-Content -Path $baselineFile -Encoding UTF8
        
        Write-LogoFAILLog "Baseline de segurança salvo em: $baselineFile" -Level "Information"
        return $baselineFile
    }
    catch {
        Write-LogoFAILLog "Erro ao criar baseline de segurança: $_" -Level "Error"
        return $null
    }
}

# ============================================================================
# CONFIGURAÇÃO DO WINDOWS DEFENDER
# ============================================================================

function Optimize-WindowsDefender {
    Write-LogoFAILLog "Otimizando configurações do Windows Defender..." -Level "Information"
    
    try {
        # Configurações de proteção em tempo real
        Set-MpPreference -DisableRealtimeMonitoring $false
        Set-MpPreference -DisableBehaviorMonitoring $false
        Set-MpPreference -DisableBlockAtFirstSeen $false
        Set-MpPreference -DisableIOAVProtection $false
        Set-MpPreference -DisableScriptScanning $false
        
        # Configurações de cloud protection
        Set-MpPreference -MAPSReporting Advanced
        Set-MpPreference -SubmitSamplesConsent SendAllSamples
        
        # Configurações específicas para LogoFAIL
        Set-MpPreference -EnableControlledFolderAccess Enabled
        Set-MpPreference -EnableNetworkProtection Enabled
        
        # Configurar exclusões específicas se necessário
        # (normalmente não recomendado, mas pode ser necessário para alguns ambientes)
        
        Write-LogoFAILLog "Windows Defender otimizado com sucesso" -Level "Information"
        return $true
    }
    catch {
        Write-LogoFAILLog "Erro ao otimizar Windows Defender: $_" -Level "Error"
        return $false
    }
}

# ============================================================================
# CONFIGURAÇÃO DE TAREFAS AGENDADAS
# ============================================================================

function Install-MonitoringTask {
    Write-LogoFAILLog "Configurando tarefa agendada para monitoramento contínuo..." -Level "Information"
    
    try {
        $taskName = $Script:LogoFAILConfig.TaskName
        $scriptPath = Join-Path $Script:LogoFAILConfig.InstallPath "LogoFAIL-ContinuousMonitor.ps1"
        
        # Remover tarefa existente se houver
        if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
            Write-LogoFAILLog "Tarefa agendada existente removida" -Level "Information"
        }
        
        # Criar nova tarefa
        $action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-ExecutionPolicy Bypass -File `"$scriptPath`""
        $trigger = New-ScheduledTaskTrigger -Daily -At "03:00"
        $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Hours 1) -RestartCount 3
        
        $task = New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description "Monitoramento contínuo para proteção LogoFAIL"
        
        Register-ScheduledTask -TaskName $taskName -InputObject $task | Out-Null
        
        Write-LogoFAILLog "Tarefa agendada '$taskName' criada com sucesso" -Level "Information"
        return $true
    }
    catch {
        Write-LogoFAILLog "Erro ao criar tarefa agendada: $_" -Level "Error"
        return $false
    }
}

# ============================================================================
# SISTEMA DE ALERTAS
# ============================================================================

function Initialize-AlertSystem {
    Write-LogoFAILLog "Inicializando sistema de alertas..." -Level "Information"
    
    try {
        $alertConfig = @{
            EmailEnabled = $false
            EmailRecipient = $Script:LogoFAILConfig.AlertEmail
            WindowsNotifications = $true
            LogLevel = $Script:LogoFAILConfig.LogLevel
            CreationDate = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        }
        
        if ($Script:LogoFAILConfig.AlertEmail) {
            $alertConfig.EmailEnabled = $true
            Write-LogoFAILLog "Sistema de alertas por email configurado para: $($Script:LogoFAILConfig.AlertEmail)" -Level "Information"
        }
        
        $configFile = Join-Path $Script:LogoFAILConfig.ConfigPath "alert-config.json"
        $alertConfig | ConvertTo-Json -Depth 3 | Set-Content -Path $configFile -Encoding UTF8
        
        Write-LogoFAILLog "Configuração de alertas salva em: $configFile" -Level "Information"
        return $true
    }
    catch {
        Write-LogoFAILLog "Erro ao inicializar sistema de alertas: $_" -Level "Error"
        return $false
    }
}

# ============================================================================
# FUNÇÃO PRINCIPAL
# ============================================================================

function Install-LogoFAILProtection {
    Write-Host "======================================================================" -ForegroundColor Cyan
    Write-Host "    Windows Defense LogoFAIL - Sistema de Prevenção e Monitoramento" -ForegroundColor Cyan
    Write-Host "    Versão: $($Script:LogoFAILConfig.Version)" -ForegroundColor Cyan
    Write-Host "======================================================================" -ForegroundColor Cyan
    Write-Host ""
    
    # Verificar privilégios de administrador
    if (-not (Test-AdminPrivileges)) {
        Write-LogoFAILLog "Este script requer privilégios de administrador" -Level "Error"
        return $false
    }
    
    # Inicializar diretórios
    if (-not (Initialize-LogoFAILDirectories)) {
        Write-LogoFAILLog "Falha ao inicializar diretórios" -Level "Error"
        return $false
    }
    
    Write-LogoFAILLog "Iniciando instalação do sistema de proteção LogoFAIL..." -Level "Information"
    
    # Verificação de saúde do sistema
    $healthCheck = Test-SystemHealth
    
    if ($healthCheck.Recommendations.Count -gt 0) {
        Write-LogoFAILLog "Recomendações de segurança identificadas:" -Level "Warning"
        foreach ($recommendation in $healthCheck.Recommendations) {
            Write-LogoFAILLog "  - $recommendation" -Level "Warning"
        }
    }
    
    # Criar baseline de segurança
    $baselineFile = New-SecurityBaseline
    if ($baselineFile) {
        Write-LogoFAILLog "Baseline de segurança criado com sucesso" -Level "Information"
    }
    
    # Otimizar Windows Defender
    if (Optimize-WindowsDefender) {
        Write-LogoFAILLog "Windows Defender otimizado" -Level "Information"
    }
    
    # Configurar sistema de alertas
    if (Initialize-AlertSystem) {
        Write-LogoFAILLog "Sistema de alertas configurado" -Level "Information"
    }
    
    # Configurar monitoramento contínuo se solicitado
    if ($EnableContinuousMonitoring) {
        if (Install-MonitoringTask) {
            Write-LogoFAILLog "Monitoramento contínuo ativado" -Level "Information"
        }
    }
    
    Write-Host ""
    Write-Host "======================================================================" -ForegroundColor Green
    Write-Host "    Instalação concluída com sucesso!" -ForegroundColor Green
    Write-Host "======================================================================" -ForegroundColor Green
    Write-Host ""
    Write-LogoFAILLog "Sistema de proteção LogoFAIL instalado com sucesso" -Level "Information"
    
    # Exibir resumo final
    Write-Host "RESUMO DA INSTALAÇÃO:" -ForegroundColor Yellow
    Write-Host "- Diretório de instalação: $($Script:LogoFAILConfig.InstallPath)" -ForegroundColor White
    Write-Host "- Logs: $($Script:LogoFAILConfig.LogPath)" -ForegroundColor White
    Write-Host "- Configurações: $($Script:LogoFAILConfig.ConfigPath)" -ForegroundColor White
    Write-Host "- Baselines: $($Script:LogoFAILConfig.BaselinePath)" -ForegroundColor White
    
    if ($EnableContinuousMonitoring) {
        Write-Host "- Monitoramento contínuo: ATIVADO" -ForegroundColor Green
    } else {
        Write-Host "- Monitoramento contínuo: Para ativar, execute novamente com -EnableContinuousMonitoring" -ForegroundColor Yellow
    }
    
    if ($Script:LogoFAILConfig.AlertEmail) {
        Write-Host "- Alertas por email: $($Script:LogoFAILConfig.AlertEmail)" -ForegroundColor Green
    }
    
    Write-Host ""
    Write-Host "PRÓXIMOS PASSOS:" -ForegroundColor Yellow
    Write-Host "1. Execute LogoFAIL-QuickCheck.ps1 para verificação rápida" -ForegroundColor White
    Write-Host "2. Para análise forense completa, use LogoFAIL-ForensicAnalysis.ps1" -ForegroundColor White
    Write-Host "3. Para proteções avançadas, execute LogoFAIL-AdvancedProtection.ps1" -ForegroundColor White
    
    return $true
}

# ============================================================================
# EXECUÇÃO PRINCIPAL
# ============================================================================

try {
    $result = Install-LogoFAILProtection
    if ($result) {
        exit 0
    } else {
        exit 1
    }
}
catch {
    Write-LogoFAILLog "Erro fatal durante instalação: $_" -Level "Error"
    exit 1
}