#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    LogoFAIL Alert System - Sistema de Alertas e Notificações
    
.DESCRIPTION
    Sistema centralizado de alertas para detectar e notificar sobre atividades
    suspeitas relacionadas à vulnerabilidade LogoFAIL. Suporta múltiplos canais
    de notificação incluindo email, Windows notifications e logs estruturados.
    
.PARAMETER ConfigureEmail
    Configura sistema de alertas por email
    
.PARAMETER TestAlerts
    Executa teste de todos os sistemas de alerta
    
.PARAMETER MonitorMode
    Ativa modo de monitoramento contínuo
    
.PARAMETER EmailServer
    Servidor SMTP para envio de emails
    
.PARAMETER EmailFrom
    Endereço de email remetente
    
.PARAMETER EmailTo
    Endereço de email destinatário
    
.EXAMPLE
    .\LogoFAIL-AlertSystem.ps1 -ConfigureEmail -EmailServer "smtp.gmail.com" -EmailFrom "admin@empresa.com" -EmailTo "security@empresa.com"
    
.NOTES
    Author: Matheus-TestUser1
    Version: 1.0.0
    Requires: Windows 10/11, PowerShell 5.1+, Administrator privileges
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [switch]$ConfigureEmail,
    
    [Parameter(Mandatory = $false)]
    [switch]$TestAlerts,
    
    [Parameter(Mandatory = $false)]
    [switch]$MonitorMode,
    
    [Parameter(Mandatory = $false)]
    [string]$EmailServer,
    
    [Parameter(Mandatory = $false)]
    [string]$EmailFrom,
    
    [Parameter(Mandatory = $false)]
    [string]$EmailTo
)

# ============================================================================
# CONFIGURAÇÕES GLOBAIS
# ============================================================================

$Script:AlertConfig = @{
    Version = "1.0.0"
    BasePath = "$env:ProgramData\WindowsDefenseLogoFAIL"
    ConfigPath = "$env:ProgramData\WindowsDefenseLogoFAIL\Config"
    LogPath = "$env:ProgramData\WindowsDefenseLogoFAIL\Logs"
    AlertsPath = "$env:ProgramData\WindowsDefenseLogoFAIL\Alerts"
    TemplatesPath = "$env:ProgramData\WindowsDefenseLogoFAIL\Templates"
    CurrentSession = (Get-Date -Format "yyyyMMdd-HHmmss")
    SupportedChannels = @("Email", "WindowsNotification", "EventLog", "FileLog")
}

# Templates de alerta
$Script:AlertTemplates = @{
    Email = @{
        CriticalAlert = @{
            Subject = "CRÍTICO: LogoFAIL Security Alert - {ComputerName}"
            Body = @"
ALERTA DE SEGURANÇA CRÍTICO - LogoFAIL

Computador: {ComputerName}
Data/Hora: {Timestamp}
Tipo: {AlertType}
Severidade: {Severity}

DESCRIÇÃO:
{Description}

DETALHES:
{Details}

AÇÃO REQUERIDA:
Este é um alerta crítico que requer ação imediata. Verifique o sistema imediatamente.

RECOMENDAÇÕES:
- Desconecte da rede se necessário
- Execute análise forense completa
- Verifique logs de sistema
- Contate a equipe de segurança

Este alerta foi gerado automaticamente pelo Windows Defense LogoFAIL v{Version}
"@
        }
        HighAlert = @{
            Subject = "ALTO: LogoFAIL Security Alert - {ComputerName}"
            Body = @"
ALERTA DE SEGURANÇA ALTO - LogoFAIL

Computador: {ComputerName}
Data/Hora: {Timestamp}
Tipo: {AlertType}
Severidade: {Severity}

DESCRIÇÃO:
{Description}

DETALHES:
{Details}

AÇÃO RECOMENDADA:
Verifique o sistema e tome as medidas adequadas.

Este alerta foi gerado automaticamente pelo Windows Defense LogoFAIL v{Version}
"@
        }
        MediumAlert = @{
            Subject = "MÉDIO: LogoFAIL Security Alert - {ComputerName}"
            Body = @"
ALERTA DE SEGURANÇA MÉDIO - LogoFAIL

Computador: {ComputerName}
Data/Hora: {Timestamp}
Tipo: {AlertType}
Severidade: {Severity}

DESCRIÇÃO:
{Description}

DETALHES:
{Details}

Este alerta foi gerado automaticamente pelo Windows Defense LogoFAIL v{Version}
"@
        }
    }
    
    WindowsNotification = @{
        CriticalAlert = @{
            Title = "LogoFAIL: Alerta Crítico"
            Text = "{AlertType}: {Description}"
        }
        HighAlert = @{
            Title = "LogoFAIL: Alerta Alto"
            Text = "{AlertType}: {Description}"
        }
        MediumAlert = @{
            Title = "LogoFAIL: Alerta Médio"
            Text = "{AlertType}: {Description}"
        }
    }
}

# ============================================================================
# FUNÇÕES DE LOGGING
# ============================================================================

function Write-AlertLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("Info", "Warning", "Error", "Success", "Debug")]
        [string]$Level = "Info",
        
        [Parameter(Mandatory = $false)]
        [string]$Component = "AlertSystem"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = @{
        Timestamp = $timestamp
        Level = $Level
        Component = $Component
        Message = $Message
        ComputerName = $env:COMPUTERNAME
        SessionId = $Script:AlertConfig.CurrentSession
    }
    
    # Console output
    $color = switch ($Level) {
        "Info" { "Cyan" }
        "Warning" { "Yellow" }
        "Error" { "Red" }
        "Success" { "Green" }
        "Debug" { "Gray" }
    }
    
    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $color
    
    # Log para arquivo
    try {
        if (-not (Test-Path $Script:AlertConfig.LogPath)) {
            New-Item -Path $Script:AlertConfig.LogPath -ItemType Directory -Force | Out-Null
        }
        
        $logFile = Join-Path $Script:AlertConfig.LogPath "alert-system-$(Get-Date -Format 'yyyy-MM-dd').json"
        $logEntry | ConvertTo-Json -Compress | Add-Content -Path $logFile -Encoding UTF8
    }
    catch {
        Write-Warning "Falha ao escrever log: $_"
    }
}

# ============================================================================
# CONFIGURAÇÃO DO SISTEMA DE ALERTAS
# ============================================================================

function Initialize-AlertSystem {
    Write-AlertLog "Inicializando sistema de alertas..." -Level "Info"
    
    try {
        # Criar diretórios necessários
        $directories = @(
            $Script:AlertConfig.ConfigPath,
            $Script:AlertConfig.LogPath,
            $Script:AlertConfig.AlertsPath,
            $Script:AlertConfig.TemplatesPath
        )
        
        foreach ($dir in $directories) {
            if (-not (Test-Path $dir)) {
                New-Item -Path $dir -ItemType Directory -Force | Out-Null
                Write-AlertLog "Diretório criado: $dir" -Level "Debug"
            }
        }
        
        # Criar arquivo de configuração padrão se não existir
        $configFile = Join-Path $Script:AlertConfig.ConfigPath "alert-system-config.json"
        
        if (-not (Test-Path $configFile)) {
            $defaultConfig = @{
                Version = $Script:AlertConfig.Version
                CreatedAt = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                Channels = @{
                    Email = @{
                        Enabled = $false
                        Server = ""
                        Port = 587
                        UseSSL = $true
                        Username = ""
                        Password = ""
                        From = ""
                        To = @()
                        TestMode = $false
                    }
                    WindowsNotification = @{
                        Enabled = $true
                        ShowForAllSeverities = $false
                        MinimumSeverity = "High"
                    }
                    EventLog = @{
                        Enabled = $true
                        LogName = "Application"
                        SourceName = "LogoFAILDefense"
                    }
                    FileLog = @{
                        Enabled = $true
                        LogPath = $Script:AlertConfig.AlertsPath
                        MaxFileSize = "10MB"
                        MaxFiles = 30
                    }
                }
                AlertRules = @{
                    CriticalFileChanges = @{
                        Enabled = $true
                        Severity = "Critical"
                        Channels = @("Email", "WindowsNotification", "EventLog", "FileLog")
                    }
                    SuspiciousProcesses = @{
                        Enabled = $true
                        Severity = "High"
                        Channels = @("Email", "WindowsNotification", "EventLog", "FileLog")
                    }
                    RegistryChanges = @{
                        Enabled = $true
                        Severity = "Medium"
                        Channels = @("WindowsNotification", "EventLog", "FileLog")
                    }
                    NetworkAnomalies = @{
                        Enabled = $true
                        Severity = "Medium"
                        Channels = @("EventLog", "FileLog")
                    }
                    SystemIntegrityIssues = @{
                        Enabled = $true
                        Severity = "High"
                        Channels = @("Email", "WindowsNotification", "EventLog", "FileLog")
                    }
                }
            }
            
            $defaultConfig | ConvertTo-Json -Depth 4 | Set-Content -Path $configFile -Encoding UTF8
            Write-AlertLog "Configuração padrão criada: $configFile" -Level "Success"
        }
        
        # Registrar fonte de eventos no Event Log
        try {
            $eventSource = "LogoFAILDefense"
            if (-not [System.Diagnostics.EventLog]::SourceExists($eventSource)) {
                [System.Diagnostics.EventLog]::CreateEventSource($eventSource, "Application")
                Write-AlertLog "Fonte de eventos registrada: $eventSource" -Level "Success"
            }
        }
        catch {
            Write-AlertLog "Erro ao registrar fonte de eventos: $_" -Level "Warning"
        }
        
        Write-AlertLog "Sistema de alertas inicializado com sucesso" -Level "Success"
        return $true
    }
    catch {
        Write-AlertLog "Erro ao inicializar sistema de alertas: $_" -Level "Error"
        return $false
    }
}

function Set-EmailConfiguration {
    if (-not $ConfigureEmail) {
        return $true
    }
    
    Write-AlertLog "Configurando sistema de alertas por email..." -Level "Info"
    
    try {
        $configFile = Join-Path $Script:AlertConfig.ConfigPath "alert-system-config.json"
        
        if (-not (Test-Path $configFile)) {
            Write-AlertLog "Arquivo de configuração não encontrado. Execute Initialize-AlertSystem primeiro." -Level "Error"
            return $false
        }
        
        $config = Get-Content $configFile | ConvertFrom-Json
        
        # Solicitar informações se não fornecidas
        if (-not $EmailServer) {
            $EmailServer = Read-Host "Digite o servidor SMTP (ex: smtp.gmail.com)"
        }
        
        if (-not $EmailFrom) {
            $EmailFrom = Read-Host "Digite o email remetente"
        }
        
        if (-not $EmailTo) {
            $EmailTo = Read-Host "Digite o email destinatário"
        }
        
        # Solicitar credenciais
        $credentials = Get-Credential -Message "Digite as credenciais para o servidor SMTP"
        
        if (-not $credentials) {
            Write-AlertLog "Credenciais não fornecidas. Configuração cancelada." -Level "Warning"
            return $false
        }
        
        # Atualizar configuração
        $config.Channels.Email.Enabled = $true
        $config.Channels.Email.Server = $EmailServer
        $config.Channels.Email.Username = $credentials.UserName
        $config.Channels.Email.From = $EmailFrom
        $config.Channels.Email.To = @($EmailTo)
        
        # Salvar senha de forma segura (para demonstração - em produção usar métodos mais seguros)
        $config.Channels.Email.Password = $credentials.Password | ConvertFrom-SecureString
        
        # Salvar configuração
        $config | ConvertTo-Json -Depth 4 | Set-Content -Path $configFile -Encoding UTF8
        
        Write-AlertLog "Configuração de email salva com sucesso" -Level "Success"
        Write-AlertLog "AVISO: A senha foi salva de forma básica. Para produção, use Azure Key Vault ou similar." -Level "Warning"
        
        return $true
    }
    catch {
        Write-AlertLog "Erro ao configurar email: $_" -Level "Error"
        return $false
    }
}

# ============================================================================
# FUNÇÕES DE ENVIO DE ALERTAS
# ============================================================================

function Send-SecurityAlert {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$AlertType,
        
        [Parameter(Mandatory = $true)]
        [string]$Description,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet("Low", "Medium", "High", "Critical")]
        [string]$Severity,
        
        [Parameter(Mandatory = $false)]
        [hashtable]$Details = @{},
        
        [Parameter(Mandatory = $false)]
        [string[]]$ForcedChannels = @()
    )
    
    try {
        # Carregar configuração
        $configFile = Join-Path $Script:AlertConfig.ConfigPath "alert-system-config.json"
        
        if (-not (Test-Path $configFile)) {
            Write-AlertLog "Configuração não encontrada. Execute Initialize-AlertSystem primeiro." -Level "Error"
            return $false
        }
        
        $config = Get-Content $configFile | ConvertFrom-Json
        
        # Criar objeto de alerta
        $alert = @{
            Id = [guid]::NewGuid().ToString()
            Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            AlertType = $AlertType
            Description = $Description
            Severity = $Severity
            Details = $Details
            ComputerName = $env:COMPUTERNAME
            Username = $env:USERNAME
            Version = $Script:AlertConfig.Version
        }
        
        # Determinar canais a usar
        $channelsToUse = if ($ForcedChannels.Count -gt 0) {
            $ForcedChannels
        } else {
            $config.AlertRules.$AlertType.Channels
        }
        
        if (-not $channelsToUse) {
            $channelsToUse = @("FileLog")  # Fallback
        }
        
        $alertSent = $false
        
        # Enviar para cada canal
        foreach ($channel in $channelsToUse) {
            try {
                switch ($channel) {
                    "Email" {
                        if ($config.Channels.Email.Enabled) {
                            $result = Send-EmailAlert -Alert $alert -Config $config.Channels.Email
                            if ($result) { $alertSent = $true }
                        }
                    }
                    "WindowsNotification" {
                        if ($config.Channels.WindowsNotification.Enabled) {
                            $result = Send-WindowsNotification -Alert $alert -Config $config.Channels.WindowsNotification
                            if ($result) { $alertSent = $true }
                        }
                    }
                    "EventLog" {
                        if ($config.Channels.EventLog.Enabled) {
                            $result = Send-EventLogAlert -Alert $alert -Config $config.Channels.EventLog
                            if ($result) { $alertSent = $true }
                        }
                    }
                    "FileLog" {
                        if ($config.Channels.FileLog.Enabled) {
                            $result = Send-FileLogAlert -Alert $alert -Config $config.Channels.FileLog
                            if ($result) { $alertSent = $true }
                        }
                    }
                }
            }
            catch {
                Write-AlertLog "Erro ao enviar alerta via $channel`: $_" -Level "Error"
            }
        }
        
        Write-AlertLog "Alerta $Severity gerado: $AlertType - $Description" -Level $(if ($Severity -eq "Critical") { "Error" } else { "Warning" })
        
        return $alertSent
    }
    catch {
        Write-AlertLog "Erro ao processar alerta: $_" -Level "Error"
        return $false
    }
}

function Send-EmailAlert {
    param([hashtable]$Alert, [object]$Config)
    
    try {
        if (-not $Config.Enabled -or -not $Config.To -or $Config.To.Count -eq 0) {
            return $false
        }
        
        # Selecionar template baseado na severidade
        $templateKey = "$($Alert.Severity)Alert"
        if (-not $Script:AlertTemplates.Email.ContainsKey($templateKey)) {
            $templateKey = "MediumAlert"
        }
        
        $template = $Script:AlertTemplates.Email[$templateKey]
        
        # Substituir placeholders
        $subject = $template.Subject
        $body = $template.Body
        
        $replacements = @{
            "{ComputerName}" = $Alert.ComputerName
            "{Timestamp}" = $Alert.Timestamp
            "{AlertType}" = $Alert.AlertType
            "{Severity}" = $Alert.Severity
            "{Description}" = $Alert.Description
            "{Details}" = ($Alert.Details | ConvertTo-Json -Depth 3)
            "{Version}" = $Alert.Version
        }
        
        foreach ($replacement in $replacements.GetEnumerator()) {
            $subject = $subject -replace [regex]::Escape($replacement.Key), $replacement.Value
            $body = $body -replace [regex]::Escape($replacement.Key), $replacement.Value
        }
        
        # Configurar credenciais
        $securePassword = $Config.Password | ConvertTo-SecureString
        $credentials = New-Object System.Management.Automation.PSCredential($Config.Username, $securePassword)
        
        # Enviar email
        $emailParams = @{
            SmtpServer = $Config.Server
            Port = $Config.Port
            UseSsl = $Config.UseSSL
            Credential = $credentials
            From = $Config.From
            To = $Config.To
            Subject = $subject
            Body = $body
            BodyAsHtml = $false
        }
        
        if ($Config.TestMode) {
            Write-AlertLog "MODO TESTE - Email seria enviado para: $($Config.To -join ', ')" -Level "Info"
            Write-AlertLog "Assunto: $subject" -Level "Debug"
            return $true
        } else {
            Send-MailMessage @emailParams
            Write-AlertLog "Email enviado com sucesso para: $($Config.To -join ', ')" -Level "Success"
            return $true
        }
    }
    catch {
        Write-AlertLog "Erro ao enviar email: $_" -Level "Error"
        return $false
    }
}

function Send-WindowsNotification {
    param([hashtable]$Alert, [object]$Config)
    
    try {
        if (-not $Config.Enabled) {
            return $false
        }
        
        # Verificar se deve mostrar baseado na severidade
        $severityOrder = @("Low", "Medium", "High", "Critical")
        $alertSeverityIndex = $severityOrder.IndexOf($Alert.Severity)
        $minSeverityIndex = $severityOrder.IndexOf($Config.MinimumSeverity)
        
        if ($alertSeverityIndex -lt $minSeverityIndex -and -not $Config.ShowForAllSeverities) {
            return $false
        }
        
        # Selecionar template
        $templateKey = "$($Alert.Severity)Alert"
        if (-not $Script:AlertTemplates.WindowsNotification.ContainsKey($templateKey)) {
            $templateKey = "MediumAlert"
        }
        
        $template = $Script:AlertTemplates.WindowsNotification[$templateKey]
        
        # Substituir placeholders
        $title = $template.Title -replace "{AlertType}", $Alert.AlertType
        $text = $template.Text -replace "{AlertType}", $Alert.AlertType -replace "{Description}", $Alert.Description
        
        # Tentar usar BurntToast se disponível
        if (Get-Module -ListAvailable -Name BurntToast) {
            Import-Module BurntToast -ErrorAction SilentlyContinue
            if (Get-Command New-BurntToastNotification -ErrorAction SilentlyContinue) {
                New-BurntToastNotification -Text $title, $text -AppLogo "$env:SystemRoot\System32\shield.ico"
                Write-AlertLog "Notificação Windows enviada via BurntToast" -Level "Success"
                return $true
            }
        }
        
        # Fallback para msg.exe
        try {
            $message = "$title`n$text"
            & msg.exe * $message 2>$null
            Write-AlertLog "Notificação Windows enviada via msg.exe" -Level "Success"
            return $true
        }
        catch {
            Write-AlertLog "Erro ao enviar notificação Windows: $_" -Level "Warning"
            return $false
        }
    }
    catch {
        Write-AlertLog "Erro ao processar notificação Windows: $_" -Level "Error"
        return $false
    }
}

function Send-EventLogAlert {
    param([hashtable]$Alert, [object]$Config)
    
    try {
        if (-not $Config.Enabled) {
            return $false
        }
        
        # Mapear severidade para EventLogEntryType
        $eventType = switch ($Alert.Severity) {
            "Critical" { "Error" }
            "High" { "Error" }
            "Medium" { "Warning" }
            "Low" { "Information" }
            default { "Warning" }
        }
        
        # Mapear severidade para Event ID
        $eventId = switch ($Alert.Severity) {
            "Critical" { 1001 }
            "High" { 1002 }
            "Medium" { 1003 }
            "Low" { 1004 }
            default { 1000 }
        }
        
        $message = @"
LogoFAIL Security Alert

Alert Type: $($Alert.AlertType)
Severity: $($Alert.Severity)
Description: $($Alert.Description)
Computer: $($Alert.ComputerName)
Timestamp: $($Alert.Timestamp)

Details:
$($Alert.Details | ConvertTo-Json -Depth 3)
"@
        
        Write-EventLog -LogName $Config.LogName -Source $Config.SourceName -EventId $eventId -EntryType $eventType -Message $message
        
        Write-AlertLog "Alerta registrado no Event Log (ID: $eventId)" -Level "Success"
        return $true
    }
    catch {
        Write-AlertLog "Erro ao registrar no Event Log: $_" -Level "Error"
        return $false
    }
}

function Send-FileLogAlert {
    param([hashtable]$Alert, [object]$Config)
    
    try {
        if (-not $Config.Enabled) {
            return $false
        }
        
        $alertFile = Join-Path $Config.LogPath "security-alerts-$(Get-Date -Format 'yyyy-MM-dd').json"
        
        # Criar diretório se não existir
        if (-not (Test-Path $Config.LogPath)) {
            New-Item -Path $Config.LogPath -ItemType Directory -Force | Out-Null
        }
        
        # Adicionar alerta ao arquivo
        $Alert | ConvertTo-Json -Compress | Add-Content -Path $alertFile -Encoding UTF8
        
        Write-AlertLog "Alerta salvo em: $alertFile" -Level "Success"
        return $true
    }
    catch {
        Write-AlertLog "Erro ao salvar alerta em arquivo: $_" -Level "Error"
        return $false
    }
}

# ============================================================================
# TESTES DO SISTEMA DE ALERTAS
# ============================================================================

function Test-AlertSystem {
    if (-not $TestAlerts) {
        return $true
    }
    
    Write-AlertLog "Executando testes do sistema de alertas..." -Level "Info"
    
    try {
        # Teste de alertas em diferentes severidades
        $testAlerts = @(
            @{
                AlertType = "TestCritical"
                Description = "Este é um teste de alerta crítico"
                Severity = "Critical"
                Details = @{ TestMode = $true; TestTime = (Get-Date).ToString() }
            },
            @{
                AlertType = "TestHigh" 
                Description = "Este é um teste de alerta alto"
                Severity = "High"
                Details = @{ TestMode = $true; TestTime = (Get-Date).ToString() }
            },
            @{
                AlertType = "TestMedium"
                Description = "Este é um teste de alerta médio"
                Severity = "Medium"
                Details = @{ TestMode = $true; TestTime = (Get-Date).ToString() }
            },
            @{
                AlertType = "TestLow"
                Description = "Este é um teste de alerta baixo"
                Severity = "Low"
                Details = @{ TestMode = $true; TestTime = (Get-Date).ToString() }
            }
        )
        
        $successCount = 0
        $totalCount = $testAlerts.Count
        
        foreach ($testAlert in $testAlerts) {
            Write-AlertLog "Testando alerta $($testAlert.Severity)..." -Level "Info"
            
            $result = Send-SecurityAlert -AlertType $testAlert.AlertType -Description $testAlert.Description -Severity $testAlert.Severity -Details $testAlert.Details
            
            if ($result) {
                $successCount++
                Write-AlertLog "Teste $($testAlert.Severity) executado com sucesso" -Level "Success"
            } else {
                Write-AlertLog "Teste $($testAlert.Severity) falhou" -Level "Error"
            }
            
            Start-Sleep -Seconds 2  # Pausa entre testes
        }
        
        Write-AlertLog "Testes concluídos: $successCount de $totalCount testes bem-sucedidos" -Level "Info"
        
        return $successCount -eq $totalCount
    }
    catch {
        Write-AlertLog "Erro durante testes: $_" -Level "Error"
        return $false
    }
}

# ============================================================================
# MODO MONITOR CONTÍNUO
# ============================================================================

function Start-AlertMonitor {
    if (-not $MonitorMode) {
        return $true
    }
    
    Write-AlertLog "Iniciando modo de monitoramento contínuo..." -Level "Info"
    
    try {
        $monitoringInterval = 300  # 5 minutos
        $maxRunTime = 3600        # 1 hora
        $startTime = Get-Date
        
        do {
            Write-AlertLog "Executando verificação de monitoramento..." -Level "Debug"
            
            # Verificar diretório de alertas para novos alertas
            $alertsPath = $Script:AlertConfig.AlertsPath
            $recentAlerts = Get-ChildItem -Path $alertsPath -Filter "alert-*.json" -ErrorAction SilentlyContinue | 
                Where-Object { $_.LastWriteTime -gt (Get-Date).AddMinutes(-10) }
            
            if ($recentAlerts) {
                Write-AlertLog "Encontrados $($recentAlerts.Count) alertas recentes" -Level "Info"
                
                foreach ($alertFile in $recentAlerts) {
                    try {
                        $alertData = Get-Content $alertFile.FullName | ConvertFrom-Json
                        
                        # Processar alerta se ainda não foi processado
                        if (-not $alertData.Processed) {
                            Write-AlertLog "Processando alerta: $($alertData.Title)" -Level "Info"
                            
                            # Marcar como processado
                            $alertData.Processed = $true
                            $alertData.ProcessedAt = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                            $alertData | ConvertTo-Json -Depth 4 | Set-Content -Path $alertFile.FullName -Encoding UTF8
                        }
                    }
                    catch {
                        Write-AlertLog "Erro ao processar alerta $($alertFile.Name): $_" -Level "Error"
                    }
                }
            }
            
            # Verificar integridade do sistema de alertas
            $configFile = Join-Path $Script:AlertConfig.ConfigPath "alert-system-config.json"
            if (-not (Test-Path $configFile)) {
                Send-SecurityAlert -AlertType "SystemIntegrityIssues" -Description "Configuração do sistema de alertas não encontrada" -Severity "High"
            }
            
            # Pausa antes da próxima verificação
            Start-Sleep -Seconds $monitoringInterval
            
        } while (((Get-Date) - $startTime).TotalSeconds -lt $maxRunTime)
        
        Write-AlertLog "Monitoramento contínuo finalizado" -Level "Info"
        return $true
    }
    catch {
        Write-AlertLog "Erro durante monitoramento: $_" -Level "Error"
        return $false
    }
}

# ============================================================================
# FUNÇÃO PRINCIPAL
# ============================================================================

function Start-LogoFAILAlertSystem {
    Write-Host "======================================================================" -ForegroundColor Cyan
    Write-Host "    LogoFAIL Alert System - Sistema de Alertas e Notificações" -ForegroundColor Cyan
    Write-Host "    Versão: $($Script:AlertConfig.Version)" -ForegroundColor Cyan
    Write-Host "======================================================================" -ForegroundColor Cyan
    Write-Host ""
    
    # Verificar privilégios de administrador
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-AlertLog "Este script requer privilégios de administrador" -Level "Error"
        return $false
    }
    
    # Inicializar sistema
    if (-not (Initialize-AlertSystem)) {
        Write-AlertLog "Falha ao inicializar sistema de alertas" -Level "Error"
        return $false
    }
    
    # Configurar email se solicitado
    if ($ConfigureEmail) {
        if (-not (Set-EmailConfiguration)) {
            Write-AlertLog "Falha ao configurar email" -Level "Error"
            return $false
        }
    }
    
    # Executar testes se solicitado
    if ($TestAlerts) {
        if (-not (Test-AlertSystem)) {
            Write-AlertLog "Alguns testes falharam" -Level "Warning"
        }
    }
    
    # Iniciar modo monitor se solicitado
    if ($MonitorMode) {
        if (-not (Start-AlertMonitor)) {
            Write-AlertLog "Falha no modo monitor" -Level "Error"
            return $false
        }
    }
    
    Write-Host ""
    Write-Host "======================================================================" -ForegroundColor Green
    Write-Host "    Sistema de Alertas Configurado com Sucesso!" -ForegroundColor Green
    Write-Host "======================================================================" -ForegroundColor Green
    Write-Host ""
    
    # Exibir informações de configuração
    $configFile = Join-Path $Script:AlertConfig.ConfigPath "alert-system-config.json"
    if (Test-Path $configFile) {
        $config = Get-Content $configFile | ConvertFrom-Json
        
        Write-Host "CANAIS DE ALERTA CONFIGURADOS:" -ForegroundColor Yellow
        foreach ($channel in $config.Channels.PSObject.Properties) {
            $status = if ($channel.Value.Enabled) { "ATIVADO" } else { "DESATIVADO" }
            $color = if ($channel.Value.Enabled) { "Green" } else { "Red" }
            Write-Host "  - $($channel.Name): $status" -ForegroundColor $color
        }
        
        Write-Host ""
        Write-Host "REGRAS DE ALERTA:" -ForegroundColor Yellow
        foreach ($rule in $config.AlertRules.PSObject.Properties) {
            $status = if ($rule.Value.Enabled) { "ATIVADO" } else { "DESATIVADO" }
            $color = if ($rule.Value.Enabled) { "Green" } else { "Red" }
            Write-Host "  - $($rule.Name) ($($rule.Value.Severity)): $status" -ForegroundColor $color
        }
    }
    
    Write-Host ""
    Write-Host "COMANDOS ÚTEIS:" -ForegroundColor Yellow
    Write-Host "  - Configurar email: .\LogoFAIL-AlertSystem.ps1 -ConfigureEmail" -ForegroundColor White
    Write-Host "  - Testar alertas: .\LogoFAIL-AlertSystem.ps1 -TestAlerts" -ForegroundColor White
    Write-Host "  - Modo monitor: .\LogoFAIL-AlertSystem.ps1 -MonitorMode" -ForegroundColor White
    Write-Host "  - Arquivo de config: $configFile" -ForegroundColor Gray
    
    return $true
}

# ============================================================================
# EXECUÇÃO PRINCIPAL
# ============================================================================

try {
    $result = Start-LogoFAILAlertSystem
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