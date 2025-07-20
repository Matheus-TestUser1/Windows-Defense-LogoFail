#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    LogoFAIL Continuous Monitor - Monitoramento Contínuo de Segurança
    
.DESCRIPTION
    Script para monitoramento contínuo de segurança contra vulnerabilidades LogoFAIL.
    Executa verificações automáticas de integridade, detecta alterações suspeitas
    e gera alertas em tempo real. Projetado para execução via tarefa agendada.
    
.PARAMETER MonitoringMode
    Modo de monitoramento: Light, Standard, Intensive
    
.PARAMETER AlertThreshold
    Limite de alertas antes de enviar notificação: Low, Medium, High
    
.PARAMETER RunOnce
    Executa uma única verificação ao invés de monitoramento contínuo
    
.EXAMPLE
    .\LogoFAIL-ContinuousMonitor.ps1 -MonitoringMode Standard -AlertThreshold Medium
    
.NOTES
    Author: Matheus-TestUser1
    Version: 1.0.0
    Intended for: Scheduled Task execution
    Requires: Windows 10/11, PowerShell 5.1+, Administrator privileges
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateSet("Light", "Standard", "Intensive")]
    [string]$MonitoringMode = "Standard",
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("Low", "Medium", "High")]
    [string]$AlertThreshold = "Medium",
    
    [Parameter(Mandatory = $false)]
    [switch]$RunOnce
)

# ============================================================================
# CONFIGURAÇÕES GLOBAIS
# ============================================================================

$Script:MonitorConfig = @{
    Version = "1.0.0"
    StartTime = Get-Date
    BasePath = "$env:ProgramData\WindowsDefenseLogoFAIL"
    LogPath = "$env:ProgramData\WindowsDefenseLogoFAIL\Logs"
    BaselinePath = "$env:ProgramData\WindowsDefenseLogoFAIL\Baselines"
    ConfigPath = "$env:ProgramData\WindowsDefenseLogoFAIL\Config"
    AlertsPath = "$env:ProgramData\WindowsDefenseLogoFAIL\Alerts"
    MonitoringMode = $MonitoringMode
    AlertThreshold = $AlertThreshold
    RunOnce = $RunOnce
    CurrentSession = (Get-Date -Format "yyyyMMdd-HHmmss")
    AlertsGenerated = @()
    ChangesDetected = @()
}

# Configurações de monitoramento por modo
$Script:MonitoringSettings = @{
    Light = @{
        CheckInterval = 300  # 5 minutos
        MaxRunTime = 600     # 10 minutos
        CheckCriticalFiles = $true
        CheckProcesses = $false
        CheckRegistry = $true
        CheckNetwork = $false
        CheckEventLogs = $false
        DeepFileAnalysis = $false
    }
    Standard = @{
        CheckInterval = 180  # 3 minutos
        MaxRunTime = 1800    # 30 minutos
        CheckCriticalFiles = $true
        CheckProcesses = $true
        CheckRegistry = $true
        CheckNetwork = $true
        CheckEventLogs = $true
        DeepFileAnalysis = $false
    }
    Intensive = @{
        CheckInterval = 60   # 1 minuto
        MaxRunTime = 3600    # 60 minutos
        CheckCriticalFiles = $true
        CheckProcesses = $true
        CheckRegistry = $true
        CheckNetwork = $true
        CheckEventLogs = $true
        DeepFileAnalysis = $true
    }
}

# Limites de alerta
$Script:AlertLimits = @{
    Low = @{
        CriticalFileChanges = 1
        SuspiciousProcesses = 3
        RegistryChanges = 5
        NetworkAnomalies = 10
    }
    Medium = @{
        CriticalFileChanges = 0
        SuspiciousProcesses = 1
        RegistryChanges = 2
        NetworkAnomalies = 5
    }
    High = @{
        CriticalFileChanges = 0
        SuspiciousProcesses = 0
        RegistryChanges = 1
        NetworkAnomalies = 2
    }
}

# ============================================================================
# FUNÇÕES DE LOGGING E ALERTAS
# ============================================================================

function Write-MonitorLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("Info", "Warning", "Error", "Critical", "Success")]
        [string]$Level = "Info",
        
        [Parameter(Mandatory = $false)]
        [string]$Component = "Monitor"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = @{
        Timestamp = $timestamp
        Level = $Level
        Component = $Component
        Message = $Message
        ComputerName = $env:COMPUTERNAME
        SessionId = $Script:MonitorConfig.CurrentSession
        MonitoringMode = $Script:MonitorConfig.MonitoringMode
    }
    
    # Console output com cores
    $color = switch ($Level) {
        "Info" { "Cyan" }
        "Warning" { "Yellow" }
        "Error" { "Red" }
        "Critical" { "Magenta" }
        "Success" { "Green" }
    }
    
    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $color
    
    # Log para arquivo JSON
    try {
        $logFile = Join-Path $Script:MonitorConfig.LogPath "continuous-monitor-$(Get-Date -Format 'yyyy-MM-dd').json"
        $logEntry | ConvertTo-Json -Compress | Add-Content -Path $logFile -Encoding UTF8
    }
    catch {
        Write-Warning "Falha ao escrever log: $_"
    }
    
    return $logEntry
}

function New-SecurityAlert {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Title,
        
        [Parameter(Mandatory = $true)]
        [string]$Description,
        
        [Parameter(Mandatory = $true)]
        [ValidateSet("Low", "Medium", "High", "Critical")]
        [string]$Severity,
        
        [Parameter(Mandatory = $false)]
        [string]$Category = "General",
        
        [Parameter(Mandatory = $false)]
        [hashtable]$Details = @{}
    )
    
    $alert = @{
        Id = [guid]::NewGuid().ToString()
        Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        Title = $Title
        Description = $Description
        Severity = $Severity
        Category = $Category
        Details = $Details
        ComputerName = $env:COMPUTERNAME
        SessionId = $Script:MonitorConfig.CurrentSession
        Acknowledged = $false
    }
    
    $Script:MonitorConfig.AlertsGenerated += $alert
    
    # Salvar alerta
    try {
        $alertFile = Join-Path $Script:MonitorConfig.AlertsPath "alert-$($alert.Id).json"
        $alert | ConvertTo-Json -Depth 4 | Set-Content -Path $alertFile -Encoding UTF8
    }
    catch {
        Write-MonitorLog "Erro ao salvar alerta: $_" -Level "Error"
    }
    
    # Log do alerta
    Write-MonitorLog "ALERTA $Severity`: $Title - $Description" -Level $(if ($Severity -eq "Critical") { "Critical" } else { "Warning" }) -Component "AlertSystem"
    
    # Enviar notificação se threshold atingido
    Send-AlertNotification -Alert $alert
    
    return $alert
}

function Send-AlertNotification {
    param([hashtable]$Alert)
    
    try {
        # Verificar se deve enviar notificação baseado no threshold
        $currentAlerts = $Script:MonitorConfig.AlertsGenerated | Where-Object { $_.Severity -in @("High", "Critical") }
        
        if ($currentAlerts.Count -ge 1) {
            # Notificação do Windows
            try {
                $notificationTitle = "LogoFAIL Security Alert"
                $notificationText = "$($Alert.Severity): $($Alert.Title)"
                
                # Usar toast notification se disponível
                if (Get-Command New-BurntToastNotification -ErrorAction SilentlyContinue) {
                    New-BurntToastNotification -Text $notificationTitle, $notificationText
                } else {
                    # Fallback para msg.exe
                    & msg.exe * "LogoFAIL Alert: $($Alert.Title) - $($Alert.Description)"
                }
            }
            catch {
                Write-MonitorLog "Erro ao enviar notificação Windows: $_" -Level "Warning"
            }
            
            # Email (se configurado)
            Send-EmailAlert -Alert $Alert
        }
    }
    catch {
        Write-MonitorLog "Erro ao processar notificação: $_" -Level "Error"
    }
}

function Send-EmailAlert {
    param([hashtable]$Alert)
    
    try {
        $alertConfigFile = Join-Path $Script:MonitorConfig.ConfigPath "alert-config.json"
        if (Test-Path $alertConfigFile) {
            $alertConfig = Get-Content $alertConfigFile | ConvertFrom-Json
            
            if ($alertConfig.EmailEnabled -and $alertConfig.EmailRecipient) {
                # Implementar envio de email (placeholder)
                Write-MonitorLog "Email alert would be sent to: $($alertConfig.EmailRecipient)" -Level "Info"
                # TODO: Implementar envio real de email
            }
        }
    }
    catch {
        Write-MonitorLog "Erro ao processar alerta por email: $_" -Level "Warning"
    }
}

# ============================================================================
# VERIFICAÇÃO DE INTEGRIDADE DE ARQUIVOS
# ============================================================================

function Test-FileIntegrity {
    Write-MonitorLog "Verificando integridade de arquivos críticos..." -Level "Info"
    
    $results = @{
        ChangedFiles = @()
        NewFiles = @()
        DeletedFiles = @()
        Issues = @()
    }
    
    try {
        # Encontrar baseline mais recente
        $baselineFiles = Get-ChildItem -Path $Script:MonitorConfig.BaselinePath -Filter "security-baseline-*.json" -ErrorAction SilentlyContinue
        if (-not $baselineFiles) {
            Write-MonitorLog "Nenhum baseline encontrado - criando novo baseline" -Level "Warning"
            return $results
        }
        
        $latestBaseline = $baselineFiles | Sort-Object LastWriteTime -Descending | Select-Object -First 1
        $baselineData = Get-Content $latestBaseline.FullName | ConvertFrom-Json
        
        if (-not $baselineData.CriticalFiles) {
            Write-MonitorLog "Baseline inválido - sem dados de arquivos críticos" -Level "Warning"
            return $results
        }
        
        # Verificar arquivos críticos do baseline
        foreach ($filePath in $baselineData.CriticalFiles.PSObject.Properties.Name) {
            try {
                if (Test-Path $filePath) {
                    $currentFile = Get-FileHash -Path $filePath -Algorithm SHA256 -ErrorAction SilentlyContinue
                    $baselineHash = $baselineData.CriticalFiles.$filePath.SHA256
                    
                    if ($currentFile.Hash -ne $baselineHash) {
                        $changedFile = @{
                            Path = $filePath
                            BaselineHash = $baselineHash
                            CurrentHash = $currentFile.Hash
                            ChangeDetected = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                        }
                        
                        $results.ChangedFiles += $changedFile
                        $results.Issues += "Arquivo crítico modificado: $filePath"
                        
                        Write-MonitorLog "CRÍTICO: Arquivo modificado detectado: $filePath" -Level "Critical"
                        
                        New-SecurityAlert -Title "Arquivo Crítico Modificado" -Description "O arquivo $filePath foi modificado" -Severity "Critical" -Category "FileIntegrity" -Details $changedFile
                    }
                } else {
                    $results.DeletedFiles += $filePath
                    $results.Issues += "Arquivo crítico removido: $filePath"
                    
                    Write-MonitorLog "CRÍTICO: Arquivo crítico removido: $filePath" -Level "Critical"
                    
                    New-SecurityAlert -Title "Arquivo Crítico Removido" -Description "O arquivo crítico $filePath foi removido" -Severity "Critical" -Category "FileIntegrity"
                }
            }
            catch {
                Write-MonitorLog "Erro ao verificar arquivo $filePath`: $_" -Level "Error"
            }
        }
        
        return $results
    }
    catch {
        Write-MonitorLog "Erro durante verificação de integridade: $_" -Level "Error"
        return $results
    }
}

# ============================================================================
# MONITORAMENTO DE PROCESSOS
# ============================================================================

function Test-SuspiciousProcesses {
    Write-MonitorLog "Verificando processos suspeitos..." -Level "Info"
    
    $results = @{
        SuspiciousProcesses = @()
        Issues = @()
    }
    
    try {
        $suspiciousPatterns = @(
            "*lenovo*",
            "*vantage*",
            "*logo*",
            "*.tmp.exe",
            "*.temp.exe"
        )
        
        $runningProcesses = Get-Process | Select-Object Id, Name, ProcessName, Path, Company, StartTime
        
        foreach ($process in $runningProcesses) {
            $isSuspicious = $false
            $suspicionReasons = @()
            
            # Verificar padrões suspeitos
            foreach ($pattern in $suspiciousPatterns) {
                if ($process.ProcessName -like $pattern) {
                    $isSuspicious = $true
                    $suspicionReasons += "Nome corresponde ao padrão suspeito: $pattern"
                }
            }
            
            # Verificar processos sem assinatura ou de locais incomuns
            if ($process.Path -and (Test-Path $process.Path)) {
                try {
                    $signature = Get-AuthenticodeSignature -FilePath $process.Path -ErrorAction SilentlyContinue
                    if ($signature.Status -ne "Valid") {
                        $isSuspicious = $true
                        $suspicionReasons += "Assinatura digital inválida: $($signature.Status)"
                    }
                    
                    # Verificar locais suspeitos
                    $suspiciousLocations = @("$env:TEMP", "$env:APPDATA", "C:\Users\Public")
                    foreach ($location in $suspiciousLocations) {
                        if ($process.Path -like "$location*") {
                            $isSuspicious = $true
                            $suspicionReasons += "Executando de local suspeito: $location"
                        }
                    }
                }
                catch {
                    # Ignorar erros de verificação para processos do sistema
                }
            }
            
            if ($isSuspicious) {
                $suspiciousProcess = @{
                    ProcessId = $process.Id
                    Name = $process.ProcessName
                    Path = $process.Path
                    Company = $process.Company
                    StartTime = $process.StartTime
                    Reasons = $suspicionReasons
                    DetectedAt = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                }
                
                $results.SuspiciousProcesses += $suspiciousProcess
                $results.Issues += "Processo suspeito: $($process.ProcessName) (PID: $($process.Id))"
                
                Write-MonitorLog "Processo suspeito detectado: $($process.ProcessName) (PID: $($process.Id))" -Level "Warning"
                
                New-SecurityAlert -Title "Processo Suspeito Detectado" -Description "Processo $($process.ProcessName) detectado com características suspeitas" -Severity "High" -Category "ProcessMonitoring" -Details $suspiciousProcess
            }
        }
        
        return $results
    }
    catch {
        Write-MonitorLog "Erro durante monitoramento de processos: $_" -Level "Error"
        return $results
    }
}

# ============================================================================
# MONITORAMENTO DE REGISTRO
# ============================================================================

function Test-RegistryChanges {
    Write-MonitorLog "Verificando alterações no registro..." -Level "Info"
    
    $results = @{
        ChangedKeys = @()
        Issues = @()
    }
    
    try {
        # Chaves críticas para monitorar
        $criticalKeys = @(
            "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State",
            "HKLM:\SYSTEM\CurrentControlSet\Control\BootDriverFlags",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "HKLM:\SOFTWARE\Lenovo",
            "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"
        )
        
        foreach ($keyPath in $criticalKeys) {
            try {
                if (Test-Path $keyPath) {
                    $currentKey = Get-ItemProperty -Path $keyPath -ErrorAction SilentlyContinue
                    $keyLastWrite = (Get-Item $keyPath).LastWriteTime
                    
                    # Verificar se foi modificado recentemente (última hora)
                    $oneHourAgo = (Get-Date).AddHours(-1)
                    if ($keyLastWrite -gt $oneHourAgo) {
                        $changedKey = @{
                            Path = $keyPath
                            LastWriteTime = $keyLastWrite.ToString("yyyy-MM-dd HH:mm:ss")
                            DetectedAt = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                        }
                        
                        $results.ChangedKeys += $changedKey
                        $results.Issues += "Chave de registro modificada recentemente: $keyPath"
                        
                        Write-MonitorLog "Chave de registro modificada: $keyPath" -Level "Warning"
                        
                        New-SecurityAlert -Title "Alteração de Registro Detectada" -Description "A chave de registro $keyPath foi modificada recentemente" -Severity "Medium" -Category "RegistryMonitoring" -Details $changedKey
                    }
                }
            }
            catch {
                Write-MonitorLog "Erro ao verificar chave $keyPath`: $_" -Level "Warning"
            }
        }
        
        return $results
    }
    catch {
        Write-MonitorLog "Erro durante monitoramento de registro: $_" -Level "Error"
        return $results
    }
}

# ============================================================================
# MONITORAMENTO DE REDE
# ============================================================================

function Test-NetworkAnomalies {
    Write-MonitorLog "Verificando anomalias de rede..." -Level "Info"
    
    $results = @{
        SuspiciousConnections = @()
        Issues = @()
    }
    
    try {
        # Obter conexões de rede ativas
        $connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue
        
        # Domínios suspeitos relacionados ao LogoFAIL
        $suspiciousDomains = @(
            "*lenovo.com",
            "*vantage*",
            "*logo*"
        )
        
        foreach ($connection in $connections) {
            try {
                $process = Get-Process -Id $connection.OwningProcess -ErrorAction SilentlyContinue
                if ($process) {
                    $isSuspicious = $false
                    $suspicionReasons = @()
                    
                    # Verificar se o processo é suspeito
                    foreach ($domain in $suspiciousDomains) {
                        if ($process.ProcessName -like $domain -or $connection.RemoteAddress -like $domain) {
                            $isSuspicious = $true
                            $suspicionReasons += "Conexão com domínio suspeito relacionado ao LogoFAIL"
                        }
                    }
                    
                    # Verificar conexões para IPs externos na porta 443/80 de processos suspeitos
                    if ($process.ProcessName -like "*lenovo*" -or $process.ProcessName -like "*vantage*") {
                        if ($connection.RemotePort -in @(80, 443, 8080, 8443)) {
                            $isSuspicious = $true
                            $suspicionReasons += "Processo Lenovo/Vantage comunicando externamente"
                        }
                    }
                    
                    if ($isSuspicious) {
                        $suspiciousConnection = @{
                            ProcessName = $process.ProcessName
                            ProcessId = $connection.OwningProcess
                            LocalAddress = $connection.LocalAddress
                            LocalPort = $connection.LocalPort
                            RemoteAddress = $connection.RemoteAddress
                            RemotePort = $connection.RemotePort
                            State = $connection.State
                            Reasons = $suspicionReasons
                            DetectedAt = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                        }
                        
                        $results.SuspiciousConnections += $suspiciousConnection
                        $results.Issues += "Conexão suspeita: $($process.ProcessName) -> $($connection.RemoteAddress):$($connection.RemotePort)"
                        
                        Write-MonitorLog "Conexão suspeita: $($process.ProcessName) -> $($connection.RemoteAddress):$($connection.RemotePort)" -Level "Warning"
                        
                        New-SecurityAlert -Title "Conexão de Rede Suspeita" -Description "Processo $($process.ProcessName) estabeleceu conexão suspeita" -Severity "Medium" -Category "NetworkMonitoring" -Details $suspiciousConnection
                    }
                }
            }
            catch {
                # Ignorar erros de processos que não existem mais
            }
        }
        
        return $results
    }
    catch {
        Write-MonitorLog "Erro durante monitoramento de rede: $_" -Level "Error"
        return $results
    }
}

# ============================================================================
# VERIFICAÇÃO DE LOGS DE EVENTOS
# ============================================================================

function Test-EventLogs {
    Write-MonitorLog "Verificando logs de eventos para atividades suspeitas..." -Level "Info"
    
    $results = @{
        SuspiciousEvents = @()
        Issues = @()
    }
    
    try {
        # Eventos suspeitos para monitorar
        $suspiciousEventIds = @{
            "System" = @(1074, 6005, 6006, 6008, 6009)  # Shutdown/startup events
            "Security" = @(4624, 4625, 4648, 4719, 4720, 4722, 4724) # Logon events, policy changes
            "Application" = @() # Application specific events
        }
        
        $oneHourAgo = (Get-Date).AddHours(-1)
        
        foreach ($logName in $suspiciousEventIds.Keys) {
            try {
                $events = Get-WinEvent -FilterHashtable @{LogName=$logName; StartTime=$oneHourAgo} -ErrorAction SilentlyContinue
                
                foreach ($event in $events) {
                    if ($event.Id -in $suspiciousEventIds[$logName]) {
                        $suspiciousEvent = @{
                            LogName = $logName
                            EventId = $event.Id
                            TimeCreated = $event.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
                            Message = $event.Message
                            Level = $event.LevelDisplayName
                            Source = $event.ProviderName
                        }
                        
                        $results.SuspiciousEvents += $suspiciousEvent
                        
                        # Eventos críticos que podem indicar comprometimento
                        if ($event.Id -in @(4719, 6008)) { # Policy change, unexpected shutdown
                            $results.Issues += "Evento crítico detectado: $($event.Id) - $($event.Message)"
                            Write-MonitorLog "Evento crítico: $($event.Id) em $logName" -Level "Warning"
                            
                            New-SecurityAlert -Title "Evento de Segurança Crítico" -Description "Evento ID $($event.Id) detectado em $logName" -Severity "High" -Category "EventMonitoring" -Details $suspiciousEvent
                        }
                    }
                }
            }
            catch {
                Write-MonitorLog "Erro ao verificar log $logName`: $_" -Level "Warning"
            }
        }
        
        return $results
    }
    catch {
        Write-MonitorLog "Erro durante verificação de logs: $_" -Level "Error"
        return $results
    }
}

# ============================================================================
# FUNÇÃO PRINCIPAL DE MONITORAMENTO
# ============================================================================

function Start-ContinuousMonitoring {
    Write-MonitorLog "Iniciando monitoramento contínuo de segurança LogoFAIL..." -Level "Info"
    Write-MonitorLog "Modo: $($Script:MonitorConfig.MonitoringMode) | Threshold: $($Script:MonitorConfig.AlertThreshold)" -Level "Info"
    
    # Criar diretórios necessários
    try {
        $directories = @(
            $Script:MonitorConfig.LogPath,
            $Script:MonitorConfig.AlertsPath,
            $Script:MonitorConfig.ConfigPath
        )
        
        foreach ($dir in $directories) {
            if (-not (Test-Path $dir)) {
                New-Item -Path $dir -ItemType Directory -Force | Out-Null
            }
        }
    }
    catch {
        Write-MonitorLog "Erro ao criar diretórios: $_" -Level "Error"
        return $false
    }
    
    $settings = $Script:MonitoringSettings[$Script:MonitorConfig.MonitoringMode]
    $monitoringResults = @{
        FileIntegrity = @{}
        ProcessMonitoring = @{}
        RegistryMonitoring = @{}
        NetworkMonitoring = @{}
        EventLogMonitoring = @{}
        Summary = @{
            StartTime = $Script:MonitorConfig.StartTime.ToString("yyyy-MM-dd HH:mm:ss")
            EndTime = $null
            TotalAlerts = 0
            CriticalAlerts = 0
            HighAlerts = 0
            MediumAlerts = 0
            LowAlerts = 0
        }
    }
    
    try {
        $loopCount = 0
        $maxLoops = if ($Script:MonitorConfig.RunOnce) { 1 } else { [math]::Floor($settings.MaxRunTime / $settings.CheckInterval) }
        
        do {
            $loopCount++
            $loopStartTime = Get-Date
            
            Write-MonitorLog "Iniciando ciclo de verificação $loopCount..." -Level "Info"
            
            # Verificação de integridade de arquivos
            if ($settings.CheckCriticalFiles) {
                try {
                    $fileResults = Test-FileIntegrity
                    $monitoringResults.FileIntegrity = $fileResults
                    $Script:MonitorConfig.ChangesDetected += $fileResults.Issues
                }
                catch {
                    Write-MonitorLog "Erro durante verificação de arquivos: $_" -Level "Error"
                }
            }
            
            # Monitoramento de processos
            if ($settings.CheckProcesses) {
                try {
                    $processResults = Test-SuspiciousProcesses
                    $monitoringResults.ProcessMonitoring = $processResults
                    $Script:MonitorConfig.ChangesDetected += $processResults.Issues
                }
                catch {
                    Write-MonitorLog "Erro durante monitoramento de processos: $_" -Level "Error"
                }
            }
            
            # Monitoramento de registro
            if ($settings.CheckRegistry) {
                try {
                    $registryResults = Test-RegistryChanges
                    $monitoringResults.RegistryMonitoring = $registryResults
                    $Script:MonitorConfig.ChangesDetected += $registryResults.Issues
                }
                catch {
                    Write-MonitorLog "Erro durante monitoramento de registro: $_" -Level "Error"
                }
            }
            
            # Monitoramento de rede
            if ($settings.CheckNetwork) {
                try {
                    $networkResults = Test-NetworkAnomalies
                    $monitoringResults.NetworkMonitoring = $networkResults
                    $Script:MonitorConfig.ChangesDetected += $networkResults.Issues
                }
                catch {
                    Write-MonitorLog "Erro durante monitoramento de rede: $_" -Level "Error"
                }
            }
            
            # Verificação de logs de eventos
            if ($settings.CheckEventLogs) {
                try {
                    $eventResults = Test-EventLogs
                    $monitoringResults.EventLogMonitoring = $eventResults
                    $Script:MonitorConfig.ChangesDetected += $eventResults.Issues
                }
                catch {
                    Write-MonitorLog "Erro durante verificação de logs: $_" -Level "Error"
                }
            }
            
            # Contabilizar alertas por severidade
            $alertCounts = @{
                Critical = ($Script:MonitorConfig.AlertsGenerated | Where-Object { $_.Severity -eq "Critical" }).Count
                High = ($Script:MonitorConfig.AlertsGenerated | Where-Object { $_.Severity -eq "High" }).Count
                Medium = ($Script:MonitorConfig.AlertsGenerated | Where-Object { $_.Severity -eq "Medium" }).Count
                Low = ($Script:MonitorConfig.AlertsGenerated | Where-Object { $_.Severity -eq "Low" }).Count
            }
            
            $loopDuration = ((Get-Date) - $loopStartTime).TotalSeconds
            Write-MonitorLog "Ciclo $loopCount concluído em $([math]::Round($loopDuration, 2))s | Alertas: C:$($alertCounts.Critical) H:$($alertCounts.High) M:$($alertCounts.Medium) L:$($alertCounts.Low)" -Level "Info"
            
            # Pausa entre verificações (exceto se RunOnce)
            if (-not $Script:MonitorConfig.RunOnce -and $loopCount -lt $maxLoops) {
                $remainingTime = $settings.CheckInterval - $loopDuration
                if ($remainingTime -gt 0) {
                    Start-Sleep -Seconds $remainingTime
                }
            }
            
        } while (-not $Script:MonitorConfig.RunOnce -and $loopCount -lt $maxLoops -and ((Get-Date) - $Script:MonitorConfig.StartTime).TotalSeconds -lt $settings.MaxRunTime)
        
        # Finalizar resumo
        $monitoringResults.Summary.EndTime = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        $monitoringResults.Summary.TotalAlerts = $Script:MonitorConfig.AlertsGenerated.Count
        $monitoringResults.Summary.CriticalAlerts = $alertCounts.Critical
        $monitoringResults.Summary.HighAlerts = $alertCounts.High
        $monitoringResults.Summary.MediumAlerts = $alertCounts.Medium
        $monitoringResults.Summary.LowAlerts = $alertCounts.Low
        
        # Salvar relatório de monitoramento
        try {
            $reportFile = Join-Path $Script:MonitorConfig.LogPath "monitoring-report-$($Script:MonitorConfig.CurrentSession).json"
            $monitoringResults | ConvertTo-Json -Depth 5 | Set-Content -Path $reportFile -Encoding UTF8
            Write-MonitorLog "Relatório de monitoramento salvo: $reportFile" -Level "Success"
        }
        catch {
            Write-MonitorLog "Erro ao salvar relatório: $_" -Level "Error"
        }
        
        $duration = ((Get-Date) - $Script:MonitorConfig.StartTime).TotalMinutes
        Write-MonitorLog "Monitoramento concluído em $([math]::Round($duration, 2)) minutos" -Level "Success"
        Write-MonitorLog "Total de alertas gerados: $($Script:MonitorConfig.AlertsGenerated.Count)" -Level "Info"
        Write-MonitorLog "Alterações detectadas: $($Script:MonitorConfig.ChangesDetected.Count)" -Level "Info"
        
        return $true
    }
    catch {
        Write-MonitorLog "Erro fatal durante monitoramento: $_" -Level "Error"
        return $false
    }
}

# ============================================================================
# EXECUÇÃO PRINCIPAL
# ============================================================================

try {
    # Verificar privilégios de administrador
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-MonitorLog "Este script requer privilégios de administrador" -Level "Error"
        exit 1
    }
    
    $result = Start-ContinuousMonitoring
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