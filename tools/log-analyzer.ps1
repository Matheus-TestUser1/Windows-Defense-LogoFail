#Requires -Version 5.1

<#
.SYNOPSIS
    LogoFAIL Log Analyzer - Análise e Correlação de Logs de Segurança
    
.DESCRIPTION
    Ferramenta para análise, correlação e geração de relatórios a partir dos logs
    gerados pelo sistema de proteção LogoFAIL. Identifica padrões, tendências
    e indicadores de comprometimento nos dados de monitoramento.
    
.PARAMETER LogPath
    Caminho para os diretórios de logs
    
.PARAMETER StartDate
    Data inicial para análise (formato: yyyy-MM-dd)
    
.PARAMETER EndDate
    Data final para análise (formato: yyyy-MM-dd)
    
.PARAMETER OutputFormat
    Formato de saída: JSON, CSV, HTML, Console
    
.PARAMETER AlertsOnly
    Analisa apenas logs de alertas
    
.PARAMETER GenerateReport
    Gera relatório detalhado de análise
    
.EXAMPLE
    .\log-analyzer.ps1 -LogPath "C:\ProgramData\WindowsDefenseLogoFAIL\Logs" -StartDate "2024-01-01" -GenerateReport
    
.NOTES
    Author: Matheus-TestUser1
    Version: 1.0.0
    Requires: PowerShell 5.1+
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$LogPath = "$env:ProgramData\WindowsDefenseLogoFAIL\Logs",
    
    [Parameter(Mandatory = $false)]
    [datetime]$StartDate = (Get-Date).AddDays(-7),
    
    [Parameter(Mandatory = $false)]
    [datetime]$EndDate = (Get-Date),
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("JSON", "CSV", "HTML", "Console")]
    [string]$OutputFormat = "Console",
    
    [Parameter(Mandatory = $false)]
    [switch]$AlertsOnly,
    
    [Parameter(Mandatory = $false)]
    [switch]$GenerateReport
)

# ============================================================================
# CONFIGURAÇÕES GLOBAIS
# ============================================================================

$Script:AnalyzerConfig = @{
    Version = "1.0.0"
    StartTime = Get-Date
    LogPath = $LogPath
    StartDate = $StartDate
    EndDate = $EndDate
    OutputFormat = $OutputFormat
    ProcessedEvents = 0
    AlertsFound = 0
    PatternsDetected = @()
    TimelineEvents = @()
    Statistics = @{}
}

# ============================================================================
# FUNÇÕES DE LOGGING
# ============================================================================

function Write-AnalyzerLog {
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
# FUNÇÕES DE ANÁLISE
# ============================================================================

function Get-LogFiles {
    Write-AnalyzerLog "Identificando arquivos de log..." -Level "Info"
    
    try {
        if (-not (Test-Path $Script:AnalyzerConfig.LogPath)) {
            Write-AnalyzerLog "Diretório de logs não encontrado: $($Script:AnalyzerConfig.LogPath)" -Level "Error"
            return @()
        }
        
        $logFiles = @()
        
        # Diferentes tipos de logs do sistema
        $logPatterns = if ($AlertsOnly) {
            @("security-alerts-*.json", "alert-system-*.json")
        } else {
            @(
                "logofail-*.json",
                "security-alerts-*.json", 
                "continuous-monitor-*.json",
                "advanced-protection-*.json",
                "forensic-*.json",
                "quick-check-*.json",
                "alert-system-*.json"
            )
        }
        
        foreach ($pattern in $logPatterns) {
            $files = Get-ChildItem -Path $Script:AnalyzerConfig.LogPath -Filter $pattern -ErrorAction SilentlyContinue
            $logFiles += $files
        }
        
        # Filtrar por data se especificado
        $filteredFiles = $logFiles | Where-Object {
            $_.LastWriteTime -ge $Script:AnalyzerConfig.StartDate -and 
            $_.LastWriteTime -le $Script:AnalyzerConfig.EndDate
        }
        
        Write-AnalyzerLog "Encontrados $($filteredFiles.Count) arquivos de log no período especificado" -Level "Success"
        
        return $filteredFiles
    }
    catch {
        Write-AnalyzerLog "Erro ao identificar arquivos de log: $_" -Level "Error"
        return @()
    }
}

function Parse-LogEvents {
    param([array]$LogFiles)
    
    Write-AnalyzerLog "Processando eventos de log..." -Level "Info"
    
    $allEvents = @()
    
    foreach ($logFile in $LogFiles) {
        try {
            Write-AnalyzerLog "Processando: $($logFile.Name)" -Level "Info"
            
            $content = Get-Content $logFile.FullName -Encoding UTF8
            
            foreach ($line in $content) {
                try {
                    if ($line.Trim() -ne "") {
                        $event = $line | ConvertFrom-Json
                        
                        # Padronizar campos de evento
                        $standardEvent = @{
                            Timestamp = $event.Timestamp
                            Level = $event.Level
                            Component = $event.Component
                            Message = $event.Message
                            ComputerName = $event.ComputerName
                            SourceFile = $logFile.Name
                            SessionId = $event.SessionId
                        }
                        
                        # Adicionar campos específicos se existirem
                        if ($event.PSObject.Properties.Name -contains "AlertType") {
                            $standardEvent.AlertType = $event.AlertType
                        }
                        if ($event.PSObject.Properties.Name -contains "Severity") {
                            $standardEvent.Severity = $event.Severity
                        }
                        if ($event.PSObject.Properties.Name -contains "Details") {
                            $standardEvent.Details = $event.Details
                        }
                        
                        $allEvents += $standardEvent
                        $Script:AnalyzerConfig.ProcessedEvents++
                    }
                }
                catch {
                    # Ignorar linhas que não são JSON válido
                    continue
                }
            }
        }
        catch {
            Write-AnalyzerLog "Erro ao processar arquivo $($logFile.Name): $_" -Level "Warning"
        }
    }
    
    Write-AnalyzerLog "Total de eventos processados: $($Script:AnalyzerConfig.ProcessedEvents)" -Level "Success"
    
    return $allEvents
}

function Analyze-SecurityPatterns {
    param([array]$Events)
    
    Write-AnalyzerLog "Analisando padrões de segurança..." -Level "Info"
    
    $patterns = @{
        CriticalAlerts = @()
        SuspiciousActivity = @()
        SystemChanges = @()
        TimeAnomalies = @()
        FrequencyAnomalies = @()
    }
    
    # Alertas críticos
    $criticalEvents = $Events | Where-Object { 
        $_.Level -in @("Critical", "Error") -or 
        $_.Severity -eq "Critical" 
    }
    
    foreach ($event in $criticalEvents) {
        $patterns.CriticalAlerts += @{
            Timestamp = $event.Timestamp
            Message = $event.Message
            Component = $event.Component
            Details = $event.Details
        }
        $Script:AnalyzerConfig.AlertsFound++
    }
    
    # Atividade suspeita - múltiplos alertas em curto período
    $groupedEvents = $Events | Group-Object { (Get-Date $_.Timestamp).ToString("yyyy-MM-dd HH") }
    
    foreach ($group in $groupedEvents) {
        if ($group.Count -gt 10) {  # Mais de 10 eventos por hora
            $patterns.FrequencyAnomalies += @{
                TimeWindow = $group.Name
                EventCount = $group.Count
                Events = $group.Group | Select-Object -First 5
            }
        }
    }
    
    # Mudanças no sistema
    $systemChangeKeywords = @("modificado", "alterado", "removido", "detectado", "suspeito")
    
    foreach ($event in $Events) {
        foreach ($keyword in $systemChangeKeywords) {
            if ($event.Message -like "*$keyword*") {
                $patterns.SystemChanges += @{
                    Timestamp = $event.Timestamp
                    ChangeType = $keyword
                    Message = $event.Message
                    Component = $event.Component
                }
                break
            }
        }
    }
    
    # Anomalias de tempo - eventos fora do horário comercial
    $afterHoursEvents = $Events | Where-Object {
        $hour = (Get-Date $_.Timestamp).Hour
        $hour -lt 8 -or $hour -gt 18  # Fora do horário 8h-18h
    }
    
    if ($afterHoursEvents.Count -gt 0) {
        $patterns.TimeAnomalies = $afterHoursEvents | Group-Object { (Get-Date $_.Timestamp).ToString("yyyy-MM-dd") } | ForEach-Object {
            @{
                Date = $_.Name
                EventCount = $_.Count
                Components = ($_.Group.Component | Sort-Object -Unique)
            }
        }
    }
    
    $Script:AnalyzerConfig.PatternsDetected = $patterns
    
    return $patterns
}

function Generate-Statistics {
    param([array]$Events)
    
    Write-AnalyzerLog "Gerando estatísticas..." -Level "Info"
    
    $stats = @{
        TotalEvents = $Events.Count
        EventsByLevel = @{}
        EventsByComponent = @{}
        EventsByDay = @{}
        EventsByHour = @{}
        TopMessages = @{}
        SystemsInvolved = @()
    }
    
    # Eventos por nível
    $levelGroups = $Events | Group-Object Level
    foreach ($group in $levelGroups) {
        $stats.EventsByLevel[$group.Name] = $group.Count
    }
    
    # Eventos por componente
    $componentGroups = $Events | Group-Object Component
    foreach ($group in $componentGroups) {
        $stats.EventsByComponent[$group.Name] = $group.Count
    }
    
    # Eventos por dia
    $dayGroups = $Events | Group-Object { (Get-Date $_.Timestamp).ToString("yyyy-MM-dd") }
    foreach ($group in $dayGroups) {
        $stats.EventsByDay[$group.Name] = $group.Count
    }
    
    # Eventos por hora do dia
    $hourGroups = $Events | Group-Object { (Get-Date $_.Timestamp).Hour }
    foreach ($group in $hourGroups) {
        $stats.EventsByHour["$($group.Name):00"] = $group.Count
    }
    
    # Top mensagens
    $messageGroups = $Events | Group-Object Message | Sort-Object Count -Descending | Select-Object -First 10
    foreach ($group in $messageGroups) {
        $stats.TopMessages[$group.Name] = $group.Count
    }
    
    # Sistemas envolvidos
    $stats.SystemsInvolved = $Events | Select-Object -ExpandProperty ComputerName -Unique | Sort-Object
    
    $Script:AnalyzerConfig.Statistics = $stats
    
    return $stats
}

function Generate-Timeline {
    param([array]$Events)
    
    Write-AnalyzerLog "Gerando linha do tempo..." -Level "Info"
    
    $timeline = $Events | Sort-Object { Get-Date $_.Timestamp } | ForEach-Object {
        @{
            Timestamp = $_.Timestamp
            Level = $_.Level
            Component = $_.Component
            Message = $_.Message
            Computer = $_.ComputerName
        }
    }
    
    $Script:AnalyzerConfig.TimelineEvents = $timeline
    
    return $timeline
}

# ============================================================================
# FUNÇÕES DE SAÍDA
# ============================================================================

function Export-Results {
    param(
        [array]$Events,
        [hashtable]$Patterns,
        [hashtable]$Statistics,
        [array]$Timeline
    )
    
    $results = @{
        AnalysisMetadata = @{
            GeneratedAt = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            AnalyzerVersion = $Script:AnalyzerConfig.Version
            Period = @{
                StartDate = $Script:AnalyzerConfig.StartDate.ToString("yyyy-MM-dd")
                EndDate = $Script:AnalyzerConfig.EndDate.ToString("yyyy-MM-dd")
            }
            ProcessedEvents = $Script:AnalyzerConfig.ProcessedEvents
            AlertsFound = $Script:AnalyzerConfig.AlertsFound
        }
        Statistics = $Statistics
        SecurityPatterns = $Patterns
        Timeline = $Timeline
        RawEvents = if ($Script:AnalyzerConfig.OutputFormat -eq "JSON") { $Events } else { @() }
    }
    
    switch ($Script:AnalyzerConfig.OutputFormat) {
        "JSON" {
            $outputFile = "logofail-analysis-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
            $results | ConvertTo-Json -Depth 6 | Set-Content -Path $outputFile -Encoding UTF8
            Write-AnalyzerLog "Análise exportada para: $outputFile" -Level "Success"
        }
        
        "CSV" {
            $outputFile = "logofail-analysis-$(Get-Date -Format 'yyyyMMdd-HHmmss').csv"
            $Events | Export-Csv -Path $outputFile -NoTypeInformation -Encoding UTF8
            Write-AnalyzerLog "Eventos exportados para: $outputFile" -Level "Success"
        }
        
        "HTML" {
            $outputFile = "logofail-analysis-$(Get-Date -Format 'yyyyMMdd-HHmmss').html"
            $htmlContent = Generate-HTMLReport -Results $results
            $htmlContent | Set-Content -Path $outputFile -Encoding UTF8
            Write-AnalyzerLog "Relatório HTML gerado: $outputFile" -Level "Success"
        }
        
        "Console" {
            Display-ConsoleReport -Results $results
        }
    }
}

function Generate-HTMLReport {
    param([hashtable]$Results)
    
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>LogoFAIL Security Analysis Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { background: #2c3e50; color: white; padding: 20px; border-radius: 5px; margin-bottom: 20px; }
        .section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
        .critical { background: #ffebee; border-left: 5px solid #f44336; }
        .warning { background: #fff3e0; border-left: 5px solid #ff9800; }
        .info { background: #e3f2fd; border-left: 5px solid #2196f3; }
        .success { background: #e8f5e8; border-left: 5px solid #4caf50; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background: #f5f5f5; }
        .metric { display: inline-block; margin: 10px; padding: 15px; background: #f8f9fa; border-radius: 5px; text-align: center; }
        .metric-value { font-size: 24px; font-weight: bold; color: #2c3e50; }
        .metric-label { font-size: 12px; color: #666; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>LogoFAIL Security Analysis Report</h1>
            <p>Generated: $($Results.AnalysisMetadata.GeneratedAt)</p>
            <p>Period: $($Results.AnalysisMetadata.Period.StartDate) to $($Results.AnalysisMetadata.Period.EndDate)</p>
        </div>
        
        <div class="section info">
            <h2>Analysis Summary</h2>
            <div class="metric">
                <div class="metric-value">$($Results.AnalysisMetadata.ProcessedEvents)</div>
                <div class="metric-label">Total Events</div>
            </div>
            <div class="metric">
                <div class="metric-value">$($Results.AnalysisMetadata.AlertsFound)</div>
                <div class="metric-label">Critical Alerts</div>
            </div>
            <div class="metric">
                <div class="metric-value">$($Results.Statistics.SystemsInvolved.Count)</div>
                <div class="metric-label">Systems Involved</div>
            </div>
        </div>
        
        <div class="section">
            <h2>Event Statistics</h2>
            <h3>Events by Level</h3>
            <table>
                <tr><th>Level</th><th>Count</th></tr>
"@
    
    foreach ($level in $Results.Statistics.EventsByLevel.GetEnumerator()) {
        $html += "<tr><td>$($level.Key)</td><td>$($level.Value)</td></tr>"
    }
    
    $html += @"
            </table>
        </div>
        
        <div class="section $(if ($Results.SecurityPatterns.CriticalAlerts.Count -gt 0) { 'critical' } else { 'success' })">
            <h2>Security Patterns</h2>
            <p><strong>Critical Alerts:</strong> $($Results.SecurityPatterns.CriticalAlerts.Count)</p>
            <p><strong>System Changes:</strong> $($Results.SecurityPatterns.SystemChanges.Count)</p>
            <p><strong>Frequency Anomalies:</strong> $($Results.SecurityPatterns.FrequencyAnomalies.Count)</p>
            <p><strong>Time Anomalies:</strong> $($Results.SecurityPatterns.TimeAnomalies.Count)</p>
        </div>
    </div>
</body>
</html>
"@
    
    return $html
}

function Display-ConsoleReport {
    param([hashtable]$Results)
    
    Write-Host ""
    Write-Host "======================================================================" -ForegroundColor Cyan
    Write-Host "    LogoFAIL Security Analysis Report" -ForegroundColor Cyan
    Write-Host "======================================================================" -ForegroundColor Cyan
    Write-Host ""
    
    # Resumo da análise
    Write-Host "RESUMO DA ANÁLISE:" -ForegroundColor Yellow
    Write-Host "- Período analisado: $($Results.AnalysisMetadata.Period.StartDate) a $($Results.AnalysisMetadata.Period.EndDate)" -ForegroundColor White
    Write-Host "- Total de eventos processados: $($Results.AnalysisMetadata.ProcessedEvents)" -ForegroundColor White
    Write-Host "- Alertas críticos encontrados: $($Results.AnalysisMetadata.AlertsFound)" -ForegroundColor White
    Write-Host "- Sistemas envolvidos: $($Results.Statistics.SystemsInvolved.Count)" -ForegroundColor White
    
    # Estatísticas por nível
    Write-Host ""
    Write-Host "EVENTOS POR NÍVEL:" -ForegroundColor Yellow
    foreach ($level in $Results.Statistics.EventsByLevel.GetEnumerator()) {
        $color = switch ($level.Key) {
            "Critical" { "Red" }
            "Error" { "Red" }
            "Warning" { "Yellow" }
            default { "White" }
        }
        Write-Host "  - $($level.Key): $($level.Value)" -ForegroundColor $color
    }
    
    # Padrões de segurança
    Write-Host ""
    Write-Host "PADRÕES DE SEGURANÇA DETECTADOS:" -ForegroundColor Yellow
    Write-Host "  - Alertas críticos: $($Results.SecurityPatterns.CriticalAlerts.Count)" -ForegroundColor $(if ($Results.SecurityPatterns.CriticalAlerts.Count -gt 0) { "Red" } else { "Green" })
    Write-Host "  - Mudanças no sistema: $($Results.SecurityPatterns.SystemChanges.Count)" -ForegroundColor White
    Write-Host "  - Anomalias de frequência: $($Results.SecurityPatterns.FrequencyAnomalies.Count)" -ForegroundColor White
    Write-Host "  - Anomalias de horário: $($Results.SecurityPatterns.TimeAnomalies.Count)" -ForegroundColor White
    
    # Top componentes
    Write-Host ""
    Write-Host "TOP COMPONENTES (por atividade):" -ForegroundColor Yellow
    $topComponents = $Results.Statistics.EventsByComponent.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 5
    foreach ($component in $topComponents) {
        Write-Host "  - $($component.Key): $($component.Value) eventos" -ForegroundColor White
    }
    
    # Alertas críticos recentes
    if ($Results.SecurityPatterns.CriticalAlerts.Count -gt 0) {
        Write-Host ""
        Write-Host "ALERTAS CRÍTICOS RECENTES:" -ForegroundColor Red
        $recentCritical = $Results.SecurityPatterns.CriticalAlerts | Select-Object -First 5
        foreach ($alert in $recentCritical) {
            Write-Host "  - [$($alert.Timestamp)] $($alert.Message)" -ForegroundColor Red
        }
    }
    
    # Sistemas envolvidos
    if ($Results.Statistics.SystemsInvolved.Count -gt 0) {
        Write-Host ""
        Write-Host "SISTEMAS ENVOLVIDOS:" -ForegroundColor Yellow
        foreach ($system in $Results.Statistics.SystemsInvolved) {
            Write-Host "  - $system" -ForegroundColor White
        }
    }
    
    Write-Host ""
    Write-Host "======================================================================" -ForegroundColor Cyan
}

# ============================================================================
# FUNÇÃO PRINCIPAL
# ============================================================================

function Start-LogAnalysis {
    Write-Host "======================================================================" -ForegroundColor Cyan
    Write-Host "    LogoFAIL Log Analyzer - Análise de Logs de Segurança" -ForegroundColor Cyan
    Write-Host "    Versão: $($Script:AnalyzerConfig.Version)" -ForegroundColor Cyan
    Write-Host "======================================================================" -ForegroundColor Cyan
    Write-Host ""
    
    try {
        # Obter arquivos de log
        $logFiles = Get-LogFiles
        if ($logFiles.Count -eq 0) {
            Write-AnalyzerLog "Nenhum arquivo de log encontrado para análise" -Level "Warning"
            return $false
        }
        
        # Processar eventos
        $events = Parse-LogEvents -LogFiles $logFiles
        if ($events.Count -eq 0) {
            Write-AnalyzerLog "Nenhum evento válido encontrado nos logs" -Level "Warning"
            return $false
        }
        
        # Análise de padrões
        $patterns = Analyze-SecurityPatterns -Events $events
        
        # Gerar estatísticas
        $statistics = Generate-Statistics -Events $events
        
        # Gerar linha do tempo
        $timeline = Generate-Timeline -Events $events
        
        # Exportar resultados
        Export-Results -Events $events -Patterns $patterns -Statistics $statistics -Timeline $timeline
        
        $duration = ((Get-Date) - $Script:AnalyzerConfig.StartTime).TotalSeconds
        Write-AnalyzerLog "Análise concluída em $([math]::Round($duration, 2)) segundos" -Level "Success"
        
        return $true
    }
    catch {
        Write-AnalyzerLog "Erro durante análise: $_" -Level "Error"
        return $false
    }
}

# ============================================================================
# EXECUÇÃO PRINCIPAL
# ============================================================================

try {
    $result = Start-LogAnalysis
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