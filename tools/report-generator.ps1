#Requires -Version 5.1

<#
.SYNOPSIS
    LogoFAIL Report Generator - Gerador de Relatórios de Segurança
    
.DESCRIPTION
    Ferramenta para geração de relatórios executivos e técnicos a partir dos dados
    coletados pelo sistema de proteção LogoFAIL. Suporta múltiplos formatos de saída
    e templates personalizáveis para diferentes audiências.
    
.PARAMETER ReportType
    Tipo de relatório: Executive, Technical, Compliance, Forensic
    
.PARAMETER DataPath
    Caminho para os dados de entrada (logs, alertas, análises)
    
.PARAMETER OutputPath
    Caminho para salvar o relatório gerado
    
.PARAMETER Template
    Template específico a ser usado
    
.PARAMETER Format
    Formato de saída: HTML, PDF, Word, PowerPoint
    
.PARAMETER Period
    Período para o relatório: Daily, Weekly, Monthly, Custom
    
.PARAMETER IncludeCharts
    Inclui gráficos e visualizações no relatório
    
.EXAMPLE
    .\report-generator.ps1 -ReportType Executive -Period Weekly -Format HTML -IncludeCharts
    
.NOTES
    Author: Matheus-TestUser1
    Version: 1.0.0
    Requires: PowerShell 5.1+
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateSet("Executive", "Technical", "Compliance", "Forensic")]
    [string]$ReportType = "Technical",
    
    [Parameter(Mandatory = $false)]
    [string]$DataPath = "$env:ProgramData\WindowsDefenseLogoFAIL",
    
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = ".\Reports",
    
    [Parameter(Mandatory = $false)]
    [string]$Template = "",
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("HTML", "PDF", "Word", "PowerPoint")]
    [string]$Format = "HTML",
    
    [Parameter(Mandatory = $false)]
    [ValidateSet("Daily", "Weekly", "Monthly", "Custom")]
    [string]$Period = "Weekly",
    
    [Parameter(Mandatory = $false)]
    [switch]$IncludeCharts
)

# ============================================================================
# CONFIGURAÇÕES GLOBAIS
# ============================================================================

$Script:ReportConfig = @{
    Version = "1.0.0"
    GenerationTime = Get-Date
    ReportType = $ReportType
    DataPath = $DataPath
    OutputPath = $OutputPath
    Format = $Format
    Period = $Period
    IncludeCharts = $IncludeCharts
    CollectedData = @{}
    ReportSections = @()
}

# Templates de relatório
$Script:ReportTemplates = @{
    Executive = @{
        Title = "LogoFAIL Security Executive Summary"
        Sections = @("ExecutiveSummary", "SecurityPosture", "KeyMetrics", "RiskAssessment", "Recommendations")
        Style = "executive"
    }
    Technical = @{
        Title = "LogoFAIL Technical Security Report"
        Sections = @("TechnicalSummary", "SecurityAnalysis", "ThreatDetection", "SystemStatus", "DetailedFindings", "TechnicalRecommendations")
        Style = "technical"
    }
    Compliance = @{
        Title = "LogoFAIL Compliance and Audit Report"
        Sections = @("ComplianceOverview", "SecurityControls", "AuditFindings", "ComplianceStatus", "RemediationPlan")
        Style = "compliance"
    }
    Forensic = @{
        Title = "LogoFAIL Forensic Investigation Report"
        Sections = @("IncidentOverview", "ForensicTimeline", "EvidenceAnalysis", "ThreatActorProfile", "ImpactAssessment", "ForensicConclusions")
        Style = "forensic"
    }
}

# ============================================================================
# FUNÇÕES DE LOGGING
# ============================================================================

function Write-ReportLog {
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
# COLETA DE DADOS
# ============================================================================

function Collect-SecurityData {
    Write-ReportLog "Coletando dados de segurança..." -Level "Info"
    
    $data = @{
        SystemInfo = @{}
        SecurityMetrics = @{}
        Alerts = @()
        Monitoring = @{}
        Forensics = @{}
        QuickChecks = @()
    }
    
    try {
        # Informações do sistema
        $data.SystemInfo = Get-SystemInformation
        
        # Métricas de segurança
        $data.SecurityMetrics = Get-SecurityMetrics
        
        # Alertas recentes
        $data.Alerts = Get-RecentAlerts
        
        # Dados de monitoramento
        $data.Monitoring = Get-MonitoringData
        
        # Dados forenses
        $data.Forensics = Get-ForensicData
        
        # Verificações rápidas
        $data.QuickChecks = Get-QuickCheckData
        
        $Script:ReportConfig.CollectedData = $data
        
        Write-ReportLog "Coleta de dados concluída" -Level "Success"
        return $data
    }
    catch {
        Write-ReportLog "Erro durante coleta de dados: $_" -Level "Error"
        return $data
    }
}

function Get-SystemInformation {
    try {
        $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
        $computerInfo = Get-CimInstance -ClassName Win32_ComputerSystem
        
        return @{
            ComputerName = $env:COMPUTERNAME
            OSVersion = $osInfo.Caption
            OSBuild = $osInfo.BuildNumber
            Manufacturer = $computerInfo.Manufacturer
            Model = $computerInfo.Model
            TotalMemory = [math]::Round($computerInfo.TotalPhysicalMemory / 1GB, 2)
            LastBootTime = $osInfo.LastBootUpTime
            InstallDate = $osInfo.InstallDate
        }
    }
    catch {
        Write-ReportLog "Erro ao coletar informações do sistema: $_" -Level "Warning"
        return @{}
    }
}

function Get-SecurityMetrics {
    try {
        $metrics = @{
            SecureBootStatus = $false
            DefenderStatus = $false
            TPMStatus = $false
            HVCIStatus = $false
            SecurityScore = 0
            LastUpdate = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        }
        
        # Verificar Secure Boot
        try {
            $metrics.SecureBootStatus = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
        } catch { }
        
        # Verificar Windows Defender
        try {
            $defenderStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
            $metrics.DefenderStatus = $defenderStatus.RealTimeProtectionEnabled
        } catch { }
        
        # Verificar TPM
        try {
            $tpm = Get-Tpm -ErrorAction SilentlyContinue
            $metrics.TPMStatus = $tpm.TpmEnabled
        } catch { }
        
        # Calcular score de segurança
        $score = 0
        if ($metrics.SecureBootStatus) { $score += 25 }
        if ($metrics.DefenderStatus) { $score += 25 }
        if ($metrics.TPMStatus) { $score += 25 }
        if ($metrics.HVCIStatus) { $score += 25 }
        
        $metrics.SecurityScore = $score
        
        return $metrics
    }
    catch {
        Write-ReportLog "Erro ao coletar métricas de segurança: $_" -Level "Warning"
        return @{}
    }
}

function Get-RecentAlerts {
    try {
        $alertsPath = Join-Path $Script:ReportConfig.DataPath "Alerts"
        $alerts = @()
        
        if (Test-Path $alertsPath) {
            $alertFiles = Get-ChildItem -Path $alertsPath -Filter "security-alerts-*.json" | Sort-Object LastWriteTime -Descending | Select-Object -First 10
            
            foreach ($file in $alertFiles) {
                $content = Get-Content $file.FullName -Encoding UTF8
                foreach ($line in $content) {
                    try {
                        $alert = $line | ConvertFrom-Json
                        $alerts += $alert
                    } catch { continue }
                }
            }
        }
        
        return $alerts | Sort-Object { Get-Date $_.Timestamp } -Descending | Select-Object -First 50
    }
    catch {
        Write-ReportLog "Erro ao coletar alertas: $_" -Level "Warning"
        return @()
    }
}

function Get-MonitoringData {
    try {
        $logsPath = Join-Path $Script:ReportConfig.DataPath "Logs"
        $monitoringData = @{
            TotalEvents = 0
            CriticalEvents = 0
            LastMonitoringRun = $null
            MonitoringStatus = "Unknown"
        }
        
        if (Test-Path $logsPath) {
            $logFiles = Get-ChildItem -Path $logsPath -Filter "continuous-monitor-*.json" | Sort-Object LastWriteTime -Descending | Select-Object -First 5
            
            $totalEvents = 0
            $criticalEvents = 0
            
            foreach ($file in $logFiles) {
                $content = Get-Content $file.FullName -Encoding UTF8
                foreach ($line in $content) {
                    try {
                        $event = $line | ConvertFrom-Json
                        $totalEvents++
                        if ($event.Level -in @("Critical", "Error")) {
                            $criticalEvents++
                        }
                        
                        if (-not $monitoringData.LastMonitoringRun -or (Get-Date $event.Timestamp) -gt $monitoringData.LastMonitoringRun) {
                            $monitoringData.LastMonitoringRun = Get-Date $event.Timestamp
                        }
                    } catch { continue }
                }
            }
            
            $monitoringData.TotalEvents = $totalEvents
            $monitoringData.CriticalEvents = $criticalEvents
            $monitoringData.MonitoringStatus = if ($monitoringData.LastMonitoringRun -and $monitoringData.LastMonitoringRun -gt (Get-Date).AddHours(-2)) { "Active" } else { "Inactive" }
        }
        
        return $monitoringData
    }
    catch {
        Write-ReportLog "Erro ao coletar dados de monitoramento: $_" -Level "Warning"
        return @{}
    }
}

function Get-ForensicData {
    try {
        $forensicData = @{
            LastForensicScan = $null
            ThreatLevel = "Unknown"
            IoCs = @()
            SuspiciousActivities = @()
        }
        
        # Procurar por relatórios forenses recentes
        $logsPath = Join-Path $Script:ReportConfig.DataPath "Logs"
        if (Test-Path $logsPath) {
            $forensicFiles = Get-ChildItem -Path $logsPath -Filter "forensic-report-*.json" | Sort-Object LastWriteTime -Descending | Select-Object -First 1
            
            if ($forensicFiles) {
                try {
                    $forensicReport = Get-Content $forensicFiles.FullName | ConvertFrom-Json
                    $forensicData.LastForensicScan = $forensicReport.ReportMetadata.GeneratedAt
                    $forensicData.ThreatLevel = $forensicReport.ReportMetadata.ThreatLevel
                } catch { }
            }
        }
        
        return $forensicData
    }
    catch {
        Write-ReportLog "Erro ao coletar dados forenses: $_" -Level "Warning"
        return @{}
    }
}

function Get-QuickCheckData {
    try {
        $quickChecks = @()
        $logsPath = Join-Path $Script:ReportConfig.DataPath "Logs"
        
        if (Test-Path $logsPath) {
            $quickCheckFiles = Get-ChildItem -Path $logsPath -Filter "quick-check-report-*.json" | Sort-Object LastWriteTime -Descending | Select-Object -First 5
            
            foreach ($file in $quickCheckFiles) {
                try {
                    $report = Get-Content $file.FullName | ConvertFrom-Json
                    $quickChecks += @{
                        Timestamp = $report.Timestamp
                        SecurityScore = $report.SecurityScore
                        OverallStatus = $report.OverallStatus
                        MaxScore = $report.MaxScore
                    }
                } catch { }
            }
        }
        
        return $quickChecks
    }
    catch {
        Write-ReportLog "Erro ao coletar dados de verificação rápida: $_" -Level "Warning"
        return @()
    }
}

# ============================================================================
# GERAÇÃO DE SEÇÕES
# ============================================================================

function Generate-ExecutiveSummary {
    param([hashtable]$Data)
    
    $criticalAlerts = ($Data.Alerts | Where-Object { $_.Severity -eq "Critical" }).Count
    $securityScore = $Data.SecurityMetrics.SecurityScore
    $threatLevel = $Data.Forensics.ThreatLevel
    
    $status = if ($criticalAlerts -eq 0 -and $securityScore -ge 80) {
        "SECURE"
    } elseif ($criticalAlerts -le 2 -and $securityScore -ge 60) {
        "MODERATE RISK"
    } else {
        "HIGH RISK"
    }
    
    return @{
        Title = "Executive Summary"
        Content = @{
            OverallStatus = $status
            SecurityScore = "$securityScore/100"
            CriticalAlerts = $criticalAlerts
            ThreatLevel = $threatLevel
            LastUpdate = $Data.SecurityMetrics.LastUpdate
            KeyFindings = @(
                "System security score: $securityScore/100",
                "$criticalAlerts critical security alerts detected",
                "Threat level assessed as: $threatLevel",
                "Monitoring status: $($Data.Monitoring.MonitoringStatus)"
            )
            ExecutiveRecommendations = if ($criticalAlerts -gt 0) {
                @("Immediate attention required for critical alerts", "Review and update security policies", "Enhance monitoring capabilities")
            } else {
                @("Maintain current security posture", "Continue regular monitoring", "Review security policies quarterly")
            }
        }
    }
}

function Generate-SecurityAnalysis {
    param([hashtable]$Data)
    
    return @{
        Title = "Security Analysis"
        Content = @{
            SecureBootStatus = if ($Data.SecurityMetrics.SecureBootStatus) { "Enabled" } else { "Disabled" }
            DefenderStatus = if ($Data.SecurityMetrics.DefenderStatus) { "Active" } else { "Inactive" }
            TPMStatus = if ($Data.SecurityMetrics.TPMStatus) { "Enabled" } else { "Disabled" }
            HVCIStatus = if ($Data.SecurityMetrics.HVCIStatus) { "Enabled" } else { "Disabled" }
            SystemInformation = $Data.SystemInfo
            MonitoringStatistics = @{
                TotalEvents = $Data.Monitoring.TotalEvents
                CriticalEvents = $Data.Monitoring.CriticalEvents
                LastMonitoringRun = $Data.Monitoring.LastMonitoringRun
                MonitoringStatus = $Data.Monitoring.MonitoringStatus
            }
            AlertAnalysis = @{
                TotalAlerts = $Data.Alerts.Count
                CriticalAlerts = ($Data.Alerts | Where-Object { $_.Severity -eq "Critical" }).Count
                HighAlerts = ($Data.Alerts | Where-Object { $_.Severity -eq "High" }).Count
                MediumAlerts = ($Data.Alerts | Where-Object { $_.Severity -eq "Medium" }).Count
                RecentAlerts = $Data.Alerts | Select-Object -First 10
            }
        }
    }
}

function Generate-KeyMetrics {
    param([hashtable]$Data)
    
    $scoreHistory = @()
    if ($Data.QuickChecks.Count -gt 0) {
        $scoreHistory = $Data.QuickChecks | Sort-Object { Get-Date $_.Timestamp } | ForEach-Object {
            @{
                Date = (Get-Date $_.Timestamp).ToString("yyyy-MM-dd")
                Score = $_.SecurityScore
                Status = $_.OverallStatus
            }
        }
    }
    
    return @{
        Title = "Key Security Metrics"
        Content = @{
            CurrentSecurityScore = $Data.SecurityMetrics.SecurityScore
            ScoreHistory = $scoreHistory
            SecurityControls = @{
                SecureBoot = $Data.SecurityMetrics.SecureBootStatus
                WindowsDefender = $Data.SecurityMetrics.DefenderStatus
                TPM = $Data.SecurityMetrics.TPMStatus
                HVCI = $Data.SecurityMetrics.HVCIStatus
            }
            ThreatMetrics = @{
                TotalAlerts = $Data.Alerts.Count
                AlertsLast24h = ($Data.Alerts | Where-Object { (Get-Date $_.Timestamp) -gt (Get-Date).AddDays(-1) }).Count
                AlertsLast7d = ($Data.Alerts | Where-Object { (Get-Date $_.Timestamp) -gt (Get-Date).AddDays(-7) }).Count
                CurrentThreatLevel = $Data.Forensics.ThreatLevel
            }
        }
    }
}

function Generate-TechnicalRecommendations {
    param([hashtable]$Data)
    
    $recommendations = @()
    
    if (-not $Data.SecurityMetrics.SecureBootStatus) {
        $recommendations += @{
            Priority = "Critical"
            Category = "Firmware Security"
            Recommendation = "Enable Secure Boot in UEFI firmware settings"
            Impact = "Prevents unauthorized code execution during boot process"
            Implementation = "Access UEFI settings and enable Secure Boot option"
        }
    }
    
    if (-not $Data.SecurityMetrics.DefenderStatus) {
        $recommendations += @{
            Priority = "Critical"
            Category = "Endpoint Protection"
            Recommendation = "Enable Windows Defender Real-Time Protection"
            Impact = "Provides active malware detection and prevention"
            Implementation = "Enable through Windows Security settings or Group Policy"
        }
    }
    
    if (-not $Data.SecurityMetrics.TPMStatus) {
        $recommendations += @{
            Priority = "High"
            Category = "Hardware Security"
            Recommendation = "Enable TPM 2.0 if available"
            Impact = "Enhances cryptographic operations and secure storage"
            Implementation = "Enable TPM in UEFI settings and initialize in Windows"
        }
    }
    
    if ($Data.Monitoring.MonitoringStatus -eq "Inactive") {
        $recommendations += @{
            Priority = "High"
            Category = "Monitoring"
            Recommendation = "Activate continuous security monitoring"
            Impact = "Enables real-time threat detection and response"
            Implementation = "Execute LogoFAIL-ContinuousMonitor.ps1 with appropriate settings"
        }
    }
    
    return @{
        Title = "Technical Recommendations"
        Content = @{
            Recommendations = $recommendations
            ImplementationPriority = @(
                "Address all Critical priority items immediately",
                "Plan High priority items within 30 days", 
                "Schedule Medium priority items within 90 days"
            )
        }
    }
}

# ============================================================================
# GERAÇÃO DE RELATÓRIO
# ============================================================================

function Generate-Report {
    param([hashtable]$Data)
    
    Write-ReportLog "Gerando relatório $($Script:ReportConfig.ReportType)..." -Level "Info"
    
    $template = $Script:ReportTemplates[$Script:ReportConfig.ReportType]
    $sections = @()
    
    foreach ($sectionName in $template.Sections) {
        try {
            $section = switch ($sectionName) {
                "ExecutiveSummary" { Generate-ExecutiveSummary -Data $Data }
                "SecurityPosture" { Generate-SecurityAnalysis -Data $Data }
                "KeyMetrics" { Generate-KeyMetrics -Data $Data }
                "TechnicalSummary" { Generate-SecurityAnalysis -Data $Data }
                "SecurityAnalysis" { Generate-SecurityAnalysis -Data $Data }
                "TechnicalRecommendations" { Generate-TechnicalRecommendations -Data $Data }
                default { 
                    @{
                        Title = $sectionName
                        Content = @{ Message = "Section not yet implemented" }
                    }
                }
            }
            
            $sections += $section
        }
        catch {
            Write-ReportLog "Erro ao gerar seção $sectionName`: $_" -Level "Warning"
        }
    }
    
    $report = @{
        Metadata = @{
            Title = $template.Title
            GeneratedAt = $Script:ReportConfig.GenerationTime.ToString("yyyy-MM-dd HH:mm:ss")
            ReportType = $Script:ReportConfig.ReportType
            Period = $Script:ReportConfig.Period
            Version = $Script:ReportConfig.Version
            Computer = $env:COMPUTERNAME
        }
        Sections = $sections
        Data = $Data
    }
    
    $Script:ReportConfig.ReportSections = $sections
    
    return $report
}

function Export-Report {
    param([hashtable]$Report)
    
    Write-ReportLog "Exportando relatório em formato $($Script:ReportConfig.Format)..." -Level "Info"
    
    # Criar diretório de saída se não existir
    if (-not (Test-Path $Script:ReportConfig.OutputPath)) {
        New-Item -Path $Script:ReportConfig.OutputPath -ItemType Directory -Force | Out-Null
    }
    
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $fileName = "LogoFAIL-Report-$($Script:ReportConfig.ReportType)-$timestamp"
    
    switch ($Script:ReportConfig.Format) {
        "HTML" {
            $outputFile = Join-Path $Script:ReportConfig.OutputPath "$fileName.html"
            $htmlContent = Generate-HTMLReport -Report $Report
            $htmlContent | Set-Content -Path $outputFile -Encoding UTF8
        }
        
        "JSON" {
            $outputFile = Join-Path $Script:ReportConfig.OutputPath "$fileName.json"
            $Report | ConvertTo-Json -Depth 6 | Set-Content -Path $outputFile -Encoding UTF8
        }
        
        default {
            $outputFile = Join-Path $Script:ReportConfig.OutputPath "$fileName.json"
            $Report | ConvertTo-Json -Depth 6 | Set-Content -Path $outputFile -Encoding UTF8
            Write-ReportLog "Formato $($Script:ReportConfig.Format) não implementado, usando JSON" -Level "Warning"
        }
    }
    
    Write-ReportLog "Relatório exportado para: $outputFile" -Level "Success"
    return $outputFile
}

function Generate-HTMLReport {
    param([hashtable]$Report)
    
    $html = @"
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>$($Report.Metadata.Title)</title>
    <style>
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            margin: 0; 
            padding: 20px; 
            background: #f8f9fa; 
            color: #333;
        }
        .container { 
            max-width: 1200px; 
            margin: 0 auto; 
            background: white; 
            border-radius: 10px; 
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        .header { 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
            color: white; 
            padding: 40px; 
            text-align: center;
        }
        .header h1 { margin: 0; font-size: 2.5em; font-weight: 300; }
        .header p { margin: 10px 0 0 0; opacity: 0.9; }
        .section { 
            margin: 0; 
            padding: 30px; 
            border-bottom: 1px solid #eee;
        }
        .section:last-child { border-bottom: none; }
        .section h2 { 
            color: #2c3e50; 
            border-bottom: 3px solid #3498db; 
            padding-bottom: 10px; 
            margin-bottom: 20px;
        }
        .metric-grid { 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); 
            gap: 20px; 
            margin: 20px 0;
        }
        .metric-card { 
            background: #f8f9fa; 
            border-radius: 8px; 
            padding: 20px; 
            text-align: center; 
            border-left: 4px solid #3498db;
        }
        .metric-value { 
            font-size: 2em; 
            font-weight: bold; 
            color: #2c3e50; 
            margin-bottom: 5px;
        }
        .metric-label { 
            color: #7f8c8d; 
            font-size: 0.9em;
        }
        .status-good { color: #27ae60; }
        .status-warning { color: #f39c12; }
        .status-critical { color: #e74c3c; }
        .recommendations { 
            background: #fff3cd; 
            border: 1px solid #ffeaa7; 
            border-radius: 8px; 
            padding: 20px; 
            margin: 20px 0;
        }
        .recommendation-item { 
            margin: 10px 0; 
            padding: 10px; 
            background: white; 
            border-radius: 5px;
            border-left: 4px solid #f39c12;
        }
        table { 
            width: 100%; 
            border-collapse: collapse; 
            margin: 20px 0; 
            background: white;
        }
        th, td { 
            border: 1px solid #ddd; 
            padding: 12px; 
            text-align: left;
        }
        th { 
            background: #34495e; 
            color: white; 
            font-weight: 500;
        }
        tr:nth-child(even) { background: #f8f9fa; }
        .footer { 
            background: #2c3e50; 
            color: white; 
            padding: 20px; 
            text-align: center; 
            font-size: 0.9em;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>$($Report.Metadata.Title)</h1>
            <p>Generated: $($Report.Metadata.GeneratedAt) | Computer: $($Report.Metadata.Computer)</p>
            <p>Report Type: $($Report.Metadata.ReportType) | Period: $($Report.Metadata.Period)</p>
        </div>
"@
    
    # Adicionar seções
    foreach ($section in $Report.Sections) {
        $html += "`n        <div class='section'>`n"
        $html += "            <h2>$($section.Title)</h2>`n"
        
        # Processar conteúdo baseado no tipo de seção
        if ($section.Title -eq "Executive Summary") {
            $statusClass = switch ($section.Content.OverallStatus) {
                "SECURE" { "status-good" }
                "MODERATE RISK" { "status-warning" }
                "HIGH RISK" { "status-critical" }
                default { "status-warning" }
            }
            
            $html += @"
            <div class="metric-grid">
                <div class="metric-card">
                    <div class="metric-value $statusClass">$($section.Content.OverallStatus)</div>
                    <div class="metric-label">Overall Status</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value">$($section.Content.SecurityScore)</div>
                    <div class="metric-label">Security Score</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value">$($section.Content.CriticalAlerts)</div>
                    <div class="metric-label">Critical Alerts</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value">$($section.Content.ThreatLevel)</div>
                    <div class="metric-label">Threat Level</div>
                </div>
            </div>
"@
        }
        
        if ($section.Content.Recommendations) {
            $html += "            <div class='recommendations'>`n"
            $html += "                <h3>Recommendations</h3>`n"
            foreach ($rec in $section.Content.Recommendations) {
                $html += "                <div class='recommendation-item'>$rec</div>`n"
            }
            $html += "            </div>`n"
        }
        
        $html += "        </div>`n"
    }
    
    $html += @"
        <div class="footer">
            <p>Generated by LogoFAIL Report Generator v$($Report.Metadata.Version)</p>
            <p>For technical support, contact your system administrator</p>
        </div>
    </div>
</body>
</html>
"@
    
    return $html
}

# ============================================================================
# FUNÇÃO PRINCIPAL
# ============================================================================

function Start-ReportGeneration {
    Write-Host "======================================================================" -ForegroundColor Cyan
    Write-Host "    LogoFAIL Report Generator - Geração de Relatórios de Segurança" -ForegroundColor Cyan
    Write-Host "    Versão: $($Script:ReportConfig.Version)" -ForegroundColor Cyan
    Write-Host "======================================================================" -ForegroundColor Cyan
    Write-Host ""
    
    try {
        # Coletar dados
        $data = Collect-SecurityData
        
        # Gerar relatório
        $report = Generate-Report -Data $data
        
        # Exportar relatório
        $outputFile = Export-Report -Report $report
        
        Write-Host ""
        Write-Host "======================================================================" -ForegroundColor Green
        Write-Host "    Relatório Gerado com Sucesso!" -ForegroundColor Green
        Write-Host "======================================================================" -ForegroundColor Green
        Write-Host ""
        
        Write-Host "DETALHES DO RELATÓRIO:" -ForegroundColor Yellow
        Write-Host "- Tipo: $($Script:ReportConfig.ReportType)" -ForegroundColor White
        Write-Host "- Formato: $($Script:ReportConfig.Format)" -ForegroundColor White
        Write-Host "- Período: $($Script:ReportConfig.Period)" -ForegroundColor White
        Write-Host "- Arquivo: $outputFile" -ForegroundColor White
        Write-Host "- Seções incluídas: $($report.Sections.Count)" -ForegroundColor White
        
        $duration = ((Get-Date) - $Script:ReportConfig.GenerationTime).TotalSeconds
        Write-Host "- Tempo de geração: $([math]::Round($duration, 2)) segundos" -ForegroundColor White
        
        return $true
    }
    catch {
        Write-ReportLog "Erro durante geração do relatório: $_" -Level "Error"
        return $false
    }
}

# ============================================================================
# EXECUÇÃO PRINCIPAL
# ============================================================================

try {
    $result = Start-ReportGeneration
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