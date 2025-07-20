#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Uninstall LogoFAIL Protection - Remoção Limpa do Sistema de Proteção
    
.DESCRIPTION
    Script para remoção completa e segura do sistema de proteção LogoFAIL.
    Remove configurações, tarefas agendadas, logs e restaura configurações
    do sistema quando apropriado, mantendo backups de segurança.
    
.PARAMETER PreserveBackups
    Mantém arquivos de backup durante a desinstalação
    
.PARAMETER PreserveLogs
    Mantém arquivos de log durante a desinstalação
    
.PARAMETER RestoreOriginalConfig
    Restaura configurações originais do sistema a partir dos backups
    
.PARAMETER Force
    Força a remoção mesmo se houver erros
    
.PARAMETER WhatIf
    Mostra o que seria removido sem executar a remoção
    
.EXAMPLE
    .\Uninstall-LogoFAILProtection.ps1 -PreserveBackups -PreserveLogs
    
.NOTES
    Author: Matheus-TestUser1
    Version: 1.0.0
    Requires: Windows 10/11, PowerShell 5.1+, Administrator privileges
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory = $false)]
    [switch]$PreserveBackups,
    
    [Parameter(Mandatory = $false)]
    [switch]$PreserveLogs,
    
    [Parameter(Mandatory = $false)]
    [switch]$RestoreOriginalConfig,
    
    [Parameter(Mandatory = $false)]
    [switch]$Force,
    
    [Parameter(Mandatory = $false)]
    [switch]$WhatIf
)

# ============================================================================
# CONFIGURAÇÕES GLOBAIS
# ============================================================================

$Script:UninstallConfig = @{
    Version = "1.0.0"
    StartTime = Get-Date
    BasePath = "$env:ProgramData\WindowsDefenseLogoFAIL"
    InstallPath = "$env:ProgramFiles\WindowsDefenseLogoFAIL"
    TaskName = "LogoFAIL-ContinuousMonitor"
    EventSource = "LogoFAILDefense"
    ItemsToRemove = @()
    ItemsPreserved = @()
    BackupsRestored = @()
    Errors = @()
}

# ============================================================================
# FUNÇÕES DE LOGGING
# ============================================================================

function Write-UninstallLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("Info", "Warning", "Error", "Success", "Debug")]
        [string]$Level = "Info"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    
    $color = switch ($Level) {
        "Info" { "Cyan" }
        "Warning" { "Yellow" }
        "Error" { "Red" }
        "Success" { "Green" }
        "Debug" { "Gray" }
    }
    
    $prefix = if ($WhatIf) { "[WHAT-IF] " } else { "" }
    Write-Host "$prefix[$timestamp] $Message" -ForegroundColor $color
    
    # Log para arquivo se possível
    try {
        if (Test-Path "$($Script:UninstallConfig.BasePath)\Logs") {
            $logFile = Join-Path "$($Script:UninstallConfig.BasePath)\Logs" "uninstall-$(Get-Date -Format 'yyyy-MM-dd').log"
            "$prefix[$timestamp] [$Level] $Message" | Add-Content -Path $logFile -Encoding UTF8
        }
    }
    catch {
        # Ignore logging errors during uninstall
    }
}

function Add-RemovalItem {
    param(
        [string]$ItemType,
        [string]$ItemPath,
        [string]$Description
    )
    
    $Script:UninstallConfig.ItemsToRemove += @{
        Type = $ItemType
        Path = $ItemPath
        Description = $Description
        Removed = $false
    }
}

# ============================================================================
# VERIFICAÇÕES PRÉ-REMOÇÃO
# ============================================================================

function Test-UninstallPrerequisites {
    Write-UninstallLog "Verificando pré-requisitos para desinstalação..." -Level "Info"
    
    $issues = @()
    
    try {
        # Verificar privilégios de administrador
        $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
        if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            $issues += "Privilégios de administrador são necessários"
        }
        
        # Verificar se o sistema está instalado
        if (-not (Test-Path $Script:UninstallConfig.BasePath)) {
            $issues += "Sistema LogoFAIL não parece estar instalado"
            Write-UninstallLog "Diretório base não encontrado: $($Script:UninstallConfig.BasePath)" -Level "Warning"
        }
        
        # Verificar processos em execução
        $runningProcesses = Get-Process | Where-Object { $_.ProcessName -like "*LogoFAIL*" }
        if ($runningProcesses) {
            $issues += "Processos LogoFAIL ainda em execução: $($runningProcesses.ProcessName -join ', ')"
        }
        
        # Verificar tarefa agendada
        $scheduledTask = Get-ScheduledTask -TaskName $Script:UninstallConfig.TaskName -ErrorAction SilentlyContinue
        if ($scheduledTask -and $scheduledTask.State -eq "Running") {
            $issues += "Tarefa agendada ainda em execução"
        }
        
        if ($issues.Count -gt 0) {
            Write-UninstallLog "Problemas encontrados:" -Level "Warning"
            foreach ($issue in $issues) {
                Write-UninstallLog "  - $issue" -Level "Warning"
            }
            
            if (-not $Force) {
                Write-UninstallLog "Use -Force para prosseguir mesmo com problemas" -Level "Warning"
                return $false
            }
        }
        
        Write-UninstallLog "Pré-requisitos verificados" -Level "Success"
        return $true
    }
    catch {
        Write-UninstallLog "Erro durante verificação de pré-requisitos: $_" -Level "Error"
        return $Force
    }
}

# ============================================================================
# INVENTÁRIO DE ITENS INSTALADOS
# ============================================================================

function Get-InstalledComponents {
    Write-UninstallLog "Identificando componentes instalados..." -Level "Info"
    
    try {
        # Diretórios principais
        $directories = @(
            @{ Path = $Script:UninstallConfig.BasePath; Description = "Diretório principal de dados" },
            @{ Path = $Script:UninstallConfig.InstallPath; Description = "Diretório de instalação" },
            @{ Path = "$($Script:UninstallConfig.BasePath)\Logs"; Description = "Logs do sistema" },
            @{ Path = "$($Script:UninstallConfig.BasePath)\Config"; Description = "Configurações" },
            @{ Path = "$($Script:UninstallConfig.BasePath)\Baselines"; Description = "Baselines de segurança" },
            @{ Path = "$($Script:UninstallConfig.BasePath)\Backups"; Description = "Backups do sistema" },
            @{ Path = "$($Script:UninstallConfig.BasePath)\Alerts"; Description = "Alertas gerados" }
        )
        
        foreach ($dir in $directories) {
            if (Test-Path $dir.Path) {
                $itemType = if ($dir.Path -like "*Logs*" -and $PreserveLogs) { "PreservedDirectory" } 
                           elseif ($dir.Path -like "*Backups*" -and $PreserveBackups) { "PreservedDirectory" }
                           else { "Directory" }
                
                Add-RemovalItem -ItemType $itemType -ItemPath $dir.Path -Description $dir.Description
            }
        }
        
        # Tarefa agendada
        $scheduledTask = Get-ScheduledTask -TaskName $Script:UninstallConfig.TaskName -ErrorAction SilentlyContinue
        if ($scheduledTask) {
            Add-RemovalItem -ItemType "ScheduledTask" -ItemPath $Script:UninstallConfig.TaskName -Description "Tarefa de monitoramento contínuo"
        }
        
        # Fonte de eventos
        try {
            if ([System.Diagnostics.EventLog]::SourceExists($Script:UninstallConfig.EventSource)) {
                Add-RemovalItem -ItemType "EventSource" -ItemPath $Script:UninstallConfig.EventSource -Description "Fonte de eventos do sistema"
            }
        }
        catch {
            # Source may not exist or not accessible
        }
        
        # Configurações de registro específicas (se existirem)
        $registryPaths = @(
            "HKLM:\SOFTWARE\WindowsDefenseLogoFAIL",
            "HKCU:\SOFTWARE\WindowsDefenseLogoFAIL"
        )
        
        foreach ($regPath in $registryPaths) {
            if (Test-Path $regPath) {
                Add-RemovalItem -ItemType "RegistryKey" -ItemPath $regPath -Description "Configurações de registro"
            }
        }
        
        # Scripts em locais do sistema
        $systemScripts = @(
            "$env:SystemRoot\System32\WindowsPowerShell\v1.0\Modules\LogoFAILDefense",
            "$env:ProgramFiles\WindowsPowerShell\Modules\LogoFAILDefense"
        )
        
        foreach ($scriptPath in $systemScripts) {
            if (Test-Path $scriptPath) {
                Add-RemovalItem -ItemType "Directory" -ItemPath $scriptPath -Description "Módulos PowerShell"
            }
        }
        
        $totalItems = $Script:UninstallConfig.ItemsToRemove.Count
        Write-UninstallLog "Encontrados $totalItems componentes para remoção" -Level "Info"
        
        return $true
    }
    catch {
        Write-UninstallLog "Erro ao identificar componentes: $_" -Level "Error"
        return $false
    }
}

# ============================================================================
# BACKUP E RESTAURAÇÃO
# ============================================================================

function Restore-OriginalConfigurations {
    if (-not $RestoreOriginalConfig) {
        return $true
    }
    
    Write-UninstallLog "Restaurando configurações originais do sistema..." -Level "Info"
    
    try {
        $backupPath = Join-Path $Script:UninstallConfig.BasePath "Backups"
        
        if (-not (Test-Path $backupPath)) {
            Write-UninstallLog "Nenhum backup encontrado para restauração" -Level "Warning"
            return $true
        }
        
        # Encontrar backups mais recentes
        $backupDirs = Get-ChildItem -Path $backupPath -Directory | Sort-Object LastWriteTime -Descending
        
        if ($backupDirs.Count -eq 0) {
            Write-UninstallLog "Nenhum diretório de backup encontrado" -Level "Warning"
            return $true
        }
        
        $latestBackup = $backupDirs[0]
        Write-UninstallLog "Usando backup: $($latestBackup.Name)" -Level "Info"
        
        # Restaurar arquivos de registro
        $regFiles = Get-ChildItem -Path $latestBackup.FullName -Filter "*.reg"
        foreach ($regFile in $regFiles) {
            try {
                if ($WhatIf) {
                    Write-UninstallLog "Restauraria registro: $($regFile.Name)" -Level "Info"
                } else {
                    & reg.exe import $regFile.FullName 2>$null
                    if ($LASTEXITCODE -eq 0) {
                        Write-UninstallLog "Registro restaurado: $($regFile.Name)" -Level "Success"
                        $Script:UninstallConfig.BackupsRestored += $regFile.Name
                    } else {
                        Write-UninstallLog "Erro ao restaurar registro: $($regFile.Name)" -Level "Warning"
                    }
                }
            }
            catch {
                Write-UninstallLog "Erro ao restaurar $($regFile.Name): $_" -Level "Warning"
            }
        }
        
        # Restaurar políticas de segurança
        $securityBackup = Get-ChildItem -Path $latestBackup.FullName -Filter "secedit-backup.inf"
        if ($securityBackup) {
            try {
                if ($WhatIf) {
                    Write-UninstallLog "Restauraria políticas de segurança" -Level "Info"
                } else {
                    $tempDb = "$env:TEMP\secedit-restore.sdb"
                    & secedit.exe /configure /cfg $securityBackup.FullName /db $tempDb /quiet
                    
                    if ($LASTEXITCODE -eq 0) {
                        Write-UninstallLog "Políticas de segurança restauradas" -Level "Success"
                        $Script:UninstallConfig.BackupsRestored += "Security Policies"
                    } else {
                        Write-UninstallLog "Erro ao restaurar políticas de segurança" -Level "Warning"
                    }
                    
                    # Limpar arquivo temporário
                    if (Test-Path $tempDb) {
                        Remove-Item $tempDb -Force -ErrorAction SilentlyContinue
                    }
                }
            }
            catch {
                Write-UninstallLog "Erro ao restaurar políticas de segurança: $_" -Level "Warning"
            }
        }
        
        Write-UninstallLog "Restauração de configurações concluída" -Level "Success"
        return $true
    }
    catch {
        Write-UninstallLog "Erro durante restauração: $_" -Level "Error"
        return $Force
    }
}

function Create-UninstallBackup {
    Write-UninstallLog "Criando backup antes da desinstalação..." -Level "Info"
    
    try {
        $backupDir = Join-Path $Script:UninstallConfig.BasePath "Uninstall-Backup-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
        
        if ($WhatIf) {
            Write-UninstallLog "Criaria backup em: $backupDir" -Level "Info"
            return $true
        }
        
        if (-not (Test-Path $backupDir)) {
            New-Item -Path $backupDir -ItemType Directory -Force | Out-Null
        }
        
        # Backup de configurações importantes
        $configPath = Join-Path $Script:UninstallConfig.BasePath "Config"
        if (Test-Path $configPath) {
            $configBackup = Join-Path $backupDir "Config"
            Copy-Item -Path $configPath -Destination $configBackup -Recurse -Force
            Write-UninstallLog "Configurações salvas no backup" -Level "Success"
        }
        
        # Backup de alguns logs recentes
        $logsPath = Join-Path $Script:UninstallConfig.BasePath "Logs"
        if (Test-Path $logsPath) {
            $recentLogs = Get-ChildItem -Path $logsPath -File | Where-Object { $_.LastWriteTime -gt (Get-Date).AddDays(-7) }
            if ($recentLogs) {
                $logsBackup = Join-Path $backupDir "RecentLogs"
                New-Item -Path $logsBackup -ItemType Directory -Force | Out-Null
                $recentLogs | Copy-Item -Destination $logsBackup -Force
                Write-UninstallLog "Logs recentes salvos no backup" -Level "Success"
            }
        }
        
        # Backup de alertas
        $alertsPath = Join-Path $Script:UninstallConfig.BasePath "Alerts"
        if (Test-Path $alertsPath) {
            $alertsBackup = Join-Path $backupDir "Alerts"
            Copy-Item -Path $alertsPath -Destination $alertsBackup -Recurse -Force
            Write-UninstallLog "Alertas salvos no backup" -Level "Success"
        }
        
        Write-UninstallLog "Backup de desinstalação criado: $backupDir" -Level "Success"
        return $true
    }
    catch {
        Write-UninstallLog "Erro ao criar backup de desinstalação: $_" -Level "Warning"
        return $Force
    }
}

# ============================================================================
# REMOÇÃO DE COMPONENTES
# ============================================================================

function Remove-ScheduledTasks {
    Write-UninstallLog "Removendo tarefas agendadas..." -Level "Info"
    
    try {
        $task = Get-ScheduledTask -TaskName $Script:UninstallConfig.TaskName -ErrorAction SilentlyContinue
        
        if ($task) {
            if ($WhatIf) {
                Write-UninstallLog "Removeria tarefa agendada: $($Script:UninstallConfig.TaskName)" -Level "Info"
            } else {
                Unregister-ScheduledTask -TaskName $Script:UninstallConfig.TaskName -Confirm:$false
                Write-UninstallLog "Tarefa agendada removida: $($Script:UninstallConfig.TaskName)" -Level "Success"
            }
        } else {
            Write-UninstallLog "Tarefa agendada não encontrada" -Level "Info"
        }
        
        return $true
    }
    catch {
        $error = "Erro ao remover tarefa agendada: $_"
        Write-UninstallLog $error -Level "Error"
        $Script:UninstallConfig.Errors += $error
        return $Force
    }
}

function Remove-EventSources {
    Write-UninstallLog "Removendo fontes de eventos..." -Level "Info"
    
    try {
        if ([System.Diagnostics.EventLog]::SourceExists($Script:UninstallConfig.EventSource)) {
            if ($WhatIf) {
                Write-UninstallLog "Removeria fonte de eventos: $($Script:UninstallConfig.EventSource)" -Level "Info"
            } else {
                [System.Diagnostics.EventLog]::DeleteEventSource($Script:UninstallConfig.EventSource)
                Write-UninstallLog "Fonte de eventos removida: $($Script:UninstallConfig.EventSource)" -Level "Success"
            }
        } else {
            Write-UninstallLog "Fonte de eventos não encontrada" -Level "Info"
        }
        
        return $true
    }
    catch {
        $error = "Erro ao remover fonte de eventos: $_"
        Write-UninstallLog $error -Level "Warning"
        # Not critical error
        return $true
    }
}

function Remove-RegistryEntries {
    Write-UninstallLog "Removendo entradas de registro..." -Level "Info"
    
    try {
        $registryPaths = @(
            "HKLM:\SOFTWARE\WindowsDefenseLogoFAIL",
            "HKCU:\SOFTWARE\WindowsDefenseLogoFAIL"
        )
        
        foreach ($regPath in $registryPaths) {
            if (Test-Path $regPath) {
                if ($WhatIf) {
                    Write-UninstallLog "Removeria chave de registro: $regPath" -Level "Info"
                } else {
                    Remove-Item -Path $regPath -Recurse -Force
                    Write-UninstallLog "Chave de registro removida: $regPath" -Level "Success"
                }
            }
        }
        
        return $true
    }
    catch {
        $error = "Erro ao remover entradas de registro: $_"
        Write-UninstallLog $error -Level "Error"
        $Script:UninstallConfig.Errors += $error
        return $Force
    }
}

function Remove-FileSystemComponents {
    Write-UninstallLog "Removendo componentes do sistema de arquivos..." -Level "Info"
    
    try {
        $itemsToRemove = $Script:UninstallConfig.ItemsToRemove | Where-Object { $_.Type -in @("Directory", "File") }
        
        foreach ($item in $itemsToRemove) {
            try {
                if (Test-Path $item.Path) {
                    if ($WhatIf) {
                        Write-UninstallLog "Removeria: $($item.Path) ($($item.Description))" -Level "Info"
                    } else {
                        if (Test-Path $item.Path -PathType Container) {
                            Remove-Item -Path $item.Path -Recurse -Force
                        } else {
                            Remove-Item -Path $item.Path -Force
                        }
                        
                        Write-UninstallLog "Removido: $($item.Description)" -Level "Success"
                        $item.Removed = $true
                    }
                } else {
                    Write-UninstallLog "Não encontrado: $($item.Path)" -Level "Debug"
                }
            }
            catch {
                $error = "Erro ao remover $($item.Path): $_"
                Write-UninstallLog $error -Level "Warning"
                $Script:UninstallConfig.Errors += $error
            }
        }
        
        return $true
    }
    catch {
        $error = "Erro durante remoção de arquivos: $_"
        Write-UninstallLog $error -Level "Error"
        $Script:UninstallConfig.Errors += $error
        return $Force
    }
}

function Stop-RunningProcesses {
    Write-UninstallLog "Parando processos em execução..." -Level "Info"
    
    try {
        $logoFailProcesses = Get-Process | Where-Object { $_.ProcessName -like "*LogoFAIL*" }
        
        foreach ($process in $logoFailProcesses) {
            try {
                if ($WhatIf) {
                    Write-UninstallLog "Pararia processo: $($process.ProcessName) (PID: $($process.Id))" -Level "Info"
                } else {
                    Stop-Process -Id $process.Id -Force
                    Write-UninstallLog "Processo parado: $($process.ProcessName) (PID: $($process.Id))" -Level "Success"
                }
            }
            catch {
                Write-UninstallLog "Erro ao parar processo $($process.ProcessName): $_" -Level "Warning"
            }
        }
        
        return $true
    }
    catch {
        Write-UninstallLog "Erro ao parar processos: $_" -Level "Warning"
        return $true  # Not critical
    }
}

# ============================================================================
# FUNÇÃO PRINCIPAL
# ============================================================================

function Start-LogoFAILUninstall {
    Write-Host "======================================================================" -ForegroundColor Cyan
    Write-Host "    Uninstall LogoFAIL Protection - Remoção do Sistema de Proteção" -ForegroundColor Cyan
    Write-Host "    Versão: $($Script:UninstallConfig.Version)" -ForegroundColor Cyan
    Write-Host "======================================================================" -ForegroundColor Cyan
    
    if ($WhatIf) {
        Write-Host ""
        Write-Host "MODO WHAT-IF: Mostrando o que seria removido sem executar a remoção" -ForegroundColor Yellow
    }
    
    Write-Host ""
    
    # Verificar pré-requisitos
    if (-not (Test-UninstallPrerequisites)) {
        Write-UninstallLog "Falha na verificação de pré-requisitos" -Level "Error"
        return $false
    }
    
    # Identificar componentes instalados
    if (-not (Get-InstalledComponents)) {
        Write-UninstallLog "Falha ao identificar componentes" -Level "Error"
        return $false
    }
    
    # Mostrar resumo do que será removido
    Write-Host "COMPONENTES IDENTIFICADOS PARA REMOÇÃO:" -ForegroundColor Yellow
    
    $normalItems = $Script:UninstallConfig.ItemsToRemove | Where-Object { $_.Type -ne "PreservedDirectory" }
    $preservedItems = $Script:UninstallConfig.ItemsToRemove | Where-Object { $_.Type -eq "PreservedDirectory" }
    
    foreach ($item in $normalItems) {
        Write-Host "  ✗ $($item.Description): $($item.Path)" -ForegroundColor Red
    }
    
    if ($preservedItems.Count -gt 0) {
        Write-Host ""
        Write-Host "COMPONENTES PRESERVADOS:" -ForegroundColor Green
        foreach ($item in $preservedItems) {
            Write-Host "  ✓ $($item.Description): $($item.Path)" -ForegroundColor Green
            $Script:UninstallConfig.ItemsPreserved += $item
        }
    }
    
    Write-Host ""
    
    # Confirmação para prosseguir
    if (-not $WhatIf -and -not $Force) {
        $response = Read-Host "Deseja prosseguir com a desinstalação? (y/N)"
        if ($response -notmatch '^[Yy]') {
            Write-UninstallLog "Desinstalação cancelada pelo usuário" -Level "Info"
            return $false
        }
    }
    
    Write-UninstallLog "Iniciando processo de desinstalação..." -Level "Info"
    
    # Criar backup antes da remoção
    if (-not (Create-UninstallBackup)) {
        Write-UninstallLog "Falha ao criar backup - continuando..." -Level "Warning"
    }
    
    # Restaurar configurações originais se solicitado
    if (-not (Restore-OriginalConfigurations)) {
        Write-UninstallLog "Falha na restauração de configurações" -Level "Warning"
    }
    
    # Parar processos em execução
    if (-not (Stop-RunningProcesses)) {
        Write-UninstallLog "Falha ao parar processos" -Level "Warning"
    }
    
    # Remover tarefas agendadas
    if (-not (Remove-ScheduledTasks)) {
        Write-UninstallLog "Falha ao remover tarefas agendadas" -Level "Warning"
    }
    
    # Remover fontes de eventos
    if (-not (Remove-EventSources)) {
        Write-UninstallLog "Falha ao remover fontes de eventos" -Level "Warning"
    }
    
    # Remover entradas de registro
    if (-not (Remove-RegistryEntries)) {
        Write-UninstallLog "Falha ao remover entradas de registro" -Level "Warning"
    }
    
    # Remover arquivos e diretórios
    if (-not (Remove-FileSystemComponents)) {
        Write-UninstallLog "Falha ao remover componentes de arquivos" -Level "Warning"
    }
    
    # Exibir resumo final
    Write-Host ""
    Write-Host "======================================================================" -ForegroundColor Green
    Write-Host "    Desinstalação Concluída" -ForegroundColor Green
    Write-Host "======================================================================" -ForegroundColor Green
    Write-Host ""
    
    # Estatísticas
    $removedItems = ($Script:UninstallConfig.ItemsToRemove | Where-Object { $_.Removed }).Count
    $totalItems = ($Script:UninstallConfig.ItemsToRemove | Where-Object { $_.Type -ne "PreservedDirectory" }).Count
    
    Write-Host "RESUMO DA DESINSTALAÇÃO:" -ForegroundColor Yellow
    Write-Host "- Itens removidos: $removedItems de $totalItems" -ForegroundColor White
    Write-Host "- Itens preservados: $($Script:UninstallConfig.ItemsPreserved.Count)" -ForegroundColor White
    Write-Host "- Configurações restauradas: $($Script:UninstallConfig.BackupsRestored.Count)" -ForegroundColor White
    Write-Host "- Erros encontrados: $($Script:UninstallConfig.Errors.Count)" -ForegroundColor White
    
    if ($Script:UninstallConfig.ItemsPreserved.Count -gt 0) {
        Write-Host ""
        Write-Host "ITENS PRESERVADOS:" -ForegroundColor Yellow
        foreach ($item in $Script:UninstallConfig.ItemsPreserved) {
            Write-Host "  - $($item.Description): $($item.Path)" -ForegroundColor Gray
        }
    }
    
    if ($Script:UninstallConfig.BackupsRestored.Count -gt 0) {
        Write-Host ""
        Write-Host "CONFIGURAÇÕES RESTAURADAS:" -ForegroundColor Yellow
        foreach ($backup in $Script:UninstallConfig.BackupsRestored) {
            Write-Host "  - $backup" -ForegroundColor Gray
        }
    }
    
    if ($Script:UninstallConfig.Errors.Count -gt 0) {
        Write-Host ""
        Write-Host "ERROS ENCONTRADOS:" -ForegroundColor Red
        foreach ($error in $Script:UninstallConfig.Errors) {
            Write-Host "  - $error" -ForegroundColor Red
        }
        
        Write-Host ""
        Write-Host "NOTA: Alguns erros são normais durante a desinstalação." -ForegroundColor Yellow
        Write-Host "Se problemas persistirem, execute novamente com -Force" -ForegroundColor Yellow
    }
    
    # Recomendações finais
    Write-Host ""
    Write-Host "RECOMENDAÇÕES PÓS-DESINSTALAÇÃO:" -ForegroundColor Yellow
    Write-Host "1. Reinicie o sistema para garantir que todas as alterações tenham efeito" -ForegroundColor White
    Write-Host "2. Verifique se não há processos órfãos em execução" -ForegroundColor White
    Write-Host "3. Revise configurações de segurança do sistema" -ForegroundColor White
    
    if ($Script:UninstallConfig.ItemsPreserved.Count -gt 0) {
        Write-Host "4. Remova manualmente os itens preservados se não precisar mais deles" -ForegroundColor White
    }
    
    $duration = ((Get-Date) - $Script:UninstallConfig.StartTime).TotalSeconds
    Write-Host ""
    Write-Host "Desinstalação concluída em $([math]::Round($duration, 1)) segundos" -ForegroundColor Gray
    
    return $Script:UninstallConfig.Errors.Count -eq 0
}

# ============================================================================
# EXECUÇÃO PRINCIPAL
# ============================================================================

try {
    $result = Start-LogoFAILUninstall
    if ($result) {
        Write-Host ""
        Write-Host "✓ Desinstalação bem-sucedida!" -ForegroundColor Green
        exit 0
    } else {
        Write-Host ""
        Write-Host "⚠ Desinstalação concluída com avisos" -ForegroundColor Yellow
        exit 0
    }
}
catch {
    Write-Host ""
    Write-Host "✗ Erro fatal durante desinstalação: $_" -ForegroundColor Red
    exit 1
}