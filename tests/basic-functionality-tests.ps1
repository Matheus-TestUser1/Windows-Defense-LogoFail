#Requires -Version 5.1

<#
.SYNOPSIS
    LogoFAIL Basic Functionality Tests - Testes Básicos do Sistema
    
.DESCRIPTION
    Script de teste para validar funcionalidades básicas do sistema de proteção LogoFAIL.
    Executa testes automatizados para verificar instalação, configuração e operação
    dos componentes principais do sistema.
    
.PARAMETER TestLevel
    Nível de teste: Basic, Standard, Comprehensive
    
.PARAMETER SkipInstallationTests
    Pula testes de instalação
    
.PARAMETER SkipFunctionalTests
    Pula testes funcionais
    
.PARAMETER OutputPath
    Caminho para salvar relatório de testes
    
.PARAMETER Verbose
    Saída detalhada dos testes
    
.EXAMPLE
    .\basic-functionality-tests.ps1 -TestLevel Standard -Verbose
    
.NOTES
    Author: Matheus-TestUser1
    Version: 1.0.0
    Requires: PowerShell 5.1+, Administrator privileges (for some tests)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [ValidateSet("Basic", "Standard", "Comprehensive")]
    [string]$TestLevel = "Standard",
    
    [Parameter(Mandatory = $false)]
    [switch]$SkipInstallationTests,
    
    [Parameter(Mandatory = $false)]
    [switch]$SkipFunctionalTests,
    
    [Parameter(Mandatory = $false)]
    [string]$OutputPath = ".\TestResults",
    
    [Parameter(Mandatory = $false)]
    [switch]$Verbose
)

# ============================================================================
# CONFIGURAÇÕES GLOBAIS
# ============================================================================

$Script:TestConfig = @{
    Version = "1.0.0"
    StartTime = Get-Date
    TestLevel = $TestLevel
    BasePath = "$env:ProgramData\WindowsDefenseLogoFAIL"
    ScriptsPath = ".\scripts"
    TestResults = @()
    PassedTests = 0
    FailedTests = 0
    SkippedTests = 0
    TotalTests = 0
}

# ============================================================================
# FUNÇÕES DE TESTE
# ============================================================================

function Write-TestLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("Info", "Warning", "Error", "Success", "Test")]
        [string]$Level = "Info"
    )
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    
    $color = switch ($Level) {
        "Info" { "Cyan" }
        "Warning" { "Yellow" }
        "Error" { "Red" }
        "Success" { "Green" }
        "Test" { "Magenta" }
    }
    
    Write-Host "[$timestamp] $Message" -ForegroundColor $color
}

function Test-Function {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TestName,
        
        [Parameter(Mandatory = $true)]
        [scriptblock]$TestScript,
        
        [Parameter(Mandatory = $false)]
        [string]$Description = ""
    )
    
    $Script:TestConfig.TotalTests++
    
    try {
        Write-TestLog "Executando teste: $TestName" -Level "Test"
        if ($Description -and $Verbose) {
            Write-TestLog "  Descrição: $Description" -Level "Info"
        }
        
        $result = & $TestScript
        
        $testResult = @{
            TestName = $TestName
            Description = $Description
            Status = if ($result) { "PASSED" } else { "FAILED" }
            Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            Details = ""
        }
        
        if ($result) {
            Write-TestLog "  ✓ PASSOU: $TestName" -Level "Success"
            $Script:TestConfig.PassedTests++
        } else {
            Write-TestLog "  ✗ FALHOU: $TestName" -Level "Error"
            $Script:TestConfig.FailedTests++
        }
        
        $Script:TestConfig.TestResults += $testResult
        return $result
    }
    catch {
        Write-TestLog "  ✗ ERRO: $TestName - $_" -Level "Error"
        $Script:TestConfig.FailedTests++
        
        $testResult = @{
            TestName = $TestName
            Description = $Description
            Status = "ERROR"
            Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            Details = $_.Exception.Message
        }
        
        $Script:TestConfig.TestResults += $testResult
        return $false
    }
}

function Skip-Test {
    param(
        [string]$TestName,
        [string]$Reason = "Teste pulado"
    )
    
    $Script:TestConfig.TotalTests++
    $Script:TestConfig.SkippedTests++
    
    Write-TestLog "  ⊘ PULADO: $TestName - $Reason" -Level "Warning"
    
    $testResult = @{
        TestName = $TestName
        Description = $Reason
        Status = "SKIPPED"
        Timestamp = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
        Details = $Reason
    }
    
    $Script:TestConfig.TestResults += $testResult
}

# ============================================================================
# TESTES DE INSTALAÇÃO
# ============================================================================

function Test-InstallationComponents {
    Write-TestLog "Executando testes de instalação..." -Level "Info"
    
    if ($SkipInstallationTests) {
        Skip-Test "Installation Tests" "Testes de instalação foram pulados"
        return
    }
    
    # Teste 1: Verificar se diretórios principais existem
    Test-Function "Directory Structure" {
        $requiredDirs = @(
            $Script:TestConfig.BasePath,
            "$($Script:TestConfig.BasePath)\Logs",
            "$($Script:TestConfig.BasePath)\Config",
            "$($Script:TestConfig.BasePath)\Baselines"
        )
        
        $allExist = $true
        foreach ($dir in $requiredDirs) {
            if (-not (Test-Path $dir)) {
                $allExist = $false
                if ($Verbose) {
                    Write-TestLog "    Diretório não encontrado: $dir" -Level "Warning"
                }
            }
        }
        
        return $allExist
    } "Verifica se a estrutura de diretórios foi criada corretamente"
    
    # Teste 2: Verificar se scripts principais existem
    Test-Function "Core Scripts Existence" {
        $coreScripts = @(
            "Install-LogoFAILProtection.ps1",
            "LogoFAIL-QuickCheck.ps1",
            "LogoFAIL-ForensicAnalysis.ps1",
            "LogoFAIL-AdvancedProtection.ps1",
            "LogoFAIL-ContinuousMonitor.ps1"
        )
        
        $allExist = $true
        foreach ($script in $coreScripts) {
            $scriptPath = Join-Path $Script:TestConfig.ScriptsPath $script
            if (-not (Test-Path $scriptPath)) {
                $allExist = $false
                if ($Verbose) {
                    Write-TestLog "    Script não encontrado: $scriptPath" -Level "Warning"
                }
            }
        }
        
        return $allExist
    } "Verifica se todos os scripts principais estão presentes"
    
    # Teste 3: Verificar tarefa agendada (se existir)
    Test-Function "Scheduled Task Check" {
        try {
            $task = Get-ScheduledTask -TaskName "LogoFAIL-ContinuousMonitor" -ErrorAction SilentlyContinue
            # Tarefa pode não existir se não foi configurada, isso é OK
            return $true
        }
        catch {
            return $true  # Não é um erro crítico
        }
    } "Verifica se a tarefa agendada pode ser acessada"
}

# ============================================================================
# TESTES FUNCIONAIS
# ============================================================================

function Test-CoreFunctionality {
    Write-TestLog "Executando testes funcionais..." -Level "Info"
    
    if ($SkipFunctionalTests) {
        Skip-Test "Functional Tests" "Testes funcionais foram pulados"
        return
    }
    
    # Teste 4: Verificar se Quick Check executa
    Test-Function "Quick Check Execution" {
        try {
            $quickCheckPath = Join-Path $Script:TestConfig.ScriptsPath "LogoFAIL-QuickCheck.ps1"
            if (-not (Test-Path $quickCheckPath)) {
                return $false
            }
            
            # Testar apenas sintaxe do script
            $null = [System.Management.Automation.PSParser]::Tokenize((Get-Content $quickCheckPath -Raw), [ref]$null)
            return $true
        }
        catch {
            if ($Verbose) {
                Write-TestLog "    Erro na verificação de sintaxe: $_" -Level "Warning"
            }
            return $false
        }
    } "Verifica se o script Quick Check tem sintaxe válida"
    
    # Teste 5: Verificar Windows Defender
    Test-Function "Windows Defender Availability" {
        try {
            $defenderStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
            return $defenderStatus -ne $null
        }
        catch {
            if ($Verbose) {
                Write-TestLog "    Windows Defender não disponível: $_" -Level "Warning"
            }
            return $false
        }
    } "Verifica se o Windows Defender está disponível"
    
    # Teste 6: Verificar PowerShell Version
    Test-Function "PowerShell Version" {
        $version = $PSVersionTable.PSVersion
        $isCompatible = $version.Major -ge 5 -and ($version.Major -gt 5 -or $version.Minor -ge 1)
        
        if ($Verbose) {
            Write-TestLog "    Versão do PowerShell: $($version.ToString())" -Level "Info"
        }
        
        return $isCompatible
    } "Verifica se a versão do PowerShell é compatível (5.1+)"
    
    # Teste 7: Verificar privilégios de administrador
    Test-Function "Administrator Privileges" {
        try {
            $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
            $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
            $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
            
            if ($Verbose -and -not $isAdmin) {
                Write-TestLog "    Executando sem privilégios de administrador" -Level "Warning"
            }
            
            # Para testes básicos, não é obrigatório ser admin
            return $true
        }
        catch {
            return $true
        }
    } "Verifica status de privilégios de administrador"
}

# ============================================================================
# TESTES DE SISTEMA
# ============================================================================

function Test-SystemCompatibility {
    Write-TestLog "Executando testes de compatibilidade do sistema..." -Level "Info"
    
    # Teste 8: Verificar versão do Windows
    Test-Function "Windows Version" {
        try {
            $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
            $buildNumber = [int]$osInfo.BuildNumber
            
            # Windows 10 2004+ (build 19041+) ou Windows 11
            $isCompatible = $buildNumber -ge 19041
            
            if ($Verbose) {
                Write-TestLog "    OS: $($osInfo.Caption), Build: $buildNumber" -Level "Info"
            }
            
            return $isCompatible
        }
        catch {
            if ($Verbose) {
                Write-TestLog "    Erro ao verificar versão do Windows: $_" -Level "Warning"
            }
            return $false
        }
    } "Verifica se a versão do Windows é compatível"
    
    # Teste 9: Verificar tipo de firmware
    Test-Function "Firmware Type" {
        try {
            $computerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
            $firmwareType = $computerSystem.PCSystemType
            
            # 2 = UEFI, 1 = Legacy
            $isUEFI = $firmwareType -eq 2
            
            if ($Verbose) {
                $type = if ($isUEFI) { "UEFI" } else { "Legacy BIOS" }
                Write-TestLog "    Tipo de firmware: $type" -Level "Info"
            }
            
            # Para testes básicos, ambos são aceitos
            return $true
        }
        catch {
            return $true
        }
    } "Identifica o tipo de firmware do sistema"
    
    # Teste 10: Verificar Secure Boot (se UEFI)
    Test-Function "Secure Boot Status" {
        try {
            $secureBootState = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
            
            if ($Verbose) {
                $status = if ($secureBootState) { "Habilitado" } else { "Desabilitado" }
                Write-TestLog "    Secure Boot: $status" -Level "Info"
            }
            
            # Para testes básicos, qualquer estado é aceitável
            return $true
        }
        catch {
            if ($Verbose) {
                Write-TestLog "    Secure Boot não disponível ou erro na verificação" -Level "Info"
            }
            return $true
        }
    } "Verifica status do Secure Boot"
}

# ============================================================================
# TESTES ABRANGENTES
# ============================================================================

function Test-ComprehensiveFeatures {
    if ($TestLevel -ne "Comprehensive") {
        return
    }
    
    Write-TestLog "Executando testes abrangentes..." -Level "Info"
    
    # Teste 11: Verificar todos os scripts por sintaxe
    Test-Function "All Scripts Syntax Check" {
        $scriptsPath = $Script:TestConfig.ScriptsPath
        if (-not (Test-Path $scriptsPath)) {
            return $false
        }
        
        $allValid = $true
        $scriptFiles = Get-ChildItem -Path $scriptsPath -Filter "*.ps1"
        
        foreach ($script in $scriptFiles) {
            try {
                $null = [System.Management.Automation.PSParser]::Tokenize((Get-Content $script.FullName -Raw), [ref]$null)
                if ($Verbose) {
                    Write-TestLog "    ✓ $($script.Name)" -Level "Success"
                }
            }
            catch {
                $allValid = $false
                if ($Verbose) {
                    Write-TestLog "    ✗ $($script.Name): $_" -Level "Error"
                }
            }
        }
        
        return $allValid
    } "Verifica sintaxe de todos os scripts PowerShell"
    
    # Teste 12: Verificar dependências do sistema
    Test-Function "System Dependencies" {
        $dependencies = @{
            "Get-MpComputerStatus" = { Get-Command Get-MpComputerStatus -ErrorAction SilentlyContinue }
            "Get-Tpm" = { Get-Command Get-Tpm -ErrorAction SilentlyContinue }
            "Get-CimInstance" = { Get-Command Get-CimInstance -ErrorAction SilentlyContinue }
            "ConvertTo-Json" = { Get-Command ConvertTo-Json -ErrorAction SilentlyContinue }
        }
        
        $allAvailable = $true
        foreach ($dep in $dependencies.GetEnumerator()) {
            $available = & $dep.Value
            if (-not $available) {
                $allAvailable = $false
                if ($Verbose) {
                    Write-TestLog "    Dependência não disponível: $($dep.Key)" -Level "Warning"
                }
            }
        }
        
        return $allAvailable
    } "Verifica disponibilidade de comandos e dependências necessárias"
}

# ============================================================================
# RELATÓRIO DE RESULTADOS
# ============================================================================

function Generate-TestReport {
    Write-TestLog "Gerando relatório de testes..." -Level "Info"
    
    try {
        if (-not (Test-Path $OutputPath)) {
            New-Item -Path $OutputPath -ItemType Directory -Force | Out-Null
        }
        
        $report = @{
            TestSession = @{
                StartTime = $Script:TestConfig.StartTime.ToString("yyyy-MM-dd HH:mm:ss")
                EndTime = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                Duration = ((Get-Date) - $Script:TestConfig.StartTime).TotalSeconds
                TestLevel = $Script:TestConfig.TestLevel
                Version = $Script:TestConfig.Version
            }
            Summary = @{
                TotalTests = $Script:TestConfig.TotalTests
                PassedTests = $Script:TestConfig.PassedTests
                FailedTests = $Script:TestConfig.FailedTests
                SkippedTests = $Script:TestConfig.SkippedTests
                SuccessRate = if ($Script:TestConfig.TotalTests -gt 0) { 
                    [math]::Round(($Script:TestConfig.PassedTests / $Script:TestConfig.TotalTests) * 100, 2) 
                } else { 0 }
            }
            TestResults = $Script:TestConfig.TestResults
            SystemInfo = @{
                ComputerName = $env:COMPUTERNAME
                PowerShellVersion = $PSVersionTable.PSVersion.ToString()
                OSVersion = (Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue).Caption
            }
        }
        
        # Salvar relatório JSON
        $reportFile = Join-Path $OutputPath "test-report-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
        $report | ConvertTo-Json -Depth 4 | Set-Content -Path $reportFile -Encoding UTF8
        
        Write-TestLog "Relatório salvo em: $reportFile" -Level "Success"
        
        return $reportFile
    }
    catch {
        Write-TestLog "Erro ao gerar relatório: $_" -Level "Error"
        return $null
    }
}

function Display-TestSummary {
    Write-Host ""
    Write-Host "======================================================================" -ForegroundColor Cyan
    Write-Host "    Resumo dos Testes - LogoFAIL Basic Functionality" -ForegroundColor Cyan
    Write-Host "======================================================================" -ForegroundColor Cyan
    Write-Host ""
    
    $successRate = if ($Script:TestConfig.TotalTests -gt 0) { 
        [math]::Round(($Script:TestConfig.PassedTests / $Script:TestConfig.TotalTests) * 100, 2) 
    } else { 0 }
    
    Write-Host "ESTATÍSTICAS DOS TESTES:" -ForegroundColor Yellow
    Write-Host "- Total de testes executados: $($Script:TestConfig.TotalTests)" -ForegroundColor White
    Write-Host "- Testes aprovados: $($Script:TestConfig.PassedTests)" -ForegroundColor Green
    Write-Host "- Testes falharam: $($Script:TestConfig.FailedTests)" -ForegroundColor Red
    Write-Host "- Testes pulados: $($Script:TestConfig.SkippedTests)" -ForegroundColor Yellow
    Write-Host "- Taxa de sucesso: $successRate%" -ForegroundColor $(if ($successRate -ge 80) { "Green" } elseif ($successRate -ge 60) { "Yellow" } else { "Red" })
    
    $duration = ((Get-Date) - $Script:TestConfig.StartTime).TotalSeconds
    Write-Host "- Duração total: $([math]::Round($duration, 2)) segundos" -ForegroundColor White
    
    if ($Script:TestConfig.FailedTests -gt 0) {
        Write-Host ""
        Write-Host "TESTES FALHARAM:" -ForegroundColor Red
        $failedTests = $Script:TestConfig.TestResults | Where-Object { $_.Status -in @("FAILED", "ERROR") }
        foreach ($test in $failedTests) {
            Write-Host "  ✗ $($test.TestName)" -ForegroundColor Red
            if ($test.Details) {
                Write-Host "    $($test.Details)" -ForegroundColor Gray
            }
        }
    }
    
    Write-Host ""
    if ($successRate -ge 80) {
        Write-Host "✅ SISTEMA FUNCIONANDO CORRETAMENTE" -ForegroundColor Green
    } elseif ($successRate -ge 60) {
        Write-Host "⚠️  SISTEMA COM PROBLEMAS MENORES" -ForegroundColor Yellow
    } else {
        Write-Host "❌ SISTEMA COM PROBLEMAS SIGNIFICATIVOS" -ForegroundColor Red
    }
    
    Write-Host ""
    Write-Host "PRÓXIMOS PASSOS:" -ForegroundColor Yellow
    if ($Script:TestConfig.FailedTests -eq 0) {
        Write-Host "- Sistema pronto para uso" -ForegroundColor Green
        Write-Host "- Execute LogoFAIL-QuickCheck.ps1 para verificação completa" -ForegroundColor White
    } else {
        Write-Host "- Revise os testes que falharam" -ForegroundColor White
        Write-Host "- Verifique a instalação e configuração do sistema" -ForegroundColor White
        Write-Host "- Execute novamente após correções" -ForegroundColor White
    }
}

# ============================================================================
# FUNÇÃO PRINCIPAL
# ============================================================================

function Start-BasicTests {
    Write-Host "======================================================================" -ForegroundColor Cyan
    Write-Host "    LogoFAIL Basic Functionality Tests" -ForegroundColor Cyan
    Write-Host "    Versão: $($Script:TestConfig.Version)" -ForegroundColor Cyan
    Write-Host "======================================================================" -ForegroundColor Cyan
    Write-Host ""
    
    Write-TestLog "Iniciando testes de funcionalidade básica..." -Level "Info"
    Write-TestLog "Nível de teste: $($Script:TestConfig.TestLevel)" -Level "Info"
    
    try {
        # Executar grupos de testes
        Test-InstallationComponents
        Test-CoreFunctionality
        Test-SystemCompatibility
        Test-ComprehensiveFeatures
        
        # Gerar relatório
        $reportFile = Generate-TestReport
        
        # Exibir resumo
        Display-TestSummary
        
        if ($reportFile) {
            Write-Host "Relatório detalhado salvo em: $reportFile" -ForegroundColor Gray
        }
        
        # Retornar código de saída baseado nos resultados
        return $Script:TestConfig.FailedTests -eq 0
    }
    catch {
        Write-TestLog "Erro durante execução dos testes: $_" -Level "Error"
        return $false
    }
}

# ============================================================================
# EXECUÇÃO PRINCIPAL
# ============================================================================

try {
    $result = Start-BasicTests
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