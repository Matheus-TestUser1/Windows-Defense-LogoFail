# Installation Guide

This guide provides detailed instructions for installing and configuring the Windows Defense LogoFAIL protection system.

## 📋 Prerequisites

### System Requirements

- **Operating System**: Windows 10 version 2004+ or Windows 11
- **PowerShell**: Version 5.1 or later
- **Architecture**: x64 (64-bit)
- **Memory**: Minimum 4GB RAM (8GB recommended)
- **Disk Space**: 500MB free space for installation and logs
- **Network**: Internet connection for updates and alerts

### Hardware Requirements

- **Firmware**: UEFI-based system (strongly recommended)
- **TPM**: TPM 2.0 (recommended for advanced features)
- **Secure Boot**: Capable hardware
- **Virtualization**: VT-x/AMD-V support (for HVCI features)

### User Requirements

- **Administrator Privileges**: Required for installation and operation
- **PowerShell Execution Policy**: Must allow script execution

## 🛠️ Pre-Installation Checks

### 1. Verify PowerShell Version

```powershell
# Check PowerShell version
$PSVersionTable.PSVersion

# Expected output: 5.1.x or higher
```

### 2. Check Execution Policy

```powershell
# View current execution policy
Get-ExecutionPolicy

# If restricted, allow script execution (as Administrator)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### 3. Verify Administrator Privileges

```powershell
# Check if running as Administrator
([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")

# Should return: True
```

### 4. System Compatibility Check

```powershell
# Check OS version
Get-CimInstance Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber

# Check firmware type
(Get-CimInstance -ClassName Win32_ComputerSystem).PCSystemType
# 2 = UEFI, 1 = Legacy BIOS
```

## 📥 Installation Methods

### Method 1: Direct Download (Recommended)

1. **Download the repository**:
   ```powershell
   # Using Git
   git clone https://github.com/Matheus-TestUser1/Windows-Defense-LogoFail.git
   cd Windows-Defense-LogoFail
   
   # Or download and extract ZIP from GitHub
   ```

2. **Verify file integrity** (optional):
   ```powershell
   # Check script signatures and hashes
   Get-ChildItem .\scripts\*.ps1 | Get-FileHash -Algorithm SHA256
   ```

### Method 2: PowerShell Direct Execution

```powershell
# Download and execute main installer directly
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/Matheus-TestUser1/Windows-Defense-LogoFail/main/scripts/Install-LogoFAILProtection.ps1" -OutFile "Install-LogoFAILProtection.ps1"
.\Install-LogoFAILProtection.ps1
```

## 🚀 Installation Process

### Basic Installation

```powershell
# Navigate to the scripts directory
cd Windows-Defense-LogoFail\scripts

# Run basic installation
.\Install-LogoFAILProtection.ps1
```

### Standard Installation (Recommended)

```powershell
# Installation with continuous monitoring
.\Install-LogoFAILProtection.ps1 -EnableContinuousMonitoring
```

### Full Installation with Alerts

```powershell
# Complete installation with email alerts
.\Install-LogoFAILProtection.ps1 -EnableContinuousMonitoring -AlertEmail "admin@yourcompany.com" -LogLevel Information
```

## ⚙️ Installation Parameters

### Install-LogoFAILProtection.ps1 Parameters

| Parameter | Type | Description | Default |
|-----------|------|-------------|---------|
| `EnableContinuousMonitoring` | Switch | Activates background monitoring | False |
| `AlertEmail` | String | Email for alert notifications | None |
| `LogLevel` | String | Logging verbosity (Error, Warning, Information, Verbose) | Information |

### Example Installations

#### Enterprise Workstation
```powershell
.\Install-LogoFAILProtection.ps1 -EnableContinuousMonitoring -AlertEmail "soc@company.com" -LogLevel Warning
```

#### Critical Server
```powershell
.\Install-LogoFAILProtection.ps1 -EnableContinuousMonitoring -AlertEmail "security@company.com" -LogLevel Verbose
```

#### Personal Computer
```powershell
.\Install-LogoFAILProtection.ps1 -LogLevel Information
```

## 📁 Installation Directories

The installer creates the following directory structure:

```
C:\ProgramData\WindowsDefenseLogoFAIL\
├── Logs\                    # System logs and monitoring data
├── Config\                  # Configuration files
├── Baselines\              # Security baselines
├── Backups\                # System configuration backups
└── Alerts\                 # Generated alerts

C:\Program Files\WindowsDefenseLogoFAIL\
└── (Optional script copies)
```

## 🔧 Post-Installation Configuration

### 1. Verify Installation

```powershell
# Run quick security check
.\LogoFAIL-QuickCheck.ps1 -Detailed

# Expected output: Security score and status summary
```

### 2. Configure Advanced Protection

```powershell
# Enable advanced security features (requires compatible hardware)
.\LogoFAIL-AdvancedProtection.ps1 -EnableHVCI -EnableDeviceGuard -CreateSystemBackup
```

### 3. Setup Alert System

```powershell
# Configure email alerts
.\LogoFAIL-AlertSystem.ps1 -ConfigureEmail

# Test alert system
.\LogoFAIL-AlertSystem.ps1 -TestAlerts
```

### 4. Verify Scheduled Tasks

```powershell
# Check if monitoring task was created
Get-ScheduledTask -TaskName "LogoFAIL-ContinuousMonitor" -ErrorAction SilentlyContinue
```

## 🛡️ Initial Security Baseline

After installation, the system creates security baselines for:

- **Critical System Files**: Hash verification for core Windows files
- **Registry Keys**: Important security configuration keys
- **Services**: Critical Windows services status
- **Boot Configuration**: Secure boot and boot loader settings

## 📊 Monitoring Configuration

### Monitoring Modes

| Mode | Frequency | Resource Usage | Recommended For |
|------|-----------|----------------|-----------------|
| Light | 5 minutes | Low | Basic workstations |
| Standard | 3 minutes | Medium | Business computers |
| Intensive | 1 minute | High | Critical servers |

### Configure Monitoring

```powershell
# Run continuous monitoring manually
.\LogoFAIL-ContinuousMonitor.ps1 -MonitoringMode Standard -AlertThreshold Medium

# For automated execution, the scheduled task handles this
```

## 🚨 Alert Configuration

### Email Setup

```powershell
# Interactive email configuration
.\LogoFAIL-AlertSystem.ps1 -ConfigureEmail

# Non-interactive email setup
.\LogoFAIL-AlertSystem.ps1 -ConfigureEmail -EmailServer "smtp.company.com" -EmailFrom "noreply@company.com" -EmailTo "security@company.com"
```

### Alert Channels

The system supports multiple alert channels:

- **Email**: SMTP-based notifications
- **Windows Notifications**: Toast notifications
- **Event Log**: Windows Event Log integration
- **File Logs**: JSON-structured log files

## 🔍 Verification Steps

### 1. Check Core Components

```powershell
# Verify main directories exist
Test-Path "C:\ProgramData\WindowsDefenseLogoFAIL"
Test-Path "C:\ProgramData\WindowsDefenseLogoFAIL\Logs"
Test-Path "C:\ProgramData\WindowsDefenseLogoFAIL\Config"
```

### 2. Validate Windows Defender Configuration

```powershell
# Check Windows Defender status
Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled, AntivirusEnabled
```

### 3. Verify Secure Boot Status

```powershell
# Check Secure Boot (requires UEFI)
try {
    Confirm-SecureBootUEFI
    Write-Host "Secure Boot: Enabled" -ForegroundColor Green
} catch {
    Write-Host "Secure Boot: Not Available or Disabled" -ForegroundColor Yellow
}
```

### 4. Test Quick Check

```powershell
# Run comprehensive security check
.\LogoFAIL-QuickCheck.ps1 -Detailed -ExportReport

# Review the security score and recommendations
```

## 🔄 Scheduled Tasks

The installation creates a scheduled task for continuous monitoring:

- **Task Name**: LogoFAIL-ContinuousMonitor
- **Schedule**: Daily at 3:00 AM
- **User**: SYSTEM
- **Action**: Execute monitoring script

### Modify Scheduled Task

```powershell
# View current task configuration
Get-ScheduledTask -TaskName "LogoFAIL-ContinuousMonitor" | Get-ScheduledTaskInfo

# Modify task schedule (example: every 2 hours)
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Hours 2) -RepetitionDuration (New-TimeSpan -Days 365)
Set-ScheduledTask -TaskName "LogoFAIL-ContinuousMonitor" -Trigger $trigger
```

## 🏢 Enterprise Deployment

### Group Policy Deployment

For domain environments, you can deploy via Group Policy:

1. **Copy scripts** to a network share
2. **Create startup script** to run installer
3. **Configure via GPO**:
   ```
   Computer Configuration → Windows Settings → Scripts → Startup
   ```

### SCCM Deployment

```powershell
# SCCM deployment package example
$InstallCommand = "PowerShell.exe -ExecutionPolicy Bypass -File Install-LogoFAILProtection.ps1 -EnableContinuousMonitoring -AlertEmail soc@company.com"
```

### Intune Deployment

Create a PowerShell script deployment in Microsoft Intune with the installation command.

## 🔧 Troubleshooting Installation

### Common Issues

#### Error: "Execution Policy Restricted"
```powershell
# Solution: Update execution policy
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

#### Error: "Access Denied"
```powershell
# Solution: Run PowerShell as Administrator
# Right-click PowerShell → "Run as Administrator"
```

#### Error: "Windows Defender Not Found"
```powershell
# Solution: Enable Windows Defender
# Windows Security → Virus & threat protection → Manage settings
```

#### Error: "Secure Boot Not Available"
```powershell
# Solution: Check UEFI firmware settings
# This is not critical but recommended for full protection
```

### Validation Script

```powershell
# Create a validation script to check installation
$ValidationResults = @{
    DirectoryExists = Test-Path "C:\ProgramData\WindowsDefenseLogoFAIL"
    ScheduledTaskExists = Get-ScheduledTask -TaskName "LogoFAIL-ContinuousMonitor" -ErrorAction SilentlyContinue
    DefenderActive = (Get-MpComputerStatus).RealTimeProtectionEnabled
    LogsCreated = (Get-ChildItem "C:\ProgramData\WindowsDefenseLogoFAIL\Logs" -ErrorAction SilentlyContinue).Count -gt 0
}

$ValidationResults | Format-Table -AutoSize
```

## 📋 Next Steps

After successful installation:

1. **📖 Read the Configuration Guide**: [docs/configuration.md](configuration.md)
2. **🔍 Learn about Forensic Analysis**: [docs/forensic-analysis.md](forensic-analysis.md)
3. **🛡️ Explore Security Features**: [docs/security-features.md](security-features.md)
4. **⚡ Set up Quick Checks**: Schedule regular security assessments
5. **📧 Configure Alerts**: Set up notification channels for your environment

## 🆘 Getting Help

If you encounter issues during installation:

- **📚 Documentation**: Check the [troubleshooting guide](troubleshooting.md)
- **🐛 Issues**: Report problems on [GitHub Issues](https://github.com/Matheus-TestUser1/Windows-Defense-LogoFail/issues)
- **💬 Community**: Join discussions on [GitHub Discussions](https://github.com/Matheus-TestUser1/Windows-Defense-LogoFail/discussions)

---

✅ **Installation complete!** Your system is now protected against LogoFAIL vulnerabilities.