# Windows Defense LogoFAIL

> **Comprehensive prevention, detection and forensic analysis system for LogoFAIL vulnerabilities**

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![PowerShell 5.1+](https://img.shields.io/badge/PowerShell-5.1%2B-blue.svg)](https://github.com/PowerShell/PowerShell)
[![Windows](https://img.shields.io/badge/Platform-Windows%2010%2F11-blue.svg)](https://www.microsoft.com/windows)
[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg)](https://github.com/Matheus-TestUser1/Windows-Defense-LogoFail/graphs/commit-activity)

## 🛡️ About LogoFAIL Vulnerability

LogoFAIL is a collection of critical security vulnerabilities discovered in UEFI firmware implementations. These vulnerabilities allow attackers to bypass Secure Boot protections by exploiting image parsing routines during the boot process. The vulnerabilities affect multiple firmware implementations from various vendors and can lead to:

- **Bypass of Secure Boot**: Allowing unsigned or malicious code to execute during boot
- **Persistent malware installation**: Code that survives OS reinstallation and disk formatting  
- **Supply chain attacks**: Compromising systems during manufacturing or updates
- **Privilege escalation**: Gaining highest level system access

### Affected Systems

- Systems with UEFI firmware (most modern computers)
- Particularly vulnerable: Lenovo devices with Vantage software
- Various firmware vendors including AMI, Phoenix, and others

## 🎯 Project Overview

This comprehensive security solution provides:

- **🔍 Proactive Detection**: Early warning system for LogoFAIL indicators
- **🛡️ Advanced Protection**: Multi-layered security configurations
- **🔬 Forensic Analysis**: Detailed investigation capabilities
- **📊 Continuous Monitoring**: Real-time threat detection
- **🚨 Alert System**: Multi-channel notification system
- **📈 Quick Assessment**: Rapid security posture evaluation

## 🚀 Quick Start

### Prerequisites

- Windows 10 version 2004+ or Windows 11
- PowerShell 5.1 or later
- Administrator privileges
- UEFI-based system (recommended)

### Installation

1. **Clone the repository**:
   ```powershell
   git clone https://github.com/Matheus-TestUser1/Windows-Defense-LogoFail.git
   cd Windows-Defense-LogoFail
   ```

2. **Run basic protection setup**:
   ```powershell
   # Run as Administrator
   .\scripts\Install-LogoFAILProtection.ps1
   ```

3. **Enable continuous monitoring** (recommended):
   ```powershell
   .\scripts\Install-LogoFAILProtection.ps1 -EnableContinuousMonitoring -AlertEmail "your-email@domain.com"
   ```

4. **Quick security check**:
   ```powershell
   .\scripts\LogoFAIL-QuickCheck.ps1 -Detailed
   ```

## 📋 Core Scripts

### 🔧 Main Installation & Protection

| Script | Purpose | Usage |
|--------|---------|-------|
| `Install-LogoFAILProtection.ps1` | Main installation and configuration | `.\Install-LogoFAILProtection.ps1 -EnableContinuousMonitoring` |
| `LogoFAIL-AdvancedProtection.ps1` | Advanced security features (HVCI, Device Guard) | `.\LogoFAIL-AdvancedProtection.ps1 -EnableHVCI -EnableDeviceGuard` |
| `Uninstall-LogoFAILProtection.ps1` | Clean removal of all components | `.\Uninstall-LogoFAILProtection.ps1 -PreserveBackups` |

### 🔍 Detection & Analysis

| Script | Purpose | Usage |
|--------|---------|-------|
| `LogoFAIL-QuickCheck.ps1` | Rapid security assessment | `.\LogoFAIL-QuickCheck.ps1 -Detailed -ExportReport` |
| `LogoFAIL-ForensicAnalysis.ps1` | Comprehensive forensic investigation | `.\LogoFAIL-ForensicAnalysis.ps1 -IncludeLenovoAnalysis -DeepScan` |
| `LogoFAIL-ContinuousMonitor.ps1` | Real-time monitoring | `.\LogoFAIL-ContinuousMonitor.ps1 -MonitoringMode Standard` |

### 🚨 Alerting & Notifications

| Script | Purpose | Usage |
|--------|---------|-------|
| `LogoFAIL-AlertSystem.ps1` | Configure alert channels | `.\LogoFAIL-AlertSystem.ps1 -ConfigureEmail -TestAlerts` |

## 🔒 Security Features

### ⚡ Quick Check Results
The Quick Check script provides a comprehensive security score:

```
✓ Secure Boot Active                    (20 points)
✓ Windows Defender Real-Time Protection (15 points)  
✓ TPM Enabled                          (15 points)
✓ System File Integrity               (15 points)
✓ HVCI Enabled                         (15 points)
✓ No Lenovo Vantage Detected          (15 points)
✓ Boot Configuration Secure           (10 points)

SECURITY SCORE: 95/100 (EXCELLENT)
```

### 🛡️ Protection Layers

1. **Firmware Level**
   - Secure Boot verification
   - TPM utilization
   - Boot configuration hardening

2. **OS Level**
   - Windows Defender optimization
   - HVCI (Hypervisor-protected Code Integrity)
   - Device Guard / Credential Guard
   - Application Guard

3. **File System**
   - Critical file integrity monitoring
   - Baseline creation and comparison
   - Suspicious file detection

4. **Network**
   - Suspicious connection monitoring
   - Lenovo/Vantage communication detection
   - Network protection policies

5. **Registry**
   - Critical key monitoring
   - Boot configuration protection
   - Security policy enforcement

## 📊 Monitoring & Analysis

### Real-time Monitoring
```powershell
# Light monitoring (basic checks every 5 minutes)
.\LogoFAIL-ContinuousMonitor.ps1 -MonitoringMode Light

# Standard monitoring (comprehensive checks every 3 minutes)  
.\LogoFAIL-ContinuousMonitor.ps1 -MonitoringMode Standard

# Intensive monitoring (deep analysis every minute)
.\LogoFAIL-ContinuousMonitor.ps1 -MonitoringMode Intensive
```

### Forensic Analysis
```powershell
# Basic forensic scan
.\LogoFAIL-ForensicAnalysis.ps1

# Comprehensive analysis with Lenovo-specific checks
.\LogoFAIL-ForensicAnalysis.ps1 -IncludeLenovoAnalysis -DeepScan -ExportEvidence

# Quick verification
.\LogoFAIL-QuickCheck.ps1 -CheckBaseline -ExportReport
```

## 🚨 Alert System

### Supported Alert Channels

- **📧 Email Notifications**: SMTP-based alerts for critical events
- **💻 Windows Notifications**: Toast notifications for immediate attention
- **📝 Event Log**: Integration with Windows Event Log
- **📄 File Logging**: Structured JSON logs for analysis

### Configuration Example
```powershell
# Configure email alerts
.\LogoFAIL-AlertSystem.ps1 -ConfigureEmail -EmailServer "smtp.gmail.com" -EmailFrom "security@company.com" -EmailTo "admin@company.com"

# Test all alert channels
.\LogoFAIL-AlertSystem.ps1 -TestAlerts

# Enable continuous monitoring mode
.\LogoFAIL-AlertSystem.ps1 -MonitorMode
```

## 📁 Project Structure

```
Windows-Defense-LogoFail/
├── scripts/                           # Main PowerShell scripts
│   ├── Install-LogoFAILProtection.ps1       # Main installation
│   ├── LogoFAIL-ForensicAnalysis.ps1        # Forensic analysis
│   ├── LogoFAIL-AdvancedProtection.ps1      # Advanced protections
│   ├── LogoFAIL-ContinuousMonitor.ps1       # Continuous monitoring
│   ├── LogoFAIL-QuickCheck.ps1              # Quick verification
│   ├── LogoFAIL-AlertSystem.ps1             # Alert system
│   └── Uninstall-LogoFAILProtection.ps1     # Clean removal
├── docs/                              # Documentation
│   ├── installation.md                      # Installation guide
│   ├── configuration.md                     # Configuration guide
│   ├── forensic-analysis.md                 # Forensic analysis guide
│   ├── about-logofail.md                    # Vulnerability details
│   ├── troubleshooting.md                   # Troubleshooting guide
│   └── security-features.md                 # Security features
├── examples/                          # Example configurations
│   ├── alert-config-examples/               # Alert configurations
│   ├── monitoring-logs/                     # Example logs
│   └── forensic-reports/                    # Example reports
├── tests/                             # Test scripts
├── tools/                             # Additional tools
└── .github/                           # GitHub configuration
```

## 💼 Enterprise Usage

### Deployment at Scale
```powershell
# Silent installation for enterprise deployment
.\Install-LogoFAILProtection.ps1 -EnableContinuousMonitoring -AlertEmail "soc@enterprise.com" -LogLevel Information

# Advanced protection for critical servers
.\LogoFAIL-AdvancedProtection.ps1 -EnableHVCI -EnableDeviceGuard -EnableApplicationGuard -CreateSystemBackup

# Scheduled forensic analysis
.\LogoFAIL-ForensicAnalysis.ps1 -OutputPath "\\server\security-logs\logofail" -IncludeLenovoAnalysis
```

### Centralized Monitoring
The system generates structured JSON logs that can be ingested by:
- **SIEM systems** (Splunk, QRadar, Sentinel)
- **Log aggregation** (ELK Stack, Fluentd)
- **Security orchestration** (SOAR platforms)

## 🔧 Advanced Configuration

### Custom Alert Rules
```json
{
  "AlertRules": {
    "CriticalFileChanges": {
      "Enabled": true,
      "Severity": "Critical",
      "Channels": ["Email", "WindowsNotification", "EventLog"]
    },
    "SuspiciousProcesses": {
      "Enabled": true,
      "Severity": "High", 
      "Channels": ["Email", "EventLog"]
    }
  }
}
```

### Monitoring Intervals
| Mode | Interval | Use Case |
|------|----------|----------|
| Light | 5 minutes | Basic workstations |
| Standard | 3 minutes | Business computers |
| Intensive | 1 minute | Critical servers |

## 🛠️ Troubleshooting

### Common Issues

**🔴 "Secure Boot not detected"**
- Solution: Enable Secure Boot in UEFI firmware settings
- Access: Restart → F2/F12/Del → Security Settings

**🔴 "Windows Defender not optimized"**  
- Solution: Run `Set-MpPreference` commands as Administrator
- Check: Windows Security app settings

**🔴 "Permission denied errors"**
- Solution: Run PowerShell as Administrator
- Check: Execution policy with `Get-ExecutionPolicy`

**🔴 "HVCI fails to enable"**
- Solution: Ensure Hyper-V is installed and hardware supports VBS
- Check: `systeminfo | findstr Hyper-V`

### Debug Mode
```powershell
# Enable verbose logging
.\LogoFAIL-QuickCheck.ps1 -Detailed -Verbose

# Check system compatibility  
.\LogoFAIL-AdvancedProtection.ps1 -WhatIf
```

## 📚 Documentation

- 📖 [Installation Guide](docs/installation.md) - Step-by-step setup instructions
- ⚙️ [Configuration Guide](docs/configuration.md) - Advanced configuration options
- 🔍 [Forensic Analysis](docs/forensic-analysis.md) - Investigation procedures
- 🛡️ [Security Features](docs/security-features.md) - Detailed feature descriptions
- ❓ [Troubleshooting](docs/troubleshooting.md) - Common issues and solutions
- 🔬 [About LogoFAIL](docs/about-logofail.md) - Vulnerability technical details

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md) for details.

### Areas for Contribution
- Additional IoC (Indicators of Compromise) patterns
- Support for other firmware vendors
- Integration with additional SIEM platforms
- Mobile device detection
- Cloud deployment scripts

## 🔐 Security Policy

Please report security vulnerabilities through our [Security Policy](SECURITY.md).

## 📄 License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Security Researchers**: Who discovered and disclosed LogoFAIL vulnerabilities
- **Microsoft**: For Windows Defender and security framework APIs
- **Community**: For testing, feedback, and contributions

## ⚠️ Disclaimer

This tool is provided for educational and legitimate security testing purposes only. Users are responsible for ensuring compliance with applicable laws and regulations. The authors are not responsible for any misuse or damage caused by this software.

## 📞 Support

- 🐛 **Bug Reports**: [GitHub Issues](https://github.com/Matheus-TestUser1/Windows-Defense-LogoFail/issues)
- 💬 **Discussions**: [GitHub Discussions](https://github.com/Matheus-TestUser1/Windows-Defense-LogoFail/discussions)
- 📧 **Security Issues**: See [Security Policy](SECURITY.md)

---

**🔒 Stay secure. Stay protected. Stay ahead of LogoFAIL.**