# IR-Toolkit

> **Attack & Defense Incident Response Toolkit**  
> 面向 Windows 主机应急响应的本地证据采集、关联分析与时间线还原工具。

IR-Toolkit 的目标不是替分析人员“自动判案”，而是尽可能把主机上的证据采集出来、规范化、关联起来，并按照时间顺序还原主机活动过程。

它真正关注的不是“采集多少数据”，而是：

> **把登录、进程、PowerShell、RDP、计划任务、WMI 等分散事件串联起来，并统一展示到同一条时间线上。**

---

## 核心能力

IR-Toolkit 可以采集常见 Windows 主机证据，包括：

- 主机信息
- 当前进程与完整命令行
- Process Token / Authentication ID
- TCP / UDP 网络连接
- 外部连接识别
- Windows Services
- Run / RunOnce
- Scheduled Tasks
- 登录事件
- 文件 Triage
- ADS / Zone.Identifier
- Windows Event
- PowerShell 4103 / 4104
- Security Provider
- Audit Capability
- IOC Match

这些只是基础。

IR-Toolkit 更重要的能力，是在这些数据之上继续建立关联。

---

# 核心特色：把分散事件重新串起来

Windows 应急分析中，真正麻烦的通常不是“没有日志”，而是日志分散在不同来源：

```text
Security Log
PowerShell Operational
Terminal Services
Task Scheduler
WMI Activity
Current Process Snapshot
Network Snapshot
```

IR-Toolkit 会把这些来源统一规范化，并尝试建立证据之间的关系。

例如：

```text
RDP_SESSION_LOGON
        ↓
4624 Logon Session
        ↓
cmd.exe
        ↓
powershell.exe
        ↓
PowerShell 4104 ScriptBlock
        ↓
SCHEDULED_TASK_REGISTERED
```

最终，这些事件会进入统一时间线：

```text
01:10:02  RDP_SESSION_LOGON
01:10:09  PROCESS_CREATE cmd.exe
01:10:12  PROCESS_CREATE powershell.exe
01:10:13  POWERSHELL_SCRIPT
01:11:05  SCHEDULED_TASK_REGISTERED
```

这样分析人员不需要在多个日志源之间反复切换、手工记 PID、对时间、拼接攻击过程。

---

## 证据关联

IR-Toolkit 会尽量使用明确的系统标识符建立关系。

### 登录 → 进程

Windows 登录事件中的：

```text
Logon ID
```

可以与进程 Token 中的：

```text
Authentication ID
```

进行关联。

从而回答：

> 某次登录会话启动了哪些进程？

### 历史进程 → PowerShell

如果系统存在 4688 进程创建日志，IR-Toolkit 可以恢复已经退出的历史进程，并尽可能还原父子关系：

```text
w3wp.exe
   ↓
cmd.exe
   ↓
powershell.exe
   ↓
certutil.exe
```

随后还可以继续关联 PowerShell 4104 ScriptBlock。

### RDP → 登录会话

对于没有直接唯一标识符的事件，IR-Toolkit 会综合：

- User
- Source IP
- Logon Type
- Timestamp

建立关联，并保留关联置信度。

---

## Confidence：不把推断伪装成事实

不同证据关系的可靠程度不同。

IR-Toolkit 会区分：

```text
High Confidence
Medium Confidence
Low Confidence
```

例如：

```text
4624 Logon ID == 4688 Subject Logon ID
```

属于强关联。

而：

```text
Same User
+ Same Source IP
+ Similar Timestamp
```

则只能作为较弱的分析关系。

工具会尽量保留：

```text
Evidence Basis
Confidence
```

最终判断仍然交给分析人员。

---

# Unified Timeline

IR-Toolkit 会将不同证据源统一映射到时间线。

目前可进入 Timeline 的数据包括：

- 登录事件
- RDP Session
- 历史进程创建
- PowerShell ScriptBlock
- Scheduled Task
- WMI Activity
- Persistence
- 其他 Windows Event

示例：

```text
2026-09-05 01:10:02  remote_session   RDP_SESSION_LOGON
2026-09-05 01:10:09  process_history  PROCESS_CREATE
2026-09-05 01:10:12  process_history  PROCESS_CREATE
2026-09-05 01:10:13  powershell       POWERSHELL_SCRIPT
2026-09-05 01:11:05  scheduled_task   SCHEDULED_TASK_REGISTERED
```

这也是 IR-Toolkit 当前最核心的设计方向：

> **Evidence → Relationship → Timeline**

---

# Historical Correlation

在时间线基础上，IR-Toolkit 会进一步建立历史关联图。

例如：

```text
RDP
 ↓
DOMAIN\Admin
 ↓
cmd.exe
 ↓
powershell.exe
 ↓
PowerShell ScriptBlock
 ↓
Scheduled Task
```

输出中会保留：

```text
Severity
Confidence
Evidence Basis
```

注意：

> Historical Chain 表示“现有证据支持这些活动之间存在关联”，并不等同于自动确认攻击链。

---

# Evidence Coverage

真实环境里一个非常重要的问题是：

> **没有发现日志，不等于没有发生过。**

目标机器可能根本没有开启：

- Logon Audit
- Process Creation Audit
- PowerShell Script Block Logging
- Sysmon

IR-Toolkit 会主动检测主机当前的证据能力。

例如：

```text
Collection Mode        : historical_partial
Historical Coverage    : 20%
Snapshot Coverage      : 100%

Security Log           : available
Logon Audit            : disabled
Process Creation Audit : disabled
PowerShell 4104        : disabled
Defender Operational   : available
Sysmon                 : not_installed
```

这样可以明确区分：

```text
No evidence found
```

和：

```text
No evidence coverage
```

这是应急分析中非常重要的区别。

---

# PowerShell ScriptBlock 重组

PowerShell 4104 可能将一个完整 ScriptBlock 拆成多个 Event。

IR-Toolkit 会根据：

```text
ScriptBlockId
MessageNumber
MessageTotal
```

自动重组。

同时会辅助识别一些高关注行为，例如：

- IEX / Invoke-Expression
- Invoke-WebRequest
- Invoke-RestMethod
- WebClient
- Base64
- Reflection
- Assembly Load
- AMSI 相关行为
- Credential 相关行为
- Native Process Execution

这些只是分析线索，不会被单独作为恶意结论。

---

# IOC Scan

已经采集完成的 Case 可以继续离线扫描 IOC。

支持：

- Hash
- IP
- Domain
- Path
- Process Name
- Command Line

示例：

```powershell
ir.exe ioc scan --file ioc.yaml case-20260905-010000
```

无需重新登录目标机器。

---

# 快速开始

## 1. 采集

```powershell
ir.exe collect --last 24h
```

也支持：

```powershell
ir.exe collect --last 6h
```

或指定绝对时间：

```powershell
ir.exe collect `
  --since 2026-09-05T00:00:00Z `
  --until 2026-09-05T06:00:00Z
```

采集完成后会生成独立 Case：

```text
case-YYYYMMDD-HHMMSS/
```

## 2. 分析

```powershell
ir.exe analyze case-YYYYMMDD-HHMMSS
```

分析阶段会生成：

- Network Analysis
- Process Relationship Analysis
- Persistence Analysis
- Login Analysis
- Activity Analysis
- File Analysis
- Historical Process Analysis
- PowerShell Analysis
- Windows Event Analysis
- Historical Correlation
- Unified Timeline
- Case Report

## 3. IOC 扫描

```powershell
ir.exe ioc scan `
  --file ioc.yaml `
  case-YYYYMMDD-HHMMSS
```

---

# Case 目录结构

典型 Case：

```text
case-YYYYMMDD-HHMMSS/
├── capabilities/
│   ├── capabilities.json
│   └── security_providers.json
├── host/
│   └── host.json
├── process/
│   └── processes.json
├── network/
│   └── network.json
├── persistence/
│   └── persistence.json
├── login/
│   └── login.json
├── files/
│   └── files.json
├── events/
│   ├── process_events.json
│   ├── powershell_events.json
│   └── windows_events.json
├── analysis/
│   ├── network_analysis.json
│   ├── process_relationship_analysis.json
│   ├── persistence_analysis.json
│   ├── login_analysis.json
│   ├── activity_analysis.json
│   ├── file_analysis.json
│   ├── process_history_analysis.json
│   ├── powershell_analysis.json
│   ├── windows_event_analysis.json
│   ├── historical_correlation.json
│   ├── report.json
│   └── report.txt
└── timeline/
    ├── timeline.json
    └── events.jsonl
```

---

# 当前 Windows 数据源

### Security Event

```text
4624  Successful Logon
4625  Failed Logon
4648  Explicit Credentials
4672  Special Privileges
4688  Process Creation
```

### PowerShell

```text
4103  Module Logging
4104  Script Block Logging
```

### Terminal Services

```text
RDP Session Logon
Shell Start
Logoff
Disconnect
Reconnect
```

### Task Scheduler

```text
Task Registered
Task Updated
Task Deleted
Action Started
Action Completed
```

### WMI Activity

```text
5857
5858
5860
5861
```

更多 Windows Event 数据源会逐步加入。

---

# 设计原则

### 默认只读

采集过程中不会自动：

- Kill Process
- Delete File
- Modify Registry
- Enable Audit Policy
- Enable PowerShell Logging

避免因为采集工具本身改变现场状态。

### 不自动“判案”

IR-Toolkit 不会简单输出：

```text
HOST COMPROMISED
```

它提供：

```text
Evidence
Relationship
Confidence
Timeline
Historical Chain
```

最终结论由分析人员做出。

### 不把“没有日志”解释为“没有活动”

如果审计源未启用，会明确记录 Evidence Coverage。

### 原生 API 优先

Windows 采集优先使用：

- WinAPI
- Event Log API
- COM / WMI
- Registry API
- Service API

尽量减少对外部命令和 PowerShell 子进程的依赖。

---

# 当前状态

IR-Toolkit 仍在持续开发中。

当前重点：

```text
Windows Incident Response
    ↓
Evidence Collection
    ↓
Historical Reconstruction
    ↓
Cross-source Correlation
    ↓
Unified Timeline
```

Linux 架构已经预留，但当前主要精力仍然放在 Windows 主机应急响应能力上。

---

# 适用场景

IR-Toolkit 比较适合：

- Windows 主机疑似失陷排查
- Web Server 入侵后的主机侧分析
- RDP / 横向移动调查
- PowerShell 活动分析
- 攻防演练应急响应
- SOC 主机深度排查
- 历史攻击痕迹还原
- IOC 扩线分析

---

# Build

项目使用 Go 开发。

```bash
go build ./...
```

Windows ARM64：

```bash
GOOS=windows GOARCH=arm64 go build -o ir-windows-arm64.exe ./cmd/ir
```

Windows AMD64：

```bash
GOOS=windows GOARCH=amd64 go build -o ir-windows-amd64.exe ./cmd/ir
```

---

# 免责声明

IR-Toolkit 用于合法授权环境中的安全测试、应急响应、取证分析和防御研究。

使用者应确保拥有目标系统的合法授权。

---

# Contributing

项目仍处于持续迭代阶段。

欢迎：

- Bug Report
- Event Source 建议
- Windows 兼容性反馈
- ARM64 / AMD64 测试反馈
- Evidence Correlation 思路
- Timeline 改进建议

如果你有真实应急环境中的 Case 经验，也非常欢迎提出改进意见。

---

# IR-Toolkit

> **不要再把大量时间花在找日志、对时间、记 PID、拼事件上。**

让工具负责：

```text
采集
 ↓
规范化
 ↓
关联
 ↓
时间线
```

让分析人员专注于：

```text
分析
 ↓
判断
```
