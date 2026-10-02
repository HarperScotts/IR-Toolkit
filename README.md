# IR Toolkit

IR Toolkit 是一个面向攻防与事件响应（Incident Response）的本地命令行/ Web 工具集，目标是帮助调查人员在主机上收集证据、分析恶意行为、识别 IOC，并在本地浏览调查结果。

该项目目前以 Go 语言实现，围绕“收集证据 → 分析关联 → 识别 IOC → 浏览结果”这一链路组织。

## 项目概览

IR Toolkit 主要提供以下能力：

- 采集主机证据：进程、网络连接、持久化、登录、文件、事件日志等
- 分析关联：分析进程历史、网络活动、权限/启动项、登录行为、文件活动等
- 查找 IOC：对收集到的证据进行规则匹配与扫描
- 构建时间线：汇总事件，形成可审计的调查序列
- 提供本地 Web UI：用于查看 case、关联关系与证据细节
- 支持多主机只读调查视图：基于 central-store 的设计，支持跨主机视图查询

## 目录结构

```text
.
├── cmd/
│   └── ir/                    # 程序入口
├── internal/
│   ├── analyzer/              # 分析模块
│   ├── cli/                   # Cobra 命令行入口
│   ├── collection/            # 采集时间窗口与上下文
│   ├── collector/             # 证据采集器
│   ├── evidence/              # 输出与持久化
│   ├── ioc/                   # IOC 规则与扫描逻辑
│   ├── model/                 # 领域模型
│   ├── report/                # 报告相关逻辑
│   ├── store/                 # 只读存储与 case store
│   ├── timeline/              # 时间线相关逻辑
│   └── web/                   # Web 服务器与页面
├── docs/
│   └── central-store-contract.md
├── rules/
├── configs/
├── case-*/                   # 示例 case 目录
├── go.mod
├── go.sum
├── package.json
├── ir-windows-amd64.exe
├── ir-windows-arm64.exe
├── README.md
└── test-ioc.yaml
```

## 技术特点

- 基于 Go + Cobra 构建命令行工具
- 采集与分析逻辑分离，适合事件响应工作流
- 支持按时间窗口采集证据
- Web UI 用于浏览 single-host 和 multi-host case
- 设计中包含 central store / 只读调查视图的抽象，便于后续扩展到统一调查平台

## 快速开始

### 1. 安装依赖

```bash
go mod tidy
```

### 2. 构建命令行工具

```bash
go build -o ir ./cmd/ir
```

### 3. 查看命令帮助

```bash
./ir --help
```

## 常用命令

### 查看工具信息

```bash
./ir info
```

### 收集证据

```bash
./ir collect --output case-20260831-042516
```

也可以指定时间窗口：

```bash
./ir collect --output case-demo --since 2026-01-01T00:00:00Z --until 2026-01-02T00:00:00Z
./ir collect --output case-last-1h --last 1h
```

### 分析采集结果

```bash
./ir analyze case-20260831-042516
```

### 启动本地 Web UI

```bash
./ir web case-20260831-042516
```

默认监听地址为：

```text
http://127.0.0.1:8080
```

### IOC 扫描

```bash
./ir ioc scan case-20260831-042516
```

### 生成/查看进程树

```bash
./ir tree
```

## 工作流示例

典型使用流程如下：

```bash
# 1. 采集证据
./ir collect --output case-demo

# 2. 分析证据
./ir analyze case-demo

# 3. 扫描 IOC
./ir ioc scan case-demo

# 4. 打开 Web 界面
./ir web case-demo
```

## 说明

这个项目更偏向“调查工具/实验性资料收集框架”，而不是普通的业务应用。它更适合：

- 事件响应
- 取证与调查
- 攻防场景下的本地证据审计
- 快速构建单机/多机调查视图

另外，仓库中已经包含了多项设计文档和实现约束说明（例如 `docs/central-store-contract.md`），说明这套工具在设计上也考虑了后续向统一 central-store / multi-host investigation 演进。

## 许可证

本项目采用 IR Toolkit Non-Commercial License（非商业用途许可证）。

使用条件：

- 允许个人学习、研究、内部评估和非商业用途的使用、复制、修改和分发。
- 禁止任何商业用途，包括但不限于：销售、付费服务、企业内部商业部署、SaaS、广告/营销用途、商业平台集成或以盈利为目的使用。
- 若需要商业授权，请提前书面许可。

完整文本见 [LICENSE](/Users/ll/Documents/ir-toolkit/LICENSE)。

## 备注

- 该项目并非通用型生产级 SaaS 应用，而是具备安全调查与取证分析能力的研究/工具型项目。
- 某些采集和分析能力会依赖宿主操作系统特性与权限，因此需要在受信任环境中运行。

## 贡献/扩展

如果你要扩展这个项目，可以优先关注以下模块：

- `internal/collector/`：新增新的证据收集器
- `internal/analyzer/`：增加新的关联或恶意行为分析
- `internal/ioc/`：扩展 IOC 规则与匹配逻辑
- `internal/web/`：增强 UI 与证据展示
- `docs/`：补充设计文档、数据契约和案例说明

## 相关文档

- `docs/central-store-contract.md` ： central store 与 conformance 契约说明
- `rules/`：IOC 规则或策略目录
- `configs/`：配置文件目录

如果你需要，我也可以继续把这个 README 改成更偏“GitHub 展示风格”的完整版，或者再补一份英文版 README。