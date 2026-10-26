# IR Toolkit

当前开发版本：`0.3.0`。更新内容与未完成验收见 [CHANGELOG](CHANGELOG.md)。

IR Toolkit 是一个面向攻防与事件响应（Incident Response）的本地命令行/ Web 工具集，目标是帮助调查人员在主机上收集证据、分析恶意行为、识别 IOC，并在本地浏览调查结果。

该项目目前以 Go 语言实现，围绕“收集证据 → 分析关联 → 识别 IOC → 浏览结果”这一链路组织。

目前仍以 Windows 为主。Linux 已接通主机/进程基础快照、TCP/UDP 网络采集与基础分析，
以及 systemd/cron 候选采集、文件级解析、有限 systemd 观测合并和列表查询。
Linux 登录已支持有限 SSH 认证日志采集/解析、独立调查页/API 及查询时间窗口（未知时间保留上下文）；真实有效配置确认、完整登录会话、
文件调查和原生 audit/journal 历史仍未实现。login1 已接入独立原始观察、可空属性分析及调查页；不等于已确认活动会话，仍需真实 logind 验收。
能力范围、限制和后续顺序见 [Linux 支持说明](docs/linux-support.md)。
Linux login1 的只读兼容性诊断可用 `ir diagnose-login1`；[实机验收流程](docs/linux-login1-acceptance.md)区分自动观察与仍待执行的真实 logind 验收。

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

## 本地 Central 快照仓库

完整、已分析的 case 可复制到独立仓库，再从仓库启动只读调查：

```bash
./ir central-import --repository central-data --case-id investigation-1 case-host-a case-host-b
./ir central-web --repository central-data --case-id investigation-1
```

导入期间不要重写源 case。仓库不能放在源 case 内；同一 case/host/version 不允许覆盖。
服务重启只需要仓库，不再依赖原目录。原有按目录启动的 `central-web` 保持不变。
仓库包含敏感证据，使用可信本地磁盘和受限访问，勿提交到 Git 或公开共享。
格式、完整性检查和恢复限制见 [Central 契约](docs/central-store-contract.md#16-文件快照持久化与重启恢复)。
异常中断后不会自动接管锁；请先核实 writer 已停止及批次提交状态，再按
[显式恢复流程](docs/central-store-contract.md#17-异常中断与锁恢复)处理，勿删除仓库或手工发布暂存目录。

## 离线 case 包

停止对源 case 的采集、分析及其它写入后，导出到源目录之外的新文件：

```bash
./ir case-pack case-host-a --output case-host-a.ircase.tar
./ir case-verify case-host-a.ircase.tar
```

输出父目录必须已存在且可信；已有文件或链接不覆盖。导出保持原始证据字节，
复用现有 loader 检查全部领域，正常失败时仅清理本次新建的未完成输出。
输出不是原子发布：运行中可能观察到部分文件；异常终止可能遗留它，应先停止 writer
并核实状态，不自动覆盖或恢复。只有命令成功才表示导出完成。

命令返回 JSON 回执。`case-verify` 只读核对容器、完整文件清单、哈希和源身份，
`domains_loaded` 为 false，不能证明完整领域可加载或来源真实；两命令的 `committed`
均为 false，不解包、不写 Central 仓库。

导入时明确选择接收调查 ID、可信仓库和已存在且权限/ACL 受限的临时父目录：

```bash
./ir central-import-package --repository central-data --case-id investigation-1 --temp-parent ir-private-temp case-host-a.ircase.tar
./ir central-web --repository central-data --case-id investigation-1
```

一条命令只导入一个包；受限解包与完整领域加载通过后才提交，保持包内展示名称与原始证据字节。
同一 case/host/version 拒绝重复，不覆盖也不自动视为重试成功。正常结束仅清理本次临时树，
不删除输入包。不要用通用 tar 解包后当作可信目录导入。
提交回执为 `status: committed`、`committed: true`；提交阶段报错可能标记
`commit-outcome-unknown`、`committed: null`，必须核实仓库状态再重试，勿自行解锁或删除批次。
预算、格式、异常恢复和 Windows 待验收边界见 [离线包契约](docs/offline-package-contract.md)。

在授权 Windows 测试机上，可运行 [离线包验收脚本](scripts/windows-package-acceptance.ps1)。
需要 PowerShell 7、Go 和已构建的本机 `ir.exe`；指定可信私有工作父目录，
脚本只生成独立合成样例并保留日志，不使用真实 case、不自动清理或恢复仓库锁。
命令、覆盖范围和待验收项见 [运行验收记录](docs/runtime-acceptance.md#windows-离线包合成验收工具)。

## 开发验证

需要 Go（版本见 `go.mod`）、支持 `node:test` 的 Node.js 和 ripgrep。运行统一检查：

```bash
sh scripts/check.sh
```

也可使用 `npm run check`；单独运行前端交互测试使用 `npm test`，测试不需要安装额外的 npm 包。统一检查覆盖 Go 格式、Store/Web 依赖方向、canonical Network ID、vet、完整 Go 测试、离线包黑盒合成验收、前端语法及交互，以及 Windows/Linux amd64/arm64 交叉编译。交叉编译检查编译兼容性，不代替目标主机上的运行验证。

受限环境下可显式设置一个可写的 Go 缓存，例如 `GOCACHE=/tmp/ir-toolkit-go-cache sh scripts/check.sh`。脚本不覆盖已有可执行文件，也不读取或修改 case 证据。
离线包资源 profile 为单独的合成重型检查，不在默认检查中执行：
`sh scripts/measure-package-resources.sh`。预算、采样口径和测量结果见
[资源测量记录](docs/package-resource-profile.md)，不代表真实 case 或 Windows 的资源上限。

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
