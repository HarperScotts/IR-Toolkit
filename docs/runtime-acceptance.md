# 运行验收记录

## 2026-10-18：login1 只读兼容性诊断与实机验收捕获流程

新增 `ir diagnose-login1` JSON 命令和 `scripts/linux-login1-acceptance.sh`，
详见 [实机验收流程](linux-login1-acceptance.md)。这是可执行的诊断/材料捕获入口，
**真实 logind 的人工验收仍未执行**，不把脚本、编译或隔离合成运行称为目标机验收完成。

- 诊断复用生产固定 busctl/本地系统总线/禁用 auto-start 和交互授权的采集路径，只额外读取
  `/usr/bin/busctl --version`（2秒、stdout/stderr 各8KiB上界），不做完整 collect、不读取认证日志/
  accounting、不安装/提权/启动服务。环境记录 OS/架构/有效 UID，发行版与主机授权由人工补记。
- JSON 保留版本 bytes/hash、原始 login1、真实 Analyzer 输出、逐阶段 observed/failed/
  not_exercised 检查和人工清单；空列表明确 GetAll 未执行。CLI 先输出报告，不完整返回非零；
  `real_host_acceptance` 始终 not_attested，自动 observed_subset 也不是实机通过。
- 捕获脚本固定基础工具 PATH/locale、umask077、只接受绝对路径与新目录；0700目录、0600文件，
  保留原始 stdout/stderr/实际退出码、二进制前后摘要和 SHA256SUMS。已存在目录/符号链接拒绝，
  不覆盖或删除失败材料。捕获非原子，不认证输入二进制，人工需检查材料完整性与摘要。
- 命令状态机回归覆盖正常/空列表/部分拒读/损坏分析/非Linux、参数拒绝、源快照不变；
  inspection 取消/nil/非Linux无总线访问回归通过。相关 CLI/collector race 与增量10次回归通过。
- Linux/arm64 非root隔离容器中，将容器专用 `/run/dbus` tmpfs 的 socket 路径指向私有测试总线，
  使用真实生产二进制与采集脚本。总线缺失、合成 login1 正常、合成属性拒读三条完整捕获路径
  各连续10次通过，检查 JSON/schema/状态/false、权限、所有摘要、失败输出、旧目录/符号链接拒绝。
  `/run/dbus` 是新建的容器内测试挂载，不是宿主机总线；更换合成 fixture 时只结束了对应测试
  子进程，没有运行/修改真实 logind 或 sshd。无外网、只读根目录、cap-drop=ALL、no-new-privileges，
  只挂载测试源码、脚本和二进制，不访问宿主机日志、总线或 `/proc`。
- 完整检查通过：格式、边界/生成检查、vet、全量Go、离线包合成验收、脚本语法、前端原有21项
  以及 Windows/Linux amd64/arm64 生产代码交叉编译。没有新增 Web 页面或浏览器视觉验收。

显式集成配置 `IR_LOGIN1_CAPTURE_SCRIPT`、`IR_LOGIN1_DIAGNOSTIC_BINARY`、
`IR_LOGIN1_TEST_EXPECTATION` 仅供 `linux && login1integration` 测试二进制使用；
生产命令不接受这些环境变量作为地址/程序覆盖。缺少显式配置则测试失败，不会偷偷访问开发机总线。

当前仍需授权真实 Linux 主机材料来验证发行版、不同 busctl 版本、普通权限可见性、已有会话
准确性和自然变化；尚无这些材料，不登记为已完成，也不为完成验收主动创建认证活动或改配置。

## 2026-10-18：login1 属性观察规范化与独立调查页

新增 `login1-observation-v1` 分析 profile、独立 `linux-login1:` 证据 ID、Local/Central 查询/精确
详情、只读 `/api/linux-login1` 及独立首页卡片。来源仍是服务报告，不确认活动/身份、没有加入
Windows 会话/SSH 计数、风险、进程边或 Timeline。旧分析不自动迁移，原始数据不改写。

本轮自动验证通过：

- Analyzer 检查来源状态/限额、列表 hash/tuple/重复身份/字段匹配、属性调用引用及 hash；
  重复 JSON 键、错误签名/类型、null、非法 bool/uint32、Id 不一致保持未知或撤下值。
  false/0/空字符串、缺失及完整 uint64 分别保留；创建微秒值通过 JSON 十进制字符串输出，
  不转换成活动时间。原始字节、未来属性与来源告警仍保留。
- Local/Central 分页/总数/ID 排序、user 大小写、state 精确/active=false 不匹配未知、精确详情、
  错误传播、非法/重复 ID 和未知 profile 拒绝。Central 防御复制覆盖可空属性指针及原始字节，
  Store 包装使用现有生成器更新并通过生成校验；不在 Web 重做业务筛选。
- API 列表去掉大原始响应、详情保留来源与公共上下文；active 参数错误400、缺失 ID400、
  未知 ID404、缺失分析500；since/until/last 明确400，避免静默忽略时间窗。
  嵌入脚本可达。前端新增3项测试：false/0/空/Unknown 和大整数文本、安全原文展示，
  分页/过期列表/详情/失败清理、关闭后 reset 不产生隐藏请求；原有交互回归保持通过。
- Linux/arm64 非 root 隔离容器中，真实私有 D-Bus + busctl + 明确合成的 login1 服务响应
  接入真实 Analyzer，正常/空列表/拒读/对象消失及既有边界回归连续10次通过；
  CLI collect→analyze 与合成来源持久化回归也连续10次通过。未运行真实 logind/sshd，
  未访问宿主机总线/日志/`/proc`、无外网、只读根目录、cap-drop=ALL、no-new-privileges。
- 新属性解析 fuzz 15秒 697,182 次执行通过（单worker，关闭语料最小化）；
  Analyzer/Local/Central/Web/CLI race通过。完整检查通过：gofmt、边界/生成检查、vet、
  全量 Go、离线包合成验收、前端21项和 Windows/Linux amd64/arm64 交叉编译。

未执行本轮浏览器视觉验收或真实 logind 发行版/权限/动态会话变化验收；私有总线合成服务不是
真实登录全流程。多主机 Search/scoped detail、Timeline 和二进制 accounting 解码未接入。
来源 profile 和 API 语义见 [第二阶段说明](linux-login-sources.md#login1-属性观察与调查展示第二阶段2026-10-18)。

增量入口：

```sh
go test ./internal/analyzer ./internal/store/local ./internal/web -run '^TestLogin1' -count=10
go test -race ./internal/analyzer ./internal/store/local ./internal/store/central ./internal/web ./internal/cli
go test ./internal/analyzer -run '^$' -fuzz '^FuzzLogin1Properties$' -fuzztime=15s -fuzzminimizetime=0s -parallel=1
node --test internal/web/frontend_tests/linux-login1.test.cjs
```

## 2026-10-17：login1 公开接口原始观察采集

已接入 Linux LoginCollector，单独保存 `login/login.json` 的 `linux_login1`；
不是已确认活动会话、历史重建、SSH 认证结果、Windows 登录模型或进程关系。
本批没有新增属性规范化、Store/API 或页面。utmp/wtmp/btmp 仍不透明。
细节与复现入口见 [来源说明](linux-login-sources.md#login1-原始观察采集第一阶段)。

- 固定 `/usr/bin/busctl`、固定本地总线地址、清理环境，不经 shell；禁用自动启动与交互授权。
  只调用 GetId/GetNameOwner/ListSessions/GetAll，向 unique owner 读取属性，再核对 owner/bus ID。
  原生入口前后校验 collector kernel boot ID，不能将这些检查等同原子快照或真实性证明。
- 保存读取时间、bus/boot/owner 上下文、会话列表来源字段和每条 busctl stdout 字节/hash/
  stderr/error。属性字典本阶段保持不透明，保留 false/缺失/未知值，不从 PID 建立进程身份。
  工具/服务/权限/格式失败不伪装为空列表；错误通过 joined errors 保留，范围与失败进入报告。
- 单响应/总响应预算、64 个对象、严格 tuple/UID/路径/重复身份验证、取消/超时、对象消失、
  owner/bus 变化、错误返回及原文字节/hash 回归通过；15 秒新列表解析 fuzz 743,759 次通过
  （单 worker、关闭语料最小化）。collector/CLI race 通过。
- 现有隔离 Linux/arm64 镜像（Kali 2026.3、busctl/systemd 261.1）运行真实 private dbus-daemon
  加明确合成的 libsystemd 测试 peer。正常/空列表/拒读/消失及命令输出限额/取消测试连续 10 次通过，
  服务检查实际消息没有 auto-start/interactive 标志；恶意 DBUS/PATH 环境未改变指定传输路径。
  编译命令 `cc -std=c11 -Wall -Wextra -Werror ... -Wl,-l:libsystemd.so.0`；不依赖开发头文件。
- 同一非 root 隔离容器的原生 collect→analyze 连续 10 次通过：实际缺少系统总线时保留失败
  状态，原始快照含 login1 观察/时间字段，报告保留 login1 范围警告，而不是生成成功会话。
  只读根目录、无外网、cap-drop=ALL、no-new-privileges；只挂载测试源码/二进制，
  未挂载宿主机总线、日志或 `/proc`，未启动 logind/sshd、未主动认证。
- 全量 Go 测试、完整检查通过（格式、边界/生成校验、vet、离线包合成验收、前端原有 18 项及
  Windows/Linux amd64/arm64 交叉编译）。生产实现无新增 Go 模块依赖；缺失或不兼容 busctl 会报错。

增量检查：

```sh
go test ./internal/collector/linux -run '^TestLogin1' -count=10
go test -race ./internal/collector/linux ./internal/cli
go test ./internal/collector/linux -run '^$' -fuzz '^FuzzLogin1SessionEnvelope$' -fuzztime=15s -fuzzminimizetime=0s -parallel=1
```

标准测试使用有界传输 fixture 检查状态机；显式 `login1integration` tag 才启用真实私有总线集成，
缺少测试工具会失败而非跳过。合成 peer 不是真实 logind，本轮仍未验收真实会话权限/覆盖、
目标发行版/旧版 busctl、动态 daemon 重启或登录全流程，不把这些结果称为完整 Linux 会话支持。

## 2026-10-17：当前会话来源评估与 utmp ABI 开发探针

本批是来源/布局验证，不是新增当前会话或二进制登录历史能力。没有修改生产采集、
Analyzer、Store/Web 契约或旧 case。utmp/wtmp/btmp 仍不透明；不解析 systemd 私有状态文件。
来源选择与完整命令见 [来源及 ABI 验证记录](linux-login-sources.md)。

- 新增原生 Linux C 探针：测量 `<utmp.h>` 布局并输出两条完全初始化的合成内存对象，
  不打开 accounting 文件，不调用登录读写函数。探针不编入 `ir`。
- 新增有界 Go 校验工具和已测 JSON fixture；测试覆盖大小/对齐、字段集合、偏移/重叠/
  整数溢出、宽度、常量集合、正负整数哨兵、数组字节、padding、截断/非法 JSON/hex。
  合成大端变换仅测试校验器，不是大端 ABI 原生验收。
- Linux/arm64、Kali 2026.3、GCC 15.3.0、glibc 2.42 头文件：实际结构 400 字节、对齐 8，
  时间字段 8 字节。C 探针与 Linux/arm64 Go 程序串联连续 10 次通过。
  首次编译后执行被 noexec 临时挂载拒绝，使用容器专用 exec tmpfs 后才完成运行验证。
- 容器非 root、无外网、根文件系统只读、全部 capabilities 移除；仅挂载测试源码及生成工具。
  不启动镜像默认应用或登录服务，不接入宿主机日志、系统总线或宿主机 `/proc`。
- 完整检查通过：gofmt、边界与生成校验、vet、全量 Go 测试、离线包合成验收、前端 18 项、
  Windows/Linux amd64/arm64 生产代码交叉编译；开发工具的显式 vet/test 已加入统一检查。
  Go 校验器 race 通过。
- fuzz 首次双 worker 15 秒运行以 context deadline exceeded 失败；单 worker 10 秒虽通过但仅
  5 次执行，不作为有效覆盖依据。关闭语料最小化后，单 worker 15 秒完成 1,136,096 次执行并通过。
  未把首次失败隐去，也未发现或据此声称存在已复现的校验器逻辑缺陷。

增量命令：

```sh
go test -race scripts/utmp-abi-check.go scripts/utmp-abi-check_test.go
go test scripts/utmp-abi-check.go scripts/utmp-abi-check_test.go -run '^$' -fuzz '^FuzzUtmpABIReport$' -fuzztime=15s -fuzzminimizetime=0s -parallel=1
```

未验证其他 libc/架构/time64 组合、真实 writer 历史、login1 运行时权限/覆盖或实际登录流程。
探针测到的当前编译布局不能证明已有文件的 writer ABI；这些缺口阻止自动生产解码，
但不影响已有原始字节采集和 SSH 文本认证报告调查。

## 2026-10-17：Linux 原生登录调查页与查询时间窗口

独立 Linux SSH authentication 面板提供条件筛选、分页、来源状态/告警及原文详情，
不混入 Windows 会话，不生成 reported PID 进程链接。时间范围只作用于调查查询，
不改写采集、分析、原始日志或已保存统计；未知时间默认作为上下文保留。

自动回归覆盖：Local/Central 含首尾边界及纳秒边界、未知时间 include/exclude/only、
反向窗口/非法策略拒绝；HTTP 带偏移时间等价、无偏移时间拒绝、来源告警返回。
前端新增两项交互测试覆盖筛选编码、分页/重置、未知时间显示、原文与告警安全文本显示、
旧列表/详情响应失效、关闭取消及错误清理。

本轮已通过完整检查（gofmt、边界/生成校验、vet、全量 Go 测试、离线包合成验收、
前端 18 项测试与 Windows/Linux amd64/arm64 交叉编译），相关 Local/Central/Web race
通过；原生登录 Store/API 增量回归连续 10 次通过。嵌入首页与新增脚本的 HTTP 可达性也有回归。

本轮没有启动 sshd、主动认证、读取真实认证日志；未执行 Chrome 视觉验收，
也不构成发行版兼容性、二进制 accounting 解码或多主机原生搜索验收。

验证入口：

```sh
go test -race ./internal/store/local ./internal/store/central ./internal/web
node --test internal/web/frontend_tests/linux-logins.test.cjs
sh scripts/check.sh
```

## 2026-10-16：Linux 登录证据第一阶段

新增固定原始来源和有限 OpenSSH 认证报告解析，不声称当前会话或完整历史覆盖。实际通过：

- auth.log/secure 原文及哈希、utmp 非 UTF-8 二进制保真、空文件与缺失文件区分；
  链接不跟随、限额无成功截断内容、取消保持 errors.Is、非 root 拒读和 FIFO 安全回归。
  与持久化共用的稳定普通文件读取路径也做了回归，仍检查身份/大小/mtime/模式并计入读取预算。
- SSH Accepted/Failed、invalid user、IPv4/IPv6、认证方法、PID 原文、行号；
  RFC3339 偏移时间与缺少年份/时区的传统 syslog 区分，后者不补年份。
  非法 IP/端口、无偏移时间、EOF 尾部残片、其他格式/注入式文本、哈希不匹配/链接/二进制/
  重复路径/取消等回归通过；新解析 fuzz 15 秒通过（37,063 次执行），不代表完整语法覆盖。
- 原生记录不进入 Windows sessions/findings；同一文本来自不同来源仍分别保留，
  不伪造独立尝试数或会话关联。CLI 输出原生计数，范围与未覆盖项进入报告。
- Local/Central 原生分页/筛选/零时间排序、精确 ID、错误传播、重复 ID 拒绝；
  Central LoginAnalysis 原生数组、来源数组和统计指针经修改不污染后续读取。
- 独立原生列表/详情 HTTP API、无效 outcome/IP 与缺失 ID 返回码通过；
  尚未实现原生前端面板，也未手工验收 Chrome 新页面或多主机原生查询。
- Linux/arm64 非 root 隔离容器中，采集/权限/共用读取回归、认证解析和 CLI 原生/合成链路
  分别连续 10 次通过；没有运行 sshd、主动认证或写系统日志。只读镜像、无外网、移除 capabilities，
  仅挂载生成的测试程序并写容器临时目录，不读取宿主机认证日志。
- 全量 Go 测试、相关 collector/analyzer/CLI/Local/Central/Web race、完整检查通过，
  包括 Store 包装生成校验、前端原有 16 项及 Windows/Linux amd64/arm64 交叉编译。

增量入口：

```sh
go test ./internal/collector/linux -run 'Test(LinuxLogin|NativeLinuxLogin)' -count=10
go test ./internal/analyzer ./internal/store/local ./internal/web -run '^TestLinux(SSH|Login)' -count=10
go test ./internal/analyzer -run '^$' -fuzz '^FuzzLinuxSSHAuthentication$' -fuzztime=15s -parallel=2
```

未验证真实 sshd 认证全流程、发行版日志布局或二进制 ABI；utmp/wtmp/btmp 仍未解码，
原生记录尚不按采集时间窗口裁剪，也不进入原生 Timeline/Search/会话图。
详见 [Linux 登录证据说明](linux-support.md#linux-登录证据第一阶段)。

## 2026-10-16：systemd dash 层级与模板/实例来源选择

新增 `observed-system-service-v2`；保留 v1 读取，不改 canonical 证据 ID、不自动升级旧分析。
实际通过：

- 连字符逐级截断、连续/尾部/前导连字符、实例字符串内连字符不误作 prefix；
  模板、实例、普通前缀递归名称顺序、去重、255 字节名称和 64 项展开边界。
- 同源具体名称优先、跨来源先比较来源层级，type-wide 最低同名优先级，
  模板/实例同名 drop-in 及递归前缀组合的选择回归。
- 全部来源先查精确实例、完全没有精确候选时才查模板；高优先级模板不替换低优先级精确实例。
  拒读、空文件、alias/mask 精确实例不回退；相关层级/模板目录链接、拒读模板阻塞合并。
- 模板定义与具体实例分别输出，模板不产生隐含实例，通用前缀目录不产生 unit；
  `%i/%I` 等字面值不展开，activation 一律 unknown，不生成风险 Finding/进程关系/执行时间线。
- CLI 合成 Linux case 的模板 fallback、name_kind/profile/base_lookup 随分析 JSON 持久化；
  Store 接受已知 v1/v2、拒绝未知 profile，原输入摘要防陈旧机制保持不变。
  前端折叠 JSON 原样显示实例元数据和说明符，并验证切换后无残留；未进行本轮 Chrome 视觉验收。
- 新名称展开 fuzz 15 秒通过（2,243,143 次执行）；完整 Go 测试、相关包 race、完整检查通过，
  包含前端 16 项及 Windows/Linux amd64/arm64 交叉编译。
- 非 root Linux/arm64 隔离容器中，全部 systemd 回归及 CLI 流程分别连续 10 次通过。
  容器仅运行测试程序、读取自身环境和临时合成 case，无外网、只读根目录、移除 capabilities；
  不启动 systemd/cron，不执行配置中的命令，不采集宿主机，不修改服务或任务。

新增回归入口：

```sh
go test ./internal/analyzer -run '^TestSystemd' -count=10
go test ./internal/analyzer -run '^$' -fuzz '^FuzzSystemdDropinNames$' -fuzztime=15s -parallel=2
```

这是受限 profile 的来源选择验收，不是运行中 manager 或发行版矩阵的兼容验收。
别名、转义/非 ASCII、多 `@`、依赖链接中的实例发现、说明符展开和真实激活状态均不在本轮范围。
详细规则见 [systemd 观测合并说明](linux-support.md#systemd-观测合并有限配置投影)。

## 2026-10-16：systemd 来源优先级与有限观测合并

实现 `observed-system-service-v1`，仅普通系统级 `.service`；不确认实际 manager 加载状态。
已验证：

- base unit 优先级、generator.early、同名 drop-in 遮蔽、类型级与具名 drop-in、
  不同文件名字典序，以及 scalar 最后赋值、Exec 列表追加/空赋值清空和行号来源。
- 高优先级不可读/空文件/链接不回退，unit mask/alias 不解析、drop-in 的 `/dev/null` 链接
  保留抑制来源，vendor lib 同级冲突、重复/缺失/不完整/矛盾来源状态、坏 drop-in、
  链接目录、只有 drop-in 无 unit 均不产生合并设置；用户 scope 不混入系统 scope。
- 目录占用 unit 文件名保留错误，不再被采集器当作缺失；新增 control/transient/attached 固定来源。
- 模板/实例、dash 层级和转义名称明确 blocked；限额/取消回归及合并 fuzz 15 秒通过。
- Local/Central 校验整组输入摘要，新增文件、变更字节但保留旧声明哈希、来源状态/读错改变后
  不附加旧投影；重复或未知 profile 不附加。Central 深层 Values 修改隔离通过。
- Analyzer→Local→单 case Web 详情回归通过，UI 以折叠纯文本保留“非实际有效配置”警告，
  切换后无残留；没有本轮 Chrome 手工视觉验收。

Linux/arm64 非 root 隔离容器的原生合并测试、采集回归及 CLI 链路分别连续 10 次通过。
容器条件同前阶段，已有镜像、无外网、只读根目录、capabilities 全移除，只读挂载生成的测试程序，
数据仅在容器临时目录；未启动 systemd/cron、未修改宿主机服务或任务。
Go 全量测试、相关包 race、完整检查（前端 16 项、Windows/Linux 双架构交叉编译）通过。

复现增量测试：

```sh
go test ./internal/analyzer ./internal/store/local ./internal/web -run '^TestSystemd' -count=10
go test ./internal/analyzer -run '^$' -fuzz '^FuzzSystemdObservedMerge$' -fuzztime=15s -parallel=2
```

这不是 systemd daemon 验收、发行版矩阵或完整有效配置合并；激活与执行均 unknown，
不因投影生成风险 Finding/关联边/时间线。具体支持范围和资源上限见
[systemd 观测合并说明](linux-support.md#systemd-观测合并有限配置投影)。

## 2026-10-16：Linux 持久化文件级语法解析

接候选配置采集，新增 Analyzer 的来源绑定语法结果，未实现 effective-unit 合并或任务生效判定。
实际通过：

- systemd 节、重复/空赋值、跨注释续行、物理起止行号、坏节、未结束续行；
  单独 unit/drop-in 保留独立结果，不以 PID/路径生成运行关系。
- cron 系统表与用户 spool、声明用户来源、环境赋值、常见五字段及宏、非法/未支持时间字段；
  命令引号、内部空白、行内注释及百分号原文保留，脚本/anacrontab 不误解析成任务。
- 不可读、链接、缺失/不匹配 SHA-256、非 UTF-8/NUL、大小/行数/记录限制与取消回归；
  解析器多轮 fuzz（每轮 15 秒）通过，最终一轮 572,410 次执行，不代表完整语法覆盖。
- CLI 合成 Linux case 生成解析结果及统计，解析范围警告进入报告；Windows/旧 case 的事件文件
  必需行为保持不变。Local/Central 精确详情只关联匹配来源哈希的唯一结果，陈旧/重复结果不附加；
  Central 解析数组修改隔离测试通过。列表不附加解析大对象。
- 单 case API/UI 展示来源与文件级解析 JSON，前端验证纯文本渲染及切换后不残留。
  未进行本轮 Chrome 视觉验收；多主机 scoped 详情尚不展示解析内容。
- 原生 Linux/arm64 非 root 隔离容器中，新增合成解析回归及 CLI 基础链路分别连续 10 次通过。
  同前两节的隔离条件，不启动 systemd/cron，不修改服务或任务，不采集宿主机。
- `go test ./...`、analyzer/CLI/Local/Central/Web race、完整 `scripts/check.sh` 通过；
  前端 16 项及 Windows/Linux amd64/arm64 交叉编译通过。

新增回归入口：

```sh
go test ./internal/analyzer -run '^TestLinux(Systemd|Cron|Config)' -count=10
go test ./internal/store/local ./internal/web -run '^TestLinux(Config|Persistence)' -count=10
go test ./internal/analyzer -run '^$' -fuzz '^FuzzLinuxPersistenceConfig$' -fuzztime=15s -parallel=2
```

这是文件内的有限语法解析，不是守护进程兼容性、有效配置或执行验收。
全部解析结果的 activation 仍为 unknown，不因此生成风险结论/执行时间线/进程关联。
具体语法与边界见 [Linux 文件级解析说明](linux-support.md#systemdcron-文件级解析)。

## 2026-10-16：Linux 持久化候选配置采集

接上一阶段，仅实现原始配置采集和证据清单；不把配置存在解释为已启用、已执行或失陷。

本轮实际通过：

- 合成目录覆盖 systemd unit/drop-in/wants 链接、mask 目标、悬空链接、后代目录链接不跟随、
  cron 文件和 spool、空文件/非 UTF-8 字节及哈希、文件替换、条数/字节限额、取消。
- Linux/arm64 非 root 隔离容器中上述采集测试连续 10 次通过，额外验证数字 UID/GID、
  拒读普通文件、FIFO 不阻塞及 O_PATH 安全打开拒绝链接/FIFO。
- 同一容器中的真实 `runCollect → runAnalyze → Store` 连续 10 次通过；
  实际观测到 cron root 文件权限拒绝，元数据/错误保留，并正常生成带限制说明的报告。
- Local/Central 列表、分页、mtime 排序、精确 ID、大小写路径不合并及原 Windows ID 回归通过；
  Central 返回的原始字节、UID 指针、来源状态经修改后不会污染下一次读取。
- 单 case Web 详情 API 保留原始 Linux 证据，前端以折叠纯文本 JSON 展示，旧选择不残留；
  非 UTF-8 内容保留为 Base64。没有进行本轮 Chrome 手工视觉验收。
- 报告在生成摘要前纳入采集警告，摘要的 gap 数与最终列表一致，保留主机 OS/架构。
- `go test ./...`、相关 collector/analyzer/CLI/Store/Web 包 race、完整 `scripts/check.sh`
  通过；前端现为 16 项，Windows/Linux amd64/arm64 均交叉编译通过。

容器隔离条件同下节：已有镜像、无外部网络、非 root、只读根目录、capabilities 全移除，
仅挂载生成的测试程序并写容器临时目录，不启动 PostgreSQL，不修改宿主机配置。
原生增量回归入口：

```sh
go test ./internal/collector/linux -run 'Test(NativePersistence|Persistence)' -count=10
go test ./internal/cli -run '^TestNativeLinuxCollectAnalyze$' -count=10
```

这不是运行中 systemd/cron 的调度或生效验收，亦不是发行版/权限矩阵验收。
有效配置解析、用户 home、自定义加载路径、其他持久化机制和历史执行证据均未覆盖。
范围和上限见 [Linux 持久化说明](linux-support.md#持久化候选配置)。

## 2026-10-16：Linux 基础网络与分析链路

环境：macOS 开发宿主；实际运行环境为已有 `postgres:17-alpine` 镜像中的 Linux/arm64，
覆盖入口为 Go 测试程序，不启动 PostgreSQL。容器以 UID 65534 非 root、无外部网络、
只读根目录、移除 capabilities、no-new-privileges 运行；只读挂载本轮生成的测试二进制，
输出写容器 `/tmp` tmpfs。没有挂载或采集宿主机 `/proc`，没有下载新镜像，测试容器自动移除。

实际通过：

- 真实 IPv4/IPv6 回环 TCP、UDP 套接字 → `/proc` 网络采集 → 自身 PID/实例键 →
  Analyzer → Local Store 查询，连续 10 次；IPv6 在该环境实际运行并通过，非跳过。
- CLI 的 `runCollect` → `runAnalyze` → Store 查询真实 IPv4 TCP/UDP，连续 10 次；
  使用独立临时 case，确认自身进程实例键及未实现登录模块警告保留。
- Linux 缺少 Windows 事件文件可分析且不伪造原始文件；已有文件格式损坏仍失败；
  Windows/旧 case 缺少该文件仍失败，以上回归连续 10 次。
- 合成 procfs 的 IPv4/IPv6 字节序、共享 inode、不同进程命名空间、inode 0、未知状态、
  读取失败、取消、进程实例及缺失证据回归；解析器 fuzz 20 秒通过。
- Go 全量测试、相关包 race，以及完整 `scripts/check.sh`，含前端 15 项和
  Windows/Linux amd64、arm64 交叉编译。

原生测试复现入口（仅在授权 Linux 环境；测试读取运行环境自身 `/proc`，创建回环监听和临时文件）：

```sh
go test ./internal/collector/linux -run '^TestNativeNetworkCollectorOwnLoopback$' -count=10 -v
go test ./internal/cli -run '^TestNativeLinuxCollectAnalyze$' -count=10
```

这不是 Linux 发行版矩阵、Linux/amd64 运行验收、hidepid/SELinux/AppArmor 验收，
也没有新增 Windows 实机验收。登录、持久化、文件、原生 audit/journal 仍未实现；
能力覆盖率未量化，未归属网络连接暂不出现在 Store 网络列表。完整限制和后续计划见
[Linux 支持说明](linux-support.md)。

## 2026-10-10：Chrome 多主机交互

环境：macOS 宿主、真实 Google Chrome、本机 loopback 服务。使用
`TestCentralBrowserFixture` 生成的合成证据，没有采集或修改用户主机证据。
这不是 Windows 运行验收，也不是全部浏览器兼容性验收。

复现入口：

```sh
IR_TOOLKIT_BROWSER_TEST_ADDR=127.0.0.1:18087 go test ./internal/cli -run '^TestCentralBrowserFixture$' -v -timeout 12m
```

打开 `http://127.0.0.1:18087`。服务最多运行十分钟。两个 view 为
`fixture-investigation / fixture-alpha / collection-1` 和
`fixture-investigation / fixture-beta / collection-2`。

| 检查 | 实际观察 |
| --- | --- |
| 同 ID 跨主机 Search | `needle` + Process 返回两个 `process:42`，结果分别保留 alpha、beta 来源 |
| 精确详情 | beta 详情的 Source 为 beta / collection-2，PID 为 42，PPID 为 0 |
| 详情链接刷新 | 刷新后恢复查询、Process 类型和同一个 beta process 详情 |
| 单 view 筛选 | 只选 beta 后返回 1 match / 1 host view；改变选择清除旧详情与链接 |
| Timeline 全局分页 | 两个 view 共 104 matches；第一页 50 条、第二页 50 条、末页 4 条 |
| 分页前统计 | 分类摘要 process: 104；alpha、beta 各 52 条 |
| 末页边界 | Previous 可用，Next 禁用 |
| 零时间排序 | 降序末页最后两条为各 host 的 event:0，均显示 Time unknown |
| 末页链接刷新 | 刷新仍为 offset 100、4 shown，没有回到第一页 |
| 零时间详情链接 | beta event:0 详情及再次刷新保留 beta / collection-2、timeline、event:0 |
| 原始详情 | Raw JSON 可展开，包含同一 view 与原始零时间；结构化详情截图中字段与来源清楚可读 |

本次没有手工验证所有筛选组合、异常 HTTP 响应、剪贴板复制或不同窗口尺寸；
对应自动化测试不能替代这些项目的实机验收。

## 2026-10-10：归档模式跨进程恢复

环境仍为 macOS + 真实 Chrome；此轮使用编译后的 `ir` 可执行文件启动
`central-web --repository`，不是测试内部 Web Server。所有数据仍为合成 fixture。
合成源 case 随准备测试正常退出由 `t.TempDir` 清理，并通过文件存在性检查确认
两个原目录已经不存在，随后才启动归档服务。

实际验证：

| 检查 | 实际观察 |
| --- | --- |
| 独立副本启动 | 只提供仓库路径与 fixture-investigation，恢复 alpha / collection-1、beta / collection-2 两个 view |
| 全局分页 | needle Timeline 共 104 条，分页为 50 / 50 / 4，末页 Next 禁用 |
| 保存链接 | 页面生成的链接包含两 view、timeline、needle、limit 50、offset 100，以及 beta 的 timeline / event:0 |
| 真正进程重启 | Ctrl+C 后旧进程正常退出，端口释放；用同一可执行文件和仓库启动新进程 |
| 跨进程链接恢复 | 在 Chrome 重新打开保存的链接，返回 104 matches / 4 shown，并恢复 beta / collection-2 / event:0 详情 |
| 详情展示 | 实际截图中 Source、PID 42、Time unknown 和折叠 Raw JSON 显示清楚 |
| 无效版本 | 将链接里的 beta 版本改为 unpublished-version 后，页面明确报 host/version unavailable，复制按钮禁用，旧结果/详情清除，不自动放宽查询范围 |
| 返回有效链接 | 重新打开原有效链接，再次恢复同一末页与 beta 详情 |

本轮没有发现需要修改的业务行为。新加入 opt-in 的
`TestPrepareArchivedBrowserFixture`，只接受专用的空目标目录，复用现有两主机
fixture 并调用导入命令实现。它正常退出后不保留源 case，归档副本由操作者管理。

复现准备（项目根目录；shell 使用任务专用临时目录变量）：

```sh
task_fixture=$(mktemp -d /tmp/ir-toolkit-browser-XXXXXX)
mkdir "$task_fixture/archive"
IR_TOOLKIT_ARCHIVE_BROWSER_ROOT="$task_fixture/archive" go test ./internal/cli -run '^TestPrepareArchivedBrowserFixture$' -v
go build -o "$task_fixture/ir" ./cmd/ir
"$task_fixture/ir" central-web --repository "$task_fixture/archive" --case-id fixture-investigation --listen 127.0.0.1:18087
```

用 Chrome 打开 `http://127.0.0.1:18087`，查询 needle Timeline，连续 Next 到末页，
选择 beta 的 event:0，保存面板里的调查链接。停止服务后再次执行最后一条命令，
重新打开链接。此流程验证正常停止/启动，不验证断电、强制终止或文件系统崩溃。
测试服务只绑定 loopback；临时仓库是合成数据，不包含真实采集证据。

## 2026-10-10：异常中断与锁恢复回归

在当前 macOS 宿主运行 `TestArchiveForcedTerminationAndExplicitLockRecovery`。
测试启动独立 Go 测试子进程，以 pipe 同步到三个准确检查点后强制终止：
首个 case 完成、整批暂存完成、rename 提交后但锁释放前。

已观察到：

- 前两种情况只恢复旧 view，第三种恢复旧 view 和完整新批次，没有半批次。
- 活跃进程和被终止进程留下的锁均拒绝新写入；拒绝操作不修改或替换锁。
- 父进程 Wait 确认 writer 死亡并完成校验后，显式解除测试锁。
  未提交批次重新导入成功，已提交批次同版本重试被拒绝。
- 重试不清理另一调用遗留的 stage；恢复后的正常调用释放自己的新锁。

检查点回归重复运行十次，并运行 race 检查。所有数据只位于测试自己的临时目录，
没有恢复真实仓库的锁。测试使用最小 Store stub 验证存储提交边界；完整领域与真实 Chrome
验收仍分别见前面的记录与领域 fixture 测试，不能用该 stub 代替目标机采集测试。

复现：

```sh
go test ./internal/store/archive -run '^TestArchiveForcedTerminationAndExplicitLockRecovery$' -v -count=10
go test -race ./internal/store/archive ./internal/cli ./internal/store/central
```

这不是断电恢复、磁盘故障或 Windows 实机验收。操作流程和未覆盖边界见
[异常中断与锁恢复](central-store-contract.md#17-异常中断与锁恢复)。

## 2026-10-10：离线包元数据校验回归

新增 internal/packageio，仅校验描述文件与声明；没有解包、验证实际 payload、
写仓库或 Agent 传输。验证内容包括严格 JSON、Unicode/重复键、整数大小、
可移植路径、目录别名/前缀冲突、预算边界、不改写输入与 IO 错误保留。
指纹固定样例由独立 Node crypto 计算，覆盖零/非零文件大小和原始 SHA-256。

两个 fuzz target 分别配置 -fuzztime=5s、-parallel=2，在当前宿主实际各运行约 6 秒，
ReadMetadata 执行 392369 次，ValidatePayloadPath 执行 203872 次，均未发现失败。
短时 fuzz 不代表安全证明或覆盖全部攻击输入。

元数据测试、race、统一检查与 Windows 交叉编译通过；Windows 实机仍待验证。
完整包和领域验证边界见 [离线包契约](offline-package-contract.md#8-当前实现与已验证边界)。

## 2026-10-10：受限容器与实际字节校验回归

新增 VerifyContainer，只流式读取，不解包、不写仓库。使用标准库 Writer 构造实际
USTAR/PAX/GNU/gzip/ZIP fixture；受限读取器拒绝隐藏扩展与压缩封装。
合法容器的实际字节数、payload SHA-256 与 inventory 一致，零/512/513 字节文件通过；
样例容器的每个截断前缀均失败。

回归同时覆盖不安全文件头、大小/名称/哈希不符、乱序/重复/缺失/额外条目、
非零填充、完整双结束块、尾部非零/拼接/超量零块和实际读取预算。
底层同时返回末批字节与 EOF/错误也不会掩盖超限或 IO 失败；
取消与连续无进展读取明确失败，所有失败不返回部分成功结果。

FuzzVerifyContainer 配置 -fuzztime=5s、-parallel=2，在当前宿主运行约 6 秒、
执行 271206 次，未发现失败。短时 fuzz 不是安全证明。
该层尚不验证 manifest 引用、源身份和领域完整性；不是完整 case 验收，也不是远程入口。

## 离线包源一致性回归（2026-10-10）

VerifySource 复用容器实际字节校验，随后检查 manifest 原始证据引用和源 host/version。
合成自洽容器覆盖引用子集、空/null 清单、hostname 优先/回退/trim、身份不一致、
缺失源文件、重复/大小写/Unicode 别名、坏 JSON/Unicode、非法路径、错误引用及大小类型。
无效尾部、取消和每份源 JSON 的独立预算均明确失败，且不返回部分结果。
只暂存两份有界源 JSON，不解包、不写仓库；这些测试不证明完整领域加载或发送者真实性。
全量开发检查、packageio 竞态检查通过；FuzzVerifySource 两 worker 短时运行
149314 次无失败。另有重算容器哈希的源 JSON fuzz target，以覆盖内层解析。

## 离线包底层导出回归（2026-10-10）

ExportCase → VerifySource 合成 case 往返保留全部文件原始字节、IOC 顺序、
canonical Network ID 字符串、历史关联字段及零时间；这些是字节保真测试，不是 12 类
Store 详情集成验收。分析输出与空文件均进入 inventory，空目录不生成条目。
重复导出字节稳定，展示名称与源身份分离；源证据不改写。
负例覆盖坏源引用/身份、非法文件名、软链接、树内硬链接别名、FIFO、大小/数量预算、
容器精确预算、写入错误/短写/取消及导出间文件编辑（包括恢复 mtime）、新增/删除/替换。
目录大小写别名在文件系统可创建 distinct case-only 名称时测试，否则明确跳过。
当前仅 io.Writer 底层 API；没有新包文件发布、解包、导入提交或新 CLI 命令。
全量 scripts/check.sh（含前端 15 项测试与 Windows 双架构交叉编译）、
packageio 竞态检查及导出回归连续 10 次运行均通过。交叉编译不等于 Windows 实机验收。

## 离线包 CLI 回归（2026-10-10）

真实 Cobra case-pack/case-verify 命令以合成完整 case 往返，核对回执、文件数量、
内容指纹与源字节不变；命令注册和参数/必填 output 规则覆盖。
导出端复用全部领域预加载，坏/缺失领域拒绝并清理本次新文件；
坏领域但容器/源声明自洽的包可以通过只读 verify，回执 domains_loaded=false。
覆盖现有输出及链接不覆盖、输出在源内/通过父目录链接回到源内的拒绝、
取消、无效尾部、非普通输入、失败输出清理和不删除被替换的输出路径。
回执 IO 失败保留已完成包，并报告已完成输出而非假称未导出。
本阶段不解包、不创建仓库或发布 view；12 类 pack→import→重启详情流程仍待包导入实现。
全量 scripts/check.sh、CLI/packageio 竞态检查及命令回归连续 10 次运行均通过；
go run 实际入口的两个命令 --help 可用。Windows 双架构交叉编译通过，实机仍待验收。

## 受限临时解包回归（2026-10-10）

ExportCase → Extract 合成往返保留全部原始 payload 字节，临时 case 路径不取自展示名称。
Unix 临时根/目录 0700、文件 0600，描述文件不写为证据；Close 幂等，父目录原文件和源 case 不变。
覆盖截断、坏哈希/填充/尾部/拼接、链接/目录/PAX header、路径逃逸、源身份/引用错误，
所有失败不返回部分解包结果并清理本次树。测试还覆盖取消、末批 IO 错误、容器/源 JSON 预算、
目标独占创建、已有目录/叶子链接拒绝、唯一随机新根以及不删除被替换的根。
私有 capture 生命周期测试确认 130 份 payload 逐份关闭，关闭错误不被吞掉；新增 Extract fuzz target。
本轮没有包导入 CLI，不加载完整领域、不写仓库；Windows ACL 与实机行为仍待验证。
全量 scripts/check.sh、packageio/CLI 竞态检查及解包回归连续 10 次均通过。
FuzzExtract 两 worker、5 秒配置实际运行约 6 秒，执行 365 次，无失败；
短时文件系统 fuzz 覆盖有限，不是安全证明。该阶段进程级回归尚待补齐，后续结果见下文。

## 显式包导入与重启回归（2026-10-10）

两个合成完整 case 具有相同 12 类原 ID；case-pack → case-verify → Cobra
central-import-package → 清理临时根 → 新 archive.Load/调查 Store 的链路通过。
接收调查为操作者指定 receiving-case，不使用包中的 collection version 作为调查归属。
重启前删除源 process JSON；重启后所有归档原始字节、展示名称及 12 类精确详情仍与原 Store 相等。
按类 Search 结果/原 ID、零时间 Timeline/counts、CurrentProcess 历史 PID 关系、
PowerShell 历史 ID 关系和可选 SecurityProviders/Report 缺失语义保持不变。
坏/缺失领域、非法尾部和预取消不创建仓库；writer busy/重复 view 不增加 view、不删除他人锁。
测试覆盖展示名称包含斜线但仅作显示、回执 IO 失败后提交仍可恢复，以及整个临时根/别名的仓库包含拒绝。
正常成功/失败均清理本次临时树且输入包不变；提交错误回执明确 unknown/null，不假称未提交。
该阶段尚未完成包流程进程强杀；后续结果见下文。真实大 case 资源测量和 Windows ACL 仍待验收。
全量 scripts/check.sh（含前端 15 项及 Windows 双架构交叉编译）、CLI/packageio/archive/central
竞态检查及包导入回归连续 10 次均通过；实际 go run 命令入口 --help 已确认。

## 包流程进程强制终止回归（2026-10-10）

macOS 子测试进程以 pipe 同步到精确边界后由父进程 Kill/Wait，使用可信 t.TempDir 与合成 case。
导出 fixture 首个 payload 为 96 KiB，验证部分输出与完成但回执前的两种中断状态。

| 检查点 | 仓库/输出状态 | 遗留物及显式重试 |
| --- | --- | --- |
| 导出 payload 写到一半 | 部分包无法 VerifySource | 输出保留，同路径重试拒绝覆盖；选择新路径可成功 |
| 导出 Sync/Close 后、回执前 | 完整包可校验 | 同路径不覆盖；源证据始终不变 |
| 导入解包首个文件写到一半 | 只有原有 view | 部分提取根遗留，无 lock/stage；新提取/提交成功且旧根保留 |
| 解包校验完成、领域预加载前 | 只有原有 view | 完整提取根遗留，无 lock/stage；新调用不清理旧根 |
| 领域预加载完成、提交前 | 只有原有 view | 同上，不把临时根当作已提交 |
| stage case 副本完成、commit.json 前 | 只有原有 view | lock + stage + 提取根遗留；重试被锁拒绝 |
| Commit 返回后、回执/提取清理前 | 原有 + 新完整 view | lock 已释放，提取根遗留；重复重试拒绝，不覆盖已提交 view |

stage 场景先在子进程运行时确认 writer busy；Kill/Wait 后再次确认 lock 的内容和身份未被重试改变。
只在父进程已证明子 writer 死亡且 archive.Load 校验通过后，将本次精确 lock 移到另一个
t.TempDir 恢复记录目录，再显式重试。遗留 stage/提取根在新调用后保持字节和路径不变。
旧批次始终不变，输入包不改写；正常新调用只清理自己的提取根。测试结束由框架清理其临时 fixtures。
这些检查补充已有 archive 三个提交内部强杀边界，不替代断电/硬件故障、真实大 case 资源测量、
归档单文件复制中途或 Windows 实机验收。生产 CLI 不读取测试 helper 环境变量或接受检查点参数。
七个边界连续 10 次（70 次测试子进程强制终止）通过；全量 scripts/check.sh、
CLI/packageio/archive 竞态检查通过。Windows 双架构交叉编译仅验证构建，不代表目标系统运行。

## 合成预算边界资源测量（2026-10-10）

单独 opt-in 入口在新子进程中测量三种 case 的 export/verify/extract/import，共 12 个操作，
覆盖恰好 256 MiB payload、4096 文件和恰好 64 MiB process JSON（125176 条不同 PID 记录）。
首轮完成约 21.5 秒；256 MiB payload import 堆采样峰值约 2.14 MiB、逻辑工作区峰值约 1 GiB；
密集 JSON import 堆峰值约 292.84 MiB；4096 文件 import 本次约 16.3 秒。
这些是 macOS 合成样本、含采样开销，不是系统 RSS、实际磁盘分配或真实 case 上限。
默认开发检查跳过重型 profile；可复现入口、完整表格和限制见 [资源测量记录](package-resource-profile.md)。
第二轮 12 个操作全部通过（约 21.1 秒），并记录 GC/内存限制环境值；
全量 scripts/check.sh、CLI/packageio/archive 竞态检查通过。

## 多文件缓冲分配优化回归（2026-10-10）

导出与 archive.inventory 的复制缓冲改为操作独占复用；不共享全局状态，不改变限额、源字节、
逐文件 Sync/Close、commit.json、writer lock 或 rename 边界。
同口径默认资源 profile 的 12 操作全部通过；4096 文件 export 分配约 604 → 89 MiB。
独立两遍 copySource benchmark 的参考按文件分配版与复用版约 17.94 MB/op → 0.63 MB/op。
新增只测关键边界磁盘的测试模式，确认周期目录采样会造成显著累计分配；
不将含采样开销的旧 import 1.5 GiB 分配误认为产品自身成本或堆峰值。
完整 import 本次仍约 16–17 秒，没有宣称 IO/持久化耗时改善；详情见 [资源测量记录](package-resource-profile.md)。
全量 scripts/check.sh、CLI/packageio/archive 竞态检查，以及包导入/导出强杀回归连续 10 次通过。
12 类原 ID/详情与重启查询测试均通过；Windows 仍仅交叉编译，未扩大实机/断电验收结论。

## 剩余成本阶段定位（2026-10-10）

新增 source scan、metadata read/validate、archive copy/Sync benchmark，并通过测试核对
观测版与正常 inventory 的哈希/原始字节一致、复制时每文件恰好一次 Sync、只读哈希不 Sync。
生产 inventory 不装回调、不取时间戳；无新运行时故障注入/测量开关。
本机本次 4096×512 字节文件的归档 inventory 约 18.14 秒，其中 File.Sync 调用约 15.45 秒
（4096 次，约 85%）；目录+路径+硬链接检查约 28.65 ms，
严格元数据读取约 14.51 ms、分配约 16.45 MB。不因此删除或合并原有 Sync。
这不是内核 IO tracing、Windows 指标或完整导入 SLA；口径与复现命令见
[资源记录](package-resource-profile.md)。
全量 scripts/check.sh、CLI/packageio/archive 竞态检查通过；
观测接口原始字节/哈希/同步次数回归连续 10 次通过。普通检查不执行重型 IO benchmark。

## 2026-10-11 元数据解析分配回归

files 条目共享 JSON decoder，保留精确字段/重复键、Unicode、int64 和限额拒绝规则。
旧解析器保留在测试中，用确定性样例和 20 秒差分 fuzz 比较接受结果及字段值；
完整 ReadMetadata fuzz 同时运行。4096 文件读取基准从 16452965 降到 8262706 B/op，
约减少 49.8%；逐文件 Sync、归档提交、查询语义均未更改。
全量 scripts/check.sh（含 Windows 两架构交叉编译）和 packageio/CLI/archive 竞态检查通过。
这不是 Windows 运行验收或完整导入 SLA；详细测量口径见
[资源记录](package-resource-profile.md)。

## 2026-10-11 源目录身份检测扩展性

macOS/Linux 源扫描添加设备号+inode 索引，命中仍用 os.SameFile 确认；
未知身份和键碰撞保留逐对回退。Windows 和其它平台继续原检查，不新增未实机验证的句柄逻辑。
固定随机排列与旧逐对实现对照，覆盖硬链接、不同大小快照、未知身份和包装对象；
设备/inode/typed nil 与晚出现硬链接回归连续 10 次通过。
本机 4096 文件扫描约 26.53 → 17.88 ms/op，分配约 4.69 → 5.11 MB/op。
这是额外索引内存换取正常原生身份检查的扩展性，不是所有规模/平台上的性能承诺。
完整检查、packageio/CLI/archive 竞态检查通过；Linux 测试包可交叉编译，未在 Linux 执行。
详见[资源记录](package-resource-profile.md)。

## Windows 离线包合成验收工具

2026-10-11 新增 `scripts/windows-package-acceptance.ps1` 和可移植的
`scripts/package-acceptance.go` 黑盒测试程序。后者直接执行指定 IR 二进制，
不调用包内部测试钩子、不使用 shell 拼接命令、不启动服务或采集真实证据。

在授权的 Windows 测试机上，准备与项目 go.mod 相符的 Go、PowerShell 7 和本机 `ir.exe`，
选择已存在的可信私有本地工作父目录（建议 NTFS，避开共享目录、真实 case 和仓库）。
遵守机器执行策略；脚本不绕过策略，也不安装任何组件：

```powershell
pwsh -NoProfile -File .\scripts\windows-package-acceptance.ps1 `
  -IrPath 'C:\IR-Test\ir.exe' -WorkParent 'C:\IR-Test\private-work'
```

启动器在父目录内新建随机子目录，关闭其 DACL 继承并仅显式允许当前用户完全控制，
核对规则后才写入样例；不修改调用者指定父目录的 ACL。
实现依据是 [Set-Acl](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/set-acl)
和 [SetAccessRuleProtection](https://learn.microsoft.com/en-us/dotnet/api/system.security.accesscontrol.objectsecurity.setaccessruleprotection)。
这是新建验收目录的访问限制，不保证管理员/特权身份无法访问；
祖先目录、磁盘、二进制和 Go 工具链必须由操作者确保可信。
ACL 设置/回读不符会停止，不降级到宽松权限。记录 Windows 版本、OS/进程架构、
PowerShell 版本、当前用户 SID、DACL 和二进制路径到 `windows-environment.json`。

Go 测试程序在其下再生成唯一运行目录，路径含空格，使用 UTF-8 无 BOM 合成 JSON
和带 Unicode/CRLF 的原始字节；manifest 引用原始样例的精确大小和 SHA-256。
各领域文件齐全，主要使用空领域，仅包含一个合成进程；不是全领域真实调查覆盖。
14 项检查包括：

- 导出与只读验证回执、接收端选择的 case/host/version 和展示名称。
- 已有包不覆盖、源目录内输出拒绝、无效领域导出失败且本次输出清理。
- 损坏 payload 和截断包的验证/导入拒绝；失败不创建仓库，输入保持不变。
- 成功提交、解包临时树清理、commit 身份/清单与归档原始字节核对。
- 重复导入拒绝，不改已有仓库，不遗留锁/stage；不将重复视为成功重试。
- 独立新进程从归档 case 重新加载领域并打包；源 case 与原输入包未变化。

重新加载通过 `case-pack` 验证归档 case 的领域字节可读取，
不等价于 Central 仓库打开/查询/Web 重启验收；全 12 类非空详情与关系仍由既有 Go 测试覆盖。
本工具也不覆盖进程 kill、断电、锁恢复、权限不足、链接类型或预算上限场景。

每条命令保存 `.command.json`（参数/退出码/预期）、`.stdout.txt`、`.stderr.txt`；
最终 `result.json` 记录 passed/failed、已完成检查、失败原因、平台、测试程序 Go 版本、
指定二进制 SHA-256 和时间。SHA-256 仅标识本次所用二进制，不证明其来源可信。
每条命令最多运行一分钟，超时终止本次子进程并报告失败；
可能保留未完成包、stage 或锁，不表示回滚成功。
无论成功还是失败，工具不删除任何验收产物，不自动解锁、重试提交或发布 stage。
控制台显示精确保留目录；失败应先核实 writer 和提交状态，按现有恢复契约处理。
报告可能包含本机路径和用户 SID，仅本地保存，勿公开上传。

开发机可直接测试可移植部分（私有父目录权限由操作者负责）：

```bash
go run scripts/package-acceptance.go -ir /absolute/path/to/ir -work-parent /absolute/private-test-parent
go test scripts/package-acceptance.go scripts/package-acceptance_test.go
```

本轮 darwin/arm64 原生二进制黑盒测试、失败保留/无法执行误判回归和竞态测试通过；
统一 `scripts/check.sh` 纳入黑盒测试。Windows amd64/arm64 的测试程序已交叉编译，
但当前宿主无 pwsh，启动器语法检查明确跳过，DACL 和 Windows 命令执行仍待实机验证。
有 pwsh 时测试会仅调用 PowerShell parser 检查语法，不执行启动器或变更 ACL。

## 2026-10-12 搜索加载错误传递

Local SearchInvestigation 对非空查询先验证所选领域，再生成结果。
各 ensure 方法仍使用原 sync.Once 缓存及原可选文件语义，不重复读取文件；
失败返回带领域上下文且保留 errors.Is/As 身份的错误，结果统计与条目均为空，
不把加载错误当作无匹配，也不泄露其它正常领域的部分搜索结果。
空查询仍直接返回空结果；未选择的领域不加载；未知/false 类型保持原行为。
Correlation node/edge 共用同一领域，仅选择任一类型时均检查该领域。

新增 12 类搜索类型的缺失文件、损坏 JSON、文件路径为目录的读取失败回归，
覆盖重复调用缓存错误及全领域搜索。Files/Persistence 可选分析文件不存在仍允许，
但已存在且损坏必须报错。单机 Web 使用真实 Local Store 测试：加载失败返回
既有 HTTP 500 error 响应，正常无匹配仍返回 HTTP 200 空结果，无 API/schema 变化。
Search Total/ByType 在 limit 前统计、时间降序/零时间末尾、canonical ID 均未改动。

搜索回归连续 10 次通过，全量 Go/统一检查与 Local/Central/Web 竞态检查通过。
本轮仅修复搜索错误边界，不调整 Analyzer 关联、Timeline 窗口或分析发布版本；
下一步补 PID 复用、同路径不同进程实例的反例测试。

## 2026-10-12 当前进程实例匹配反例

AnalyzeProcessHistory 原先只以 PID+规范化路径设置 CurrentProcess=true，
同一程序再次启动且 PID 复用时，可能同时把旧历史实例标成当前。
新增直接 Analyzer 回归并收紧条件：非零 PID、当前快照该 PID 唯一、双方路径已知且
按原规则规范化相等、当前 StartTime 与历史创建事件 Timestamp 均非零且 time.Equal。
重复当前 PID（即便记录内容相同）保留歧义，不按输入顺序任选一条；
不使用秒级/毫秒级容差，也不在时间缺失时退回 PID+路径匹配。

当前采集器 StartTime 来自 GetProcessTimes 的 creation time，
而 4688 Timestamp 来自事件 TimeCreated，两者不是同一个字段，不能假定真实系统总相等。
参见 [GetProcessTimes](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getprocesstimes)
和 [Windows PID 生命周期](https://learn.microsoft.com/en-us/windows/win32/procthread/process-handles-and-identifiers)。
本轮条件是现有 schema 下的保守匹配，不是完备的进程实例身份认证；
真实事件延迟或精度差异可能减少匹配。CurrentProcess=false 表示本路径未确认匹配，
不能推断该历史进程已退出、恶意或不存在。不据此生成新模糊关联。

反例覆盖同 PID/路径不同时间、晚于 StartTime 的事件、1 ns 差异、未知时间/路径、
零 PID、重复 PID 顺序/第三次出现，以及正例的路径规范化、同一时刻不同时区。
同一 PID 两次启动只匹配精确一致的当前实例，事件输入倒序不改变结果；
非 4688 事件不生成历史创建记录。核对 CurrentProcessPath、匹配统计、原 ID、
原始路径及登录匹配保持既有语义。反例连续 20 次通过，完整检查和
Analyzer/Local/Central/CLI 竞态检查通过；Windows 实机匹配率仍待测量。

未迁移旧分析 JSON，也未修改原证据；只有重新运行 analyze 时新规则才作用于新结果。
Historical 父子候选选择及固定高置信度本轮尚未修改，下一步单独补日志缺口、
相同时间候选和父路径冲突的反例，再明确确认关系与不确定候选的边界。

## 2026-10-12 历史父子关系保守确认

原历史父候选选择仅按 PID 找到不晚于子事件的最近记录，时间相同的多个候选
会依赖输入顺序；缺少父路径/生命周期信息也生成边，并直接转为 high/90 的 Correlation。
新增 Analyzer 反例后收紧：父/子 ID、PID、时间必须已知且不能自指；
父时间严格早于子时间；最近的同 PID 候选必须唯一。
无时间的同 PID 候选无法排序，拒绝确认；最新候选路径冲突时不回退到旧匹配。
子事件的 ParentProcessName、父 ProcessPath 和父 CurrentProcessPath 按原路径规则一致，
且父 CurrentProcess 为 true 才生成确认边。没有创建记录、未匹配当前快照的历史父实例、
未知路径/时间及同时间候选均不生成边。

这是现有 schema 缺少完整生命周期证据时的保守边界，不是历史关系不存在的判定。
父进程已经退出、事件版本缺少 creator path 或创建时间与审计时间不一致时，
真实关系也可能无法连边；原子事件中的父 PID/路径及原始历史记录仍完整保留，
不构造模糊候选，不把“不确认”转换成恶意/不存在结论。
后续若需要恢复更多可靠历史关系，应先设计实例身份与生命周期证据，而非放宽时间容差。

Correlation 在提升 parent_child 边前，基于输入历史记录重新核对端点、PID、type
与相同确认条件；缺端点、错误 PID/type 或不满足条件的旧边不提升。
已通过条件的边仍保持原 type、ID 算法、high/90 和端点，补充 creator path 的 Basis 描述。
复核依赖输入历史记录的 CurrentProcess 字段，不是来源认证，也不能修正任意旧版
分析错误设置的 true 标志；应使用本轮与上一轮规则重新生成分析，不能认为旧 JSON
已自动迁移。Store/Web 继续读取既有 Analyzer 结果，没有自行推断或修改证据 ID。

23 组候选反例/正例覆盖原顺序与倒序，6 组 Correlation 边复核，以及
AnalyzeProcessHistory → AnalyzeHistoricalCorrelation 的实际流水线回归，
核对原父 PID/路径、历史 ID 与关系统计。全部历史语义回归连续 20 次通过；
完整检查、Analyzer/Local/Central/CLI 竞态检查通过。未执行真实 Windows 数据验收。
下一步统一 Timeline JSON/JSONL 与报告的采集时间窗口语义。

## 2026-10-12 Timeline 持久化与报告窗口一致性

runAnalyze 现在在写 Timeline JSON/JSONL 之前加载 manifest 并调用原
FilterTimelineByWindow；两种 Timeline 输出与报告 TimelineHighlights 使用同一个
过滤后的 timelineResult。没有修改过滤规则：since/until 边界包含，单边界允许，
无边界保留完整 Timeline，零时间事件作为上下文保留；统计在过滤后重算。
不修改原事件 ID、相关 ID、metadata、排序或 Store/Web 查询契约。

新增实际 runAnalyze 回归，使用六条合成 4688 记录覆盖边界前后 1 ns、两个边界、
窗口内以及未知时间事件，分别运行双边、仅 since、仅 until、无边界四种 manifest。
读取落盘 JSON 与逐行 JSONL，比较事件字段和顺序，核对过滤后统计；
该小样例的 process_history 事件均为报告 highlights 类别且未触及 50 条上限，
因此逐项核对报告投影与 Timeline，确认原 manifest/进程快照/事件文件字节未变。
另有直接 Analyzer 回归覆盖零时间 network/persistence 上下文、类别统计、
RelatedIDs/metadata 与输入不变。回归连续 10 次、完整检查及竞态检查通过。

报告仍只选择原有类别且最多 50 条 highlights，并不展示所有 Timeline 事件；
TopFindings/HistoricalChains 等其它报告内容本轮未改变其范围，也不将所有领域分析
记录裁剪为采集窗口。本轮仅修复 Timeline 与 highlights 的窗口差异。
旧 Timeline/报告不会自动迁移；重新 analyze 后新生成输出才使用统一窗口。
分析结果仍逐文件写入，错误/异常中断时不保证整批原子性；
下一步设计分析运行完成标记和发布边界，再补中断及重复分析回归。

## 2026-10-12 分析发布边界设计

已核对分析的 14 个写入产物、Local/CLI/包消费路径及独立 IOC writer，
新增[分析完成与发布契约草案](analysis-publication-contract.md)。
优先设计只读源→独立新 case→完整验证→最后发布完成清单，
不原地切换两个结果目录，不静默改 Central Version 或包 schema。
明确新标记的 reader 门禁、旧 case 兼容、取消/失败状态和平台发布原语待验证项。
本轮只新增设计记录，未实现新 CLI、标记或 reader 行为；
当前 analyze 仍逐文件写入，不能宣称已解决整批中断一致性。
下一步先实现独立完成清单 codec 和拒绝测试，暂不接入现有流程。

## 2026-10-16 独立完成声明 codec

新增 internal/analysiscommit 的 run/commit v1 解析、声明/摘要校验和编码，
包含双 inventory、14 个必需输出、11 个原始输入、可选 IOC 状态及固定 UTC 窗口。
拒绝重复/未知字段、类型/整数/Unicode 错误、路径别名和预算超限；不读取实际 case。
ASCII 摘要 golden 由独立 Node 实现核对，测试覆盖 IOC、辅助文件保留、复制输入不可变、
元数据限额+1 探测、marker 文件数/字节预算、零结果失败及 reader 错误身份。
Go 全量/竞态、连续 10 次回归、短时 run/commit fuzz 与统一检查通过；
短时 fuzz 不是安全证明，Windows 仍仅编译检查。
scripts/check.sh 增加 codec 不得依赖后端及 packageio 的边界检查。
字段与摘要定义见[契约第 8 节](analysis-publication-contract.md#8-2026-10-16-完成声明-codec-v1独立实现)。

此模块未接入 CLI/Store/离线包，没有新命令或现有格式迁移；
当前 analyze 仍逐文件写入，尚不具备完成标记、文件字节核对或整批发布保护。
下一步实现只读 inventory 校验及未完成目录的读取门禁。

## Windows 运行验收：待完成

Windows amd64/arm64 交叉编译已在开发检查中通过，但不证明目标系统上的
采集器、权限处理、路径处理和 Web 启动实际可用。本次宿主为 macOS；
`vmrun list` 未能启动，未获得可用 Windows 测试会话，也没有启动或修改虚拟机。

在授权的 Windows 测试机上，使用新建的独立 case 目录执行以下流程。
不要覆盖现有调查证据；分析会在 case 内生成分析结果。

```powershell
.\ir.exe collect --output case-runtime-acceptance --last 1h
.\ir.exe analyze case-runtime-acceptance
.\ir.exe web case-runtime-acceptance --listen 127.0.0.1:8080
```

需要记录的验收项：

- Windows 版本、架构、执行身份与权限；分别记录普通用户和授权管理员场景。
- 采集失败/权限不足是否明确报告，manifest 与实际产物是否一致。
- 分析能读取本次采集结果，时间窗口、零时间和路径字段是否保留原语义。
- 浏览器能打开单机页面，Search → 详情的 ID 与来源一致。
- 使用两个完整、已分析 case 执行 `central-web --case-id runtime-acceptance <case-a> <case-b>`，
  重复上述来源隔离、分页和链接恢复检查；只使用 loopback listener。
- 停止服务后端口释放；重新启动不会改变原始证据。保留测试日志与失败项，
  不将采集内容或调查链接发布到外部服务。

Windows 实机结果补齐前，验收状态仍为“浏览器合成流程通过，Windows 运行待验证”。
