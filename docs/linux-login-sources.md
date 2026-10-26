# Linux 当前会话与 accounting ABI：来源决策及验证工具

真实 logind 验收入口：`ir diagnose-login1` 与
[只读验收流程](linux-login1-acceptance.md)。该入口已实现，但当前仍没有真实 logind 的人工验收记录。

状态（2026-10-17）：已实现开发用 ABI 探针、合成字节校验、固定回归样本，及独立 login1
原始会话观察采集，以及独立属性观察规范化/Store/API/调查页。**尚未确认活动会话，也未实现
utmp/wtmp/btmp 运行时解码**。
现有 accounting 文件继续保留为不透明原始证据，
不因为本实验通过而自动改变旧 case 的解释。

## 来源选择

| 来源 | 能说明什么 | 本阶段决定 |
| --- | --- | --- |
| org.freedesktop.login1 的公开 D-Bus 接口 | manager 报告的会话对象及 State/Active/Remote 等属性 | 已接通独立原始列表/属性采集；隔离总线合成服务测试通过，尚未真实 logind 验收，不表示所有 Linux 都具备 logind |
| `/run/systemd/sessions/*` | systemd 内部持久化状态，可能跨 daemon 重启存在 | 不建立私有文件解析器，不作为活动会话判断依据 |
| `/run/utmp`、wtmp、btmp | 某个 writer ABI 下的 accounting 数据 | 继续保存原始字节；先验证 writer 来源和布局，不从文件长度、GOARCH 或当前 libc 自动选择解码器 |

systemd 的 [公开接口定义](https://github.com/systemd/systemd/blob/main/man/org.freedesktop.login1.xml)
提供会话属性；[内部状态保存实现](https://github.com/systemd/systemd/blob/main/src/login/logind-session.c)
明确将文件标注为私有格式，文件也可能跨 daemon 重启存在。公开接口的 State/Active 是来源报告，
不能直接等同 SSH Accepted、进程身份、交互命令执行或完整覆盖。

接入遵守有界超时与数量/大小限额，保留拒读/缺失/消失对象诊断，禁止自动启动服务或修改系统
策略；记录读取时间范围与 collector kernel boot 上下文，多次查询不是原子快照。
会话 ID 和属性中的 Leader PID 都只是来源字段，不能凭 PID 为进程图连边。
没有新增 Go D-Bus 依赖；不调用 loginctl/who/last，也不读取这些私有状态文件。

## login1 原始观察采集（第一阶段）

Linux LoginCollector 在原始文件采集后，独立执行固定路径 `/usr/bin/busctl`，直接指定
`--address=unix:path=/run/dbus/system_bus_socket`，不继承 DBUS 地址、PATH、LD_PRELOAD 等
环境配置；仅传入固定 locale/PATH/pager/color 环境，无 shell。依赖系统已有可输出 JSON 的 busctl，
不自动安装依赖、不尝试其他总线/远程地址；缺少工具/总线/服务、老版本不支持选项或权限不足
都会留下 error，而不是成功的空会话清单。

每条命令固定 `--auto-start=no --allow-interactive-authorization=no --timeout=2s --json=short
--no-pager`。语义参考 [busctl 公开文档](https://github.com/systemd/systemd/blob/main/man/busctl.xml)。
固定调用清单：

1. 总线 `GetId`，再 `GetNameOwner(org.freedesktop.login1)`；后续向 unique owner 发送调用，
   不向可能重新激活的 well-known name 发送会话请求。
2. `Manager.ListSessions`，验证 `a(susso)` 外壳、UID 类型、会话 ID/object path 唯一性及路径范围。
3. 对保留的每个对象调用 `Properties.GetAll(org.freedesktop.login1.Session)`；保留整个属性字典，
   不解释 Active=false、缺失属性、State/Remote/Leader/时间等值。
4. 重读 service owner 和 bus ID；变化或重读失败标为 partial。采集前后校验 collector kernel boot ID。

命令阶段总预算 10 秒、每条命令 context 2 秒（另有进程清理延迟），最多 64 个属性对象；
ListSessions 超限时保留列表响应及最多 64 个合法前缀对象并标 partial，重复身份等结构歧义则不
输出任意选中的列表。每响应 stdout 256 KiB、累计 4 MiB；stderr 每条最多 8 KiB，最多 69 条
调用记录。stdout/stderr 超限会丢弃该条 stdout，并停止后续传输预算，不把截断响应当作成功。
保留有界 stderr 前缀并标错。该预算不包括原始文件和前后 proc boot ID 的同步读取；不声称严格
可中断的整个采集器 I/O。异常对象仍保留在列表中并通过对应调用错误解释；未读属性索引为 -1。

证据写入 `login/login.json` 的 `linux_login1`，包含总体状态、时间范围、地址、可执行路径、
boot ID、bus ID、service owner、来源列表字段和每次调用的参数身份/时间/状态/stdout 字节/
SHA-256/stderr/error。stdout 是 **busctl JSON 的原始输出字节**（JSON 中 Base64），不是 D-Bus
线上的原始消息；摘要不证明可信度。状态 observed_subset 只表示本次受限读取成功，不是全面覆盖。
非限额类失败时保留可获得的 stdout（取消时可能不完整）并明确标 error，不能把其摘要解释成完整响应。
身份前后相等也不能排除中间变化再恢复，socket/daemon/系统本身的真实性未被认证。

第一阶段原始数据保存在 case，范围和失败告警进入报告。第二阶段独立观察分析与展示见下节；
始终不新增 Windows 会话/SSH 计数、风险 Finding、进程边或时间线。所有原始数据均可能敏感，
应保护整个 case。utmp/wtmp/btmp 仍不解码。

## login1 属性观察与调查展示（第二阶段，2026-10-18）

Analyzer 从已保存的 `linux_login1` 产生 `analysis/login_analysis.json.linux_login1`，profile 为
`login1-observation-v1`，不查询实时总线，不更改旧分析文件解释。老 case 缺少此字段时 API 说明
not_available，不伪装成已验证的空会话清单；需要使用新版本 collect/analyze 才有相应分析。

输入沿用 69 次调用、64 个对象、256 KiB 单响应、4 MiB 总响应边界；校验 UTF-8、响应哈希、
JSON 外壳/签名、列表 tuple 与保存的列表字段一致、重复身份/路径、property call 引用目标。
重复 JSON 对象键拒绝，不接受静默覆盖；来源调用 error、错误哈希或错误目标不能贡献规范化值。
列表失败/歧义（包括第一阶段列表限额标错）直接跳过规范化，原始证据仍保留。
Source partial 的合法列表可保留条件性观察，属性不可用仍保留列表观察、缺失值及诊断。

只提取明确类型的 State/Active/Remote/Leader/Type/Class/TTY/Service/RemoteHost/RemoteUser/
Timestamp，未知属性保留于原始响应。所有属性为可空指针：缺失/错误类型为 null，明确 false、0
和空字符串各自保留。可选 Id 若显式不同于列表 ID，撤下全部规范化属性，不强行关联。
reported_creation_usec 是原始 uint64 微秒值，通过 JSON 十进制**字符串**输出，避免浏览器大整数
舍入；不转换为活动时间，不推断零值含义或为其建立时间线。

[公开属性语义](https://github.com/systemd/systemd/blob/main/man/org.freedesktop.login1.xml)：
Active 是来源报告的前台提示，不等于认证成功、持续在线或命令执行。Leader 只是来源报告 PID，
不会查询/连接当前进程。RemoteHost 可以是主机名，不冒充已验证 IP，也不解析 DNS。

每条 ID 是 `linux-login1:<SHA-256>`，摘要输入以 NUL 分隔：collector boot ID、bus ID、unique
owner、采集开始时间（UTC RFC3339Nano）、对象路径、列表响应 SHA-256、属性响应 SHA-256
（未读属性为 unread）。只在当前 case/host/version 的快照来源内使用，不是跨快照稳定会话身份。
规范化列表和精确详情在 Local/Central 共享契约，Central 防御复制包括可空属性、原始字节和告警。
非法/重复 ID 或未知分析 profile 报错，不任意选一条；Store 不现场解析原始日志或重读总线。

```text
GET /api/linux-login1?q=s1&user=Alice&state=online&active=false&offset=0&limit=25
GET /api/linux-login1/detail?id=linux-login1:...
```

user 大小写敏感，state 精确匹配并保留未知的来源值；active 仅 true/false，指定筛选时不包含未知。
匹配总数先于分页，按证据 ID 排序；列表不重复返回原始属性字节，详情包含来源调用和公共范围
上下文。原生 active 参数错误返回 400，缺少 ID 400，未知 ID 404，损坏/缺失分析 500。
不支持 since/until/last；这些参数明确返回 400，避免把采集时刻或创建时刻错当活动窗口。

首页 **Linux login1 observations** 提供独立列表、筛选、分页、可空属性、折叠来源/原文（Base64）
及告警。原文使用 textContent，关闭/切换/重置会使旧响应失效，不生成 PID/SSH/Windows 跳转。
没有接多主机 Search/scoped detail、Timeline 或会话图。尚未做本阶段浏览器视觉或真实 logind
发行版/权限验收；自动化 UI 测试及私有总线合成服务测试不能代替这些验收。

### 隔离运行验证

`login1integration` 显式测试 tag 运行真实 private dbus-daemon + busctl + 合成 libsystemd 测试
服务。fixture 位于 `scripts/testdata/login1-service.c`，它不是 logind，不创建真实登录、不会话管理；
只允许临时 `/tmp` 地址，30 秒 watchdog。测试另行构建并通过 `IR_LOGIN1_TEST_SERVICE` 指定，
这些测试配置不进入生产 collector。覆盖正常、空列表、拒读、对象消失，且服务检查实际方法消息
没有 auto-start/interactive 标志；同时覆盖命令输出限额/取消、忽略恶意 DBUS/PATH 环境。
标准 Go 测试没有隐式依赖 daemon 或跳过集成失败；该集成需显式选 tag 和测试工具。

在具备 dbus-daemon、busctl、C 编译器和 libsystemd.so.0 的授权 Linux 测试环境：

```sh
task_login1_dir=$(mktemp -d /tmp/ir-login1.XXXXXX)
cc -std=c11 -Wall -Wextra -Werror scripts/testdata/login1-service.c -Wl,-l:libsystemd.so.0 -o "$task_login1_dir/service"
IR_LOGIN1_TEST_SERVICE="$task_login1_dir/service" go test -tags login1integration ./internal/collector/linux -run '^TestLogin1' -count=10
```

本次 Linux/arm64 非 root、无外网、根目录只读、cap-drop=ALL、no-new-privileges 隔离容器验证，
只挂载源码和测试二进制。没有挂载宿主机总线/日志、没有运行 logind/sshd、没有主动认证。
这是传输/边界验收，不是目标发行版真实 logind 的服务权限、会话覆盖或登录全流程验收。

## 为什么先探测 ABI

[utmp 手册](https://www.man7.org/linux/man-pages/man5/utmp.5.html)说明布局依赖 libc，
[glibc 定义](https://github.com/bminor/glibc/blob/master/bits/utmp.h)也包含不同时间兼容布局分支。
因此不能以固定字节数或工具编译架构为已有文件确定 ABI。

本仓库的 `scripts/utmp-abi-probe.c` 只使用目标环境的 `<utmp.h>`：

- 输出结构大小/对齐、十个字段的偏移/宽度、整数符号类型、字节序及四个类型常量。
- 构造两条内存中的合成对象：正整数与负数/无符号转换哨兵，各数组全部字节填充测试模式。
  这些不是有效登录记录；结构先全部清零，不输出未初始化 padding。
- 只输出 JSON，不打开系统 accounting 文件，不调用任何登录记录读写函数。
- 只适用于 Linux 原生编译/执行。非 glibc 仅标为 unidentified，不能据此推断 musl。
  architecture 目前仅标注 aarch64/x86_64，其他标为 unidentified，并非支持清单。

`scripts/utmp-abi-check.go` 在任意受支持 Go 主机上检查这份开发报告：
输入最多 64 KiB；记录最多 4096 字节；字段不得越界/重叠；校验两条合成对象的整数字节、
数组内容及其余字节为零。只接受已知报告 schema/字段集合和支持的整数宽度。
输出输入报告的 SHA-256，便于复现；不认证报告真伪，不独立证明环境标签/符号类型/常量，
不把报告提升为可用于任意文件的解码 profile。JSON 字段值是报告声明，必须保护来源。
该工具未被采集器、Analyzer 或 Web 导入。

## 可复现步骤

在授权 Linux 开发环境（只需普通用户、C 编译器及 libc 开发头文件）：

```sh
task_probe_dir=$(mktemp -d /tmp/ir-utmp-abi.XXXXXX)
cc -std=c11 -Wall -Wextra -Werror scripts/utmp-abi-probe.c -o "$task_probe_dir/probe"
"$task_probe_dir/probe" > "$task_probe_dir/probe.json"
go run scripts/utmp-abi-check.go < "$task_probe_dir/probe.json"
```

以上仅写新的临时目录。保留报告、源码摘要、完整编译命令、编译器版本、环境/镜像身份；
不要对真实日志试写，不安装/启动服务，不为消除警告提权。

固定已测样本可在非 Linux 主机回归：

```sh
go run scripts/utmp-abi-check.go < scripts/testdata/utmp-abi/glibc-2.42-aarch64.json
go test scripts/utmp-abi-check.go scripts/utmp-abi-check_test.go
```

## 本次实测及解释边界

2026-10-17：现有本地镜像 `ghcr.io/usestrix/strix-sandbox:1.3.0`（image ID 前缀
`f6906c3114e5`），aarch64 / Kali 2026.3，GCC 15.3.0，glibc 2.42 头文件。
非 root（65534）、无网络、根文件系统只读、全部 capabilities 移除、no-new-privileges；
只挂载本仓库探针和生成的校验程序为只读，编译产物在容器独立可执行 tmpfs 中。
不运行镜像默认入口、sshd/systemd 或其他服务，不挂载宿主机日志或 `/proc`。
第一次编译成功但临时挂载禁止执行，改为隔离的 exec tmpfs 后才运行成功。

实际测得 `sizeof(struct utmp)=400`、对齐 8；session/seconds/microseconds 均为 8 字节，
seconds 偏移 344、address_bytes 偏移 360。C 探针与 Linux/arm64 Go 校验程序串联 10 次通过。
这只确认这一编译环境的合成对象，不外推到 glibc amd64、其他版本、musl、time64 组合、
大端或 32 位环境。测试中的大端字节变换是校验器合成回归，不是大端 Linux 原生验收。

- 探针源码 SHA-256：`40e4c438b590d3abcf1e7e95d6e5ca0d83f3620a03b6ee204a60bf763726fe54`
- 仓库格式化报告 SHA-256：`6f298c0ff8e7827ebbff1c439acddfc684048fe8df4513aae4f3e5290792c0dd`

## 下一道解码门槛

1. 确认**每份来源文件**的 writer ABI/字节序及历史轮转来源，而非只探测当前读取环境。
2. 补齐目标 libc/架构/时间宽度的独立 C 生成样本与实测；环境不明就保持 opaque。
3. 先定义独立 accounting 观察模型和带来源/偏移的 ID，保留类型、原字段、未知值及异常字节；
   非 NUL 终止字符串、尾部残片、非法类型/时间/地址都需有明确策略。
4. utmp 候选也不默认成为活动会话；wtmp/btmp 不自动配对成会话或去重为独立认证次数。
5. 验证存储/查询/报告隔离与错误传播后，才考虑启用显式且来源受限的 profile。

当前尚不满足生产 accounting 解码条件。已保存 login1 的属性观察模型与独立调查展示已接通；
下一步仍需真实 logind 的权限、版本、覆盖与会话变化验收。缺少 logind 的系统仍保留缺口，
不回退为猜测私有格式。
