# Linux 支持范围

更新：2026-10-16。基础快照、持久化候选采集、文件级解析及有限的 systemd 观测合并已实现，不代表与 Windows 功能对等，
也不代表已通过各发行版、真实业务主机或发布验收。

## 当前能力

| 模块 | 当前状态 | 主要边界 |
| --- | --- | --- |
| 主机 | 基础信息 | 主机名、内核、架构、CPU、当前用户；不是完整资产清单 |
| 进程 | `/proc` 实时快照 | PID/PPID、名称、可读的路径/命令行/UID；无法读取或已退出的进程可能缺失 |
| 网络 | TCP/UDP、IPv4/IPv6 | 仅采集器所在网络命名空间；保留地址、端口、状态、socket inode/UID |
| 进程归属 | 可验证的观测关联 | socket inode → fd → PID，并复核进程实例及网络表；不确定时保留未归属连接 |
| 分析/报告 | 基础链路可运行 | 已归属连接进入现有 Analyzer/Store；报告保留采集限制及未实现模块警告 |
| 持久化 | 候选采集、文件级解析、有限 systemd 观测合并（含 dash/模板/实例） | 保留来源/诊断，不判断实际生效、执行或关联进程 |
| 登录 | 有限 SSH 认证日志及原始 accounting 采集 | 只提取日志报告的 Accepted/Failed，非完整会话；utmp/wtmp/btmp 不解码 |
| 文件 | 未实现 | 返回带警告的占位快照，不是成功采集到零条证据 |
| 历史进程/audit/journal | 未实现 | 不生成 Windows 事件 ID，不将 Linux 日志硬映射成 4688/4624 等事件 |
| 能力评估 | 未实现 | 覆盖率未量化；数值默认 0，不表示没有证据，不再声称快照覆盖 100% |

## 网络证据及归属

读取 `/proc/self/net/{tcp,tcp6,udp,udp6}`，不执行 `ss`、`netstat` 或外部命令。
解析遵守内核地址字节序，保留未知状态；TIME_WAIT/inode 0 不强制归属。
内核说明见 [proc TCP 接口](https://docs.kernel.org/networking/proc_net_tcp.html)。
该接口已被内核标注为应由 tcp_diag 替代；本阶段作为基线，后续可增加 inet_diag 数据源。

采集 fd 时只读取链接目标，不打开 socket。进程目录以 `os.Root` 固定，前后核对
`stat` 的 PID/starttime ticks 及网络命名空间，之后再次读取网络表，仅对 inode、
tuple、状态及 UID 均未变化的行应用观测到的归属。相关内核语义见
[proc 文件系统说明](https://docs.kernel.org/filesystems/proc.html)。

`process_instance_id` 格式为 `linux-proc:<pid>:<start_ticks>`，只用于同一运行中 procfs/case
内的进程/网络快照匹配，不是跨重启、跨主机或历史全局身份。它不是绝对时间，
Linux `StartTime` 仍保持未知，不猜测时钟频率转换时间。若任一侧有实例键，Analyzer
必须精确匹配；键缺失/不一致时不退化为仅凭 PID 连边。两侧均没有键的旧快照保留原行为。

同 inode 被多个可见 PID 持有、归属不可读、进程退出或重读不一致时，连接仍保留，
PID 设为 0 或进入 Analyzer 的 `OrphanConnections`。所谓唯一归属仅指“唯一可见观测”，
不能排除权限受限的隐藏持有者。整个采集不是原子快照；重读降低竞态风险但不能消除竞态。
命名空间变化/无法复核时撤销全部 PID 归属，不切换命名空间、不遍历其他容器。

`socket_inode`、`socket_uid` 以十进制字符串保存，保留零值并避免 JavaScript 整数精度丢失；
`network_namespace` 保留本次来源上下文。这些都不是全球唯一 ID。原始快照和 Analyzer
JSON 保留证明字段；当前 Store 的通用网络记录尚不单独暴露它们，网络列表也不展示 orphan。
应回看原始网络证据及分析 JSON，不能把列表缺失解释为没有连接。

读取上限：每张表 16 MiB、初始总行数 65,536、进程 65,536、全局 fd 1,048,576；
逐行解析亦有上限，支持 context 取消。表不可读、格式异常或达到限额返回部分结果及错误，
并把限制持久化为 Warnings。没有静默裁剪后声称完整采集。

canonical Network ID、External 的 Analyzer 判定及 Store/Web 分层不变。
UDP 仅在无远端时作为监听端点，已连接 UDP 不再误当监听；External 只是公网地址分类，
不是连接发起方向、C2 或失陷结论。

## 持久化候选配置

`persistence/persistence.json` 新增可选的 `linux_artifacts` 和 `linux_sources`；Windows
的 Services/RunKeys/ScheduledTasks 及其证据 ID 不变。Linux 不伪装成 Windows 服务/任务，
不复用其命令行规则或不区分大小写的进程路径匹配。

固定读取范围：

- systemd：`/etc/systemd/{system,user}`、`/run/systemd/{system,user}`、
  `/usr/local/lib/systemd/{system,user}`、`/usr/lib/systemd/{system,user}`、
  `/lib/systemd/{system,user}`，以及 `/run/systemd/generator{,.early,.late}`。
  另含 `/etc/systemd/system.control`、`/run/systemd/system.control`、`/run/systemd/transient`、
  `/etc/systemd/system.attached` 和 `/run/systemd/system.attached`。
  采集常见 unit 后缀，向下一层读取 `.d` 下的 `.conf` 及 `.wants/.requires/.upholds` 中的候选。
- cron：`/etc/crontab`、`/etc/anacrontab`、`/etc/cron.d`、
  `/etc/cron.{hourly,daily,weekly,monthly}`、`/var/spool/cron` 及其 `crontabs` 目录。
  目录只扫描直接条目，不执行脚本、解析表达式或推断执行用户。

这些是候选来源，不是完整 load path 或实际生效配置。systemd 的 load path、drop-in 和链接
有独立语义，见 [systemd 原始文档](https://github.com/systemd/systemd/blob/main/man/systemd.unit.xml)；
cron 文件布局/语义见 [Cronie crontab 手册](https://man7.org/linux/man-pages/man5/crontab.5.html)。
本阶段的来源优先级仅用于下述有限观测合并，不确认 manager 的实际有效配置；模板回退只选择来源，
不展开说明符或执行实例化，不实现别名解析、unit mask 生效判定或 cron 环境求值/百分号转换/时区调度，
不调用 systemctl/crontab、不使用 D-Bus、不启动守护进程，不读取每个用户的 home 或运行时目录。

每项保留区分大小写的来源路径、候选种类、文件模式、数字 UID/GID、大小、mtime，
可读普通文件保留原始字节及 SHA-256。`content` 为 JSON Base64，避免非 UTF-8 数据丢失；
空文件有空内容和正确的 SHA-256，失败文件没有成功内容/哈希。不要把 mtime 当作执行时间。
配置可能包含密码、令牌或环境变量，应按敏感证据保护整个 case，不公开原始内容。

候选符号链接仅记录目标，不跟随；包括 `/dev/null`、悬空链接及指向目录的链接。
来源根目录允许 `os.Root` 内可解析的别名（例如发行版的 lib 目录布局），不据此合并或去重证据；
无法安全解析则保留错误。后代目录固定深度，固定目录句柄并检查身份，不跟随后代符号链接目录。
Linux 普通文件先以 O_PATH/NOFOLLOW 固定并验证类型，再从自身 proc fd 读取；
FIFO/设备/socket 不作内容读取。读前后核对文件身份、大小、mtime 和模式，发现替换或变化则舍弃内容/哈希。
这仍不是原子快照，也不能检测所有修改后恢复的情况；读取可能更新 atime，不能声称零系统影响。

全局上限为 4,096 个候选、16,384 个目录条目、单文件 1 MiB、实际读取总量 32 MiB
（限界探测可能额外读取 1 字节）。超限不保存截断内容，仍保留可获得的元数据及错误。
每个来源区分 `observed`、`missing`、`partial`、`error`、`not_scanned`；
`observed` 只表示计划范围内未报告失败，不是全主机覆盖，`missing` 不是权限失败。
错误写入来源状态、候选 `read_error` 及报告警告，部分结果和采集错误同时返回。

Store 列表/分页/搜索使用 `linux_systemd`、`linux_cron`，ID 为
`persistence:linux:<SHA-256(kind + NUL + source path)>`，不转小写、不与 Windows ID 混用。
所有候选都可见，包括链接和拒读项；不把文件 owner 当作任务执行用户，不凭候选推断 PID。
单 case 详情 API/UI 可展开原始 JSON（内容为 Base64）；多主机 scoped 详情目前仍返回列表层信息，
原始内容需查看所属 case 的快照。Linux 统计独立计数，不生成风险 Finding、执行时间线或进程边。

## systemd/cron 文件级解析

Analyzer 从已采集快照读取内容，不再次打开系统配置，也不调用守护进程或 shell。
结果写入 `analysis/persistence_analysis.json` 的可选 `linux_configs`，每项绑定
大小写敏感的 `path`、`kind`、来源 `sha256`，并固定标记 `activation: unknown`。
状态 `observed_syntax` 仅表示完成本解析器支持的文件内语法提取，不表示配置有效或被守护进程接受；
`partial` 表示语法/支持范围诊断，`skipped` 表示没有解析。统计中的 config count 包括 skipped，
不是有效配置数量。

- systemd：提取节、key/value，记录物理起止行号；合并反斜杠续行并跳过续行间的注释，
  保留重复赋值、空赋值、大小写、引号、转义和行内 `#`/`;`。空赋值仅标记
  `empty_assignment`，不对所有指令套用相同 reset 规则。值不做 C 转义、变量/说明符展开或命令拆分。
  各来源和 drop-in 独立输出，尚不合并有效值。语法依据见
  [systemd.syntax 原始文档](https://github.com/systemd/systemd/blob/main/man/systemd.syntax.xml)。
- cron：仅解析 `/etc/crontab`、`/etc/cron.d` 的直接文件及 `/var/spool/cron`、
  `/var/spool/cron/crontabs` 的直接文件，明确区分系统表和用户表。
  环境赋值按文件顺序保留原文/行号，不展开、不去引号，也不重建每项任务的有效环境。
  支持五字段的常见数字、范围、列表、步长、月份/星期名及常见 `@` 宏，
  做基本范围检查，但不计算下次执行时间、日期是否实际存在或日期字段匹配逻辑。
  未支持的扩展（如随机范围、root 静默前缀）保留诊断，不猜测含义。
- cron 条目保留命令余下原文（含内部空白、行内注释、百分号和转义），不把 cron 的 `%`
  标准输入规则误作 shell 解析；出现 `%` 时明确诊断未做转换。schedule 为规范化字段组合，
  原始空白仍在来源文件。执行用户仅作为声明/来源信息保留：`system_field` 来自系统表字段，
  `spool_filename` 来自用户表文件名，既不使用文件 owner 冒充执行者，也不确认该账户存在。
- 周期目录中的脚本、`anacrontab`、链接、不可读/缺少或不匹配哈希的内容、非 UTF-8/NUL 数据
  明确 skipped；原始 Base64 仍可调查。缺少 cron 最终换行、坏节/缺失字段、未终止续行等有行号诊断。

解析边界：最多 4,096 项、总输入 32 MiB、单文件 1 MiB、每文件最多 65,536 个换行、
每文件最多 4,096 条解析记录、全局 16,384 条记录；每文件最多 64 条详细诊断及一条省略提示。
支持取消；触限、取消及 skipped/partial 摘要进入报告，不能把空解析当作没有持久化。

Store 不重算语法：列表/分页不携带大块解析内容，精确 `PersistenceItemByID` 仅附加
路径、kind、来源哈希都匹配且不重复的分析记录，陈旧/歧义记录不关联。
单 case 详情 API 的 `linux_config` 和 UI 折叠纯文本 JSON 展示该结果；多主机 scoped 详情
暂不展示文件级解析。解析命令尚未加入全文搜索，也不自动进入 Finding、关联边或执行时间线。
SHA-256 在此用于把结果绑定到采集字节，不是数字签名或真实性证明。

## systemd 观测合并（有限配置投影）

`linux_systemd_merges` 是独立于 `linux_configs` 的条件性视图，profile 为
`observed-system-service-v2`，不是 systemctl 看到的有效配置。支持系统级普通 `.service`、
连字符层级、模板定义及已观测具体实例的来源选择；用户 scope、转义/非 ASCII 名称和含额外 `@`
的实例名仍不合并。activation 始终 unknown。v1 的普通 service 历史结果仍可读取，不自动迁移为 v2；
需重新 analyze 才生成新 profile，证据 ID 和原始快照不改变。
观察范围外的编译路径、自定义 `SYSTEMD_UNIT_PATH`、manager 缓存和实时状态均未核实。

profile 的来源从高到低：system.control（etc、run）、transient、generator.early、
etc/system、etc/system.attached、run/system、run/system.attached、generator、
usr/local/lib、vendor lib、generator.late。完整路径及规则以代码中的固定 profile 为准，
来源依据见 [systemd.unit 原始文档](https://github.com/systemd/systemd/blob/main/man/systemd.unit.xml)。
`/usr/lib` 与 `/lib` 同级，采集未证明二者是同一对象；同名同优先级候选即阻塞，不凭内容相同推断别名。

只选一个 base unit；同名 `.conf` 中 type-wide `service.d` 最后考虑，其他候选先按来源层级、
再按该来源内的名称展开顺序选择。不同文件名全局按字典序应用。选中、遮蔽、同级冲突和观测到的
`/dev/null` drop-in 链接分别保留。该链接仅使同名低优先级 drop-in 不参与本投影，
不证明真实 manager 采用了它。unit 链接（含 `/dev/null`）、空 unit、不可读/解析不完整的选中内容、
链接 drop-in 目录、同级冲突或缺失/重复/不完整来源状态均 blocked，不回退到低优先级 unit。
unit/`.conf` 文件名被目录占用时也保留类型错误，不能将它当作高优先级文件不存在。

v2 的名称规则：

- 普通 `foo-bar-baz.service` 纳入自身及逐级截断的 `foo-bar-.service.d`、`foo-.service.d`。
  同一来源内更具体的名称先考虑，但高优先级来源的前缀 drop-in 可覆盖低优先级来源的具体名称同名文件。
- 实例 `worker@east.service` 在全部 profile 来源中先查精确实例文件；没有精确候选才查
  `worker@.service`。精确候选为空、拒读、链接或冲突时不回退。模板定义和实例视图独立，
  模板自身不会生成实例，也不将模板视图计作已运行实例。
- 实例的 drop-in 名称同时纳入具体实例、模板和递归前缀链，名称推导只截取 `@` 前的 prefix，
  不因实例字符串中的 `-` 派生错误的前缀目录。顺序按本 profile 对照的上游实现，
  见 [systemd drop-in 代码](https://github.com/systemd/systemd/blob/main/src/shared/dropin.c) 和
  [unit 名称代码](https://github.com/systemd/systemd/blob/main/src/basic/unit-name.c)。
- 结果新增 `name_kind`（plain/template_definition/instance）、`template`、`instance`、
  `base_lookup`（exact/template_definition/template_fallback）。名称仅来自已观测的 base 文件或
  具体 `.service.d` 配置，不枚举所有可能实例，不从 `.wants/.requires` 链接推导实例；
  仅出现通用前缀 drop-in 目录不凭空创建 unit 视图。
- `%i/%I`、其他说明符、变量和命令参数均保持字面值，不执行展开或路径推断。名字最长 255 字节，
  每个 unit 最多展开 64 个去重名称，超限阻塞，不输出不完整合并设置。

有限 Service 指令规则：`User/Group/WorkingDirectory/Type/Restart` 保留最后一次字面赋值；
`ExecCondition/ExecStartPre/ExecStart/ExecStartPost/ExecReload/ExecStop/ExecStopPost` 按次序累积，
空赋值清空列表。最终值及清空赋值保留路径、来源哈希和起止行号，其他指令留在原文件解析中。
不拆解命令、不求值、不验证某个 Type 是否允许多条 ExecStart，也不确认声明账户或目录存在。

结果仅为 `observed_subset` 或 `blocked`；后者没有 Settings。即使前者也只说明固定 profile
内有限规则的结果，不是启用/执行/失陷结论，不生成 Finding、进程关系或执行时间线。
单次最多 512 个 unit、每 unit 128 个候选引用、全局 16,384 个引用/指令和 32 MiB 指令值预算；
沿用 4,096 项、32 MiB 原始输入上限，来源状态最多 128 项，触限/取消有警告。

投影的 input digest 绑定全部 Linux 候选的路径/种类/模式/链接/读错、声明哈希与实际字节摘要，
以及全部来源路径/状态/错误和次序，不包含不影响这些规则的 UID/mtime 等元数据。
Store 只校验此输入绑定，不重算合并；新增 drop-in、修改字节但未改声明哈希、来源状态改变后，
旧投影不再附加。重复 unit 投影或未知 profile 不附加，Central 返回可变数组仍为防御性副本。
列表不携带大对象；单 case 详情可按来源展开投影。早期阻塞尚未建立来源列表的视图需查
analysis JSON/报告，多主机 scoped 详情暂不展示投影。该摘要不是数字签名。

## Linux 登录证据（第一阶段）

固定读取 `/var/log/auth.log`、`auth.log.1`、`/var/log/secure`、`secure.1`、`/run/utmp`、
`/var/log/wtmp`、`/var/log/btmp`，不运行登录命令、不主动认证、不修改日志/审计策略。
原始证据位于 `login/login.json` 的 `linux_artifacts`，保留原始 Base64 字节、SHA-256、
权限/数字 UID/GID、大小、mtime 和来源状态（observed/missing/error/not_scanned）。
读取限额每文件 8 MiB、总计 24 MiB，限界探测可能额外 1 字节；不保存截断内容并声称成功。
拒读、特殊文件、链接、文件替换/变化和取消保留错误，符号链接不跟随。
读取可能更新 atime；修改后恢复等情况不能完全检测，不提供原子快照或真实性证明。

`/run/utmp` 仅归为当前 accounting 原始来源，wtmp/btmp 仅归为历史/失败 accounting 来源，
不因文件名、架构或记录长度猜测二进制 ABI，不把它们解码成活动会话。
当前未覆盖 journal、audit、PAM/sudo 等其他文本语法、压缩/更早轮转文件或所有发行版路径。
来源缺失可能是日志未写入此处，不能据此判断没有认证活动。
当前会话来源选择、ABI 探针与实测边界见 [来源及 ABI 验证记录](linux-login-sources.md)。
该开发验证工具未启用运行时解码，不改变本阶段能力范围。
Linux collector 另已接入 login1 公开接口的**原始观察**（固定 busctl、本地系统总线、禁用自动
启动/交互授权、限额/超时、owner/bus/boot 上下文），保存在 `login/login.json.linux_login1`。
已提供独立属性观察分析、Store/API 与调查页，区分未知/false/0；不确认活动会话，也不混入 SSH
认证页面或计数。来源失败与范围警告进入报告，详见来源说明的第二阶段。
真实 logind 的发行版/权限/覆盖仍未验收；隔离总线合成服务验证不等于真实登录验收。

Analyzer 只在受支持文本来源中提取带 syslog 外壳的 OpenSSH `Accepted/Failed` 报告，
来源语义参考 [OpenSSH auth_log 实现](https://github.com/openssh/openssh-portable/blob/master/auth.c)。
`sshd`/`sshd-session` 的原生记录单独存入 `analysis/login_analysis.json` 的 `linux_records`，
保留来源文件/哈希、物理行号、行文本、认证方法、声明用户名、invalid-user 标志、literal IP/端口、
报告的主机名和 PID 字符串。PID 不是当前进程身份，Accepted 不等于交互会话建立或命令执行，
Failed 计数不是独立攻击次数；不同路径/轮转中的重复消息不强制去重。

有明确偏移的 RFC3339 时间保留时间值；传统 syslog 无年份/时区，不从当前日期、mtime 或宿主机
时区补全，Timestamp 为零、time_basis 为 unknown，timestamp_raw 保留原文。
不合规的 ISO 时间同样保持未知并诊断。CRLF 的行文本去掉终止 CR，原文件字节仍完整保留。
EOF 未终止片段不解析，过长行/限制/取消会停止后续解析并保留 partial，其他格式计入 ignored_lines。
不完整、链接、缺少/不匹配哈希、重复路径、非 UTF-8/NUL 内容跳过，原始证据仍可查看。
最大 16 个输入来源、每文件 8 MiB、总 24 MiB、每来源 131,072 行、单行 64 KiB、
全局 16,384 条记录，每来源最多 32 条详细诊断及一条省略提示。

原生统计独立于 Windows Session/4624/4625/4672；不会产生 Windows 事件 ID、会话、风险 Finding、
活动图/进程边或时间线事件。当前原始文件和原生记录均不按 collect 的 since/until/last 裁剪，
范围说明进入报告；不能把原生计数解释为所选时间窗内的活动量。

每条证据 ID 为 `linux-login:<SHA-256(path + NUL + source SHA-256 + NUL + line)>`，
只在来源版本/host/case 上下文内使用，不是跨轮转的稳定登录身份，也不是 LogonID。
Store 保留 Analyzer ID，按已知时间降序、未知时间最后、ID 排序；总数先于分页，缺失/损坏证据报错，
重复或非法 ID 不任意解析。Local/Central 支持独立的原生列表和精确详情；未混入 Windows 登录查询。

单 case Web 提供只读 API（通过正常 `web` 命令启动后使用）：

```text
GET /api/linux-logins?outcome=accepted&user=alice&ip=192.0.2.1&offset=0&limit=100
GET /api/linux-logins/detail?id=linux-login:...
```

还支持 `q` 文本筛选；user 保留大小写，IP 规范化后精确匹配，outcome 仅 accepted/failed。
每页默认 100、最多 500。详情包含原始行与来源哈希，不返回完整二进制 accounting 内容；
原始数据查看所属 case 的 login JSON。Web 首页的 **Linux SSH authentication** 卡片提供独立
原生调查面板：分页、条件筛选、精确详情及未裁剪的来源状态/解析告警。原文以文本显示，不生成
reported PID 进程跳转；切换筛选/关闭时取消并失效旧列表和详情响应。空列表不代表没有认证活动。
尚未接入多主机聚合 Search/scoped detail 或 Timeline。Windows 原接口和会话逻辑保持不变。

调查查询支持 `since`/`until`（非零 RFC3339、必须带偏移，含首尾边界），以及
`unknown_time=include|exclude|only`（默认 include）。已知时间按窗口筛选；未知时间默认保留为
上下文，也可排除或只看未知时间，不能宣称落在窗口内。筛选后计算 total，再分页；反向窗口/
无偏移时间/非法策略返回 400。URL 中正偏移的 `+` 需编码为 `%2B`，页面自动编码。
该功能只作用于 Store/Web 调查查询，**不修改 collect/analyze、保存的统计或原始证据**，
未把原生记录加入 Timeline；页面的来源/告警针对整个保存的分析而非筛选结果。
原始认证日志可能含敏感数据，请保护整个 case，不将 API 或证据公开暴露。

## 基础使用及报告解释

在已授权 Linux 测试机上，用全新的输出目录：

```sh
go build -o /tmp/ir-linux ./cmd/ir
/tmp/ir-linux collect --output /tmp/ir-case-linux-new
/tmp/ir-linux analyze /tmp/ir-case-linux-new
```

不要复用已有 case 目录；当前 collect/analyze 尚不提供整体原子发布保证。
不需要为本阶段修改审计策略、systemd 服务、防火墙或 sysctl；不要仅为减少警告自动提权。
`hidepid`、用户权限、进程退出等都会影响可见性，报告警告必须保留。

`analyze` 通过 `host/host.json` 的 OS 判断 Linux，允许缺少不适用的
`events/windows_events.json`，不伪造该原始文件。如果文件已存在但损坏或不可读，仍报错；
Windows/旧 case 缺失该文件仍报错。兼容现有输出结构会产生空的 Windows 事件分析结果，
报告明确说明不适用和 Linux 历史覆盖未建立，并保留各未实现模块的警告。
报告中的零计数、低风险和默认覆盖率均不能作为“主机安全”或“没有历史活动”的证明。

目前独立的 `analysiscommit` 完成记录 codec 仍为 Windows-oriented 输入 profile，
未接入 analyze 或 reader gate；本轮没有扩展其 Linux 发布契约，也未改变 HostID/Version 规则。

## 验证与后续顺序

验证证据见 [运行验收记录](runtime-acceptance.md#2026-10-16linux-基础网络与分析链路)。
统一检查新增 Linux amd64/arm64 交叉编译；只有实际 Linux 上执行的 native 测试才证明运行行为。

后续按独立可验证批次推进：

1. Linux 持久化：候选采集、文件级解析及含 dash/模板/实例的有限系统 service 投影已实现；别名、转义、依赖链接实例发现及真实 manager 加载范围仍待后续验证。
2. Linux 登录：SSH 文本认证报告、原始 accounting 采集、独立 API/调查页及查询时间窗口已实现；后续验证当前会话和二进制历史的来源/ABI，不强行归并。采集/分析仍不按时间窗裁剪。
3. 文件调查：围绕已观测进程路径及持久化引用，限制扫描范围/大小，保留哈希及失败原因。
4. 原生 audit/journal 事件模型、覆盖评估和时间线；不复用 Windows 事件 ID。
5. 发行版/权限/多命名空间实机验收、inet_diag、多主机及 Linux 完成记录 profile。

UNIX sockets、ICMP、内核线程 fd 差异、其他命名空间及跨采集历史关联不在本阶段范围内。
