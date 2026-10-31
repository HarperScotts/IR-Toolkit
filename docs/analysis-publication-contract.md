# 分析完成与发布边界设计

状态：2026-11-01，整体发布流程仍未实现；完成声明 v1 codec 和独立只读磁盘清单验证已实现，
后者提供 `analysis-verify` 检查入口，见第 9 节。它尚未接入 Store/Web/package reader 门禁或
生产 writer。当前 analyze 仍逐文件覆盖原目录，不能宣称已有整批发布或中断保护。
除第 9 节只读命令外，本文仍是设计，不是其它已实现 CLI 的文档。

## 1. 选择与范围

优先采用“只读源 case → 独立新 case → 完整验证 → 显式发布”，
不先引入原目录内版本指针，不原地替换 analysis/ 与 timeline/ 两个目录。
新输出维持现有普通 case 文件布局，便于复用领域 loader 与既有证据 ID。
源、旧输出、已有 Central view 均不覆盖。新模式拟显式指定新目标目录，
具体命令参数尚未实现；旧 analyze 的原地行为须继续明确标记为 legacy。

完成标记证明的是“该运行的文件集合完整且一致”，不是来源真实、分析一定正确，
也不是任意文件系统断电耐久性保证。没有标记的旧 case 可以沿用既有兼容路径，
但不能被表述为通过新完成协议验收。

## 2. 当前写入及消费边界

runAnalyze 本次应生成的固定输出共 14 个：

```text
analysis/network_analysis.json
analysis/persistence_analysis.json
analysis/login_analysis.json
analysis/activity_analysis.json
analysis/file_analysis.json
analysis/process_relationship_analysis.json
analysis/process_history_analysis.json
analysis/powershell_analysis.json
analysis/windows_event_analysis.json
analysis/historical_correlation.json
analysis/report.json
analysis/report.txt
timeline/timeline.json
timeline/events.jsonl
```

analysis/ioc_matches.json 是当前 analyze 的可选输入，由独立 ioc scan 写入，
不是本次 analyze 新生成结果。必须记录它在输入时存在/不存在及精确摘要，
禁止从旧 report 继承 IOC 结论而未读取对应输入。无 IOC 时保留现有可选语义。
其它可选证据（如 security providers）也不因此变成必需。

需要接入完成验证的入口包括：单机 Web/Local 打开、Central 目录加载/归档加载、
case-pack、central-import、central-import-package；case-verify 的只读源验证
也需能识别新标记，但仍不得宣称已做完整领域加载。
不能仅修 CLI writer，却让 reader 把未完成的新目录当作普通 legacy case。

## 3. 新目标与逻辑发布

要求源已停止写入，目标位于可信、私有本地父目录，且不位于源目录之内。
目标目录必须独占新建；已存在的文件、目录、链接都拒绝，不使用复用/覆盖模式。
不依赖硬链接复制证据，避免源被修改时影响新输出。

候选最小协议采用两个普通文件：

- analysis-run.json：在新目标写入任何证据之前建立的运行描述，包含协议版本、
  唯一 run_id；出现该文件就意味着此目录受新协议管理，不能回退 legacy。
- analysis-commit.json：全部复制、分析、验证成功后，最后发布的完成清单。

这两个名字符合既有安全 payload path 规则，不使用点号开头的隐藏 marker。
case 的数据文件可在构建过程中物理可见；“未发布”由 reader 拒绝提供调查视图保证，
不宣称所有文件在文件系统里同时出现。创建目标后、run 描述建立前的极短阶段
尚无证据文件，正常 case 打开也必须拒绝缺失的必需输入。

完成清单先在同一文件系统的本次私有工作目录写完、Sync、Close，再使用
经过平台验证的独占发布原语创建最终清单路径。可评估 os.Link 发布单个已关闭文件，
其工作副本必须在 case 树外，发布后永不修改；这样 case 树内没有同 inode 双条目。
不支持相应文件系统语义时明确失败，不降级为可能覆盖目标或暴露半写清单的操作。
该原语尚未实现/验证；Windows ACL、文件系统与目录同步行为必须实机验收。

不把 Lstat 后 os.Rename 当作通用 no-replace 保证，也不假定 Windows 的 rename
具有与 Unix 相同的原子保证；参见 [Go os.Rename 文档](https://pkg.go.dev/os#Rename)。
发布边界是已验证的完成清单可见，不是后续打印回执。边界之后发生取消、清理失败
或回执 IO 失败不能报成“未发布”，须保留结果并报告状态；有歧义则要求核实目标。

## 4. 完成清单的内容与验证

第一版需要记录协议版本、run_id、工具/分析规则版本、源身份和采集窗口，
输入文件摘要（明确包括可选 IOC 的存在状态），以及最终文件清单。
最终清单使用精确路径、字节大小、SHA-256，按路径排序，涵盖复制输入、
本次 14 个生成输出、保留的辅助文件和 analysis-run.json；排除清单自身，避免自引用。
复制源内已有旧生成文件时，14 个路径必须全部由新运行重建；旧完成标记不能
作为本次有效标记复制使用，其余辅助数据不得静默丢弃或冒称本次新生成。

字段编码/内容摘要算法和严格 JSON 解析已有第 8 节的 codec/golden vectors；
生产 writer、磁盘验证、迁移与发布原语仍未实现，不能由声明解析推导其已安全发布。
需有实际字节、文件数、单文件及总文件大小限额，不把声明大小当成资源控制。
两个新增标记也计入 case/package 文件数和预算，不能自动提高当前包限额。

只有满足以下全部条件才发布：

1. 全部输入按固定清单读取，源在结束时复核未变化；源变化或取消拒绝发布。
2. 14 个输出均成功写入、关闭、同步；Close/Sync 错误不得被忽略。
3. 完整领域加载通过，optional missing 与 malformed 的语义保持不变。
4. Timeline JSON/JSONL 与 report highlights 使用同一窗口和原有选取规则。
5. 新目录完整 inventory 与清单一致，禁止链接、越界路径、缺失/额外/重复条目。
6. run_id 与运行描述一致；已知身份、原证据 ID 与现有查询语义不变。

完整性验证并不修复 Analyzer 语义错误；继续独立运行进程实例、关系与窗口反例。

## 5. 读取、并发和兼容

出现任意新协议标记时，必须采用新验证路径：未知版本、单独 commit、缺 commit、
run 不一致、损坏 JSON 或 inventory 不符全部失败，不从旧路径补缺失文件。
标记均不存在才允许 legacy 行为，并明确“不具备本次完成协议保证”。

reader 将一次完整、已验证的结果绑定到同一 run_id，全部领域来自同一目录快照；
不能以每个领域的独立 sync.Once 代替整批一致性。加载前后检查运行身份与 inventory，
失败不发布部分 Store。已打开的 Central 冻结视图继续读取原快照。
可信父目录与禁止外部改写是前提，不声称对敌对并发文件系统修改具有无竞态防护。

新输出发布后视为不可变；ioc scan、analyze 等 writer 必须拒绝修改该输出，
否则标记必然失效。需要新 IOC/规则分析时，从输入准备新的运行，而非覆盖已发布 case。
旧工具不认识新标记，不能作为新协议 reader/writer 使用；不得承诺旧二进制安全兼容。

本轮不把 run_id 自动替换 Central Version。目前 Version 仍来源于 manifest.case_id，
因此同一 collection 的第二次分析仍可能触发既有重复 view 拒绝；不改 manifest 原始字节
来绕过拒绝。多分析版本导入需单独的身份/包契约迁移，不能夹带在完成标记实现中。

## 6. 失败与恢复验收

构建失败/取消：源和旧输出不变；新目标无有效 commit，reader 拒绝；
正常清理仅针对本次拥有的工作路径，不能删除被替换路径或其它目录。
强杀后可保留未完成目标与工作目录，不自动接管或将残留补成已发布。
同目标重试拒绝，操作者先核实进程和状态，再选择新的明确目标。

必须覆盖：已有目标与目录包含、各输入/输出读写失败、取消、Close/Sync 失败、
标记半写/损坏/未知版本、输入变化、可选 IOC、额外/缺失文件、重复分析、
发布前/后强杀与回执失败、Windows ACL/链接/文件系统行为。
发布后故障的回执与重启读回必须一致，不将已发布结果报告为回滚。
测量复制/阶段工作区和 RSS；不为性能移除同步或来源复核。

## 7. 实施顺序

1. 实现独立、严格、有界的完成清单 codec/校验及 golden vectors，不接入 CLI。
2. 增加统一 reader 门禁，保持 legacy fixture 兼容，未完成新目录明确拒绝。
3. 将分析流水线与摘要打印分开，实现只写本次新目标的 builder，补取消/故障回归。
4. 实现并实机验证独占发布原语，才开放显式新目标 CLI；同时拒绝 writer 改写已发布结果。
5. 接入离线包/归档全流程与资源验收，再考虑独立的多分析版本迁移。

上述步骤完成前，当前命令仍不具备本设计的发布保护，不得把此草案当作安全保证。

## 8. 2026-10-16 完成声明 codec v1（独立实现）

`internal/analysiscommit` 仅依赖 Go 标准库，不依赖 Store/Web/Analyzer/Collector
或 packageio。它不读取磁盘 case、不生成 run_id、不创建/发布任何结果；
后续 package reader 可使用此 codec 而不引入后端依赖。本轮没有改变现有命令或包格式。

运行描述的紧凑编码示例（99 字节，无换行）：

```json
{"format":"ir-toolkit.analysis-run","format_version":1,"run_id":"0123456789abcdef0123456789abcdef"}
```

run_id 为 32 个小写十六进制字符；唯一性和安全随机生成由未来 builder 保证，
codec 只验证语法，不假称已检查全局唯一。
完成清单所有顶层字段必须存在，编码顺序如下：

```text
format, format_version, run_id, tool_version, rules_version, host_id,
collection_id, window, inputs, ioc, files, content_digest
```

- format 固定 `ir-toolkit.analysis-commit`，format_version 固定整数 1。
- tool_version/rules_version/host_id/collection_id 为非空、无首尾空白/控制字符、
  有效 UTF-8 且不超过 256 字节的字符串。collection_id 不替换 Central Version。
- window 必须有 since/until 两个字段；各为 null（无界）或非零、规范 UTC
  RFC3339Nano 字符串。拒绝非 UTC、非规范小数/时区表示和反向窗口；相等边界允许。
- inputs/files 是严格按路径字节顺序排列的非空 File 数组，每项恰有
  path、size、sha256；size 为非负 int64，sha256 为 64 位小写十六进制。
- inputs 至少包括当前 analyze 的 11 个必需原始输入：manifest、host、capabilities、
  process、network、login、files、persistence，以及 process/powershell/windows events。
  旧运行标记不作为本次输入条目；其它辅助文件需明确列出，不默默丢弃。
- files 必须涵盖 14 个必需输出与 analysis-run.json，排除 analysis-commit.json。
  复制输入必须以相同路径/大小/摘要存在于 files，只有已知 14 个生成路径允许重建。
  其它最终辅助文件必须来自 inputs，不能额外夹带未声明条目。
- ioc 字段必需：缺失 IOC 时显式 null，且输入/最终清单不能包含该文件；
  存在时是精确 File 引用，必须与 inputs 中 `analysis/ioc_matches.json` 完全一致，
  最终副本也不能变化。仅声明“存在”不证明 IOC 内容实际可解码。

路径沿用离线 USTAR 可移植子集：ASCII、相对路径、最多 95 字节/8 层、单组件
最多 64 字节，拒绝保留设备名、遍历、盘符、链接语法、大小写别名和文件/目录冲突。
标记与 IOC 的非规范大小写或作为目录前缀也拒绝，避免 Windows 上与特殊路径混淆。
此处路径校验独立实现以保持依赖方向；未来公共路径抽取必须保持两边既有拒绝规则。

默认限额：单份元数据 1 MiB、文件数 4096、单文件 64 MiB、每份 inventory 的
声明字节总量 256 MiB；只允许收紧。files 中已包括运行描述，另为完成清单预留
一个文件数位置，因此 files 最多 4095 项。Read/Encode 还计入完成清单本身的实际
编码字节到最终 payload 声明预算；Read 以 MetadataBytes+1 探测实际元数据超限。
这些不是实际 case 文件大小验证或硬内存峰值保证；实际 payload 仍需未来 reader 逐字节核对。

所有对象拒绝未知、缺失、重复、大小写别名字段（包括转义拼写的重复键）；
只允许上述 window bound 与 ioc 为 null。拒绝非法 UTF-8/未配对代理项、
非整数/指数/溢出 size、尾随 JSON 或垃圾。合法 Unicode/转义不做身份归一化。
失败返回零结果；底层 reader 错误保留 errors.Is 身份。

摘要定义（不是 RFC 8785 或通用 canonical JSON）：

1. 将结构合法的 Commit 的 content_digest 置空字符串，仍保留该字段。
2. 按 Commit 声明字段顺序使用 Go encoding/json 紧凑编码；数组不自动排序，
   不加换行。Go 的 HTML、U+2028/U+2029 转义规则属于此编码协议。
3. SHA-256 输入为 UTF-8 `ir-toolkit.analysis-commit.digest.v1` 加一个 LF，
   再接上一步编码字节，输出小写十六进制。

独立 Node crypto/字段有序 JSON fixture 核对的 ASCII golden vector 在
metadata_test.go 中：运行描述 SHA-256 为
`db64f9f225d56c1fd9565927f9cc5a823aceaf1d3b6a52586eee82906051447c`；
11 个零大小输入、14 个零大小生成输出、该 99 字节运行描述构成 26 项 files，
完成摘要为 `78e4f64a3a12b870ce1efaea1439c0347e688de2590fb401db7becdc5eec5275`。
这是声明编码测试，不代表空文件可通过领域加载。

ContentDigest 只计算合法结构的摘要；EncodeCommit 不静默修复错误摘要。
ValidatePair 比较合法 run/commit 的 run_id，仍需未来磁盘层核对运行描述实际字节及
全部 inventory 的真实文件。codec 不证明 manifest/host 字节与声明身份相符，
也不验证领域内容、运行来源或完成发布状态。

只读文件清单验证现已实现，见第 9 节；下一阶段应接统一 reader 门禁，其后再接 builder 和发布。

## 9. 2026-11-01 只读磁盘 inventory 验证（独立入口）

```sh
ir analysis-verify /absolute/path/to/case
```

此命令在当前开发源码中可用，不向已发布的 `V0.3.0` 二进制回填。它不写入、修复、生成标记或
发布结果，也不查询总线、不重新分析、不打开 Web。stdout 为 JSON receipt，错误诊断在 stderr，
拒绝时返回非零；当前根 CLI 也可能打印错误栈。

- 两个规范标记均不存在：`legacy_unmanaged`，只表示识别为旧目录，不验证其领域内容或文件清单。
- 两个标记都存在且验证成功：`inventory_verified`，返回 run_id、content_digest、实际文件数及
  payload 字节数。所有 receipt 都有 `domains_loaded=false`、`publication_attested=false`。
- 单独标记、非规范大小写、目录/链接标记、JSON/版本/配对/清单/限额等错误：`rejected`，不回退
  legacy，不返回部分验证结果；错误 receipt 不提供成功的 managed/count 声明。

`VerifyDirectory` 使用既有严格 codec，扫描实际目录并逐字节哈希，检查精确文件集合、大小和
SHA-256（包含运行描述，完成声明自身另计），拒绝额外文件/空目录、路径别名、遍历、特殊文件、
符号链接及硬链接。v1 的必需输入仍包含 Windows 事件文件；本批未扩展 Linux 发布 profile。
即使所有域文件都是无效空 JSON，只要声明与字节匹配仍可能 inventory_verified，不能据此开放
调查视图。manifest/host 身份、IOC 可解码性、14份输出的领域正确性均尚未验证。

文件数/单文件/payload 限额沿用 codec：4096（含两份标记）、64MiB、256MiB；元数据各最多1MiB，
只允许收紧。实际文件大小和读取探测都受限，不依赖声明大小分配大内存。哈希用64KiB分块，
目录枚举分批并限制深度/条目数；根目录标记识别也受文件数预算约束。payload 数值按最终唯一
文件计数，初始解析与结束重读元数据另有最多4MiB额外I/O，不是硬内存/RSS或整体耗时保证。

要求来源已停止写入，父目录可信且私有。目录句柄固定、文件打开前后和末次 metadata/link 复核、
标记末次字节哈希复核用于拒绝**观察到**的替换/变化/增删。Unix 打开叶文件用 NOFOLLOW/NONBLOCK，
Windows 复核句柄的链接数/reparse属性；Windows 原生行为仍需实机验收。
这些检查不是原子快照，也不能抵抗敌对写入者在检查窗口之间修改并恢复数据。
context 在枚举/分块读取之间检查，普通文件同步 I/O 不承诺随取消立即中断。

本批**没有**统一 reader 门禁、完整域冻结加载、源复制 builder、Close/Sync 故障发布协议、
独占完成标记发布、writer 不可变保护或离线包/归档 gate。现有 Store/Web/导入/打包路径不会因
存在该独立命令就自动获得新协议保护；`analyze` 行为不变。不得手动创建标记后把旧 reader 当成
安全的新协议消费者。下一批需要统一失败关闭的 reader 门禁，并保持旧 case 兼容。
