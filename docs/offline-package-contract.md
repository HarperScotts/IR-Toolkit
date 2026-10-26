# 离线交付包与导入校验契约

状态：2026-10-10，元数据类型、严格解析、路径/声明限额校验和内容指纹已实现。
受限容器读取、实际 payload 大小/哈希、manifest 引用和源身份比对已实现；
底层容器导出、case-pack/case-verify 命令、独占新输出及导出端领域预加载已实现；
受限临时解包、导入端领域组装与 central-import-package 已实现；
包导出/导入的进程强制终止回归已在 macOS 合成数据上通过；
预算边界的合成资源测量已完成，见 [测量口径与结果](package-resource-profile.md)；
原子输出发布、真实 case/系统 RSS/实际磁盘分配测量、断电恢复及 Windows 实机验收仍未完成。
现有 central-import 仍只接受可信本地 case 目录；不要用它直接处理未经验证的解包结果。
本阶段不提供远程 Agent、接收端口、身份认证、签名、加密或自动重分析。

## 1. 范围与实现顺序

目标：把一个完整、停止写入且可调查的已分析 case 交付到另一台机器，
校验后复用既有 Local loader 与 archive.Commit 发布，不修改原 JSON 字节、
Store/Web schema、Network canonical ID、IOC index ID 或 Analyzer 关系。

首版一包一主机、一分析版本。接收方明确选择调查 case_id；包不能自行指定目标调查、
仓库路径或提交目录，也不能从 hostname、IP、用户名相似性推断调查归属。
多包原子导入暂不实现；不能把逐包成功宣传为多主机原子事务。

建议增量顺序：

1. 增加独立 package 契约、元数据解析、路径/限额校验、内容指纹与负例测试。
2. 增加 exporter 和只读 verifier，往返测试覆盖 12 类原 ID。
3. 增加受限解包与显式 import，最后调用现有 archive.Commit。
4. 完成恶意输入、资源上限、强制终止与 Windows 实机测试，再讨论远程传输。

业务仍属于现有 Store。internal/packageio 负责包元数据与格式边界，不导入 Web、
Local 或 Central；CLI 组装 packageio → Local 完整领域预加载 → archive.Commit。
网络接收与调查 Web 必须独立；Web 不同步查询 Agent，也不负责解包或提交。

## 2. 身份与版本

| 名称 | v1 含义与来源 |
| --- | --- |
| 接收调查 case_id | 导入操作者明确提供；不在交付包里绑定目的地 |
| host_id | 按当前 loadCentralView 规则：trim(host/host.json hostname)，为空才回退 manifest hostname |
| version | trim(manifest.case_id)，保持现有 Central View.Version 语义 |
| case_name | 原 case 的展示名称；只作显示，不用于生成文件路径或决定身份 |
| content_digest | 本文定义的内容指纹，不等于 view identity，不是凭据或签名 |

包声明的 host_id/version 必须与解包后的既有加载规则精确相等。
二者均要求非空、有效 UTF-8、无控制字符、无首尾空白，长度不超过 256 字节；
只对本包新增输入施加这些约束，不迁移或改写已有仓库。
展示名称同样要求非空、有效 UTF-8、无首尾空白、最多 256 字节且无控制字符，
不能作为提取目录名。JSON 内不成对的 Unicode surrogate 转义会被拒绝，不默默替换成 U+FFFD。

hostname 只是当前兼容标识：重名、改名和克隆主机的身份问题尚未解决。
包内 hostname 以及证据里的 PID、LogonID 都是输入数据，不证明来源真实。
未来 Agent ID 与证书映射必须有单独迁移方案；不能静默用 Agent UUID 替换已有 HostID。

同一采集目录重新分析通常不会产生新的 manifest.case_id。v1 不能把变更后的内容
覆盖为同一个已发布版本；需要新的独立 case/version，或以后显式版本化分析模型。
时间戳、随机上传 ID 和包文件名都不能自动替代 View.Version。

## 3. 容器与元数据

设计选择：未压缩 USTAR，建议扩展名 .ircase.tar。包只包含普通文件，不恢复权限、
ACL、owner、mtime 等文件系统元数据，不执行包内任何内容。首版拒绝 gzip/ZIP、
PAX/GNU 扩展、稀疏文件、目录条目、软硬链接、设备和 FIFO。
目录由接收方根据验证后的相对路径创建。

USTAR 被选作可流式处理的受限容器，不表示通用 tar 输入自动安全。
Go archive/tar 支持流式读取且会透明处理部分扩展，因此未来实现不能只看后处理后的
Header.Name 就声称已拒绝所有原始扩展。现有读取器先检查原始 512 字节 header，
再把单个 header 交给标准库校验，不让标准库跨条目吞掉隐藏扩展。
参考 [Go 1.26.5 archive/tar 文档](https://pkg.go.dev/archive/tar@go1.26.5)。

条目顺序固定：

```text
package.json                 第一条、唯一的包描述文件
case/analysis/...            以下 payload 按相对路径 ASCII 字节序排列
case/capabilities/...
case/host/...
case/manifest.json
...
```

USTAR 文件头、块填充和结尾必须完整；截断、拼接第二个归档、尾部非零数据均拒绝。
exporter 写标准结尾；verifier 必须验证结尾而不把单次 tar.Reader.Next 返回 EOF
等同于整个输入已验证。允许结尾的额外零块总计最多 10 KiB，仍计入总输入预算。

v1 读取子集要求精确 USTAR magic/version、原始 typeflag 为普通文件 '0'、
无 link/prefix/扩展尾字段，name 的 NUL 终止符后不得藏非零字节。
所有允许路径都能放入 100 字节 name 字段，因此不使用 USTAR prefix；
size 使用无符号 ASCII octal，拒绝 base-256/负数形式。文件块填充必须全零。
普通 USTAR 工具产生的其它变体也可能拒绝，后续 exporter 必须生成该明确子集，
不能静默放宽读取策略。

package.json 的 v1 字段：

| 字段 | 类型与规则 |
| --- | --- |
| format | 固定字符串 ir-toolkit.case-package |
| format_version | 整数 1；其它版本拒绝，不尝试猜测 |
| profile | 固定 analyzed-case-v1，表示需要完整领域加载；不是分析真实性声明 |
| host_id / version / case_name | 第 2 节规定的字符串 |
| content_digest | 本文规范化输入的 SHA-256，小写 64 位 hex |
| files | 非空有序数组，覆盖 case/ 下每一个普通文件，含 manifest.json |
| files[].path | 相对于 case/ 的原路径，不含 case/ 前缀，规则见第 5 节 |
| files[].size | 非负 JSON 整数，以字节计，解析不得经过浮点数 |
| files[].sha256 | 文件原始字节的 SHA-256，小写 64 位 hex |

描述文件要求一个 UTF-8 JSON 对象，不允许未知字段、重复键、null 必填值、
缺失字段、重复文件条目、尾随 JSON 或非空尾随字节。files 严格按路径字节序排列。
package.json 自己不进入 files，避免自引用；其它未列出的 payload 文件一律拒绝。
描述文件不是既有 model.Manifest 的替代，不修改原 manifest。

## 4. 全量清单与内容指纹

当前采集器在 collect 阶段生成 manifest.Files；它不包含后来生成的全部 Analyzer 输出，
也不包含 manifest.json 自身。所以不能只复制此清单作为交付包 inventory。
exporter 必须枚举完整 case 的全部普通文件，将原始证据、分析输出、manifest 和附加数据
一并纳入 package.files，不按查询命中、IOC 或 finding 过滤文件。

原 manifest.Files 仍保留原字节。包校验器还必须核验其中每个声明的原始证据文件：
路径合法且存在于 package.files，size/hash 与实际内容一致，不得出现重复声明。
该清单可以是 payload 的子集，不能要求它包括所有分析文件。
空清单不被扩展成“证据真实/完整”的证明；完整领域要求仍由现有 loader 检验。

content_digest 的规范化输入如下，所有长度与数字均用无符号 big-endian：

```text
ASCII("IR-Toolkit-Case-Package-v1") + 0x00
LP(profile) + LP(host_id) + LP(version) + LP(case_name)
uint32(file_count)
对每个已按路径排序的 file：
    LP(path) + uint64(size) + SHA256 的 32 字节解码值
LP(s) = uint32(UTF-8 字节长度) + UTF-8 字节
```

对上述字节序列计算 SHA-256。format_version 由固定标签绑定，不包含 digest 字段自身。
摘要由校验器重新计算，不信任包内声明。所有加法/转换必须在限额与溢出检查后进行。
JSON 空白、TAR header 时间与块布局不进入内容指纹；原证据的任意字节变化仍改变它。
接收调查 case_id 不进入摘要，同一包是否允许导入另一调查仍由操作者明确决定。

SHA-256 仅证明内容与声明一致，攻击者可以同时修改 payload、清单和摘要。
签名、真实性、传输机密性、来源认证与授权都未提供，不能因此默认信任任意远端包。

## 5. 路径与资源限制

可移植路径策略是 v1 的限制，不是重命名规则。payload 相对路径只允许
ASCII 字母、数字、下划线、连字符、点和 / 分隔符；每个组件必须以字母或数字开头。
拒绝绝对路径、空组件、. / ..、反斜线、冒号、控制字符、尾部点、空白和大小写折叠后的冲突。
拒绝 Windows 保留设备名（包括带扩展名的 CON、PRN、AUX、NUL、COM1..9、LPT1..9）。
路径不得与另一文件的目录前缀冲突，例如同时出现 a 与 a/b.json。

逻辑路径加 case/ 前缀后不得超过 100 ASCII 字节，组件最多 64 字节、深度最多 8 层。
超过限制或非 ASCII 的文件名拒绝导出/导入，不静默清理、规范化或改名；
证据 JSON 中的 Windows 路径、Unicode 用户名等内容不受包文件名限制，不被修改。

首版默认接收预算（仍需用真实 case 验证适用性）：

- package.json ≤ 1 MiB；payload 文件数 ≤ 4096。
- 单个 payload 文件 ≤ 64 MiB；payload size 总和 ≤ 256 MiB。
- 整个 TAR 输入 ≤ 272 MiB，包括元数据、header、填充和尾部零块。
- 单次校验/导入最多处理一个包，支持取消；不递归处理 payload 里的归档文件。

这些限制不是内存上限保证：现有 Local loader 会整文件读取并缓存对象，未来实现需测量峰值。
读取前检查声明，读取时再累计实际字节，提前 EOF、超出限额、负数、超范围数字均失败；
不能只信 Content-Length、tar header size 或 package.files 的总和。
首版不自动提升限额、重试超大包或降级跳过文件。限额将作为明确配置/拒绝原因，
不是“证据不足”或入侵判断。

当前 DefaultLimits 返回上述预算的新值；显式 Limits 只能收紧，零值、负值或扩大 v1
上限均拒绝。ReadMetadata 对描述文件最多读取 MetadataBytes+1 字节以识别超限，
精确解析 int64 大小，并检查声明的单文件/总 payload 大小，不验证实际文件字节。
ContainerBytes 由 VerifyContainer 计入全部实际输入（文件头、正文、填充、结束块与尾块）；
精确预算末尾额外探测最多 1 字节区分 EOF 和超限。ReadMetadata 单独使用仍不能确认容器大小。

解包必须写入操作者控制的、空的新建私有临时根目录；不允许用户提供复用提取目录。
验证包含关系并以独占创建方式写文件，不跟随链接，不继承源权限，不用包路径构造仓库批次名。
此设计针对包内恶意输入，不承诺防护能够并发控制接收机文件系统的本地攻击者；
临时根目录及仓库父目录必须可信且受限。
Extract 要求显式传入已存在的可信临时父目录，再自行创建随机新根，不接受复用目标。
Unix 根/子目录使用 0700，文件使用独占创建/0600；Windows Go permission bits
不建立私有 DACL，必须依赖操作者已限制的父目录 ACL，实机仍需验证。

## 6. 校验、提交与失败语义

校验链必须在提交前完成：

1. 限制输入总字节、读取唯一首条 package.json，严格校验结构、身份声明和 inventory。
2. 逐条验证原始容器类型、路径、顺序、声明 size、实际字节与 SHA-256，
   写入独立临时根目录；核对全量清单、标准结尾和无额外条目。
3. 校验原 manifest.Files，并用现有加载规则核对 host_id/version；
   预加载全部领域，保持可选 finding、SecurityProviders、Report 的既有 found/缺失语义。
4. 重新计算内容摘要，检查操作者指定的调查范围和可选的预期 host/version。
5. 经显式 import 才调用 archive.Commit，从不可变临时副本再次复制并校验，
   用已有锁与 rename 批次边界发布。只读 verify 不创建目标仓库或 writer lock。
6. 只有 archive.Commit 明确成功才报告 committed，并返回精确 view。

验包成功不是提交成功。收到字节、校验成功、创建暂存目录都不是可调查状态。
缺失必需领域、坏 JSON、hash/size 错误、路径冲突、超预算、身份不匹配、重复 view、
writer lock 或 IO 失败必须明确失败，不跳过坏文件后发布剩余内容。
已有 Store 的错误/查询语义不改变；包层错误属于输入或交付失败，不是风险判定。

一旦 rename 已发生但后续锁释放/回执输出失败，结果属于需要核实的提交状态；
不能因为调用返回错误就假定没有提交。停止 writer 后按既有恢复流程加载仓库核实，
不自动解锁、覆盖或从遗留 stage 手工提交。
临时提取失败只清理本次调用新建的临时数据；输入包、源 case 和既有批次不删除。
强制终止可能遗留提取目录，保留/清理需要独立授权。

v1 重试沿用现有重复拒绝：同 (case_id, host_id, version) 再次导入，即使摘要相同，
也不自动当作幂等成功。若未来提供幂等回执，必须将内容摘要与 view 在同一提交中持久化，
并区分相同内容重放和相同身份不同内容；当前 archive 格式不存该回执，不假定已有支持。
本轮不扩展 commit.json 或修改已存批次。

## 7. CLI 与验收门槛

以下两个命令已实现：

```text
ir case-pack <complete-case-dir> --output <new-package.ircase.tar>
ir case-verify <package.ircase.tar>
```

显式包导入命令已实现：

```text
ir central-import-package --repository <dir> --case-id <id> --temp-parent <private-existing-dir> <package.ircase.tar>
```

导出要求新输出路径，失败清理自己的未完成输出，不覆盖现有包或源 case；
只读 verify 不解包到持久位置、不访问 Agent、不写仓库。
导入只操作显式目标仓库，不把 package 元数据解释为命令、配置或远程地址。
展示名称通过包导入组装层显式传递给归档，不用临时目录 basename 替代；
现有按目录导入的 CaseName 保持不变。

case-pack 要求可信且停止写入的源和输出父目录。输出父目录必须存在；
检查真实文件系统祖先，拒绝输出位于源树内（含父目录链接/大小写别名），
用 O_EXCL/0600 创建新文件，不覆盖现有文件/目录/链接。
先有界导出并读回 VerifySource，再复用 loadCentralView 预加载全部领域；
随后向 discard sink 重新导出核对指纹，最后 Sync/Close 成功才返回 exported 回执。
展示名称为解析后源根目录 basename；内部预加载的调查 scope 不发布、不写入包。
此多次读取不是并发源的原子快照，必须保持停止写入；Local 缓存也不承诺进程内存上限。
创建时最终输出路径就存在，不保证原子发布或断电持久性。读取者不能将路径存在视作完成。
正常失败关闭输出并仅删除仍属于本次调用的文件；路径已被替换时拒绝删除并报告错误。
异常终止可能留下部分包，不自动恢复/覆盖。回执输出失败时已完成包保留，错误明确提示。

case-verify 仅接受普通非软链接本地文件，先检查文件大小再流式验证，不解包、不加载领域。
JSON 回执提供 status、host_id/version/case_name、content_digest、file_count、实际字节数、
domains_loaded 和 committed。导出为 exported/domains_loaded=true，
只读校验为 verified-framing-source/domains_loaded=false；committed 均为 false。
坏领域 JSON 但字节/源声明自洽的包仍可能通过只读校验，不能将它宣传为完整 case 可调查。

central-import-package 一次只接受一个普通非软链接包文件；repository、case-id 和
temp-parent 均必填。临时父目录必须预先建立并限制本地权限/Windows ACL，不自动设置 ACL。
临时父目录应位于仓库之外，避免原 archive 严格目录校验将临时数据当成异常仓库条目。
先有界 Extract 并关闭输入，再复用 loadCentralView 预加载所有领域并精确比对 View，
最后调用原 archive.Commit 再次复制、校验和以 rename 原子发布。目标调查仅来自操作者。
CLI 检查整个新临时根（含 case/ 的兄弟路径）不能包含目标仓库，防止清理删除提交。
archive.Source 新增可选 Name 展示字段，空值沿用原目录 basename；commit.json schema 不变，
不添加 content_digest 持久回执，不迁移旧批次。
所有正常路径都关闭/清理本次提取树，不删除输入包、不清理其它遗留树或他人 writer lock。
验证/领域加载失败不进入 Commit，也不创建目标仓库。提交阶段错误必须核实仓库，
即便错误可区分 writer busy 或重复 view，也不自动重试、解除锁或覆盖。
回执包含 status、精确 view、case_name、content_digest、committed；Commit 明确成功时
为 committed/true。Commit 返回错误时为 commit-outcome-unknown/null（不是未提交 false）。
提交后的临时清理/回执 IO 失败仍保留已提交状态并返回错误，不能因此删除批次或再次覆盖。
取消在提取读取和提交前检查，Commit 开始后只在 loader 边界合作检查，不保证中止 rename；
返回 committed 以后不因后到的取消宣称未提交。异常终止沿用原 writer lock 的显式恢复规则。

强制终止回归覆盖导出文件写到一半、导出完成但回执前，以及导入的部分解包、
解包校验完成、领域加载完成、暂存 case 副本完成但 commit.json 前、提交返回但回执/临时清理前。
测试使用独立子测试进程和私有回调，不提供生产命令/环境故障注入开关。
进程被 Kill 会绕过 defers：部分包/本次提取根可遗留；暂存阶段 lock/stage 遗留且旧 view 仍可读；
提交返回后 view 完整可恢复，lock 已释放，但提取根可遗留且没有回执。
测试确认新调用不会覆盖原输出、删除其它调用的提取根或遗留 stage，也不接管孤儿 lock；
仅在 t.TempDir、子进程 Wait 已证明退出且旧提交校验通过后模拟把精确 lock 移到独立恢复目录。
提交后重试仍拒绝重复，不把缺少回执当作未提交。这不是断电/设备故障耐久性证明，
归档单文件复制中途的强杀及 Windows 行为仍未实机覆盖。

实现验收至少包括：

- 两主机同 ID：pack → verify → import → 重启 → Search → 12 类精确详情一致。
- 原始 JSON 字节、IOC 顺序、canonical Network ID、零时间及查询统计保持原样。
- 元数据重复键、未知字段、未知版本、错误身份、坏原 manifest 清单均拒绝。
- ../、绝对路径、Windows drive/UNC/ADS、设备名、Unicode 文件名、大小写碰撞、
  文件/目录前缀冲突、链接、隐藏扩展、稀疏条目和特殊文件均拒绝，提取根外零写入。
- 截断、未列出/缺失/重复条目、大小/哈希不符、尾随拼接归档和超限输入均失败。
- 规范化摘要有固定 golden vectors，JSON 排版变化不改摘要、payload 变化改摘要。
- 对容器 framing、路径、元数据/整数解析、摘要和限额做 fuzz/边界测试。
- 拷贝、提取、提交各阶段失败/取消/强制终止不发布半批次、不解除他人锁。
- Windows 实机验证设备名、目录权限与路径行为，测量最大受限输入下的内存/磁盘占用。

上述门槛完成前，不能把新增 parser 称为安全的远程上传入口。
后续远程方案还需身份注册、授权调查映射、传输认证/加密、签名或来源验证、
限流/配额、回执与审计策略；这些不能从离线包的内容摘要推导出来。

## 8. 当前实现与已验证边界

internal/packageio 现有入口：

- ReadMetadata(io.Reader, Limits)：有界读取、精确 JSON 字段、必填/null/重复键校验，
  integer 类型与 Unicode 校验，随后校验 inventory 与声明内容指纹。
- ValidateMetadata(Metadata, Limits)：检查声明，不修改输入顺序、路径或身份。
- ValidatePayloadPath(string)：跨平台 ASCII 路径策略，拒绝而不是 sanitize。
- ContentDigest(Metadata, Limits)：按第 4 节编码计算指纹，忽略旧 ContentDigest 字段，
  供后续 exporter 构造描述文件，不替代实际内容哈希。
- VerifyContainer(context.Context, io.Reader, Limits)：流式确认原始 USTAR framing、
  精确 inventory 顺序/名称/大小、实际 SHA-256、零填充、结束块、尾部和总预算。
  返回描述文件及实际 payload/container 字节数，失败只返回零结果。
- VerifySource(context.Context, io.Reader, Limits)：先完成同一容器校验，再核对
  manifest.Files 每项路径/大小/哈希与包 inventory 一致，并比对源 host/version。
  所有失败只返回零结果，不改变 VerifyContainer 的低层语义。
- ExportCase(context.Context, directory, caseName, io.Writer, Limits)：枚举全部普通文件，
  源 JSON 身份/引用检查后生成描述文件，输出固定 USTAR 子集，保持原始 payload 字节。
  caseName 显式作为展示名称传入，不从它构造路径；不导入调查后端，不验证完整领域。
- Extract(context.Context, io.Reader, tempParent, Limits)：在随机新根下固定 case/ 目录
  流式写入 inventory 文件，完成同一容器/实际字节/源身份/manifest 引用校验后才返回 Extraction。
  CaseDir() 提供验证后路径，Verification 提供字节校验结果；不提取 package.json 为证据。
  调用方负责在领域加载/提交后 Close()，只清理本次新建树；失败不返回部分路径或结果。

错误通过 errors.Is 区分 ErrInvalidMetadata、ErrInvalidPath、ErrLimitExceeded、
ErrDigestMismatch，以及 ErrInvalidContainer 和 ErrPayloadMismatch；读取 IO 错误保留原错误身份。
源检查另有 ErrInvalidSource、ErrManifestReference、ErrSourceIdentity。
导出另有 ErrSourceChanged，用于检测源文件身份/属性/哈希或目录清单的变化。
文件头或最后完整块伴随返回的 IO 错误不会因 ReadFull 而被忽略。
字段名严格区分大小写，
共享目录前缀也不能使用不同大小写别名（A/x 与 a/y 会拒绝）。

单元测试覆盖独立计算的固定指纹样例、JSON 排版不影响摘要、声明变化影响摘要、
解析往返、恶意字段/路径、UTF-8 与 surrogate、大小整数溢出、限额边界、
不静默修正输入及 IO 错误。包含元数据与路径 fuzz target。
容器测试覆盖标准库透明处理的实际 PAX/GNU 扩展、所有截断前缀、非普通条目、
不安全路径/数值、错误校验和/大小/正文哈希、缺失/额外/重复/乱序条目、尾部拼接、
零填充与预算边界，以及取消/IO/no-progress 输入。容器另有 fuzz target。

VerifyContainer 不保留 payload 内容、不写文件系统，不检查 manifest.Files 的引用、
host/version 与源 JSON 的一致性或完整领域可加载性；因此成功不是“完整 case 验包通过”，
不是来源认证，也不是已提交 view。取消在读取前后检查，但不能抢占底层阻塞 Read：
文件/网络 reader 的 deadline 或关闭机制仍由调用方负责。
VerifySource 只暂存 manifest.json 和 host/host.json，两者均必需，且每份大小不得超过
MetadataBytes（默认 1 MiB）；其他 payload 仍只流式哈希。此预算限制原始 JSON 字节，
不是解析对象的进程内存上限。源 JSON 必须是单个对象，拒绝无效 Unicode、
顶层重复键/大小写折叠别名及 identity 字段的非规范大小写，允许未知辅助字段。
manifest.case_id 必须是字符串；hostname 可省略以保留回退语义，但显式 null/非字符串拒绝。
身份值 trim 后按当前 Local 规则比对：host.hostname 优先，为空才回退 manifest.hostname，
version 来自 manifest.case_id。接收端调查 case_id 仍不从包中取得。
为兼容既有 Manifest 的 nil slice，files 缺失/null/空数组均视为无引用；
非空引用必须含精确 path/size/sha256 字段，拒绝重复引用和不安全路径。
引用只须是 inventory 子集，不要求覆盖分析输出；任何一致性成功均不代表来源认证、
完整领域可加载或已提交 view。源检查包含独立回归与 fuzz target。

ExportCase 的输入必须是可信且已停止写入的本地目录，根目录和树内不跟随软链接，
拒绝特殊文件及树内指向同一文件的硬链接别名；单一路径的树外硬链接关系不作全盘调查。
空目录不生成容器条目，但仍验证路径/别名且限制遍历节点数为 FileCount×8+1（含根）。
先限制文件数、单文件/总大小并哈希，再检查源引用、身份、描述文件和完整输出字节预算。
输出时再次检查文件身份/大小/mtime并哈希；结束前重新枚举目录检测新增/删除/替换。
这些检查不是并发源的原子快照，也不防御能控制可信源父目录的本地攻击者。
固定 0600/Unix epoch USTAR header 不传播源权限/时间；重复导出相同输入字节可稳定复现。
源读取与输出支持边界取消，底层阻塞 IO 的 deadline/关闭仍由调用方提供。
底层导出器不创建或关闭输出文件，不保证落盘和原子发布；writer 必须位于源树外。
失败仅返回零结果，但流可能已收到部分字节，调用方必须丢弃整个输出，即使它看似完整。
新路径独占创建、不覆盖、失败清理及源 case 完整领域预加载由现有 CLI 组装实现，
不改变底层 ExportCase 或只读 VerifySource 的保证。

Extract 使用私有写入回调复用现有容器/source 校验，不暴露未验证的 payload 给公共回调。
目录按组件创建，遇到已有组件先 Lstat 核对真实目录，文件 O_EXCL，不跟随已有链接。
每份 payload 在继续下一个 header 前关闭文件；写入/关闭失败均使整个解包失败。
末尾非法、源引用/身份异常、取消、超预算等晚期失败也清理本次根；清理失败在错误中提示路径。
Extraction.Close 幂等，检查新根身份，不删除被替换的根；不清理其它调用、父目录或输入包。
这不防御能并发控制父目录的本地攻击者，也不保证临时文件断电持久性；强制终止可能遗留根。
返回只表示受限字节和源一致性通过，不意味着领域可加载、来源认证或已提交；
公开 case-verify 仍不调用 Extract，维持只读、不创建临时提取树的语义。
短时 fuzz 与这些回归不构成容器/解包的完整安全证明，Windows 实机仍未验收。
