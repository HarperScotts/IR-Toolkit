# 离线包合成资源测量

该入口只生成测试数据，不读取真实 case。默认 `scripts/check.sh` 会跳过重型 profile。

```bash
GOCACHE=/tmp/ir-toolkit-go-cache sh scripts/measure-package-resources.sh
```

需要可写测试临时目录和至少约 1.1 GiB 可用逻辑工作区预算；密集 JSON 场景会占用数百 MiB Go 堆。
使用真实权限受限的本地临时父目录，不在敏感仓库或证据目录中运行。
每个操作在新的子测试进程中运行，避免上一阶段的 Go 缓存影响基线；fixture 创建不计入操作耗时。
结果以 `RESOURCE_JSON:` 行输出，可保留为测量日志。测试框架结束时只清理自己创建的 fixtures。

## 口径与限制

- 三种 case：payload 总字节恰为 256 MiB（18 文件，最大单文件 64 MiB）；
  总文件数恰为 4096；单个 process JSON 恰为 64 MiB（125176 个不同 PID 的合成记录）。
- export 使用实际 CLI helper，包括读回验包、领域预加载和复核源指纹；verify 保持只读。
  extract 包含正常清理；import 包含完整领域加载、原 archive.Commit 和本次临时树清理。
- Go HeapAlloc/Sys 每 10 ms 采样；逻辑工作区每 100 ms 采样，并在导入关键边界补充观测。
  峰值可能漏掉更短瞬时峰值，不是硬内存上限。Sys 是 Go runtime 向系统取得的内存，不是 RSS。
- 逻辑工作区仅统计 source、TAR、提取文件和归档文件的 FileInfo.Size 总和，不包括目录元数据、
  filesystem journal、实际分配块、压缩/COW、系统页缓存或其它进程。不是实际空闲磁盘下降量。
- import 的峰值可同时包含源目录、交付 TAR、临时提取副本和归档 stage/批次；
  完成后提取副本删除，但源、TAR 和归档仍保留到 fixture 清理。
- 采样、遍历和回调本身也分配内存并消耗时间；total_alloc_delta 是累计分配（包含测量开销），
  不等于同时占用的堆，更不能直接解释成生产操作的纯分配量或泄漏。
- 耗时受文件缓存、磁盘、GC 和测量扰动影响，不是 SLA、吞吐保证或 Windows 资源指标。
  环境/Go 版本与 GOGC/GOMEMLIMIT 环境值在每条回执记录，不自动改变预算或 GC 配置。

## 2026-10-10 首轮结果

宿主 darwin/arm64，Go 1.26.5。以下为单次合成运行，MiB = 1048576 字节。

| 场景 | 操作 | 耗时 ms | 采样堆峰值 MiB | 逻辑工作区峰值 MiB |
| --- | --- | ---: | ---: | ---: |
| payload 256 MiB | export | 654 | 3.56 | 512.02 |
| payload 256 MiB | verify | 111 | 0.56 | 512.02 |
| payload 256 MiB | extract | 215 | 0.74 | 768.02 |
| payload 256 MiB | import | 465 | 2.14 | 1024.02 |
| 4096 文件 | export | 478 | 10.52 | 6.44 |
| 4096 文件 | verify | 43 | 3.52 | 6.44 |
| 4096 文件 | extract | 520 | 3.64 | 8.44 |
| 4096 文件 | import | 16338 | 7.55 | 10.81 |
| process JSON 64 MiB | export | 434 | 199.96 | 128.02 |
| process JSON 64 MiB | verify | 27 | 0.50 | 128.02 |
| process JSON 64 MiB | extract | 42 | 0.59 | 192.02 |
| process JSON 64 MiB | import | 723 | 292.84 | 256.03 |

密集领域 import 的 Go Sys 采样峰值约 316.27 MiB；与流式 verify/extract 明显不同。
第二轮 12 个操作全部通过，整体约 21.1 秒；GOGC/GOMEMLIMIT 环境值均为空（未显式设置）。
payload import 堆峰值约 2.16 MiB，密集领域 import 约 286.38 MiB，
4096 文件 import 约 16.18 秒。重复结果不是严格峰值/吞吐上限，保留首轮表格作基线。
4096 文件 export/import 的累计分配分别约 604/1509 MiB（含采样开销），
其中 archive 对每个复制文件执行 Sync；本轮不降低持久化行为或改动已有查询/领域语义。
这些数据支持“包文件预算不是 loader 内存上限”，不证明其它结构复杂度、字段形态或真实证据的最大占用。

后续优先定位多文件缓冲分配与 IO/Sync 成本，重复测量并区分测量开销；
真实授权 case、Windows ACL/运行及目标机器 RSS/实际磁盘分配测量仍待完成。
全量 scripts/check.sh、CLI/packageio/archive 竞态检查通过，普通检查不运行重型 profile。

## 2026-10-10 缓冲复用对比

ExportCase 原来两遍复制均为每个文件分配 32 KiB；现改为每次 ExportCase 独占一个缓冲。
archive.inventory 同样独占复用缓冲，并用仅暴露 Read 的包装避免 os.File.WriteTo 的
generic fallback 绕过 CopyBuffer 缓冲。没有全局 pool、并发共享、格式/限额或 IO 错误降级。
每个归档文件仍 Sync/Close，commit.json 的 Sync、锁与 rename 边界不变。

默认 sampled 模式重跑三场景 12 个操作全部通过；4096 文件 export 的累计分配由首轮
633403920 字节降至 93572336 字节（约 604.06 → 89.24 MiB，减少约 85%）。
本次该 export 约 388 ms，import 仍约 16.33 秒；不声称归档导入得到明显加速。
payload import 仍需约 1 GiB 逻辑工作区，密集领域仍有约 287 MiB 堆峰值；未改变这些边界。

为了隔离测量器的反复目录遍历分配，增加仅检查点磁盘测量模式：

```bash
IR_PACKAGE_RESOURCE_PROFILE=1 IR_PACKAGE_RESOURCE_DISK_MODE=checkpoints \
  go test ./internal/cli -run '^TestPackageResourceProfile/file-count-limit$' -count=1 -v -timeout=5m
```

仅测试环境开关，不是生产 CLI 参数。该模式仍每 10 ms 采样 Go 堆，但取消周期目录遍历，
仅在关键边界和结束时统计逻辑工作区；与默认 sampled 结果不能直接当作同口径优化对比。
回执新增 disk_mode，默认为 sampled；非法 mode 明确失败。
本次 4096 文件 import 累计分配 86563712 字节（82.55 MiB），约 17.36 秒，堆峰值约 4.85 MiB。
默认 sampled 的同操作分配约 1379.81 MiB，说明测量器自身可造成大量累计分配，
不能把旧表中的约 1.5 GiB 全部算作产品成本或泄漏。耗时波动也不证明单一 IO 瓶颈。

独立 benchmark 不进行周期磁盘采样：

```bash
go test ./internal/packageio -run '^$' -bench '^BenchmarkCopySourceBuffers$' -benchmem -benchtime=3x
go test ./internal/store/archive -run '^$' -bench '^BenchmarkInventoryManyFiles$' -benchmem -benchtime=3x
```

264 文件、两遍 copySource 的参考版按文件分配缓冲，约 17937176 B/op；
复用版本约 633536 B/op（约减少 96.5%）。相同文件读取、身份/大小/mtime/hash 检查保留。
当前 archive hash-only inventory 的 4096 文件约 3812197 B/op；
这是不含复制/Sync 的定位基准，不能拿它代替完整导入成本。
完整导出 benchmark 另见 BenchmarkExportManyFiles，正常 go test 不执行 benchmark。

后续应针对剩余解析分配、目录/硬链接检查与 IO 等待做进一步分离测量，
不通过省略校验、减少 Sync 或移除原子提交保护来获得性能数字。

## 2026-10-10 剩余阶段分离

新增独立 source scan、metadata read/validate 和 archive copy/Sync 定位 benchmark：

```bash
go test ./internal/packageio -run '^$' -bench 'Benchmark(ScanSource|MetadataStages)' -benchmem -benchtime=3x
go test ./internal/store/archive -run '^$' -bench '^BenchmarkInventoryCopySync$' -benchmem -benchtime=1x
```

复制/同步基准使用 512 字节小文件，按原路径逐文件执行 Sync，并核对同步次数等于文件数。
copy 计时包含读取、SHA-256 和输出 Write；sync 计时是 File.Sync 的调用墙钟时间；
other 包含枚举、目录/文件创建、Close、摘要编码等剩余调用开销。
生成源 fixture、新目标根创建与结果清理不计入 benchmark 时间；
不减少同步次数，不把目标目录复用为已存在文件，不测试写入用户仓库。
私有观测回调只用于测试，生产 inventory 传 nil，不取时间戳，也没有环境/CLI 开关。

宿主 darwin/arm64、Apple M4、Go 1.26.5。本轮结果：

| 阶段 | 文件数 | 平均耗时 ms/op | 分配 B/op |
| --- | ---: | ---: | ---: |
| source scan（枚举+路径+硬链接检查） | 256 | 2.24 | 273192 |
| source scan | 4096 | 28.65 | 4693544 |
| metadata read（严格 JSON+验证） | 256 | 2.35 | 1019616 |
| metadata read | 4096 | 14.51 | 16452965 |
| metadata validate（不解析） | 256 | 0.28 | 119456 |
| metadata validate | 4096 | 1.71 | 1973482 |
| archive copy+Sync（完整 inventory） | 256 | 1061.73 | 368392 |
| archive copy+Sync（完整 inventory） | 4096 | 18139.83 | 5514952 |

4096 文件归档一轮中，copy 约 914.6 ms、Sync 约 15446 ms、other 约 1779 ms；
Sync 4096 次（约占完整 inventory 墙钟时间 85%）。256 文件 Sync 256 次，
约 990.9 ms；copy 9.24 ms、other 61.54 ms。
这仅定位本机本次 File.Sync 调用成本，不是内核 IO 等待分析，也不证明其它文件系统或 Windows 相同。
计时回调、调度和其它并行 benchmark 会扰动数据；此定位基准不含完整导入的 JSON loader 等步骤，
不能将不同测量轮次的 18.1 秒与前表 16–17 秒直接相减来推断 loader 成本。

目录扫描含当前成对 SameFile 硬链接检查，不能将它的所有耗时归于目录 syscall；
下一轮可优先减少元数据解析的对象分配，保持重复键、精确字段、Unicode、整数和限额拒绝规则。
暂不改变每文件 Sync、提交格式或恢复语义；Windows/真实 case 和平台 IO tracing 仍待验收。

## 2026-10-11 元数据条目解析分配优化

files 数组共用一个 JSON decoder，以三字段位图检查精确字段、重复键和缺失字段；
不再逐条生成 RawMessage、字段 map 和独立 decoder。UseNumber + ParseInt 保留
int64 的词法和范围要求（拒绝小数、指数、字符串、null 和溢出）。
整份元数据的 UTF-8/代理项预检、顶层严格解析、文件数限额和最终声明/摘要验证均保留。
源 manifest 的引用解析、归档 Sync、提交格式和恢复语义不变。

同一宿主、fixture、3x 基准命令，本轮 metadata read：

| 文件数 | 平均耗时 ms/op | 分配 B/op | allocs/op |
| --- | ---: | ---: | ---: |
| 256 | 0.62 | 507632 | 13256 |
| 4096 | 9.32 | 8262706 | 209183 |

4096 文件相对上一轮 16452965 B/op 减少约 49.8%；validate 基准仍为 1973482 B/op。
为避免仅凭跨轮耗时判断，另保留测试专用的旧条目解析器，同一轮解析 256 条相同记录：
旧版 676234 B/op，新版 190864 B/op（约减少 71.8%），约 0.49/0.28 ms/op。

```bash
go test ./internal/packageio -run '^$' -bench 'Benchmark(MetadataStages|FileEntryDecoders)' -benchmem -benchtime=3x
go test ./internal/packageio -run '^$' -fuzz '^FuzzFileEntryCompatibility$' -fuzztime=20s -parallel=2
```

差分测试覆盖任意字段顺序、转义键、整数边界、负零、重复/未知/缺失字段、
类型错误和尾随数据；只在完整描述符 Unicode 预检通过的输入上比较条目解析。
全量 ReadMetadata 的现有 Unicode/限额/错误类别回归继续运行。
这是解析阶段的累计分配，不是 RSS/堆峰值或完整导入性能承诺；
主要 File.Sync 成本未改变。下一步可评估 source scan 的硬链接检测扩展性，
需要先验证不同平台文件身份语义，不以去掉硬链接拒绝换取速度。

## 2026-10-11 源目录文件身份索引

darwin/linux 的 os.SameFile 以设备号和 inode 判定身份，本轮在每次源目录扫描内
建立相同字段的索引，命中仍由 os.SameFile 确认；不使用大小、mtime 或链接数分桶。
未知身份逐对比较；键碰撞但 SameFile 不成立的条目进入保守回退列表，后续仍可见。
不共享跨操作缓存，也不改变导出前/后的扫描、每次打开文件后的身份检查或内容哈希。
依据已核对本机 Go 1.26.5 源码以及
[Go Unix 身份实现](https://go.dev/src/os/types_unix.go)。

Windows 的 FileInfo.Sys 不包含 SameFile 使用的完整身份，见
[Go Windows 身份实现](https://go.dev/src/os/types_windows.go)。
Windows 和其它未启用平台保留原逐对检查；本轮不增加打开句柄的身份获取逻辑，
不宣称 Windows 扫描性能改善，也不将交叉编译当作实机行为验证。

同一宿主 darwin/arm64、Apple M4、Go 1.26.5，修改前后分别运行 5x：

```bash
go test ./internal/packageio -run '^$' -bench '^Benchmark(ScanSource|SourceIdentityIndex)$' -benchmem -benchtime=5x
```

| 扫描文件数 | 原耗时 ms/op | 索引耗时 ms/op | 原分配 B/op | 索引分配 B/op |
| --- | ---: | ---: | ---: | ---: |
| 256 | 1.10 | 1.14 | 273288 | 301296 |
| 4096 | 26.53 | 17.88 | 4694289 | 5105499 |

4096 文件扫描耗时本次减少约 32.6%，增加约 411210 B/op 索引分配；
小规模未观察到耗时改善。另将已获取的 4096 个 FileInfo 在同一轮对照：
旧逐对检查约 9.36 ms/op、239984 B/op，索引约 0.245 ms/op、652331 B/op。
该隔离基准不包含目录枚举/Stat；正常原生身份索引预计线性扩展，
未知身份及碰撞回退仍可能为二次成本。耗时受调度/磁盘缓存影响，不是完整导入 SLA。

回归以 100 个固定随机排列对照旧逐对检查，包含独立同内容文件、硬链接、
同 inode 不同大小快照、无身份及原生键包装对象；另验证设备/inode 区分、typed nil
和第 257 个条目为硬链接时的扫描拒绝。身份/扫描回归连续 10 次通过。
Windows 实机和 Linux 原生运行仍待验收，跨编译只验证代码可构建。
下一步补齐可在授权 Windows 测试机运行的离线包验收流程，不修改同步/提交安全边界。
