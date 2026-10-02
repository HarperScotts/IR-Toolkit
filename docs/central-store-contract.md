# Central Store contract 与 conformance 设计

状态：12C 设计基线；阶段 13 已加入版本绑定的 CentralCaseStore；阶段 14 已加入进程内原子 Ingest Repository；阶段 15 已加入多主机调查搜索与 Timeline。本文不设计 Agent 传输协议或持久化数据库。

## 1. 设计结论

`store.CaseStore` 保持现状，不增加远程 Agent、数据库或多主机参数。它表示一个已经选定的、只读的单 case/host 调查视图。

未来 Central 层负责：

1. 根据稳定的 case/host 标识选择一个已提交的调查视图。
2. 返回实现现有 `store.CaseStore` 的 `CentralCaseStore`。
3. 用独立的上层契约承载跨 case/host 检索，不把跨主机语义塞进现有 PID、Logon ID 或 Evidence ID 查询。

因此 Web Handler 仍只依赖 `store.CaseStore`。Web 不同步访问 Agent，不判断 External，不生成关联，也不推断历史进程关系。

## 2. 作用域与标识

现有 Store 方法中的 PID、Logon ID 和 Evidence ID 都只在当前 case/host 视图内解释。

Central 持久化层必须用类似以下逻辑键隔离数据：

```text
(case_id, host_id, evidence_id)
```

这个复合键属于 Central 内部。返回给现有 Web/API 的 Evidence ID 不加 Central 前缀，以免改变当前 API schema 和既有深链接。

Network canonical ID 必须继续使用：

```text
network:%d:%s:%s:%d:%s:%d:%s
```

IOC synthetic ID 必须继续使用：

```text
ioc-match:<index>
```

Central Ingest 必须保留源数据中的稳定顺序，才能保持基于 index 的 IOC ID。若未来需要跨版本稳定 IOC ID，应另行版本化迁移，不能在 CentralCaseStore 中静默改变格式。

## 3. 一致性模型

一个 `store.CaseStore` 实例绑定到一个完整、已提交的分析版本：

- 同一个实例不能混合 ingest 前后的数据。
- 未完成的 ingest 对查询不可见。
- Analyzer 输出及其引用的原始证据应原子发布为同一版本。
- 新 ingest 完成后，通过创建新视图看到新版本；现有视图可以继续读取旧版本。

这与 LocalCaseStore 的 `sync.Once` 快照行为一致，也避免一次 Web 调查请求看到部分更新的数据。

## 4. 只读契约

`store.CaseStore` 只提供读取、过滤、排序、分页和明确证据关联。写入、ingest、删除、重分析和保留策略都不属于该接口。

CentralCaseStore 不得：

- 查询或控制远程 Agent；
- 杀进程、删除文件、修改注册表或开启审计；
- 根据日志、AV 或审计缺失推断入侵；
- 根据 IP 类型重新计算 `External`；
- 根据 PID 相同推断历史进程；
- 使用路径包含、命令相似度或其它模糊规则建立关系；
- 在读取时重新执行 Analyzer 逻辑。

## 5. 返回值与错误语义

所有实现必须遵循以下公共行为：

- `XByID`、`XByPath` 等单项查询未命中时返回零值、`false`、`nil`。
- 集合查询无结果时返回空集合语义，不把“无结果”当成错误。
- 存储读取、解码或查询失败必须返回错误，不能伪装成“未命中”。
- `SecurityProviders` 和 `Report` 通过 `found bool` 区分可选数据不存在。
- File 与 Persistence 的 Analyzer finding 文件可不存在；原始证据仍可调查。
- Local 当前的 Global Search 会把某个已选择 domain 的加载失败表现为该 domain 零结果。Central v1 为兼容现有行为应保持一致；若要改成部分失败信息，需要单独修改 contract 和 API，不能由某个后端自行改变。

Central 错误可以包装底层错误，但不能要求 Web 识别数据库专用错误类型。

## 6. Query 行为不变量

分页统一遵循：

- 负 `Offset` 归零；超过 `Total` 时钳制到 `Total`。
- `Limit <= 0` 使用 100。
- `Limit > 500` 使用 500。
- `Total` 在 pagination 前计算。
- `HasMore` 表示当前页之后仍有匹配项。

领域行为：

| 查询 | 必须保持的行为 |
| --- | --- |
| Files | `ModifiedAt DESC`，zero time 最后；finding 仅精确路径关联 |
| Persistence | 有 finding 的项优先；组内 `Timestamp DESC`，zero time 最后 |
| Timeline | 默认时间升序，仅 `Order == "desc"` 时降序；zero time 最后 |
| Timeline counts | 应用除 Category 外的其它 filter，在 pagination 前统计 |
| Processes | PID 升序 |
| Logins | Timestamp 降序 |
| Network | `External` 只读取 Analyzer membership；canonical ID 不变 |
| Search | 全局 `Timestamp DESC`，zero time 最后；`Total`、`ByType` 在 Limit 前统计 |

过滤保持当前大小写和 substring 语义。Central v1 不借数据库 collation 改变匹配结果。

## 7. 关系行为不变量

- Historical Process 的 current PID 索引只包含 `CurrentProcess == true` 的 Analyzer 结果。
- Current Process 到 PowerShell 的路径必须是：Current Process -> Analyzer-confirmed Historical Process -> `RelatedHistoricalProcessID`。
- File 与 Persistence 只允许明确、精确关系。
- Correlation node、edge、chain 直接读取 Analyzer 输出；Store 不生成新关系。
- `model.CorrelationEvidence`、`store.CorrelationEvidenceRecord` 和 Web DTO 保持三个独立层次。

## 8. Conformance suite 结构

公共 conformance suite 应只通过 `store.CaseStore` 调用后端，不访问 Local helper、SQL 表或 Web DTO。

推荐测试入口：

```go
type Factory func(t *testing.T, fixture Fixture) store.CaseStore

func RunCaseStoreConformance(t *testing.T, factory Factory)
```

每个后端只负责把同一个逻辑 `Fixture` 装载进自己的存储：

- Local adapter 写入 `t.TempDir()` JSON；
- Central adapter 写入隔离的临时数据库或事务；
- suite 负责所有公共断言。

Fixture 表示“采集证据 + 已确认 Analyzer 输出”，不在测试装载器中运行 Analyzer，也不从数据内容推断关系。

### 必须覆盖的 conformance 分组

1. Contract：实现完整 `store.CaseStore`。
2. Lookup：命中、未命中和空 key 行为。
3. Query：所有 filter、排序、分页、Total 和 HasMore。
4. Timeline：CategoryCounts 的 filter 与 pagination 顺序。
5. Identity：Network canonical ID、connection identity、IOC synthetic ID。
6. Relationship：Historical `CurrentProcess`、PowerShell 链、精确 File/Persistence 关联。
7. Search：type filter、全局排序、zero time、Total 和 ByType。
8. Optional data：可选 Analyzer/metadata 缺失行为。
9. Isolation：两个 case/host 使用相同 PID 和 Evidence ID 时互不泄漏。
10. Snapshot：未提交 ingest 不可见，同一视图不混合版本。

12A/12B 中已有的 Local fixture 是首批行为基线。建立公共 suite 时应迁移这些断言，而不是复制出一套 Central 专用预期。

## 9. CentralCaseStore 首个实现的最小边界

进入阶段 13 时，首个实现应：

1. 接受已解析的内部 case/host/view 标识，而不是文件路径。
2. 在构造时绑定一个已提交版本。
3. 实现现有 `store.CaseStore`，先达到公共 conformance suite 全绿。
4. 保持 Store-neutral Record 和 `model` 返回类型，不返回数据库 row 或 Web DTO。
5. 不同时实现 ingest、多主机聚合或 Web 路由重构。

Web 的后端选择应发生在 server 组装层，通过注入 `store.CaseStore` 完成；Handler 本身不感知 Local 或 Central。

## 10. 12C 完成条件

- `store.CaseStore` 的单 case/host 作用域已明确。
- identity、错误、排序、分页、关系和一致性语义已记录。
- 公共 conformance fixture/factory 方案已定义。
- Central v1 的最小实现边界已定义。
- 未引入 Central 数据库、ingest、多主机查询或 Web 业务逻辑。

## 11. 阶段 13 首个实现

`internal/store/central` 当前提供：

- `View`：精确标识 case、host 和已提交 version；
- `CaseStore`：把一个完整的只读 `store.CaseStore` 快照绑定到 `View`；
- `Catalog`：只读地按完整 `View` 选择版本，拒绝 nil 和重复视图。

底层快照接口在 Central 包外不可替换，因此构造后的视图不会被切换到其它版本。Local fixture 的同一组行为断言会同时运行在 Local Store 和 Central 绑定视图上。

该实现有意不决定持久化后端。当前快照由构造方提供；阶段 14 的 ingest 边界负责生成并原子发布快照，不能把写入逻辑加入 `central.CaseStore`。

## 12. 阶段 14 原子 Ingest 边界

`central.Repository` 接收一个或多个 `IngestRequest`。每个 request 包含完整 `View` 和一个已经完成的只读 `store.CaseStore` 快照。

当前保证：

- 单条和批量发布都先完整校验，再对读者可见；
- 批次任一 request 无效时不发布任何 view；
- 已发布的 case/host/version 永不原地替换，新分析使用新 version；
- `Open`、`Len`、Ingest 可并发调用；
- `Catalog()` 返回调用时刻的不可变视图，不观察后续 ingest；
- 通过 Repository 发布的 Central view 继续运行与 Local 相同的行为 fixture。

当前 Ingest 是进程内发布边界，不负责从 Agent 接收字节、不复制远程文件、不运行 Analyzer，也不提供重启后的持久化。后续传输或数据库实现必须在生成完整快照后调用同一原子发布语义，不能让未完成数据提前出现在 `Open` 中。

## 13. 阶段 15 多主机调查搜索

`central.Investigator` 在 Repository 中的多个已提交 host view 上执行 Global Search。调用方必须显式提供完整 `View` 列表，不使用隐式 latest，从而保证查询可复现。

当前保证：

- 一次多主机查询只能属于同一个 case；
- view 无效、重复、未发布或任一后端失败时返回错误，不泄露部分结果；
- `Total`、`ByType` 在全局 Limit 前聚合；
- 结果按 Timestamp 全局降序排列，zero timestamp 最后；
- Limit 继续使用默认 100、最大 500 的既有语义；
- 每项结果在外层携带 case/host/version，内部 Evidence ID 保持原值；
- 提供按 view 的 Total 和 ByType 摘要，便于调查者理解证据来源。

即使两个 host 都存在 `process:42`，Store 也不会修改其单机 Evidence ID，更不会因为 PID 或 ID 相同建立跨主机关联。跨主机关联仍必须来自明确证据或 Analyzer 已确认结果。

该能力由 Store 层只读 API 实现。Web Handler 只能调用该 API 和转换 DTO，不能自行聚合、排序或生成关系。

### 多主机 Timeline

`central.Investigator.QueryTimeline` 在相同的显式 host views 上聚合现有 `store.QueryTimeline`：

- Timeline filter 和 `Order` 继续由每个 `CaseStore` 按现有契约执行；
- `Total` 与 CategoryCounts 在全局 pagination 前按 host 汇总；
- 事件按 Timestamp 全局排序，升序或降序都保持 zero time 最后；
- 全局 Offset、Limit 和 HasMore 基于合并后的事件计算；
- 单 host 查询以最多 500 条的页面分批读取，因此较大的全局 Offset 不会截断在第一批；
- 每个事件外层携带 `View`，内部 Timeline Event ID 不改写；
- 任一 view 缺失或查询失败时不返回部分 Timeline。

该聚合只合并已存在的 Timeline 证据，不根据跨主机时间接近、相同 PID、用户名或对象值推断关系。

## 14. 多主机 Web API 边界

多主机 Store 被显式注入 `web.Options.MultiHostStore` 时，Web 注册：

- `POST /api/multi-host/search`
- `POST /api/multi-host/timeline`

未注入时不注册这些路由，因此现有本地 CLI 和所有单机 API 保持原样。

多主机 DTO 与接口定义在 `internal/store/multihost.go`。Web 只负责：

1. 限制并解析 JSON request；
2. 校验 HTTP 层字段格式；
3. 调用 `store.MultiHostInvestigationStore`；
4. 将 Store DTO 转为带 View 来源的 Web DTO；
5. 输出 JSON 和适当的 400、404、500 状态。

聚合、全局排序、pagination、CategoryCounts 和关系规则仍完全属于 Store。Web 不依赖 `internal/store/central`，也不访问远程 Agent。

## 15. Central Web 组装

本地已有多个完整、已分析 case 目录时，可以启动只读多主机调查服务：

```text
ir central-web --case-id <investigation-id> <case-dir> [case-dir...]
```

`--case-id` 是由调查者明确提供的跨主机调查分组。每个 view 的 HostID 来自 `host/host.json` 的 hostname（仅在其为空时回退到 manifest hostname），Version 来自该目录 manifest 的 case ID。工具不会根据路径、IP、用户名或相似内容推断主机身份。

启动过程：

1. 读取每个目录的 manifest 和 host evidence；
2. 预加载全部 Store domain，使 Local `sync.Once` 缓存绑定到启动时证据；
3. 用单次 `IngestBatch` 原子发布全部 views；
4. 用第一个 view 提供既有单机页面；
5. 将 Central Investigator 注入多主机 Search/Timeline 路由。

缺失必需 domain、空 hostname/version 或重复 case/host/version 会阻止服务启动。原 `ir web <case-dir>` 行为不变。

该命令仍是本地目录组装，不是 Agent 上传协议，也不提供重启后独立于这些目录的 Central 持久化。
