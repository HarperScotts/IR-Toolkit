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

### 3.1 快照所有权与调用方隔离

`central.New` 和 `Repository.IngestBatch` 接收的是已经准备完毕的快照，
不是任意正在变化的 Store。源 Store 的所有者必须在发布前完成加载、停止写入，
并在已发布 view 的整个生命周期内保证源数据不变、支持并发读取。
之前从源 Store 取得的切片、map 或指针也不能在发布后修改。
Repository 保证 view 的原子发布与不替换，不会自动复制底层存储或冻结实时 Store。

Central 对全部 `store.CaseStore` 方法实施防御性深拷贝：返回的切片、map、
嵌套对象和指针归调用方所有，修改它们不会污染后续查询、Catalog 或其它调用方。
输入中的 map/指针也会复制后再传给源 Store。错误对象、found、nil/空集合、
时间值、字段类型和 Evidence ID 保持原语义；这不改变查询、排序或 Analyzer 规则。
此保证以源快照满足上述不变与并发读取前提为基础，不保护调用方自己共享的返回对象。

`snapshot_methods.go` 从 Store 接口生成，不再通过嵌入接口漏出未经隔离的新方法。
`scripts/check.sh` 校验生成代码一致性；新增 Store 字段/方法时，contract-wide
测试检查所有输入与非 error 输出的可拷贝性和修改隔离。当前支持纯数据类型，
私有字段（除不可变 `time.Time`）、递归引用或其它可变运行时类型需要单独设计。
回归同时覆盖发布后并发修改各自返回值、finding 嵌套指针、Search map、
原始详情的嵌套字段以及错误身份不变。

`central-web` 先预加载 Local 所有领域的 `sync.Once` 数据再发布，不再访问变化中的
领域文件；它仍要求输入目录来自完整、已提交的 case。预加载不是文件系统事务，
发布期间并发重写 case 目录可能形成混合版本，因此不得在同一目录同时重新分析。
第 16 节的文件快照模式提供自有内容副本、完整性校验与批次原子可见；
更强的断电耐久性和数据库提交事务仍需另外实现。

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

Central 前端通过 `GET /api/multi-host/views` 获取已提交 views。独立 Multi-host Investigation 面板允许选择 host/version，执行 Search 和 Timeline 分页，并在每项结果及详情中展示来源。其它页面继续展示 primary host。面板不把跨主机结果跳转到单机详情路由，避免相同 PID 或 ID 导航到错误主机。

前端交互回归可运行 `node --test internal/web/frontend_tests/multi-host.test.cjs`，覆盖来源详情、翻页、输入时取消旧请求和空选择。零时间显示为 `Time unknown`。

面板支持 Search 类型筛选及 Timeline 的 category、用户、PID、IP、本地时间范围和排序条件。本地时间在提交时转换为 UTC；PID 与时间范围在提交前校验。分类计数、类型计数和各主机摘要直接来自 API；Timeline 分类计数继续遵循“不应用 Category、在 pagination 前统计”的语义。点击分类计数会重新提交该分类并从第一页查询。重置筛选保留当前 host/version 选择。

点击多主机结果通过 `POST /api/multi-host/evidence/detail` 加载原始证据，request 为 `{ "view": { "case_id": "...", "host_id": "...", "version": "..." }, "type": "process", "id": "process:42" }`。Store 的 `ScopedEvidenceStore` 精确选择已提交 view 后执行对应领域 lookup；不存在返回 404、格式或类型错误返回 400、读取失败返回 500。response 保留 view、type、id 和 evidence。Network/Persistence 在 Web 使用现有 DTO 转换，其它领域使用已有带 JSON tag 的领域模型/Store record。

支持 process、login、network、file、persistence、historical_process、powershell、windows_event、ioc、timeline、correlation_node 和 correlation_edge 的 Search ID。原单机 finding 详情入口保持不变。新的查询及 host 选择变化会取消旧详情请求，防止返回较晚的证据覆盖当前来源。

成功查询后，面板将精确 views、查询模式、筛选和 Timeline offset 保存到 URL 的 `multi_host` 参数，并提供复制链接按钮与可手动复制的只读链接框。刷新时会对照当前 catalog 核验每个 host/version，缺失版本或无效链接不自动查询。时间范围以 UTC 保存，恢复时转换为本地时间；链接不保存结果正文。筛选发生变化时旧查询链接立即失效，新的成功查询会生成新链接。该参数与既有单机 hash 导航共存。

详情面板分别展示 Source 和 Evidence fields，嵌套对象/列表按字段展开，空值、布尔值和数字保留原语义。原始 response JSON 保存在默认折叠的 Raw JSON 区域。所有证据内容通过文本节点呈现。详情加载期间或失败时显示带来源的 Result preview，避免将搜索摘要误当成完整原始证据。

成功加载详情后，调查链接追加所选证据的 view、type 和原 ID。重新打开先恢复查询，再通过精确详情 API 加载该证据，不依赖其是否出现在结果页中。详情的 view 必须属于链接所选 views；无效类型或不匹配来源会在请求前拒绝。失败或已取消的详情请求不会写入链接，旧版仅含查询的链接仍可恢复。

`internal/store/central/evidence_fixture_test.go` 使用两个 host 的原始 snake_case JSON 验证全部 12 类详情与 Search ID 的兼容性、同 ID 来源隔离、记录未命中及文件读取/解码错误。fixture 同时锁住 Network canonical ID、IOC index ID、HistoricalProcess 字段、Analyzer External membership、明确 correlation basis、精确路径和经 CurrentProcess 确认的 PowerShell 关联。

需要手工浏览器检查时，运行 `IR_TOOLKIT_BROWSER_TEST_ADDR=127.0.0.1:18087 go test ./internal/cli -run '^TestCentralBrowserFixture$' -v -timeout 12m`。测试临时生成两个主机、重复 PID/ID 和 104 条 Timeline 事件，服务在十分钟后自动关闭；临时证据由测试框架清理。

实际 Chrome 交互验收记录及尚未完成的 Windows 运行检查见 [运行验收记录](runtime-acceptance.md)。交叉编译、自动化测试和目标系统实机验收分别记录，不互相替代。

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

按 case 目录启动仍是本地目录组装，不是 Agent 上传协议；独立于原目录的恢复使用下面的显式仓库模式。

## 16. 文件快照持久化与重启恢复

首版实现位于 `internal/store/archive`，只负责完整 case 目录的内容副本、批次提交和校验。
它不导入 Web、Local 或 Analyzer；CLI 注入已有 Local 加载与完整领域预加载函数。
查询仍复用 Local → Central 的现有实现，不迁移查询规则或引入数据库。

写入与只读服务分开：

```text
ir central-import --repository <archive-dir> --case-id <investigation-id> <case-a> [case-b...]
ir central-web --repository <archive-dir> --case-id <investigation-id>
```

写入流程：

1. 检查源 case 身份及完整领域，要求源目录已提交且停止写入。
2. 用独占创建的 `.ingest.lock` 串行化合作写入者，读取已有提交并拒绝重复 view。
3. 在仓库内创建唯一 `.stage-*` 目录，流式复制全部 regular file，保留原始字节及顺序。
4. 对副本再次核验身份、加载完整 Store；记录所有内容文件的 SHA-256 和 view/原 case 名称。
5. Sync 内容文件与 commit 文件，最后同文件系统 rename 为唯一 `batch-*` 目录。
6. 正常退出释放锁；失败只清理当前调用自己新建的暂存目录，不删除旧批次或别人的暂存目录。

一次导入的多个 view 位于一个批次目录，目录 rename 是可见性提交点。
读者不观察暂存目录；旧读者不热更新，新启动的服务读取新提交。重复版本不覆盖，
也没有自动删除、保留策略或远程上传。

恢复时，先严格检查 commit 格式版本、目录索引、全量文件 inventory 和哈希，再加载 Store。
坏 JSON、缺失文件、额外文件、内容变化、错误身份或重复 view 会让整个恢复失败，
不会静默返回其它有效 view。未提交的 `.stage-*` 被忽略。源目录删除或改写不影响副本。
IOC index ID、Network canonical ID 和其它原 ID 不改写；原 case 名称单独保存，
避免归档路径编号改变单机 CaseName。

`central-web --repository` 不创建/写入仓库，只显示 `--case-id` 指定调查的 views，
不与位置参数组合；未找到该调查会报错。primary host 按 HostID、Version 字典序选择，
其它调查不进入该服务 catalog。整个仓库仍需先通过完整校验，因此其它调查损坏也会阻止恢复。
原来按位置参数组装 case 的命令不变，primary 仍为第一个输入目录。

### 限制与恢复边界

- 这是可信本地文件仓库，不是面向恶意上传包的安全解包器；源和仓库都不能被并发改写。
  拒绝符号链接与特殊文件；不能把仓库放进源 case，文件系统路径及权限需由操作者管理。
- 保存的是文件内容，不保留原文件系统的 ACL、时间戳、稀疏布局或其它元数据；
  取证字段仍来自原 JSON。源 case 不被改写；需要完整文件系统保全时应另外保存原始证据。
- SHA-256 用于检测副本意外损坏，不是签名、真实性证明、加密或访问控制。
  新目录/文件请求 0700/0600；Windows 权限需用主机 ACL 单独限制。
- 同文件系统 rename 保证正常运行下原子可见；没有承诺所有系统的断电耐久性，
  未实现父目录持久化屏障、故障注入后的断电恢复或 Windows 实机验收。
- 进程被强制终止可能留下锁和暂存目录。读操作仍可读取完整提交（可能含已经 rename 的新批次）；写操作明确报锁冲突。
  必须由操作者确认没有活跃写入者、检查日志和提交结果后，单独授权恢复锁。
  工具不会自动认定锁“过期”、接管或删除数据。
- 提交后锁释放失败可能报错但批次已经存在；先重新加载核实，不要盲目重试覆盖。
- 首版每次启动/导入会校验已有批次，成本随证据量增长；没有实时刷新、索引数据库或迁移工具。

回归覆盖双主机重启与原目录独立、12 类原 ID 的 Search → 精确详情一致性、
查询结果等价、全批次失败不发布、重复拒绝、损坏拒绝、未完成暂存忽略、
已有 writer lock 保留、符号链接拒绝及调查作用域隔离。

真实 Chrome 已完成归档模式的正常跨进程链接恢复验收，见
[运行验收记录](runtime-acceptance.md#2026-10-10归档模式跨进程恢复)。
准备 fixture 可使用 opt-in `TestPrepareArchivedBrowserFixture`；
正常退出会清理源 case，留下专用目标目录的归档副本用于重启测试。

## 17. 异常中断与锁恢复

`internal/store/archive/crash_test.go` 启动真实测试子进程，通过 pipe 在明确存储边界
同步等待，父进程检查读写行为后执行 `Process.Kill` 并 `Wait` 确认终止。
终止绕过正常 Go defer，确实留下原 writer lock，而不是手工伪造中断后的文件。
private checkpoint 仅用于测试；公开 Commit 不安装 hook，也没有环境变量触发的生产故障开关。

| 终止位置 | 恢复时可见 view | 遗留内容 | 确认 writer 死亡后的显式恢复 |
| --- | --- | --- | --- |
| 首个 case 副本完成、第二个尚未复制 | 仅原有 view | lock + 部分 stage，无 commit.json | 校验旧提交、解除锁后重试，新批次完整发布；旧 stage 保留 |
| 全批次内容和 commit.json 已写、rename 前 | 仅原有 view | lock + 完整但未提交 stage | 仍不能把 stage 当提交；解除锁后重新导入，旧 stage 保留 |
| rename 后、正常释放 lock 前 | 原有 view + 完整新批次 | lock，无该批次 stage | 校验新提交；解除锁后同版本重试报 duplicate，不覆盖 |

回归同时检查活跃 writer 与遗留 lock 都阻止写入、读者不暴露半批次、
阻塞写入不修改或替换原锁、正常恢复后自己的新锁释放、旧 stage 不被新写入者清理。
它是 macOS 上的进程强制终止测试，不是断电、存储硬件故障或 Windows 实机测试。
未覆盖文件流复制到一半时的强制终止，不因此扩大断电耐久性承诺。

### 操作者恢复流程

本版不提供自动或在线接管锁命令。以下是需要操作者协调和显式授权的维护流程，
不是工具可以凭锁的存在或时间戳自行执行的操作：

1. 停止并禁用所有可能访问该仓库的导入者，建立独占维护窗口。
   确认原 writer 已退出；锁文件自身没有可靠 PID/身份元数据，不能单凭“很旧”判断它已失效。
2. 保留错误日志、仓库内容与锁/暂存状态的记录。不要删除、改写或 rename `batch-*`。
3. 在仓库保持不变时执行只读恢复/校验，核实目标 case/host/version 是否已经完整提交。
   可使用 `central-web --repository <dir> --case-id <id>` 检查 catalog 与详情；
   如果完整性校验失败，停止恢复写入，先处理证据副本/故障，不解除锁后继续尝试导入。
4. 确认无活跃 writer、校验通过并取得恢复授权后，仅把精确的 `.ingest.lock`
   移到仓库外的独立恢复记录目录，保留其内容与操作记录。不要执行目录级清空；
   不在仓库根目录添加任意备份文件，否则严格目录校验会拒绝它。
5. 若目标 view 已存在，视为该批次已提交，不重试覆盖。若尚未提交，从完整、停止写入的源 case
   重新执行导入；不要手工把 `.stage-*` 改名为 `batch-*`。
6. 再次校验提交结果，再恢复其它导入者。遗留 stage 的保留/清理另行授权，本流程不删除它们。

测试中的锁删除只发生在 `t.TempDir`，且由父进程确认自己的 writer 已死亡后执行。
没有对真实仓库执行锁恢复或清理。

## 18. 离线交付与未来传输

格式及边界见 [离线交付包与导入校验契约](offline-package-contract.md)。
已实现 case-pack、只读 case-verify、受限临时解包与显式 central-import-package；
包导入先核验实际字节/manifest 引用/源身份及全部领域，再复用现有 archive.Commit。
archive.Source 可选 Name 仅保留展示名称；为空仍用目录 basename，不改变 commit.json schema。
现有 central-import 仍然仅处理可信本地 case 目录，不是未经验证远程包的入口。
包导出/导入强制终止与显式恢复回归已在 macOS 合成数据上通过；
合成预算边界的资源测量见 [资源记录](package-resource-profile.md)；
Windows ACL、真实 case 的 RSS/实际磁盘分配及断电恢复仍未验收。该契约不改变 Store/Web schema、
既有 view 身份与 Evidence ID，也不提供 Agent 身份认证或远程接收端口。
