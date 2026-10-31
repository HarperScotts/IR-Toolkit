# CI 与发布草稿自动化

更新：2026-11-01。此流程用于开发检查与分发构建，不证明真实主机兼容性、分析正确性或 logind
实机验收。已发布 `V0.3.0` 及其附件保持不变，不向历史标签回填不同源码的构建产物。

## 日常检查

`.github/workflows/ci.yml` 替代原 Deno 工作流，在 main push、pull request 或手动调度时运行：

- 从 go.mod 选择 Go 工具链，Node 24 运行现有无第三方依赖的前端测试。
- 复用 `sh scripts/check.sh`：格式/架构边界/生成校验、vet、Go、离线包、脚本、前端及四平台交叉编译。
- 对 Analyzer、Linux collector、Store、CLI、Web 执行 race 回归。

默认 `contents: read`，不使用 pull_request_target，不从 PR 创建 Release。Actions 固定到官方
仓库的完整提交 SHA；checkout 不保留 Git 凭据。ripgrep 缺失时仅在临时 CI runner 安装，
不属于目标取证主机上的依赖安装。

## 新版本发布顺序

1. 更新 `internal/buildinfo/version.go`、相应版本回归及 CHANGELOG 的对应版本节；检查能力边界。
2. 提交并推送，通过日常检查，再为该提交创建严格的 `Vx.y.z` 标签（例如未来的 `V0.3.1`）。
3. 新标签触发 `.github/workflows/release.yml`，也可在默认 main 分支手动指定已有的新标签。
   标签必须精确对应应用版本和当前构建源码提交。旧标签没有新的构建脚本，不支持回填。
4. 构建 job 只读，重跑完整检查并构建四平台；将唯一固定清单上传为短期 Actions artifact。
5. 独立 draft job 下载同一工作流 artifact，复核 SHA-256、固定清单、版本、标签与来源提交，
   然后用最小 `contents: write` 创建 **draft** 并上传附件。仅该步骤显式获得 GH_TOKEN。
6. 维护者检查下载、附件、说明、实际验收状态后，在 GitHub Releases 人工公开发布。

不自动修改标签、不创建不存在的标签、不自动公开、不覆盖已有 Release（包括已有草稿），
也不更新任何旧附件。并发按标签串行，不取消正在进行的发布；草稿上传中断可能留下部分草稿，
失败时应人工查看材料并确认后处置，不用 --clobber 或自动删除来掩盖失败。

手动调度依赖 workflow_dispatch；工作流需要先位于默认分支。见
[GitHub 手动运行说明](https://docs.github.com/en/actions/how-tos/manage-workflow-runs/manually-run-a-workflow)。
权限分层遵循 [GITHUB_TOKEN 最小权限](https://docs.github.com/en/actions/tutorials/authenticate-with-github_token)。
第三方/官方 Action 固定 SHA 也不等于能抵御被攻陷的 runner 或被授权发布者提交的恶意源码。

## 本地构建与产物

必须使用新的、干净的隔离 checkout，精确检出待发布标签。不得混入未跟踪或被忽略的文件，
避免 Go embed 将本地日志等意外纳入二进制；不要通过清空现有工作目录来凑出干净状态。

```sh
task_release_parent=$(mktemp -d /tmp/ir-release.XXXXXX)
# 在干净、精确检出新标签的仓库根目录执行；父目录已经存在，assets 必须不存在。
go run scripts/build-release.go --tag V0.3.1 --output "$task_release_parent/assets"
go run scripts/build-release.go --verify --tag V0.3.1 --output "$task_release_parent/assets"
```

示例版本只用于说明，必须与该 checkout 的版本实际一致。脚本不访问 GitHub、不上传；
输出必须在源码目录之外且为新目录。构建前后检查源码状态和提交，拒绝脏/忽略文件及标签不匹配。
失败可能留下部分输出，应保留并另选新目录，不覆盖或把半成品当成完整包。

固定清单：

- `ir-windows-amd64.exe`、`ir-windows-arm64.exe`
- `ir-toolkit-<version>-linux-amd64.tar.gz`、`ir-toolkit-<version>-linux-arm64.tar.gz`
- `BUILDINFO.json`：源码提交、版本、标签、Go 工具链、构建标志和 `real_host_acceptance: not_attested`
- `RELEASE_NOTES.md`：从对应 CHANGELOG 节生成，附来源与验收边界
- `SHA256SUMS.txt`：其余六份附件的摘要，拒绝额外/重复/缺失条目和文件

四平台使用 CGO_ENABLED=0、-trimpath、-buildvcs=false，避免含混的工作区 VCS 元数据，
来源提交明确记录在 BUILDINFO 中。Linux tar 内含可执行 `ir`、许可证、简明说明、Linux 文档与
只读验收脚本，固定排序/时间/所有者字段，恢复可执行权限，不复制 case、node_modules 或私有材料。
摘要清单只证明一致性，不证明来源真实；产物没有额外代码签名或供应链证明。

## 验证界限

新增回归涵盖：标签/版本/工作区守卫、固定清单/摘要/额外文件、归档路径和权限、不覆盖，
YAML 解析、SHA 固定、默认只读和草稿约束。统一检查包含这些回归。
独立临时 Git 源码快照可用于真实四平台构建验证，但其测试标签/提交不是正式发布来源，
不能把这种产物上传到现有正式标签。云端运行、草稿创建、公开发布和实机验收分别记录，
不能用本地脚本测试代替 GitHub 运行或真实 logind 验收。
