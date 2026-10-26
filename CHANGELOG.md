# Changelog

## 0.3.0 — 2026-10-26

本版本汇总当前开发阶段的代码、文档和自动化回归，不表示所有平台实机验收完成。
承接已有远端标签 `V0.2.0-13`，本次版本点为 `V0.3.0`。

- Linux：主机/进程基础快照、TCP/UDP 网络采集、systemd/cron 原始候选及有限配置解析。
- Linux 登录：有限 SSH 认证报告采集/解析、独立调查页和查询时间窗口；login1 只读原始观察、
  可空属性分析、独立 Store/API/页面及 `diagnose-login1` 兼容性诊断与私有报告捕获流程。
- 加强 Store/Central 查询契约、防御复制、错误传播和保守进程关联回归。
- 补充离线包、Central 归档相关实现、资源测量/验收工具和契约文档。
- 统一应用版本来源，支持 `ir --version`，并同步 `ir info` 和新采集清单的 tool_version。
- 更新已跟踪的 Windows amd64/arm64 可执行文件，摘要见 `SHA256SUMS-windows.txt`；
  两者为交叉编译产物，不表示 Windows 实机验收完成。

已知限制：真实 logind 的发行版/权限/会话覆盖和人工验收仍未完成；隔离合成服务测试不代替
实机验收。utmp/wtmp/btmp 仍保留原始字节，不解码为会话；Linux 文件调查、原生 audit/journal
历史以及完整登录会话支持仍有缺口。详见 `docs/linux-support.md` 和 `docs/runtime-acceptance.md`。

已有 case 的 manifest 和证据版本不会被本次版本更新改写。
