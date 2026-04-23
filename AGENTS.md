# Agent 工作指南

## Release 流程规范

### 每次打 tag 的必做项

1. **一个 tag 必须对应一篇 release 文档**
   - 文档位置：`docs/releases/v{VERSION}.md`
   - 格式参考：`docs/releases/v0.2.5.md`
   - 内容需包含：一句话总结、新增功能、文档更新、完整变更列表、兼容性说明

2. **CHANGELOG.md 同步更新**
   - 在 `# Changelog` 顶部追加新版本条目
   - 版本号、日期、变更分类（新增/修复/文档）需与 release 文档一致

3. **编译验证**
   - 执行 `go build -o ebpf-tracepoint .` 确保零报错
   - 若修改了 `bpf/*.bpf.c`，必须先执行 `go generate ./...`

4. **Git 操作顺序**
   ```bash
   git add -A
   git commit -m "release: vX.Y.Z — 一句话描述"
   git tag vX.Y.Z
   git push origin main
   git push origin vX.Y.Z
   ```

### 版本号规则

| 场景 | 版本号变化 | 示例 |
|------|-----------|------|
| 重大功能/架构变更 | 升级 minor | `0.2.5 → 0.3.0` |
| 新增功能或扩展 | 升级 minor 或 patch | `0.3.0 → 0.3.1` |
| Bug 修复 | 升级 patch | `0.3.1 → 0.3.2` |

### 测试失败的处理

如果用户反馈某个 tag **测试失败**需要废弃：

- 用户会自行删除远程的 **tag**、**GitHub Release**、**release 文档**
- Agent **不要**主动删除任何已推送的 tag 或 release
- 继续在当前代码上修复问题，然后打**新 tag**（通常是 patch 版本递增）
- 废弃的 tag 号**不再复用**

### 双模式（现代/兼容）注意事项

- 修改 `bpf/trace.bpf.c`（现代模式）后，**必须**同步考虑 `bpf/trace_legacy.bpf.c`（兼容模式）
- 两个模式的 `struct event` 大小必须**完全一致**，否则 Go 端解析会错位
- 现代模式用 `bpf_probe_read_user`，兼容模式用 `bpf_probe_read`
- 现代模式用 `bpf_ringbuf_reserve/submit`，兼容模式用 `bpf_perf_event_output`
- 新增 tracepoint 后，两个 `.go` 文件（`modern.go`、`legacy.go`）都需挂载

### 编译环境

- 修改 C 代码后必须执行 `go generate ./...`（调用 `bpf2go` 重新生成 ELF 对象）
- 需要工具：`clang`、`bpftool`、`bpf2go`（`go install github.com/cilium/ebpf/cmd/bpf2go@latest`）
