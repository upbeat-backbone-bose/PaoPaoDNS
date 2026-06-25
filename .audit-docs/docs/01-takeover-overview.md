# PaoPaoDNS 接手维护总览

> 接手日期：2026-06-25
> 接手人：upbeat-backbone-bose
> 上游原仓库：https://github.com/kkkgo/PaoPaoDNS（已停止维护）
> 本仓库：https://github.com/upbeat-backbone-bose/PaoPaoDNS

## 仓库组成

| 角色 | 路径 | 说明 |
|------|------|------|
| 编排层 | `/` (本仓) | Dockerfile、shell 脚本、yaml/conf 配置、CI |
| 预构建层 | `prebuild-paopaodns/` | Dockerfile + `build.sh`（在 alpine 内编译 unbound 与 mosdns） |
| Go 依赖源（mosdns） | `vendors/mosdns` | kkkgo/mosdns 分支，无 tag，跟随 master |
| C 依赖源（unbound） | `vendors/unbound` | NLnetLabs/unbound，本轮升级钉到 `release-1.25.1` |

> `vendors/` 目录是后续审计和补丁的本地副本，由 CI 在每次构建时重新 `git clone`，本仓用 dependabot 监控 go.mod 变化。

---

## 本轮已完成

### 1. 依赖升级与 CVE 修复（commit: 260625-chore-deps-upgrade）

| 组件 | 升级前 | 升级后 | 说明 |
|------|--------|--------|------|
| unbound | `master`（默认分支，无 pin） | `release-1.25.1` | 修复 CVE-2026-44608（RPZ UAF）、CVE-2025-11411（delegation poisoning）、CVE-2025-5994（Rebirthday Attack）等 |
| mosdns | kkkgo/mosdns master | master（保留） | 上游未发 tag，依赖二进制字符串校验 |
| mosdns Go 依赖 | go 1.26.3 | go 1.26.3（已最新） | `go mod tidy` 无变更 |
| Alpine 基础镜像 | `alpine:edge` | `alpine:3.21` | 通过 `ARG ALPINE_VERSION=3.21` 在 builder/runtime 两处 pin |
| dependabot | 仅 docker | docker + gomod × 2 + github-actions | 监控 mosdns/unbound 的 go.mod 升级 |

### 2. 构建验证

- `vendors/mosdns` 用 Go 1.25.6 本地 `go build` 通过，产物 `/tmp/mosdns-test`（14.8MB），`mosdns version` 输出 `kkkgo/mosdns:240822.1`（与 Dockerfile 字符串校验一致）。
- `build_test.sh` 完整套件需要 docker 运行环境（已确认本机无 docker，未执行），下一轮在 docker 可用环境补跑。

### 3. 代码审计

详见：
- `.audit-docs/docs/audit-orchestration.md` — Dockerfile + 编排 shell 脚本 + DNS 配置
- `.audit-docs/docs/audit-mosdns-unbound.md` — mosdns 与 unbound 源码初步摸底

总计 38 条独立发现，High 17 / Medium 18 / Low 17，P0 8 项 / P1 10 项 / P2 8 项。

---

## 下一轮待办（按优先级）

### P0 — 必须立即修

| # | 主题 | 涉及文件 | 工作量 |
|---|------|----------|--------|
| P0-1 | 容器以 root 运行 unbound/dnscrypt-proxy/mosdns | `Dockerfile`、`src/unbound.conf`（username/chroot）、`src/init.sh`（USER 切换） | 大 |
| P0-2 | `access-control: 0.0.0.0/0 allow` 开放递归 | `src/unbound.conf:301` + `init.sh` 注入 ALLOWED_NET 环境变量 | 中 |
| P0-3 | `chmod -R 777 /data` + `custom_env.ini` 解析导致命令注入 | `src/init.sh:3,25-28` | 中 |
| P0-4 | CI workflow 全部 `@v3/v4/v5` 浮动 tag | `.github/workflows/*.yml` | 小 |
| P0-5 | `prebuild-paopaodns/Dockerfile` 仍用 `alpine:edge` | `prebuild-paopaodns/Dockerfile:1` | 小 |
| P0-6 | docker-compose 用 `:latest` 部署 | `docker-compose.yaml`、`docker-compose-qnap.yaml` | 小 |
| P0-7 | 二进制身份校验仅 grep 字符串 | `Dockerfile:39-41` | 小 |
| P0-8 | 关键上游 `git clone --depth 1` 无 commit pin | `src/build.sh:22-92`、`prebuild-paopaodns/build.sh:29` | 中 |

### P1 — 应尽快修

- mosdns `httpd_server`（7889）无鉴权 + 路径处理 — `vendors/mosdns/plugin/server/httpd_server/`
- mosdns `flushd_server` unix socket 无 chmod — `vendors/mosdns/plugin/server/flushd_server/`
- `SOCKS5` 弱校验 + 命令行拼接 — `src/data_update.sh:52,64`
- unbound `control-enable: yes` + `control-use-cert: "no"` — `src/unbound.conf`
- 运行时下载无签名校验 — `src/data_update.sh`、`src/build.sh`
- 暴露 `7889/tcp`（HTTP_FILE）— `Dockerfile:81` + `src/mosdns.yaml`
- `do-not-query-localhost: no` — `src/unbound.conf:567`
- `harden-dnssec-stripped: no` — `src/unbound.conf:496`
- mosdns 53 端口与 unbound 53 端口冲突 — `src/init.sh:451,468` + `mosdns.yaml:317-326`

### P2 — 加固

- 全部 shell 脚本加 `set -euo pipefail`
- `init.sh` 日志泄露 SOCKS5/PLATFORM → debug 模式才打印
- Dockerfile 加 `HEALTHCHECK`、SBOM、provenance
- `apk add` 显式 pin 版本
- 解析 `/etc/resolv.conf` 用覆盖而非追加

### 需做但不在本轮范围

- **完整深度审计 mosdns httpd_server/flushd_server**（本轮只做风险点定位）：这两个 fork 模块无上游对等，是真正的攻击面，需在 P0-1 实施前完成代码 review
- **完整深度审计 unbound 1.25.1 的 50 commit 后置修复**：vendor 用 1.25.1 是相对保守选择，但 1.25.1 之后还有大量 malloc-failure 修复在 master 上，建议评估定期 bump
- **`:latest` 升级为版本 tag + 签发 cosign**：需先在 docker-compose 中定版本策略

---

## 下一步建议

1. 先做 P0-3（`chmod 777` + `custom_env.ini` 命令注入）—— 改动小、收效大、零依赖。
2. 然后 P0-4（CI pin SHA）+ P0-5（alpine pin）—— 几乎纯文本替换。
3. P0-1（root→unbound 用户）影响面大，需要先确认 `unbound.conf` 的 chroot 与 socket 路径在容器内是否可写，建议在专门分支做。
4. P0-2（开放递归 → 白名单）影响默认行为（README 写的"一键部署"），需在 README 中说明新默认。
5. 其余 P0/P1 在 P0-1 之后顺次做；P2 按需排期。

每一项 P0 完成后，跑一次 `build_test.sh`（需 docker）验证。

---

## 参考资料

- upstream kkkgo/PaoPaoDNS（不维护）：https://github.com/kkkgo/PaoPaoDNS
- upstream kkkgo/mosdns：https://github.com/kkkgo/mosdns
- upstream NLnetLabs/unbound：https://github.com/NLnetLabs/unbound
- unbound 1.25.1 release notes：https://github.com/NLnetLabs/unbound/releases/tag/release-1.25.1
- DNSCrypt 项目：https://github.com/DNSCrypt/dnscrypt-proxy
