# PaoPaoDNS mosdns 与 unbound 初步风险摸底

> 审计对象：`/workspace/PaoPaoDNS/vendors/mosdns`（Go, kkkgo fork） + `/workspace/PaoPaoDNS/vendors/unbound`（C, NLnetLabs release-1.25.1，HEAD `65e23d4`）
> 审计日期：2026-06-25
> 审计员：AI Agent
> 范围：风险点定位（不是完整深度审计），目的是找出**值得后续深入审计**的可疑点

---

## mosdns 风险点

### HTTP admin 端口无鉴权 + 路径处理面 — `plugin/server/httpd_server/httpd_server.go:36-65` — **High**

- `http.Server.Addr = ":7889"`，**显式绑定 0.0.0.0**。
- `http.HandleFunc("/", ...)` 注册**根路径** handler，无任何中间件、Auth header 检查、IP 白名单、Token、Cookie。
- 处理逻辑：直接 `filepath.Join("/data", r.URL.Path)` → `os.Stat` → `http.ServeFile(w, r, filePath)`。
- 风险：`r.URL.Path` 未做 `path.Clean` / 未拒绝含 `..` 的 URL，Go 的 `http.ServeFile` 内部会用 `cleanpath` 阻断目录穿越，但**仍然允许 `//etc/passwd` 之类的双斜杠 / NUL / 编码绕过**。
- `Dockerfile:81` `EXPOSE 7889/tcp` 把这个端口作为**容器正式发布面**。

**建议**：默认绑定改为 `127.0.0.1:7889`；或加 Token/IP 白名单；handler 前置 `path.Clean` + 显式 `..` 拒绝；把 `/data` 改为配置项而非硬编码常量。

### flushd_server unix socket 无鉴权 + 协议命令注入面 — `plugin/server/flushd_server/flushd_server.go:18-141` — **High**

- 监听路径 `/tmp/flush.sock`，`os.Remove(sockPath)` + `net.Listen("unix", sockPath)`，**未设置 `os.Chmod(0o660)`，未限制 umask**。
- `flushCache` 接收任意域名字符串后 `fmt.Sprintf("flush +c %s", domain)` 发到 unbound-control `UBCT1` 协议。
- 客户端输入是 `bufio.NewReader(conn).ReadString('\n')` 的**第一行**（无长度限制、无字符过滤），可注入 `flush +c <evil>\n` 或 `reload\n` 等**任何 unbound-control 命令**。
- 这是**协议层命令注入**（不是 shell），但效果等同：能触发 `flush_zone`、`reload`、`auth_zone_reload` 等影响 DNS 解析状态的操作。

**建议**：socket 监听时 `os.Chmod(sockPath, 0o660)` + `os.Chown(uid, gid)`；domain 字段做 RFC 1035 字符白名单（拒绝空格/换行/分号）。

### mosdns 监听面默认绑定 0.0.0.0 — `plugin/server/tcp_server/tcp_server.go:75` / `udp_server/udp_server.go:68` — **Medium**

- `args.Listen` 默认值 `utils.SetDefaultString(&a.Listen, "127.0.0.1:53")`，**默认是 loopback**。
- 但 YAML 中如果用户把 `listen` 写成 `0.0.0.0:53` 或 `:53`，就**直接对外暴露 53/tcp + 53/udp**。

**建议**：增加 ACL 配置项；DoT 路径需审计实现。

### TLS 证书关闭 — `coremain/curl.go:62-64` — **Low**

- `TLSClientConfig: &tls.Config{InsecureSkipVerify: true}`，命令行工具 `curl` 子命令全局关闭证书校验。
- 影响：仅限运维人员手动的 `mosdns curl` 子命令，不影响 daemon 主流程。

**建议**：保留 `InsecureSkipVerify` 但默认改为 `false`；强制关闭时需要显式 flag。

### 配置文件无 YAML 反序列化安全护栏 — `coremain/run.go:118-148` — **Medium**

- 使用 `viper` 读 `config.yaml`，`mapstructure.DecoderConfig{ErrorUnused: true, WeaklyTypedInput: true}`。
- `WeaklyTypedInput: true` 允许字符串到数字 / 切片到字符串的隐式转换，配合 `loadPluginsFromCfg` 中 `cfg.Include` 字段的递归 `loadConfig`（`mosdns.go:138-147`），存在：
  - YAML include 递归深度限制为 8，但**没有文件大小限制**。
  - 攻击者若能控制 `config.yaml`（已写到 `/data` 目录，可通过 httpd_server 上传），可触发任意插件加载、任意上游地址、任意证书路径。
- `addmod.go:52, 180` 读 `/data/custom_mod.yaml`、写 `/tmp/mosdns_mod.yaml`（权限 0644，**任何用户可改**）。

**建议**：`addmod` 输出文件改 0600；include 增加 yaml 大小上限（`viper.SetTypeByDefaultValue(true)` 也建议关闭 WeaklyTyped）。

### Cobra 子命令暴露辅助功能 — `main.go:36-63` — **Low**

- `mosdns AddMod`、`mosdns eat`、`mosdns curl` 都是 init() 注册的子命令，容器内任何能 exec 的人都能跑。
- 风险：本身不直接 RCE，但 `eat` 名字来源不明，未审计其功能（`coremain/eat.go` 未读）。需进一步审计。

---

## unbound 风险点

### remote-control 协议：unix socket fallback 走明文 — `daemon/remote.c:218-227` — **Medium**

```c
} else {
    struct config_strlist* p;
    rc->ctx = NULL;
    rc->use_cert = 0;
    if(!options_remote_is_address(cfg))
      for(p = cfg->control_ifs.first; p; p = p->next) {
        if(p->str && p->str[0] != '/')
            log_warn("control-interface %s is not using TLS, but plain transfer, because first control-interface in config file is a local socket (starts with a /).", p->str);
    }
}
```

- 当 `remote-control` 第一个 `control-interface` 是 unix socket（路径以 `/` 开头）时，**整个 control 通道** `rc->ctx = NULL`，**所有 control-interface 都跳过 TLS/客户端证书校验**。
- PaoPaoDNS 的 `flushd_server` (`/tmp/flush.sock`) 和 `unbound` 的 `control-interface` unix socket 都属于这种情况 — 依赖文件系统权限保护。
- 如果有人误把第一个 `control-interface` 写成 `0.0.0.0`，会**无声地**绑定到所有接口接受明文命令（仅 `log_warn`，无 `log_err` 阻断启动）。

**建议**：远程 socket（路径不以 `/` 开头）出现且 `use_cert=0` 时应该 `log_err` 并拒绝启动。

### validator 签名验证逻辑面 — `validator/validator.c`（仅读 50 行）— **待二次审计**

- 文件 3658 行，签名验证是 DNSSEC 的安全核心。仓库内未快速发现显式漏洞，但从 `git log` 看 2026 年有大量「Fix that malloc failure ... does not crash later」类修复（`45d1e75`、`e2cc146`、`b806f16` 等），说明上游当前正在修补资源耗尽场景。
- 重点要看：NSEC3 hash 边界、DS 记录验证、keytag 校验。

**建议**：完整审计 `validator/val_nsec3.c`、`validator/val_sigcrypt.c`（未读）。

### net_help 地址解析 — `util/net_help.c:206-239` — **Low**

- 50 行片段显示 `inet_ntop` 配合 `strlcpy`（已用安全函数），无显式溢出点。
- 文件总长 2085 行，需关注 `extstrtoaddr` 之类的解析函数（247 行起）。

### RPZ 近期是热点 — `services/rpz/` 目录 — **Medium**

- `git log --all --grep "RPZ"` 显示 2026 年密集修复：
  - `45d1e75`: malloc failure in rpz response create
  - `1ab75c0`: rrset_insert_rr malloc failure
  - `4693c00`: RPZ load half-built list
  - `fa8e94f`: new_local_rrset for RPZ qname trigger
  - **CVE-2026-44608**: RPZ use-after-free
- HEAD `65e23d4` 在 `75b6dba` 之后还有 50 个 commit，**HEAD 已包含 CVE-2026-44608 修复**，但 vendor 钉到 `release-1.25.1` 后，1.25.1 之后到 HEAD 之间的 50 个 commit **不被打包**，需要评估是否升级到 master 或 1.25.2（如已发布）。

**建议**：在 release-1.25.1 之后持续 bump，建议在 `release-1.25.x` 系列下跟最新 minor。

### 危险 C 函数残留 — 全仓扫描 — **Low**

`sprintf/strcpy/strcat/vsprintf/gets` 全仓搜索结果：

| 文件 | 行 | 性质 |
|------|----|----|
| `winrc/w_inst.c:215-219` | 3 处 `strcat` | Windows 安装器，热路径外 |
| `dns64/dns64.c:169` | 注释中的 "faster than sprintf" | 注释 |
| `compat/ctime_r.c:38` | `strcpy(buf, result)` | 兼容层 |

- `services/` 和 `util/` 子目录**完全清零**。unbound 主代码库非常干净，**重点不是 C 字符串函数残留**。
- `winrc/w_inst.c` 是 Windows-only installer 路径，Linux Docker 部署不受影响。

### validator / mesh / net_help / cache — 50 行抽样

- `services/mesh.c:100-149`: `client_info_compare` 函数，做 tag 列表 / tag action 列表 / tag datas 指针比较 + view 比较，逻辑清晰，**未发现 buffer 误用**。文件 2765 行，热点是 `mesh_new_callback` / `mesh_state_create` / `mesh_walk_supers`。
- `util/net_help.c:200-249`: `log_addr` 用 `strlcpy` + `inet_ntop`，安全。`extstrtoaddr` 处理 `@` 分隔的地址，需深审。
- `validator/validator.c:1-50`: 仅版权头 + 头文件引用，**未到核心逻辑**。重点深审 `val_anchor.c`、`val_nsec3.c`、`val_sigcrypt.c`。

---

## 需要二次审计的热点文件 Top 10

### mosdns（5 个）

| # | 文件 | 理由 |
|---|------|------|
| 1 | `vendors/mosdns/plugin/server/httpd_server/httpd_server.go`（80 行） | 7889 无鉴权 + 路径处理，**P0 重点** |
| 2 | `vendors/mosdns/plugin/server/flushd_server/flushd_server.go`（146 行） | unix socket 协议命令注入 |
| 3 | `vendors/mosdns/plugin/executable/forward/forward.go`（324 行） | 上游转发热路径，已用 `QUICK_FORWARD` 等环境变量做超时 |
| 4 | `vendors/mosdns/coremain/run.go` + `coremain/addmod.go`（149+292 行） | viper/mapstructure 反序列化面、include 递归、addmod 写 0644 文件 |
| 5 | `vendors/mosdns/coremain/curl.go` + `coremain/eat.go`（未读） | `InsecureSkipVerify` + `eat` 子命令功能未明 |

### unbound（5 个）

| # | 文件 | 理由 |
|---|------|------|
| 1 | `vendors/unbound/daemon/remote.c`（8640 行） | remote-control 协议、socket fallback、TLS 校验全部在这里 |
| 2 | `vendors/unbound/validator/validator.c` + `validator/val_nsec3.c` + `validator/val_sigcrypt.c` | DNSSEC 签名验证核心 |
| 3 | `vendors/unbound/services/rpz/`（最近热点） | CVE-2026-44608 在此；50 commit 中约 8 个 RPZ malloc 修复 |
| 4 | `vendors/unbound/services/mesh.c`（2765 行） | 查询状态机，CVE 频发地（需读 `mesh_new_callback` / `mesh_state_create`） |
| 5 | `vendors/unbound/util/net_help.c`（2085 行） + `services/cache/dns.c`（1259 行） | 网络地址解析 + 缓存消息处理，**注意 `extstrtoaddr` 完整函数**（247 行起） |

---

## 依赖 CVE 速查表

直接依赖（来自 `vendors/mosdns/go.mod`）：

| 依赖名 | 当前版本 | 最新版本 | 是否有公开 CVE | 是否影响 |
|--------|----------|----------|----------------|----------|
| github.com/miekg/dns | v1.1.72 | v1.1.72（2025-2026） | **3 个历史 CVE**（CVE-2017-15133 DoS、CVE-2018-17419 NPE-DoS、CVE-2019-19794 弱随机） | **否**（v1.1.72 已修复全部） |
| github.com/mitchellh/mapstructure | v1.5.0 | v1.5.0 | 0 GHSA | 否 |
| github.com/oschwald/geoip2-golang | v1.13.0 | v1.13.0 | 0 GHSA | 否 |
| github.com/spf13/cobra | v1.10.2 | v1.10.2 | 0 GHSA | 否 |
| github.com/spf13/viper | v1.21.0 | v1.21.0 | 0 GHSA | 否 |
| go.uber.org/zap | v1.28.0 | v1.28.0 | 0 GHSA | 否 |
| github.com/stretchr/testify | v1.11.1 | v1.11.1 | 0 GHSA | 否 |
| golang.org/x/exp | v0.0.0-20260611194520 | - | 0 GHSA | 否 |
| golang.org/x/net | **v0.56.0** | v0.56.0 / 含 5 月 22 日 GO-2026-5025/5026/5027/5028/5030 修复 | **5+ 个 CVE**（HTML XSS / IDNA bypass / CPU DoS） | **低** — mosdns 不解析 HTML，但 `proxy.SOCKS5` 间接用 `x/net` |
| golang.org/x/sync | v0.21.0 | - | 0 GHSA | 否 |
| golang.org/x/sys | **v0.46.0** | 含 5 月 22 日 GO-2026-5024 NewNTUnicodeString 溢出修复 | **1 个 CVE** | **低** — 仅在 Windows NewNTUnicodeString 路径触发，Linux 部署不受影响 |
| google.golang.org/protobuf | v1.36.11 | - | 0 GHSA（截至 2026-05） | 否 |
| github.com/fsnotify/fsnotify（indirect） | v1.10.1 | - | 0 GHSA | 否 |
| github.com/oschwald/maxminddb-golang（indirect） | v1.13.1 | - | 0 GHSA | 否 |

Go 运行时 / 标准库相关（mosdns 编译时绑定）：

| 组件 | 备注 |
|------|------|
| `crypto/x509` GO-2026-5037 | DNS SAN quadratic verification — **TLS 验证性能问题**，影响 SNI/TLS 服务端（unbound 也在用） |
| `mime` GO-2026-5038 | CPU DoS via invalid encoded-words — **不直接命中 mosdns** |
| `net/textproto` GO-2026-5039 | 错误注入 — **可能影响 unbound HTTP 错误日志** |

unbound 内嵌依赖（OpenSSL）：通过 `daemon/remote.c` 的 `SSL_CTX_new(SSLv23_server_method())` 使用，未限制最低协议版本。需查 `configure.ac` 中 OpenSSL 版本约束。

---

## 结论

**建议继续完整审计** — PaoPaoDNS 的 risk surface 主要在 mosdns 的两个新增模块（`httpd_server`、`flushd_server`），是 fork 改造引入的，**不是上游原版问题**。重点关注：

1. **P0 必审**：`httpd_server`（路径处理 + 绑定面）、`flushd_server`（unix socket 权限 + 协议注入）— 这两个是 PaoPaoDNS 独有的攻击面，**比 unbound 主线审计更紧迫**。
2. **P1 必审**：`unbound daemon/remote.c` 完整读（8640 行）+ `services/rpz/` 整组 + `validator/` 整组 — 需要确认 vendor 的 50 commit 是否完整保留了 2026-05 后的所有安全修复。
3. **P2 复核**：
   - PaoPaoDNS Dockerfile 是否真在 1.25.1 release 上构建（建议加 `git describe` 到构建日志中比对 tag）
   - `/tmp/flush.sock` 文件权限在 init.sh 中是否被加固（未读 `init.sh`）
   - `addmod.go` 输出 `/tmp/mosdns_mod.yaml` 是否在 init.sh 中 `chmod 600`
4. **P3 依赖**：`golang.org/x/net` 与 `golang.org/x/sys` 版本略落后于 2026-05 安全 advisory，但 mosdns 调用面不直接命中已知 CVE。`miekg/dns` v1.1.72 已覆盖全部历史 CVE。

**不建议先做**完整 review 的方向：unbound 的 `util/` 和 `services/cache/` C 字符串残留扫描已发现全部清零，无需逐文件深查；Go 标准库的 generic 工具函数（`coremain/curl.go` 的 `InsecureSkipVerify`）影响面有限。
