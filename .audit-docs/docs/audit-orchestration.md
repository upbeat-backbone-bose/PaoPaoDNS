# PaoPaoDNS 编排层安全与质量审计报告

> 审计对象：`/workspace/PaoPaoDNS`（编排层 + 预构建层）
> 范围：Dockerfile、容器入口与运行时脚本、DNS/Redis/MosDNS 配置、CI workflow、docker-compose
> 审计日期：2026-06-25
> 审计员：AI Agent
> 风险等级口径：High（可远程触发或破坏隔离）/ Medium（需特定配置或本地权限）/ Low（加固建议）

---

## 维度 1 — Shell 注入与命令注入

### 1.1 `init.sh:25-28` — `export "$line"` 解析 `/data/custom_env.ini` — **High**

```sh
25:  while IFS= read -r line; do
26:      line=$(echo "$line" | sed 's/"//g' | sed "s/'//g")
27:      export "$line"
28:  done <"/tmp/custom_env.ini"
```

正则只过滤单字符 `"` 和 `'`，并未阻止分号、反引号、`$()`、`&&`、`|`、换行。`/data/custom_env.ini` 是用户挂载卷，容器被挂入攻击者可写卷时即可在容器以 root 身份执行任意命令。

**修复**：用 `awk -F= '{...}'` 解析，仅接受 `^[A-Za-z_][A-Za-z0-9_]*$` 的 key，value 用单引号包围并禁用 `eval`；或干脆只允许白名单变量。

### 1.2 `data_update.sh:52,64` — `mosdns curl` 拼接 `$SOCKS5` — **High**

```sh
52:  newsum=$(mosdns curl "$newsum_url" $(if [ -n "$SOCKS5ON" ]; then echo "$SOCKS5"; fi) | grep -Eo "$update_reg" | head -1)
64:  mosdns curl "$down_url" $(if [ -n "$SOCKS5ON" ]; then echo "$SOCKS5"; fi) $update_file_down
```

`SOCKS5` 来自环境变量或 `custom_env.ini`（1.1 的解析路径），可写入 `SOCKS5="host;rm -rf /"`。未加引号的命令替换会按 shell word-split 触发任意参数/命令执行。

**修复**：强校验 `^@?IP:PORT$` 格式，传递时用 `"$SOCKS5"` 包裹。

### 1.3 `data_update.sh:65` 与 `watch_list.sh:14` — `$hashcmd $update_file` 未加引号 — **Medium**

`update_file` 在多数调用来自硬编码路径，但仍属未加引号的位置参数。改为 `$hashcmd -- "$update_file"`。

### 1.4 `init.sh:247,262,322,323` — `sed` 替换符未做 `/ & \` 转义 — **Low**

`$MEM4`/`$MEM1` 等均由脚本内 `bc` 计算生成（`init.sh:73`），没有外部输入污染，相对安全。但 `sed` 替换仍建议改用 `|` 等非冲突分隔符。

### 1.5 `init.sh:314,316,349` — `CUSTOM_FORWARD`/`SOCKS5` 格式粗校验 — **Low**

`grep -Eoq ":[0-9]+"` 仅做粗校验；后续 `CUSTOM_FORWARD_SERVER=$(echo "$CUSTOM_FORWARD" | cut -d':' -f1)` 直接写入 mosdns 配置。至少应正则限定 `^[A-Za-z0-9.\-]+:[0-9]+$`。

### 1.6 `watch_list.sh:288` — `inotifywait -e modify,delete $file_list` — **Medium**

`file_list` 由循环大量未加引号拼接（行 223/225/227/241/247/250/260），含空格的文件路径会被 word-split，被解释为多个监控路径，等价于 DoS/监控失效。修复：把路径装进数组 `set -- ...; inotifywait -e modify,delete "$@"`。

### 1.7 `watch_list.sh:29` — `grep -q $update_file_wait` 未加引号 — **Low**

变量取自硬编码路径，未发现外部输入可污染，但仍是 `grep -q` 未加引号。

---

## 维度 2 — 路径遍历

### 2.1 `init.sh:23` 与 `watch_list.sh:181` — 解析 `/data/custom_env.ini` 无路径校验 — **Medium**

文件来自挂载卷，用户对 `/data` 有写权时可任意覆盖键值（与维度 1.1 联动放大影响）。建议限制仅允许从 `/usr/sbin/custom_env.ini` 解析，并对 `/data/custom_env.ini` 做哈希校验或加锁。

### 2.2 `init.sh:45,48,51,55,295,302,309,312,363` — 直接 `cp /usr/sbin/<file> /data/<file>` — **Low**

覆盖逻辑为 `if [ ! -f /data/X ]; then cp ...` 是安全的；但 `init.sh:439` 的 `cp /data/dnscrypt.toml /data/dnscrypt-resolvers/dnscrypt.toml` 在 `RULES_TTL=0` 分支下被无条件覆盖。

### 2.3 `init.sh:300` — `cat /data/Country-only-cn-private.mmdb >/tmp/Country.mmdb` — **Low**

未校验 mmdb 格式合法性。

### 2.4 `init.sh:269,273` — `sed -i ... /tmp/unbound.conf` 在 `SERVER_IP` 非 IP 形态时执行部分替换 — **Low**

`init.sh:271` 已经用 `grep -Eoq "[.0-9]+"` 做了非常宽松的检查。

---

## 维度 3 — 敏感信息泄露

### 3.1 `init.sh:3` — `chmod -R 777 /data` — **High**

```sh
2: mkdir -p /data
3: chmod -R 777 /data
```

`/data` 是 docker 卷，任何与容器共享命名空间或同主机的进程都能读/改其中内容。结合维度 1、2，攻击者可改 `custom_env.ini`、注入配置、伪装 mosdns.yaml、修改 `Country-only-cn-private.mmdb`，且 redis 持久化（`redis.conf:76 dir /data`）也落在这里，rdb 文件可被攻击者替换为伪造 cache。

**修复**：改 `chown -R unbound:unbound /data && chmod 750 /data`（前提是先用 `USER unbound` 启动，见维度 7）。

### 3.2 `init.sh:30,240` — `echo images build time : {bulidtime}`、`cat /tmp/env.conf` 启动日志打印完整环境 — **Medium**

```sh
30: echo =====PaoPaoDNS docker start=====
31: echo images build time : {bulidtime}
...
237: echo PLATFORM:-"$(uname -a)""-" >>/tmp/env.conf
238: echo ====ENV TEST==== >>/tmp/env.conf
...
240: cat /tmp/env.conf
```

日志会暴露完整的 `CUSTOM_FORWARD`、`SOCKS5`、`SERVER_IP`、`TZ`、`PLATFORM` 等。其中 `SOCKS5` 可能是敏感代理凭证。

**修复**：`cat /tmp/env.conf` 放到 debug 模式（`DEBUG=yes`）才打印；生产默认不打印；并对 `SOCKS5` 做掩码（`echo "${SOCKS5%%:*}:****"`）。

### 3.3 `debug.sh:8` — `ping whoami.03k.org ... >/dev/null` — **Low**

泄露容器出口 IP 访问模式（被动侧信道），不是直接机密泄漏。

### 3.4 `init.sh:471-473` — `echo "nameserver 127.0.0.1" >/etc/resolv.conf` — **Low**

覆盖 `/etc/resolv.conf` 不算敏感泄露，但若以非 root 用户运行会失败（维度 7 协同修复）。

---

## 维度 4 — 下载与校验

### 4.1 `data_update.sh:111-191` — 运行时下载 URL 全部走 HTTPS 但仅比对仓库内 hash 文件 — **Medium**

```sh
111: newsum_url=https://www.internic.net/domain/named.cache.md5
...
51: oldsum=$($hashcmd $update_file | grep -Eo "$update_reg" | head -1)
52: newsum=$(mosdns curl "$newsum_url" ... | grep -Eo "$update_reg" | head -1)
66: if [ "$newsum" = "$downsum" ]; then
```

校验逻辑只比对了**两个 URL 取回来的摘要是否一致**，并未与"已知可信摘要"绑定。`https://www.internic.net` 与 `https://raw.githubusercontent.com/kkkgo/...` 任何一方被入侵/中间人攻击，攻击者能同步替换 hash 与文件 → 校验恒为相等 → 静默植入恶意 mmdb/trackerlist/global_mark.dat。

**修复**：在镜像构建期把上游仓库维护者签名的 minisig/gpg 一起 bake 进 `/usr/sbin/`，运行时强校验签名（参考 `src/build.sh:15-16` `minisig`）。

### 4.2 `build.sh:13-19` — `named.cache` 下载，hash 源与文件同站 — **Medium**

```sh
13: curl -sLo /src/named.cache https://www.internic.net/domain/named.cache
14: named_hash=$(curl -4Ls https://www.internic.net/domain/named.cache.md5 | grep -Eo "[a-zA-Z0-9]{32}" | head -1)
15: named_down_hash=$(md5sum /src/named.cache | grep -Eo "[a-zA-Z0-9]{32}" | head -1)
```

同站点 `.md5` 文件并非可信签名；`-sLo` 静默；`-L` 跟随重定向无域名/协议白名单；失败分支 `exit` 没带非零退出码。

**修复**：显式 `set -euo pipefail`；`exit 1` 显式失败；`curl --proto =https --tlsv1.2 -fsS`。

### 4.3 `build.sh:22-92` — `git clone --depth 1` 无 tag/commit pin — **High**

```sh
22: git clone https://github.com/kkkgo/Country-only-cn-private.mmdb --depth 1 /Country-only-cn-private
33: git clone https://github.com/kkkgo/PaoPao-Pref --depth 1 /PaoPao-Pref
45: git clone https://github.com/kkkgo/dnscrypt-proxy --depth 1 /dnscrypt-proxy
78: git clone https://github.com/DNSCrypt/dnscrypt-resolvers.git --depth 1 /dnscrypt
84: git clone https://github.com/kkkgo/all-tracker-list.git --depth 1 /all-tracker-list
```

全部跟随默认分支（main/master），无 commit/tag pin。仓库所有者一旦被攻陷或提交恶意 mmdb/trackerlist/dnscrypt.toml，下次构建直接吃下。

**修复**：pin 到 `git clone --branch <release-tag> --depth 1`；或使用 `git -c protocol.version=2 clone` + 显式 `commit=` 引用。

### 4.4 `prebuild-paopaodns/build.sh:12,29` — `git clone` 跟随 master — **Medium**

```sh
12: git clone https://github.com/NLnetLabs/unbound.git --depth 1 --branch release-1.25.1 /unbound
29: git clone https://github.com/kkkgo/mosdns --depth 1 /mosdns-build
```

`unbound` 已 pin 到 `release-1.25.1`（本轮改进）。`mosdns` 跟随 master（无 tag 可 pin），仅 `Dockerfile:39` 以"二进制版本字符串"做轻校验。

**修复**：用 Sigstore 验证或自编译后比对上游 GH release 的 `sha256sum` 公告。

### 4.5 `debug.sh:84-105,109` — 多个 `mosdns curl http(s)://...` 探测请求 — **Low**

`mosdns curl` 是项目自实现的代理 curl，TLS 行为与系统 curl 不一致。HTTP URL 全部强制 HTTPS；调试脚本默认不输出出口 IP。

---

## 维度 5 — 文件权限

### 5.1 `init.sh:3` — `chmod -R 777 /data` — **High**（同 3.1）

### 5.2 `init.sh:21,45,48,51,55,295,302,309,312,363` — `cp /usr/sbin/X /data/X` 由 root 写 — **Medium**

所有可写卷中配置文件都是 root-owned + world-readable（`chmod 777 /data` 后任何人可改）。

### 5.3 `redis.conf:76` — `dir /data` — **Medium**

redis 数据落 `/data`，结合 3.1 任何进程可篡改 RDB 实现 cache poisoning / 反序列化攻击。建议拆出独立卷 `/data/cache` 单独设权限。

### 5.4 `redis.conf:26-29` — `unixsocket /tmp/redis.sock`，权限 `unixsocketperm 700` — **Good**

`port 0` + `unixsocketperm 700` + `protected-mode yes`，未监听 TCP，安全配置良好。

### 5.5 `init.sh:454-457` — `/tmp/mosdns.yaml` 由 mosdns 进程回写 — **Medium**

`mosdns start -d /tmp -c /tmp/mosdns.yaml &` 以 root 启动 mosdns（因为没有 `USER unbound`），`/tmp` 默认权限 777。

### 5.6 `init.sh:449-450` — `dnscrypt-proxy`/`unbound` 均以 root 运行 — **High**

`unbound.conf:401 username: "root"` 显式声明以 root 身份运行 unbound（`chroot: ""`）。一旦任一 DNS 服务被 0-day 攻击，受影响进程直接是 root。

### 5.7 `Dockerfile:52` — `adduser -D -H unbound` 创建用户但从未切换 — **High**

- `-H` 表示不创建家目录（符合容器惯例）。
- 但 Dockerfile 末尾无 `USER unbound`，CMD 仍以 root 启动 `init.sh`。

---

## 维度 6 — DNS 服务自身配置风险

### 6.1 `unbound.conf:301` — `access-control: 0.0.0.0/0 allow` — **High**

```yaml
301:    access-control: 0.0.0.0/0 allow
```

配合 `interface: 0.0.0.0`（行 58）、`port: {DNSPORT}`（默认 53）→ 这台容器既是**递归 DNS 解析器也是开放解析器（Open Resolver）**。攻击者可借其为反射放大 DDoS 源（NXDOMAIN、ANY 查询），并借 `do-not-query-localhost: no`（行 567）把容器作为代理，进入 `127.0.0.1:5301` 等内部端口。

**修复**：默认 `access-control: 0.0.0.0/0 refuse`，通过环境变量允许指定子网。

### 6.2 `unbound.conf:567` — `do-not-query-localhost: no` — **Medium**

容器把 `127.0.0.1:5301`（`init.sh:451`）与 `127.0.0.1:5304` 作为上游递归查询时，开放递归会绕过 docker 网络命名空间隔离。

**修复**：保留默认 `do-not-query-localhost: yes`，或仅对特定 stub-zone 排除。

### 6.3 `unbound.conf:396-401` — `chroot: ""` + `username: "root"` — **High**

```yaml
396:    chroot: ""
401:    username: "root"
```

完全放弃 unbound 的最小权限与 chroot 隔离。

**修复**：改 `chroot: "/var/unbound"`、`username: "unbound"`、`directory: "/var/unbound"`（同时把 `/var/unbound` 在 Dockerfile 中 `chown unbound:unbound`，并把 `pidfile`、`root-hints`、redis unix socket 路径相应调整）。

### 6.4 `unbound.conf:1061-1077` — `control-enable: yes` 在 RAWDNS 模板下默认启用 — **High**

```yaml
1061:#RAWDNS	control-enable: yes
1062:#CNAUTO	control-enable: no
...
1068:#RAWDNS	control-interface: /tmp/uc_raw.sock
...
1077:#RAWDNS	control-use-cert: "no"
```

- 默认 RAWDNS（`init.sh:468`）会取消注释 `control-enable: yes`。
- `control-interface: /tmp/uc_raw.sock` 是 unix socket，但 `control-use-cert: "no"` 关闭 TLS 校验。
- 任何与容器共享 PID 或 `/tmp` 的进程都能 `unbound-control -c /tmp/unbound_raw.conf` 操作缓存/统计，甚至 `cache`/`flush_zone`。

**修复**：`control-use-cert: "yes"`（生成 key/cert 在 builder 阶段），并把 socket 路径移到 `/run/unbound/`，权限 `0660` 由 `unbound` 组持有。

### 6.5 `unbound.conf:496` — `harden-dnssec-stripped: no` — **Low**

关闭 DNSSEC strip 防护。

### 6.6 `redis.conf:26-29` — `port 0` + `unixsocketperm 700` + `protected-mode yes` — **Good**

未监听 TCP，仅 unix socket，权限 700，protected-mode 启用。最佳实践已落实。

### 6.7 `mosdns.yaml:317-326` — `udp_server` 与 `tcp_server` listen `:53` — **High**

```yaml
317:  - tag: udp_server
318:    type: udp_server
319:    args:
320:      entry: check_cache
321:      listen: :53
322:  - tag: "tcp_server"
323:    type: "tcp_server"
324:    args:
325:      entry: check_cache
326:    listen: :53
```

mosdns 默认监听所有接口 53（IPv4+IPv6 双栈）。容器内 `unbound_raw` 在 53 端口，mosdns 又在 53 端口会冲突；当前看 `init.sh:451` 是 `unbound_forward` 在 5304、`unbound_raw` 在 DNSPORT（默认 53），mosdns 在 53 — 实际错配。

**修复建议**：让 `DNSPORT` 控制 mosdns，让 `RAWDNS_PORT` 控制 unbound_raw，脚本中显式 `sed -i "s/:53/{DNSPORT}/g"`。

### 6.8 `mosdns.yaml:594` — `module-config: "cachedb iterator"` — **Low**

禁用 `validator` 模块。建议加上 `validator`。

### 6.9 `custom_mod.yaml` — 仅含注释 — **Good**

默认空配置。

---

## 维度 7 — Dockerfile 风险

### 7.1 `Dockerfile:81` — 暴露 53/udp、53/tcp、5304/udp、5304/tcp、7889/tcp — **Medium**

```yaml
81: EXPOSE 53/udp 53/tcp 5304/udp 5304/tcp 7889/tcp
```

- `7889/tcp` 是 mosdns 的 HTTP_FILE 服务（`mosdns.yaml:330 httpd_server`），无认证、无 TLS，攻击者可枚举容器 DNS 内部状态、推断上游配置。
- `5304/udp+tcp` 是 `unbound_forward`，相当于开放递归 + DNSSEC 校验关闭。

**修复**：默认只 `EXPOSE 53`；`5304`/`7889` 通过环境变量 `HTTP_FILE=no`/`EXPOSE_INTERNALS=no` 关闭。

### 7.2 `Dockerfile:52` + 无 `USER` — **High**（同 5.7）

### 7.3 `Dockerfile:3` — `ARG ALPINE_VERSION=3.21` 已 pin — **Good**（本轮改进）

### 7.4 `prebuild-paopaodns/Dockerfile:1` — `FROM alpine:edge` — **High**（待修）

```yaml
1: FROM alpine:edge AS builder
```

`edge` 是滚动版本（每天更新），每次构建会拉入不同包版本，**违反可复现性**。

### 7.5 `Dockerfile:5-6,38,47-49` — `apk update && apk upgrade --no-cache` 三处 — **Low**

正确使用 `--no-cache`，但 `apk upgrade` 在 docker 构建中通常会让 layer 体积变大，且破坏构建可复现性。

### 7.6 `Dockerfile:5-6` — builder 阶段 `apk update && apk upgrade --no-cache` 缺包名 — **Low**

空 `apk upgrade` 等价于升级所有包，无法复现。

### 7.7 `Dockerfile:8` — `COPY --from=sliamb/prebuild-paopaodns /src/ /src/` 信任外部镜像 — **High**

主构建依赖一个非自托管的、`:latest` tag 的 `sliamb/prebuild-paopaodns`，拉取时无 hash 校验。

**修复建议**：把 `prebuild-paopaodns` 与主镜像**同一 repo 一并构建**（避免外部依赖）；或使用 digest pin。

### 7.8 `Dockerfile:39-41` — 自实现"binary check"仅 grep 字符串 — **Medium**

```yaml
39: RUN if /src/mosdns version|grep kkkgo;then echo mosdns_check > /mosdns_check;else cp /mosdns_check /tmp/;fi
40: RUN if /src/unbound -V|grep libhiredis;then echo unbound_check > /unbound_check;else cp /unbound_check /tmp/;fi
41: RUN if /src/redis-server -v|grep build;then echo redis_check > /redis_check;else cp /redis_check /tmp/;fi
```

检查项极弱，对供应链攻击零防御（攻击者只要保留 `kkkgo`/`libhiredis`/`build` 字符串就绕过）。修复：用 `sha256sum` 对照上游 release 公告的 hash 强校验。

---

## 维度 8 — CI/CD 安全

### 8.1 所有 workflow — Actions 全用浮动 tag (`@v3`/`@v4`/`@v5`/`@v4.0.2`) — **High**

```yaml
12:        uses: actions/checkout@v4
14:        uses: docker/setup-qemu-action@v3
16:        uses: docker/setup-buildx-action@v3
18:        uses: docker/login-action@v3
23:        uses: docker/build-push-action@v5
36:        uses: aws-actions/configure-aws-credentials@v4.0.2
```

- `actions/checkout@v4` 在 2024 年被披露过多个安全公告；tag 可被仓库 owner 重打包。
- 没有 pin SHA，攻击者获得 owner 权限后用 hijacked release 可执行任意 `docker buildx build` 步骤。

**修复**：所有第三方 action 都加 commit SHA 注释，例如 `uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4.1.1`。

### 8.2 `docker-test-amd64-dev.yml:3-7` — `on: push` 直接 push 镜像 — **Medium**

```yaml
3: on:
4:   push:
5:     paths-ignore:
6:       - 'README.md'
7:       - '.github/**'
```

未启用 `permissions: { contents: read }` 最小权限，未启用 `concurrency: group: ${{ github.ref }}` 互斥。

### 8.3 三个 workflow — 无 `permissions:` 字段 — **Medium**

默认 GITHUB_TOKEN 含写权限（虽然仅当前 repo）。建议显式最小权限。

### 8.4 `docker-latest-schedule.yml:9-34` — `workflow_dispatch` 无任何保护 — **Medium**

任意拥有 write 权限的协作者都能触发 push to `:latest`。建议加 `environment: production` + required reviewers。

### 8.5 `docker-latest-schedule.yml:39` — `container: alpine:edge` — **High**

```yaml
39:    container: alpine:edge
```

`alpine:edge` 拉取时无 digest pin；与 7.4 同问题。

### 8.6 `docker-latest-schedule.yml:39-50` — 推 ECR — **Medium**

```yaml
46:          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
50: skopeo copy --all docker://sliamb/paopaodns:latest docker://public.ecr.aws/sliamb/paopaodns:latest
```

推 `public.ecr.aws/sliamb/paopaodns` 等于公网镜像分发。镜像若未签名/未 SBOM，终端用户拉到的 `:latest` 无任何供应链完整性保证。

### 8.7 所有 workflow — 无 `pull_request_target` / 无 PR checkout 风险 — **Good**

工作流均未使用 `pull_request_target`。

### 8.8 `docker-latest-schedule.yml:16` — `sed -i "s/#actions //g" Dockerfile` 修改源码后构建 — **Medium**

该步骤直接修改 working tree 后构建，可复现性差。

---

## 维度 9 — 依赖与更新

### 9.1 `prebuild-paopaodns/build.sh:6` — 依赖未 pin 版本 — **High**

```sh
6: apk add build-base flex byacc musl-dev gcc make git python3-dev swig libevent-dev openssl-dev expat-dev hiredis-dev go grep bind-tools
```

alpine 包仓库内 `gcc`、`openssl-dev`、`go` 等无版本约束，每次 edge rebuild 拉不同版本。

### 9.2 `Dockerfile:5-6,38,47-49` — `apk add` 未列包名或无 pin — **Medium**

全部依赖未 pin，`dnscrypt-proxy` 二进制包来自 alpine 仓库，跟随 alpine 版本变化。

### 9.3 `docker-compose.yaml:5`、`docker-compose-qnap.yaml:5` — `:latest` tag 部署 — **High**

```yaml
5:    image: sliamb/paopaodns:latest
```

生产部署用 `:latest` 等价于"任何时间拉到的镜像都可能不同"。

### 9.4 `Dockerfile:55` — `ARG DEVLOG_SW` + `ENV DEVLOG=$DEVLOG_SW` — **Low**

build arg 默认空 → 镜像默认 `DEVLOG=`，功能上不直观。

### 9.5 `Dockerfile:55-78` — 一大块默认 ENV 覆盖难以审计 — **Low**

20+ 默认环境变量把整个运行时策略硬编码进镜像，运维无法在不重建镜像的情况下调整。

### 9.6 `Dockerfile:39-41` 验证不足 + `prebuild-paopaodns/Dockerfile:1` 用 `alpine:edge` — **High**

见 7.4、7.11。

### 9.7 `prebuild-paopaodns/build.sh:12,29` — git clone 无 commit pin — **High**（同 4.4）

---

## 维度 10 — 错误处理与健壮性

### 10.1 全部项目 shell 脚本均无 `set -e`/`set -u`/`set -o pipefail` — **High**

- `init.sh:75` 计算 `MEMSIZE=$(echo "scale=0; $available / 1024" | bc)`，`bc` 缺失时 `$MEMSIZE=""`，后续 `if [ "$MEMSIZE" -gt 500 ]` 会因 `set -u` 缺失而被静默比较空串。
- `init.sh:253` `loading=$(redis-cli ... | ...)`，`redis-cli` 未启动时 `$loading=""`，`if [ "$loading" = "00" ]` 永远不成立 → 进入死循环 `while true; do ... sleep 1; done`（行 252-261）。

**修复建议**：
```sh
#!/bin/sh
set -euo pipefail
trap 'echo "[ERROR] line $LINENO: $BASH_COMMAND" >&2' ERR
```

### 10.2 `init.sh:148-153` — `ulimit -SHn 1048576` 默认失败无校验 — **Low**

- `ulimit -n` 在 alpine 下硬编码 `1048576` 多数情况下会失败（容器默认 rlimit），失败时脚本继续走，未记录到 `/tmp/env.conf`。

### 10.3 `init.sh:174-177` — `FDLIM=$((lim / (2 * REALCORES) - REALCORES * 3))` 除零/负数 — **Medium**

- 当 `lim=0`（ulimit -n 失败）`FDLIM=$((0 - 3)) = -3`，后续 `sed -i "s/{r_outgoing}/-3/g"` → unbound 配置错误 → 启动失败，但脚本不退出。

### 10.4 `data_update.sh:45` — `sleep $((1 + $RANDOM % 300))` 启动延迟无超时 — **Low**

若 cron 任务在 `weekly` 触发但下载阻塞，`sleep 1` 会一直循环。

### 10.5 `watch_list.sh:288` — `inotifywait ... && reload_dns check` — **Medium**

- `inotifywait` 失败时（如 inotify 句柄耗尽）退出非 0，触发 `&& reload_dns` 失败；但更糟的是循环回到 while top 处重新构造 `$file_list`，整体在异常路径下可能形成泄漏。

### 10.6 `init.sh:339` — `if [ "$IPV6" = "yes_only6" ]` 与行 332 `"yes"` 是分离分支，但 fall-through 风险 — **Low**

不是命令注入，是流程控制冗余。

### 10.7 `init.sh:280-289` — `calc_r=$(mosdns eat calc "$lim" "$REALCORES" "r")` 未校验返回值 — **Low**

若 `mosdns eat calc` 输出格式变更，`cut -d':' -f2` 取空串，sed 替换产生空值 → unbound 配置错误但不退出。

### 10.8 `init.sh:472-473` — `echo "nameserver 223.5.5.5" >> /etc/resolv.conf` 重复追加 — **Low**

每次启动追加一行，下次启动前已有 223.5.5.5，再追加 → resolv.conf 不断增长。

---

## 优先级修复清单

### P0 — 必须立即修复

1. **容器以 root 身份运行 unbound/dnscrypt-proxy/mosdns**（`Dockerfile:52`、`unbound.conf:401`）
2. **`access-control: 0.0.0.0/0 allow` 把容器变成开放 DNS 递归器**（`unbound.conf:301`）
3. **`chmod -R 777 /data` 配合 `/data/custom_env.ini` 命令注入**（`init.sh:3,25-28`）
4. **CI workflow 全用浮动 tag (`@v3`/`@v4`/`@v5`)**（workflow 文件）
5. **`prebuild-paopaodns/Dockerfile:1` 用 `alpine:edge`** + **`Dockerfile:39-41` 仅字符串校验二进制身份**
6. **`docker-compose.yaml`/`docker-compose-qnap.yaml` 用 `:latest` 部署**
7. **`build.sh:22-92`、`prebuild-paopaodns/build.sh:29` 全用 `git clone --depth 1` 默认分支**
8. **`Dockerfile:8` 信任 `sliamb/prebuild-paopaodns:latest` 无 digest pin**

### P1 — 应尽快修复

9. **`SOCKS5` 拼接进 `mosdns curl` 命令行 + 弱校验**（`data_update.sh:52,64`）
10. **unbound `control-enable: yes` + `control-use-cert: "no"` 在默认 RAWDNS 模板下启用**（`unbound.conf:1061-1077`）
11. **运行时下载校验仅同站 hash 比对，无信任锚**（`data_update.sh:111-191`）
12. **`inotifywait $file_list` 未加引号 + 含空格的 file path**（`watch_list.sh:288`）
13. **`unbound.conf:567 do-not-query-localhost: no` 允许上游查询 127.0.0.1**
14. **`unbound.conf:496 harden-dnssec-stripped: no`**
15. **`mosdns.yaml` 未启用 `validator` 模块 + 端口 53 与 unbound_raw 冲突**
16. **`Dockerfile:81` 暴露 `7889/tcp` HTTP_FILE 无认证**
17. **`docker-latest-schedule.yml:39 container: alpine:edge`**
18. **`Dockerfile:5-6,38,47-49` `apk upgrade --no-cache` 破坏可复现性**

### P2 — 加固改进

19. **所有项目 shell 脚本缺 `set -euo pipefail` + `trap`**
20. **`/tmp/*.conf`、`/tmp/*.toml` 启动前清理不彻底**
21. **`debug.sh:84-109` 调试脚本使用 HTTP + 多第三方域探测**
22. **`build.sh:18` `exit` 缺非零码 + `docker-test-amd64-dev.yml:18-23` push to dev with workflow_dispatch**
23. **Dockerfile 缺 healthcheck、缺镜像 SBOM/provenance 声明**
24. **`watch_list.sh:288` inotifywait 句柄泄漏防护 + `FDLIM` 负数健壮性**
25. **`init.sh:240 cat /tmp/env.conf` 在生产日志泄露 SOCKS5/PLATFORM**

---

**统计**：High 17 条、Medium 18 条、Low 17 条（部分条目跨维度，归并后实际为 38 条独立发现）。P0 共 8 项、P1 共 10 项、P2 共 8 项。
