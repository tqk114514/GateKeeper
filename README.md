# GateKeeper

GateKeeper 是一个专为 Web 服务设计的轻量级安全网关，主要用于提供基于 IP 的访问控制和速率限制。本项目已从传统多线程模型重构为基于 Reactor (Event Loop) 的异步架构，旨在提升并发处理能力并加强长连接安全性。

## 核心技术特性

- Reactor 引擎：采用异步事件驱动架构，Linux 环境下使用 epoll (O(1))，其他平台使用 poll，支持高并发连接处理。
- 架构解耦：I/O 引擎 (src/reactor/mod.zig) 与业务策略 (src/main.zig) 完全分离。业务层通过回调接口实现 IP 校验、重试逻辑及协议处理。
- Keep-Alive 连接防护：支持探测长连接内的 HTTP 请求。网关会对持久连接中的每一个新请求重新触发速率限制校验，防止通过长连接绕过安全检查。
- HTTP 标头解析加固：采用行感知解析算法，仅在行首严格匹配相关标头，避免通过 User-Agent 或 URI 注入伪造的 IP 标头。
- 后端管理：支持后端连接失败后的自动重试（默认 3 次）以及被动健康检查（熔断机制）。

## Cloudflare Tunnel 集成与 IP 识别

本项目针对 Cloudflare Tunnel 环境进行了特定优化：

### IP 识别机制
由于网关通常部署在 cloudflared 隧道后，TCP 层的源 IP 通常为 127.0.0.1。
- 网关仅在连接来自 127.0.0.1 时，才会解析并信任 CF-Connecting-IP 标头。
- 如果连接来自 127.0.0.1 但未探测到有效的真实 IP 标头，网关会将其视为非法请求并立即强制关闭连接，以防止 DoS 攻击风险。

### 配置要求
为了正确处理 IPv6 用户，请在 Cloudflare 仪表板中进行如下配置：
1. 进入“网络 (Network)”设置。
2. 找到“Pseudo IPv4”选项。
3. 选择“覆盖标头 (Overwrite Headers)”。

## 局限性说明

- 协议支持：GateKeeper 不是全功能 HTTP 代理。它执行轻量级的流式探测，不保证能处理极端复杂的 HTTP 分片或超大 Cookie 边界。
- SSL/TLS：网关本身不处理证书或 HTTPS 加密流，期望接收来自隧道解密后的明文流量。
- IPv4 导向：内部 IP 匹配基于 u32 逻辑。IPv6 用户需通过 Cloudflare 的 Pseudo IPv4 功能转换为 IPv4 格式。

## 构建与运行

需要安装 Zig 0.15.2 或更高版本。

```powershell
# 本地构建
zig build -Doptimize=ReleaseSafe

# 交叉编译 Linux 版本
zig build -Dtarget=x86_64-linux -Doptimize=ReleaseSafe

# 运行
./zig-out/bin/gatekeeper
```

## 注意事项

- 规则更新：修改 rules 目录下的规则文件后，需要删除 rules/blacklist.idx 并重启网关以重新构建索引。
- 性能预警：虽然网关已采用 Reactor 优化，但在极端流量下，操作系统的 TCP Backlog 仍可能成为瓶颈。
- 内存管理：使用 ArenaAllocator 管理连接生命周期内的临时分配，确保在长连接场景下无内存泄露。
