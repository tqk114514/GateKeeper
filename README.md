# GateKeeper

GateKeeper 是一个专为 Web 服务设计的轻量级安全网关，主要用于提供基于 IP 的访问控制和速率限制。

## 核心功能

- IP 黑名单：支持 .ipset 和 .netset 规则文件，构建高性能二进制索引，利用二分查找实现 O(log N) 级查询。
- 速率限制：基于分片锁和滑动窗口算法，提供细粒度的客户端频率限制。
- 负载卸载：在并发连接达到上限时立即丢弃请求，保护主线程不被挂起。
- 内存安全：使用 Zig 语言开发，严格管理线程栈空间和内存分配。

## Cloudflare Tunnel 集成与局限性

本网关专门针对 Cloudflare Tunnel (内网穿透) 环境进行了优化，但也存在相应的局限性：

### IP 识别机制
由于部署在 cloudflared 隧道后，TCP 层的源 IP 始终为 127.0.0.1。因此，GateKeeper 采用“请求头探测”机制：
- 网关会预读每个连接的前 1024 字节。
- 仅当连接来自 127.0.0.1 时，才会解析并信任 cf-connecting-ip 或 x-forwarded-for 标头。
- 如果没有探测到有效的 IP 标头，网关将退而使用 TCP 原始 IP。

### 协议局限性
- 缺乏协议栈支持：GateKeeper 不是一个完整的 HTTP 代理，由于不解析完整的 HTTP 报文，它无法处理分片发送的标头或大型 Cookie 导致的读取边界问题。
- 无 SSL/TLS 终结：网关期望接收来自隧道解密后的明文流量。它无法直接处理 HTTPS 加密流，也无法通过识别 SNI 进行分流。
- 仅限 IPv4 架构：内部存储使用 u32 整数表示 IP。对于通过 IPv6 访问的用户，必须在 Cloudflare 控制台开启 Pseudo IPv4 功能才能正常识别和限制。

## 配置要求

### Cloudflare 配置
为了确保 IPv6 用户能被正确处理，请在 Cloudflare 仪表板中：
1. 进入 网络（Network）设置。
2. 找到 Pseudo IPv4 选项。
3. 选择“覆盖标头（Overwrite Headers）”。

### 本地环境配置
- 监听端口：默认 3001
- 后端目标：默认 127.0.0.1:3000
- 规则路径：同目录下 rules 文件夹，支持以 .ipset（单行 IP）或 .netset（CIDR 网段）结尾的文件。

## 构建与运行

需要安装 Zig 0.15.0 或更高版本。

```powershell
# 构建
zig build -Doptimize=ReleaseSafe

# 运行
./zig-out/bin/gatekeeper
```

## 注意事项

- 规则更新：修改 rules 目录下的规则文件后，需要删除 rules/blacklist.idx 并重启网关以重新构建索引。
- 性能预警：虽然网关已优化主线程阻塞问题，但在极端 DDoS 洪水下，操作系统层的 TCP Backlog 仍可能成为瓶颈。
