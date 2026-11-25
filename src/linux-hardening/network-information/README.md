# 网络信息

{{#include ../../banners/hacktricks-training.md}}

本地监听服务、Unix sockets 和面向网络的软件可能暴露外部扫描无法发现的路径。先检查主机上的监听服务，以及拥有各个 endpoint 的进程。

- [流量捕获、防火墙和出站流量排查](traffic-capture-and-firewall-egress.md)介绍数据包捕获、过滤、代理和连通性测试。
- [本地网络和 socket 排查](local-network-and-socket-triage.md)介绍 loopback 服务、Unix sockets 和容器网络。
- [Socket 命令注入](socket-command-injection.md)介绍通过暴露的本地 sockets 接受的命令。
- 对于 Cisco SD-WAN Manager 设备 foothold，请参阅 [vManage 本地权限提升](../../network-services-pentesting/cisco-sd-wan-manager-local-privilege-escalation.md)；其 ConfD CLI、REST API 和 root 拥有的导入路径与常规 socket 排查不同。
{{#include ../../banners/hacktricks-training.md}}
