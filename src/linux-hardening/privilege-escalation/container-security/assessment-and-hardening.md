# 评估与加固

{{#include ../../../banners/hacktricks-training.md}}

## 概览

一次好的 container 评估应该回答两个并行的问题。首先，从当前 workload 出发，攻击者能做什么？其次，是哪些 operator 的选择使之成为可能？Enumeration 工具帮助回答第一个问题，加固指导则帮助回答第二个问题。将两者放在同一页上使本节更适合作为现场参考，而不仅仅是 escape tricks 的目录。

## 枚举工具

许多工具对于快速描述 container 环境依然很有用：

- `linpeas` 能识别许多 container 指示器、已挂载的 sockets、capability 集合、危险的 filesystems，以及 breakout 提示。
- `CDK` 专注于 container 环境，包含枚举以及一些自动化的 escape 检查。
- `amicontained` 轻量且有助于识别 container 限制、capabilities、namespace 暴露，以及可能的 breakout 类别。
- `deepce` 是另一个面向 container 的枚举器，带有以 breakout 为导向的检查。
- `grype` 在评估包含 image-package 漏洞审查而不仅仅是 runtime escape 分析时很有用。

这些工具的价值在于速度和覆盖范围，而不是确定性。它们有助于快速揭示大致的 posture，但有趣的发现仍需结合实际 runtime、namespace、capability 和 mount 模型进行人工解读。

## 加固优先级

最重要的加固原则在概念上很简单，尽管其实现因平台而异。Avoid privileged containers。Avoid 挂载的 runtime sockets。除非有非常具体的理由，否则不要给 containers 可写的 host 路径。尽可能使用 user namespaces 或 rootless execution。Drop all capabilities，并仅在 workload 确实需要时再恢复必要的 capability。保持 seccomp、AppArmor 和 SELinux 启用，而不是为了解决应用兼容性问题而禁用它们。限制资源，以防被攻破的 container 轻易使 host 拒绝服务。

Image 和 build 卫生与 runtime posture 同样重要。使用最小 images，频繁重建，扫描它们，在可行时要求 provenance，并确保 secrets 不出现在层中。以 non-root 身份运行、使用小型 image 和有限 syscall 与 capability 面的 container，比以 host-equivalent root 运行并预装调试工具的大型 convenience image 更容易防御。

## 资源耗尽示例

Resource 控制并不吸引眼球，但它们是 container 安全的一部分，因为它们限制了妥协的 blast radius。没有 memory、CPU 或 PID 限制，一个简单的 shell 就可能足以使 host 或相邻的 workloads 降级。

示例会影响主机的测试：
```bash
stress-ng --vm 1 --vm-bytes 1G --verify -t 5m
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target_ip> 4444; done
```
这些示例很有用，因为它们表明，并非每一种危险的容器结果都是一个干净的 "escape"。薄弱的 cgroup 限制仍然可以将代码执行转化为真正的运营影响。

## 加固工具

对于以 Docker 为中心的环境，`docker-bench-security` 仍然是一个有用的宿主端审计基线，因为它检查常见的配置问题并将其与广泛认可的基准指南进行对照：
```bash
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```
该工具不能替代威胁建模，但在发现随时间累积的、由疏忽造成的 daemon、mount、network 和 runtime defaults 时仍然很有价值。

## 检查

在评估期间，将这些用作快速的第一轮命令：
```bash
id
capsh --print 2>/dev/null
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
mount
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock \) 2>/dev/null
```
- 一个具有广泛权限的 root 进程且 `Seccomp: 0` 值得立即关注。
- 可疑的挂载点和运行时套接字通常比任何内核漏洞利用更快地导致影响。
- 运行时姿态薄弱与资源限制宽松的组合通常表明这是一个总体上宽松的容器环境，而不是单一的孤立错误。
