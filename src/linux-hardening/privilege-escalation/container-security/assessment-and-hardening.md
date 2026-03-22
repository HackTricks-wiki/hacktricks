# 评估与加固

{{#include ../../../banners/hacktricks-training.md}}

## 概览

一个好的容器评估应该回答两项并行的问题。首先，从当前的工作负载攻击者能做什么？其次，哪些操作人员的选择使之成为可能？枚举工具有助于回答第一个问题，加固指南有助于第二个问题。将两者放在同一页，使该部分更像现场参考，而不仅仅是 escape 技巧的目录。

## 枚举工具

一些工具在快速描述容器环境时仍然很有用：

- `linpeas` 可以识别许多容器指示器、已挂载的套接字、capability 集合、危险的文件系统以及 breakout 提示。
- `CDK` 专注于容器环境，包含枚举功能以及一些自动化的 escape 检查。
- `amicontained` 轻量且有用，用于识别容器限制、capabilities、namespace 暴露和可能的 breakout 类型。
- `deepce` 是另一个面向容器的枚举器，包含以 breakout 为导向的检查。
- `grype` 在评估包含镜像/包漏洞审查而不仅仅是运行时 escape 分析时很有用。

这些工具的价值在于速度和覆盖，而不是确定性。它们帮助快速揭示大致姿态，但有趣的发现仍需针对实际的运行时、namespace、capability 和 mount 模型进行人工解读。

## 加固优先级

最重要的加固原则在概念上很简单，尽管其实现随平台而异。避免 privileged containers。避免挂载运行时 sockets。除非有非常具体的理由，不要给容器可写的 host 路径。尽可能使用 user namespaces 或 rootless execution。移除所有 capabilities，仅在工作负载确实需要时才恢复必要的 ones。保持 seccomp、AppArmor 和 SELinux 启用，而不是为了解决应用兼容性问题而禁用它们。限制资源，以免被攻陷的容器轻易地对主机造成拒绝服务。

镜像和构建的卫生与运行时姿态同等重要。使用最小化的 images，频繁重建、扫描它们，尽可能要求 provenance，并将 secrets 保出镜像层。以非 root 身份运行、使用小镜像并且 syscall 和 capability 面窄的容器，比以 host 等价的 root 运行并预装调试工具的大型便利镜像更容易防御。

## 资源耗尽示例

资源控制虽不吸引人，但它们是容器安全的一部分，因为可以限制被攻陷后的破坏范围。如果没有内存、CPU 或 PID 限制，一个简单的 shell 就可能足以影响主机或相邻的工作负载。

示例会影响主机的测试：
```bash
stress-ng --vm 1 --vm-bytes 1G --verify -t 5m
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target_ip> 4444; done
```
这些示例很有用，因为它们表明并非每个危险的容器结果都是一个干净的 "escape"。弱的 cgroup 限制仍然可以将 code execution 转化为真正的运营影响。

## 加固工具

对于以 Docker 为中心的环境，`docker-bench-security` 仍然是一个有用的主机端审计基线，因为它会根据广泛认可的基准指南检查常见的配置问题：
```bash
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```
该工具不能替代 threat modeling，但仍然有助于发现随着时间累积的粗心 daemon、mount、network 和 runtime 的默认配置。

## 检查

在评估期间，可将下列命令用作快速初步检查：
```bash
id
capsh --print 2>/dev/null
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
mount
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock \) 2>/dev/null
```
这里值得注意的是：

- 具有广泛权限的 root process 和 `Seccomp: 0` 值得立即关注。
- 可疑的 mounts 和 runtime sockets 通常比任何 kernel exploit 更快提供到达影响的路径。
- 弱的 runtime posture 与弱的 resource limits 的组合通常表明这是一个总体宽松的 container environment，而不是单一的孤立失误。
{{#include ../../../banners/hacktricks-training.md}}
