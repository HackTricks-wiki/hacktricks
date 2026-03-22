# `no_new_privs`

{{#include ../../../../banners/hacktricks-training.md}}

`no_new_privs` é uma feature de hardening do kernel que impede que um processo ganhe mais privilégios através de `execve()`. Em termos práticos, uma vez que a flag é setada, executar um binário `setuid`, um binário `setgid`, ou um arquivo com `Linux file capabilities` não concede privilégios adicionais além dos que o processo já possuía. Em ambientes containerizados, isso é importante porque muitas cadeias de escalada de privilégio dependem de encontrar um executável dentro da image que altera privilégios quando executado.

Do ponto de vista defensivo, `no_new_privs` não substitui namespaces, seccomp, ou capability dropping. É uma camada de reforço. Bloqueia uma classe específica de escalada subsequente após a obtenção de code execution. Isso a torna particularmente valiosa em ambientes onde images contêm helper binaries, package-manager artifacts, ou legacy tools que, combinados com partial compromise, seriam perigosos.

## Operation

A kernel flag por trás desse comportamento é `PR_SET_NO_NEW_PRIVS`. Uma vez definida para um processo, chamadas posteriores a `execve()` não podem aumentar privilégios. O detalhe importante é que o processo ainda pode executar binaries; ele simplesmente não pode usar esses binaries para cruzar uma privilege boundary que o kernel normalmente honraria.

Em ambientes orientados a Kubernetes, `allowPrivilegeEscalation: false` mapeia esse comportamento para o processo do container. Em runtimes no estilo Docker e Podman, o equivalente normalmente é habilitado explicitamente através de uma security option.

## Lab

Inspecione o estado do processo atual:
```bash
grep NoNewPrivs /proc/self/status
```
Compare isso com um container onde o runtime habilita a flag:
```bash
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'grep NoNewPrivs /proc/self/status'
```
Em uma carga de trabalho endurecida, o resultado deve mostrar `NoNewPrivs: 1`.

## Impacto na Segurança

Se `no_new_privs` estiver ausente, um ponto de apoio dentro do container ainda pode ser elevado através de setuid helpers ou binaries with file capabilities. Se estiver presente, essas mudanças de privilégio pós-execução são interrompidas. O efeito é especialmente relevante em imagens base amplas que incluem muitas utilidades que a aplicação nunca precisou, desde o início.

## Configurações incorretas

O problema mais comum é simplesmente não habilitar o controle em ambientes onde ele seria compatível. Em Kubernetes, deixar `allowPrivilegeEscalation` habilitado é frequentemente o erro operacional padrão. Em Docker e Podman, omitir a opção de segurança relevante tem o mesmo efeito. Outro modo recorrente de falha é assumir que, porque um container está "not privileged", as transições de privilégio em tempo de execução são automaticamente irrelevantes.

## Abuso

Se `no_new_privs` não estiver definido, a primeira pergunta é se a imagem contém binaries que ainda podem elevar privilégios:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 50
getcap -r / 2>/dev/null | head -n 50
```
Resultados interessantes incluem:

- `NoNewPrivs: 0`
- setuid helpers como `su`, `mount`, `passwd` ou ferramentas de administração específicas da distribuição
- binários com file capabilities que concedem privilégios de rede ou do sistema de arquivos

Em uma avaliação real, essas descobertas não provam, por si só, uma escalada funcional, mas identificam exatamente os binários que vale a pena testar em seguida.

### Exemplo completo: In-Container Privilege Escalation Through setuid

Este controle normalmente previne **in-container privilege escalation** em vez de host escape diretamente. Se `NoNewPrivs` for `0` e um setuid helper existir, teste-o explicitamente:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 20
/usr/bin/passwd -S root 2>/dev/null
```
Se um binário setuid conhecido estiver presente e funcional, tente executá-lo de modo que preserve a transição de privilégios:
```bash
/bin/su -c id 2>/dev/null
```
Isso por si só não escapa do container, mas pode converter um foothold de baixa privilégio dentro do container em container-root, o que frequentemente se torna o pré-requisito para uma posterior fuga para o host através de mounts, runtime sockets ou interfaces voltadas ao kernel.

## Verificações

O objetivo dessas verificações é estabelecer se a obtenção de privilégios em tempo de execução (exec-time) está bloqueada e se a imagem ainda contém helpers que seriam relevantes caso não esteja.
```bash
grep NoNewPrivs /proc/self/status      # Whether exec-time privilege gain is blocked
find / -perm -4000 -type f 2>/dev/null | head -n 50   # setuid files
getcap -r / 2>/dev/null | head -n 50   # files with Linux capabilities
```
O que é interessante aqui:

- `NoNewPrivs: 1` normalmente é o resultado mais seguro.
- `NoNewPrivs: 0` significa que caminhos de escalada baseados em setuid e file-cap permanecem relevantes.
- Uma imagem minimalista com poucos ou nenhum binário setuid/file-cap dá ao atacante menos opções de pós-exploração mesmo quando `no_new_privs` está ausente.

## Padrões em tempo de execução

| Runtime / plataforma | Estado padrão | Comportamento padrão | Enfraquecimento manual comum |
| --- | --- | --- | --- |
| Docker Engine | Não habilitado por padrão | Habilitado explicitamente com `--security-opt no-new-privileges=true` | omitir a flag, `--privileged` |
| Podman | Não habilitado por padrão | Habilitado explicitamente com `--security-opt no-new-privileges` ou configuração de segurança equivalente | omitir a opção, `--privileged` |
| Kubernetes | Controlado pela política da carga de trabalho | `allowPrivilegeEscalation: false` habilita o efeito; muitas cargas de trabalho ainda o deixam habilitado | `allowPrivilegeEscalation: true`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Segue as configurações de carga de trabalho do Kubernetes | Normalmente herdado do Pod security context | mesmo que a linha do Kubernetes |

Essa proteção costuma estar ausente simplesmente porque ninguém a ativou, não porque o runtime não a suporta.
{{#include ../../../../banners/hacktricks-training.md}}
