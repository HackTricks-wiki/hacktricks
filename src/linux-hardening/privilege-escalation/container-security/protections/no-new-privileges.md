# `no_new_privs`

{{#include ../../../../banners/hacktricks-training.md}}

`no_new_privs` é uma funcionalidade de hardening do kernel que previne que um processo ganhe mais privilégios via `execve()`. Na prática, uma vez que a flag está definida, executar um setuid binary, um setgid binary, ou um arquivo com Linux file capabilities não concede privilégios além dos que o processo já possuía. Em ambientes conteinerizados, isso é importante porque muitas chains de privilege-escalation dependem de encontrar um executável dentro da imagem que altera privilégios ao ser executado.

Do ponto de vista defensivo, `no_new_privs` não é um substituto para namespaces, seccomp ou capability dropping. É uma camada de reforço. Bloqueia uma classe específica de escalada subsequente após a execução de código já ter sido obtida. Isso a torna particularmente valiosa em ambientes onde imagens contêm binários auxiliares, artefatos do gerenciador de pacotes ou ferramentas legadas que, de outra forma, seriam perigosas quando combinadas com comprometimento parcial.

## Operation

A flag do kernel por trás desse comportamento é `PR_SET_NO_NEW_PRIVS`. Uma vez definida para um processo, chamadas posteriores a `execve()` não podem aumentar privilégios. O detalhe importante é que o processo ainda pode executar binários; simplesmente não pode usar esses binários para atravessar uma fronteira de privilégio que o kernel normalmente honraria.

Em ambientes orientados a Kubernetes, `allowPrivilegeEscalation: false` mapeia para esse comportamento para o processo do container. Em runtimes estilo Docker e Podman, o equivalente normalmente é habilitado explicitamente por meio de uma opção de segurança.

## Lab

Inspecione o estado do processo atual:
```bash
grep NoNewPrivs /proc/self/status
```
Compare isso com um container onde o runtime ativa a flag:
```bash
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'grep NoNewPrivs /proc/self/status'
```
Em uma carga de trabalho reforçada, o resultado deve mostrar `NoNewPrivs: 1`.

## Impacto na Segurança

Se `no_new_privs` estiver ausente, um foothold dentro do container ainda pode ser elevado através de setuid helpers ou binários com file capabilities. Se estiver presente, essas mudanças de privilégio pós-exec são interrompidas. O efeito é especialmente relevante em imagens base amplas que incluem muitas utilities que a aplicação nem precisava originalmente.

## Misconfigurações

O problema mais comum é simplesmente não habilitar o controle em ambientes onde ele seria compatível. Em Kubernetes, deixar `allowPrivilegeEscalation` habilitado é frequentemente o erro operacional padrão. Em Docker e Podman, omitir a opção de segurança relevante tem o mesmo efeito. Outro modo recorrente de falha é assumir que, porque um container é "not privileged", transições de privilégio em tempo de exec são automaticamente irrelevantes.

## Abuso

Se `no_new_privs` não estiver definido, a primeira pergunta é se a imagem contém binários que ainda podem elevar privilégios:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 50
getcap -r / 2>/dev/null | head -n 50
```
Resultados interessantes incluem:

- `NoNewPrivs: 0`
- auxiliares setuid como `su`, `mount`, `passwd` ou ferramentas administrativas específicas da distribuição
- binários com file capabilities que concedem privilégios de rede ou do sistema de arquivos

Em uma avaliação real, essas descobertas por si só não provam uma escalada funcional, mas identificam exatamente os binários que valem a pena testar a seguir.

### Exemplo completo: Escalada de privilégios dentro do container através de setuid

Este controle normalmente previne a **escalada de privilégios dentro do container** em vez de escapar diretamente para o host. Se `NoNewPrivs` for `0` e existir um auxiliar setuid, teste-o explicitamente:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 20
/usr/bin/passwd -S root 2>/dev/null
```
Se um binário setuid conhecido estiver presente e funcional, tente executá-lo de forma que preserve a transição de privilégios:
```bash
/bin/su -c id 2>/dev/null
```
Isso, por si só, não permite escape the container, mas pode converter um low-privilege foothold dentro do container em container-root, o que frequentemente se torna o pré-requisito para um posterior host escape através de mounts, runtime sockets ou kernel-facing interfaces.

## Verificações

O objetivo dessas verificações é estabelecer se exec-time privilege gain está bloqueado e se a image ainda contém helpers que fariam diferença caso não esteja.
```bash
grep NoNewPrivs /proc/self/status      # Whether exec-time privilege gain is blocked
find / -perm -4000 -type f 2>/dev/null | head -n 50   # setuid files
getcap -r / 2>/dev/null | head -n 50   # files with Linux capabilities
```
O que é interessante aqui:

- `NoNewPrivs: 1` geralmente é o resultado mais seguro.
- `NoNewPrivs: 0` significa que caminhos de escalada baseados em setuid e file-cap continuam relevantes.
- Uma imagem mínima com poucos ou nenhum binário setuid/file-cap oferece ao atacante menos opções de pós-exploração mesmo quando `no_new_privs` está ausente.

## Padrões em tempo de execução

| Runtime / plataforma | Estado padrão | Comportamento padrão | Enfraquecimento manual comum |
| --- | --- | --- | --- |
| Docker Engine | Não ativado por padrão | Ativado explicitamente com `--security-opt no-new-privileges=true` | omitindo a flag, `--privileged` |
| Podman | Não ativado por padrão | Ativado explicitamente com `--security-opt no-new-privileges` ou configuração de segurança equivalente | omitindo a opção, `--privileged` |
| Kubernetes | Controlado pela política de carga de trabalho | `allowPrivilegeEscalation: false` ativa o efeito; muitas cargas de trabalho ainda o deixam ativado | `allowPrivilegeEscalation: true`, `privileged: true` |
| containerd / CRI-O sob Kubernetes | Segue as configurações de carga de trabalho do Kubernetes | Geralmente herdado do contexto de segurança do Pod | mesmo que a linha do Kubernetes |

Essa proteção costuma estar ausente simplesmente porque ninguém a ativou, e não porque o runtime não ofereça suporte a ela.
