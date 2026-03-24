# `no_new_privs`

{{#include ../../../../banners/hacktricks-training.md}}

`no_new_privs` é um recurso de hardening do kernel que impede um processo de obter mais privilégios através de `execve()`. Em termos práticos, uma vez que a flag está definida, executar um binário setuid, um binário setgid ou um arquivo com Linux file capabilities não concede privilégios adicionais além dos que o processo já possuía. Em ambientes containerized, isso é importante porque muitas cadeias de privilege-escalation dependem de encontrar um executável dentro da imagem que altera privilégios quando executado.

Do ponto de vista defensivo, `no_new_privs` não substitui namespaces, seccomp ou capability dropping. É uma camada de reforço. Bloqueia uma classe específica de escalada subsequente após a execução de código já ter sido obtida. Isso o torna particularmente valioso em ambientes onde imagens contêm binários auxiliares, artefatos do package-manager ou ferramentas legadas que seriam perigosas quando combinadas com um comprometimento parcial.

## Operação

A flag do kernel por trás desse comportamento é `PR_SET_NO_NEW_PRIVS`. Uma vez definida para um processo, chamadas posteriores a `execve()` não podem aumentar privilégios. O detalhe importante é que o processo ainda pode executar binários; simplesmente não pode usar esses binários para cruzar uma fronteira de privilégios que o kernel normalmente honraria.

Em ambientes orientados a Kubernetes, `allowPrivilegeEscalation: false` mapeia esse comportamento para o processo do container. Em runtimes no estilo Docker e Podman, o equivalente geralmente é habilitado explicitamente por uma opção de segurança.

## Lab

Inspecione o estado atual do processo:
```bash
grep NoNewPrivs /proc/self/status
```
Compare isso com um container onde o runtime habilita a flag:
```bash
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'grep NoNewPrivs /proc/self/status'
```
Em uma carga de trabalho reforçada, o resultado deve mostrar `NoNewPrivs: 1`.

## Security Impact

Se `no_new_privs` estiver ausente, um foothold dentro do container ainda pode ser elevado através de setuid helpers ou binários com file capabilities. Se estiver presente, essas alterações de privilégio pós-exec são interrompidas. O efeito é especialmente relevante em imagens base amplas que trazem muitas utilities que a aplicação nunca precisou.

## Misconfigurations

O problema mais comum é simplesmente não habilitar o controle em ambientes onde ele seria compatível. Em Kubernetes, deixar `allowPrivilegeEscalation` habilitado é frequentemente o erro operacional padrão. No Docker e Podman, omitir a opção de segurança relevante tem o mesmo efeito. Outro modo de falha recorrente é presumir que, porque um container é "not privileged", as transições de privilégio em tempo de exec são automaticamente irrelevantes.

## Abuse

Se `no_new_privs` não estiver definido, a primeira pergunta é se a imagem contém binários que ainda podem elevar privilégios:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 50
getcap -r / 2>/dev/null | head -n 50
```
Resultados interessantes incluem:

- `NoNewPrivs: 0`
- setuid helpers como `su`, `mount`, `passwd` ou ferramentas administrativas específicas da distribuição
- binários com file capabilities que concedem privilégios de rede ou do sistema de arquivos

Em uma avaliação real, essas descobertas por si só não provam uma working escalation, mas identificam exatamente os binaries que valem a pena testar em seguida.

### Exemplo completo: In-Container Privilege Escalation Through setuid

Esse controle geralmente previne **in-container privilege escalation** em vez de host escape diretamente. Se `NoNewPrivs` for `0` e existir um setuid helper, teste-o explicitamente:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 20
/usr/bin/passwd -S root 2>/dev/null
```
Se um binário setuid conhecido estiver presente e funcional, tente executá-lo de forma que preserve a transição de privilégios:
```bash
/bin/su -c id 2>/dev/null
```
Isso por si só não permite escapar do container, mas pode converter um acesso inicial de baixa privilégio dentro do container em root do container, o que frequentemente se torna o pré-requisito para uma fuga posterior para o host através de pontos de montagem (mounts), sockets em tempo de execução ou interfaces voltadas ao kernel.

## Verificações

O objetivo destas verificações é determinar se o ganho de privilégios em tempo de execução está bloqueado e se a imagem ainda contém auxiliares que seriam relevantes caso não esteja.
```bash
grep NoNewPrivs /proc/self/status      # Whether exec-time privilege gain is blocked
find / -perm -4000 -type f 2>/dev/null | head -n 50   # setuid files
getcap -r / 2>/dev/null | head -n 50   # files with Linux capabilities
```
O que é interessante aqui:

- `NoNewPrivs: 1` é geralmente o resultado mais seguro.
- `NoNewPrivs: 0` significa que caminhos de escalada baseados em setuid e file-cap permanecem relevantes.
- Uma imagem mínima com poucos ou nenhum binário setuid/file-cap dá a um atacante menos opções de post-exploitation mesmo quando `no_new_privs` está ausente.

## Padrões em tempo de execução

| Runtime / plataforma | Estado padrão | Comportamento padrão | Enfraquecimento manual comum |
| --- | --- | --- | --- |
| Docker Engine | Não habilitado por padrão | Habilitado explicitamente com `--security-opt no-new-privileges=true` | omitir a flag, `--privileged` |
| Podman | Não habilitado por padrão | Habilitado explicitamente com `--security-opt no-new-privileges` ou configuração de segurança equivalente | omitir a opção, `--privileged` |
| Kubernetes | Controlado pela política de workload | `allowPrivilegeEscalation: false` habilita o efeito; muitas workloads ainda o deixam habilitado | `allowPrivilegeEscalation: true`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Segue as configurações de workload do Kubernetes | Geralmente herdado do Pod security context | mesmo que a linha do Kubernetes |

Essa proteção costuma estar ausente simplesmente porque ninguém a ativou, e não porque o runtime não oferece suporte a ela.
{{#include ../../../../banners/hacktricks-training.md}}
