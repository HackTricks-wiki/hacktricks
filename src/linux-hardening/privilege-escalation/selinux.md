# SELinux

{{#include ../../banners/hacktricks-training.md}}

SELinux é um sistema **label-based Mandatory Access Control (MAC)**. Na prática, isso significa que mesmo que as permissões DAC, groups ou Linux capabilities pareçam suficientes para uma ação, o kernel ainda pode negá-la porque o **source context** não tem permissão para acessar o **target context** com a class/permission solicitada.

Um context normalmente se parece com:
```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```
Do ponto de vista de privesc, o `type` (domain para processos, type para objetos) costuma ser o campo mais importante:

- Um processo roda em um **domain** como `unconfined_t`, `staff_t`, `httpd_t`, `container_t`, `sysadm_t`
- Arquivos e sockets têm um **type** como `admin_home_t`, `shadow_t`, `httpd_sys_rw_content_t`, `container_file_t`
- A policy decide se um domain pode read/write/execute/transition para o outro

## Fast Enumeration

Se o SELinux estiver habilitado, enumere-o cedo porque ele pode explicar por que caminhos comuns de privesc no Linux falham ou por que um wrapper privilegiado em torno de uma ferramenta SELinux "inofensiva" é na verdade crítico:
```bash
getenforce
sestatus
id -Z
ps -eZ | head
cat /proc/self/attr/current
ls -Zd / /root /home /tmp /etc /var/www 2>/dev/null
```
Verificações úteis de follow-up:
```bash
# Installed policy modules and local customizations
semodule -lfull 2>/dev/null
semanage fcontext -C -l 2>/dev/null
semanage permissive -l 2>/dev/null
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null

# Labels that frequently reveal mistakes or unusual paths
find / -context '*:default_t:*' -o -context '*:file_t:*' 2>/dev/null

# Compare current label vs policy default for a path
matchpathcon -V /path/of/interest 2>/dev/null
restorecon -n -v /path/of/interest 2>/dev/null
```
Descobertas interessantes:

- Modo `Disabled` ou `Permissive` remove a maior parte do valor do SELinux como uma boundary.
- `unconfined_t` normalmente significa que o SELinux está presente, mas não está restringindo de forma significativa esse processo.
- `default_t`, `file_t`, ou labels obviamente incorretos em caminhos customizados frequentemente indicam mislabeling ou deployment incompleto.
- Overrides locais em `file_contexts.local` têm precedência sobre os defaults da policy, então revise-os com cuidado.

## Policy Analysis

O SELinux é muito mais fácil de atacar ou bypass quando você consegue responder a duas perguntas:

1. **A que meu domain atual pode acessar?**
2. **Para quais domains eu posso transicionar?**

As ferramentas mais úteis para isso são `sepolicy` e **SETools** (`seinfo`, `sesearch`, `sedta`):
```bash
# Transition graph from the current domain
sepolicy transition -s "$(id -Z | awk -F: '{print $3}')" 2>/dev/null

# Search allow and type_transition rules
sesearch -A -s staff_t 2>/dev/null | head
sesearch --type_transition -s staff_t 2>/dev/null | head

# Inspect policy components
seinfo -t 2>/dev/null | head
seinfo -r 2>/dev/null | head
```
Isso é especialmente útil quando um host usa **confined users** em vez de mapear todo mundo para `unconfined_u`. Nesse caso, procure por:

- mapeamentos de usuário via `semanage login -l`
- roles permitidos via `semanage user -l`
- domínios admin alcançáveis, como `sysadm_t`, `secadm_t`, `webadm_t`
- entradas em `sudoers` usando `ROLE=` ou `TYPE=`

Se `sudo -l` contiver entradas assim, SELinux faz parte da boundary de privilege:
```text
linux_user ALL=(ALL) ROLE=webadm_r TYPE=webadm_t /bin/bash
```
Além disso, verifique se `newrole` está disponível:
```bash
sudo -l
which newrole runcon
newrole -l 2>/dev/null
```
`runcon` e `newrole` não são automaticamente exploráveis, mas se um wrapper privilegiado ou uma regra `sudoers` permitir que você selecione um role/type melhor, eles se tornam primitives de escalada de alto valor.

## Files, Relabeling, and High-Value Misconfigurations

A diferença operacional mais importante entre as ferramentas comuns do SELinux é:

- `chcon`: alteração temporária de label em um path específico
- `semanage fcontext`: regra persistente de path-to-label
- `restorecon` / `setfiles`: aplica novamente a policy/label padrão

Isso importa muito durante privesc porque **relabeling não é apenas cosmético**. Pode transformar um arquivo de "bloqueado pela policy" em "legível/executável por um serviço confinado privilegiado".

Verifique regras locais de relabel e relabel drift:
```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```
Um detalhe sutil, mas útil: `restorecon` simples **nem sempre reverte totalmente um rótulo suspeito**. Se o tipo de destino estiver em `customizable_types`, você pode precisar de `-F` para forçar um reset completo. Do ponto de vista ofensivo, isso explica por que um `chcon` incomum às vezes pode sobreviver a uma limpeza casual do tipo "já rodamos `restorecon`".
```bash
grep -R . /etc/selinux/*/contexts/customizable_types 2>/dev/null | head
restorecon -n -v /path/of/interest 2>/dev/null
restorecon -F -v /path/of/interest 2>/dev/null
```
Comandos de alto valor para caçar em `sudo -l`, root wrappers, scripts de automação ou file capabilities:
```bash
which semanage restorecon chcon setfiles semodule audit2allow runcon newrole setsebool load_policy 2>/dev/null
getcap -r / 2>/dev/null | grep -E 'cap_mac_admin|cap_mac_override'
```
Se qualquer capacidade MAC aparecer, verifique também a [Linux capabilities page](linux-capabilities.md); `cap_mac_admin` e `cap_mac_override` são incomuns, mas diretamente relevantes quando SELinux faz parte da boundary.

Especialmente interessante:

- `semanage fcontext`: altera de forma persistente qual label um path deve receber
- `restorecon` / `setfiles`: reaplica essas mudanças em escala
- `semodule -i`: carrega um custom policy module
- `semanage permissive -a <domain_t>`: torna um domínio permissive sem desativar o host inteiro
- `setsebool -P`: altera permanentemente os policy booleans
- `load_policy`: recarrega a policy ativa

Isso geralmente são **helper primitives**, não root exploits independentes. O valor delas é que permitem:

- tornar um domain alvo permissive
- ampliar o acesso entre seu domain e um tipo protegido
- relabel arquivos controlados pelo atacante para que um serviço privilegiado possa lê-los ou executá-los
- enfraquecer um serviço confinado o suficiente para que um bug local existente se torne explorável

Exemplo de checks:
```bash
# If sudo exposes semanage/restorecon, think in terms of policy abuse
sudo -l | grep -E 'semanage|restorecon|setfiles|semodule|runcon|newrole|setsebool|load_policy'

# Look for places where local file-context overrides may matter
semanage fcontext -C -l 2>/dev/null
restorecon -n -v /usr/local/bin /opt /srv /var/www 2>/dev/null
```
Se você puder carregar um módulo de política como root, normalmente você controla a fronteira do SELinux:
```bash
ausearch -m AVC,USER_AVC -ts recent 2>/dev/null | audit2allow -M localfix
sudo semodule -i localfix.pp
```
É por isso que `audit2allow`, `semodule` e `semanage permissive` devem ser tratados como superfícies de admin sensíveis durante post-exploitation. Eles podem converter silenciosamente uma cadeia bloqueada em uma funcional sem alterar as permissões clássicas do UNIX.

## Negativas Ocultas e Extração de Módulos

Uma frustração ofensiva muito comum é uma cadeia que falha com um simples `EACCES` enquanto a negação AVC esperada nunca aparece. Regras `dontaudit` podem estar ocultando a permissão exata de que você precisa. Se você conseguir executar `semodule` via `sudo` ou outro wrapper privilegiado, desabilitar temporariamente `dontaudit` pode transformar uma falha silenciosa em uma pista precisa da policy:
```bash
# Rebuild policy without dontaudit rules, trigger the action again, then inspect AVCs
sudo semodule -DB
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null | tail -n 50
sudo semodule -B

# Extract installed modules for offline review / diffing
semodule -lfull 2>/dev/null
semodule -E --cil <module_name> 2>/dev/null
```
Isto também é útil para revisar o que os admins locais já alteraram. Um pequeno módulo customizado ou uma regra permissive de um único domínio costuma ser o motivo de um serviço alvo se comportar de forma muito mais relaxada do que a base policy sugeriria.

## Audit Clues

AVC denials muitas vezes são sinal ofensivo, não apenas ruído defensivo. Elas mostram para você:

- qual objeto/type alvo você atingiu
- qual permissão foi denied
- qual domain você controla atualmente
- se uma pequena mudança de policy faria a cadeia funcionar
```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```
Se um exploit local ou uma tentativa de persistence continuar falhando com `EACCES` ou erros estranhos de "permission denied" apesar de permissões DAC com aparência de root, normalmente vale a pena verificar o SELinux antes de descartar o vetor.

## SELinux Users

Existem SELinux users além dos usuários Linux normais. Cada usuário Linux é mapeado para um SELinux user como parte da policy, o que permite que o sistema imponha diferentes roles e domains permitidos em contas diferentes.

Quick checks:
```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
sudo -l 2>/dev/null
grep -R "ROLE=\|TYPE=" /etc/sudoers /etc/sudoers.d 2>/dev/null
```
Em muitos sistemas mainstream, os usuários são mapeados para `unconfined_u`, o que reduz o impacto prático do confinamento de usuário. Em implantações hardened, no entanto, usuários confined podem tornar `sudo`, `su`, `newrole` e `runcon` muito mais interessantes porque **o caminho de escalation pode depender de entrar em um melhor SELinux role/type, e não apenas de se tornar UID 0**. Lembre-se também de que alguns usuários confined não podem invocar `sudo`/`su` de forma alguma, a menos que a policy permita explicitamente a transição setuid subjacente, então um host usando `staff_u` + `sysadm_r` pode transformar uma regra aparentemente pequena de `sudo ROLE=` / `TYPE=` na verdadeira fronteira de privilege.

## SELinux in Containers

Os runtimes de container normalmente iniciam workloads em um domínio confined como `container_t` e rotulam o conteúdo do container como `container_file_t`. Se um processo do container escapar, mas ainda estiver sendo executado com o label do container, gravações no host ainda podem falhar porque a fronteira de label permaneceu intacta.

Exemplo rápido:
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
A parte `c647,c780` não é decoração. Em muitas implantações de containers, os runtimes atribuem dinamicamente categorias MCS para que dois processos executando como `container_t` ainda fiquem separados entre si. Se um escape te levar para um namespace do host, mas mantiver o conjunto original de categorias, divergências de categorias ainda podem explicar por que alguns caminhos do host permanecem ilegíveis ou não graváveis.

Operações modernas de container que vale notar:

- `--security-opt label=disable` pode efetivamente mover a carga de trabalho para um tipo relacionado a container sem restrições, como `spc_t`
- bind mounts com `:z` / `:Z` acionam relabeling do caminho do host para uso compartilhado/privado do container
- relabeling amplo de conteúdo do host pode se tornar um problema de segurança por si só

Esta página mantém o conteúdo de container curto para evitar duplicação. Para os casos de abuso específicos de container e exemplos de runtime, confira:

{{#ref}}
container-security/protections/selinux.md
{{#endref}}

## References

- [Red Hat docs: Using SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [SETools: Policy analysis tools for SELinux](https://github.com/SELinuxProject/setools)
- [Managing confined and unconfined users - RHEL 9 docs](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/using_selinux/managing-confined-and-unconfined-users_using-selinux)
- [semodule(8) - Linux manual page](https://man7.org/linux/man-pages/man8/semodule.8.html)
{{#include ../../banners/hacktricks-training.md}}
