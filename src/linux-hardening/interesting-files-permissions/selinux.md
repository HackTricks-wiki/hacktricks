# SELinux

{{#include ../../banners/hacktricks-training.md}}

SELinux é um sistema de **Mandatory Access Control (MAC) baseado em labels**. Na prática, isso significa que, mesmo que as permissões DAC, os grupos ou as Linux capabilities pareçam suficientes para uma ação, o kernel ainda pode negá-la porque o **source context** não tem permissão para acessar o **target context** com a classe/permissão solicitada.

Um context geralmente se parece com:
```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```
De uma perspectiva de privesc, o `type` (domínio para processos, tipo para objetos) geralmente é o campo mais importante:

- Um processo é executado em um **domínio**, como `unconfined_t`, `staff_t`, `httpd_t`, `container_t`, `sysadm_t`
- Arquivos e sockets têm um **tipo**, como `admin_home_t`, `shadow_t`, `httpd_sys_rw_content_t`, `container_file_t`
- A policy decide se um domínio pode ler/gravar/executar/fazer transition para o outro

## Enumeração Rápida

Se o SELinux estiver habilitado, enumere-o logo no início, pois ele pode explicar por que caminhos comuns de privesc no Linux falham ou por que um wrapper privilegiado em torno de uma ferramenta SELinux "inofensiva" é, na verdade, crítico:
```bash
getenforce
sestatus
id -Z
ps -eZ | head
cat /proc/self/attr/current
ls -Zd / /root /home /tmp /etc /var/www 2>/dev/null
```
Verificações úteis de acompanhamento:
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
Descobertas importantes:

- O modo `Disabled` ou `Permissive` remove grande parte do valor do SELinux como boundary.
- `unconfined_t` geralmente significa que o SELinux está presente, mas não está restringindo significativamente esse processo.
- `default_t`, `file_t` ou labels obviamente incorretos em paths personalizados geralmente indicam mislabeling ou deployment incompleto.
- Overrides locais em `file_contexts.local` têm precedência sobre os defaults da policy, portanto, revise-os cuidadosamente.

## Análise da Policy

O SELinux é muito mais fácil de atacar ou contornar quando você consegue responder a duas perguntas:

1. **O que meu domínio atual pode acessar?**
2. **Para quais domínios posso fazer transition?**

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
Isso é especialmente útil quando um host usa **usuários confinados** em vez de mapear todos para `unconfined_u`. Nesse caso, procure por:

- mapeamentos de usuários via `semanage login -l`
- roles permitidas via `semanage user -l`
- domínios administrativos acessíveis, como `sysadm_t`, `secadm_t`, `webadm_t`
- entradas em `sudoers` usando `ROLE=` ou `TYPE=`

Se `sudo -l` contiver entradas como esta, o SELinux faz parte do limite de privilégio:
```text
linux_user ALL=(ALL) ROLE=webadm_r TYPE=webadm_t /bin/bash
```
Verifique também se `newrole` está disponível:
```bash
sudo -l
which newrole runcon
newrole -l 2>/dev/null
```
`runcon` e `newrole` não são automaticamente exploráveis, mas, se um wrapper privilegiado ou uma regra `sudoers` permitir selecionar uma role/type melhor, eles se tornam primitives de alto valor para escalation.

## Arquivos, Relabeling e Misconfigurações de Alto Valor

A diferença operacional mais importante entre as ferramentas comuns do SELinux é:

- `chcon`: alteração temporária de label em um path específico
- `semanage fcontext`: regra persistente de path-to-label
- `restorecon` / `setfiles`: aplica novamente o label definido pela policy/default

Isso é muito importante durante o privesc porque **relabeling não é apenas cosmético**. Ele pode transformar um arquivo de "bloqueado pela policy" em "legível/executável por um serviço confinado privilegiado".

Verifique as regras locais de relabel e o relabel drift:
```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```
Um detalhe sutil, mas útil: o `restorecon` simples **nem sempre reverte completamente um label suspeito**. Se o tipo de destino estiver em `customizable_types`, talvez seja necessário usar `-F` para forçar uma redefinição completa. De uma perspectiva ofensiva, isso explica por que um `chcon` incomum às vezes pode sobreviver a uma limpeza superficial do tipo "já executamos o restorecon".
```bash
grep -R . /etc/selinux/*/contexts/customizable_types 2>/dev/null | head
restorecon -n -v /path/of/interest 2>/dev/null
restorecon -F -v /path/of/interest 2>/dev/null
```
Comandos de alto valor para buscar em `sudo -l`, wrappers de root, scripts de automação ou capacidades de arquivos:
```bash
which semanage restorecon chcon setfiles semodule audit2allow runcon newrole setsebool load_policy 2>/dev/null
getcap -r / 2>/dev/null | grep -E 'cap_mac_admin|cap_mac_override'
```
Se qualquer uma das capacidades MAC aparecer, verifique também a [página de Linux capabilities](linux-capabilities.md); `cap_mac_admin` e `cap_mac_override` são incomuns, mas diretamente relevantes quando o SELinux faz parte do limite de segurança.

Especialmente interessantes:

- `semanage fcontext`: altera persistentemente qual label um path deve receber
- `restorecon` / `setfiles`: reaplica essas alterações em escala
- `semodule -i`: carrega um módulo de policy personalizado
- `semanage permissive -a <domain_t>`: torna um domínio permissive sem alterar todo o host
- `setsebool -P`: altera permanentemente os policy booleans
- `load_policy`: recarrega a policy ativa

Frequentemente, estes são **helper primitives**, não root exploits independentes. Seu valor está em permitir que você:

- torne um domínio-alvo permissive
- amplie o acesso entre seu domínio e um tipo protegido
- faça o relabel de arquivos controlados pelo atacante para que um serviço privilegiado possa lê-los ou executá-los
- enfraqueça um serviço confinado o suficiente para que um bug local existente se torne explorável

Verificações de exemplo:
```bash
# If sudo exposes semanage/restorecon, think in terms of policy abuse
sudo -l | grep -E 'semanage|restorecon|setfiles|semodule|runcon|newrole|setsebool|load_policy'

# Look for places where local file-context overrides may matter
semanage fcontext -C -l 2>/dev/null
restorecon -n -v /usr/local/bin /opt /srv /var/www 2>/dev/null
```
Se você conseguir carregar um módulo de política como root, normalmente controlará o limite do SELinux:
```bash
ausearch -m AVC,USER_AVC -ts recent 2>/dev/null | audit2allow -M localfix
sudo semodule -i localfix.pp
```
É por isso que `audit2allow`, `semodule` e `semanage permissive` devem ser tratados como superfícies administrativas sensíveis durante o post-exploitation. Eles podem converter silenciosamente uma cadeia bloqueada em uma cadeia funcional sem alterar as permissões clássicas do UNIX.

## Denials Ocultas e Extração de Módulos

Uma frustração ofensiva muito comum é uma cadeia que falha com um `EACCES` genérico enquanto a AVC denial esperada nunca aparece. As regras `dontaudit` podem estar ocultando exatamente a permissão de que você precisa. Se você puder executar `semodule` por meio do `sudo` ou de outro wrapper privilegiado, desabilitar temporariamente `dontaudit` pode transformar uma falha silenciosa em uma indicação precisa da policy:
```bash
# Rebuild policy without dontaudit rules, trigger the action again, then inspect AVCs
sudo semodule -DB
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null | tail -n 50
sudo semodule -B

# Extract installed modules for offline review / diffing
semodule -lfull 2>/dev/null
semodule -E --cil <module_name> 2>/dev/null
```
Isso também é útil para revisar o que os administradores locais já alteraram. Um pequeno módulo customizado ou uma regra permissive para um único domínio costuma ser o motivo pelo qual um serviço-alvo se comporta de forma muito mais permissiva do que a política base sugeriria.

## Pistas de auditoria

As negações AVC geralmente são um sinal ofensivo, não apenas ruído defensivo. Elas informam:

- qual objeto/tipo-alvo você atingiu
- qual permissão foi negada
- qual domínio você controla atualmente
- se uma pequena alteração na política faria a chain funcionar
```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```
Se uma exploração local ou tentativa de persistência continuar falhando com `EACCES` ou erros estranhos de "permissão negada", apesar de permissões DAC que parecem ser de root, geralmente vale a pena verificar o SELinux antes de descartar o vetor.

## Usuários do SELinux

Além dos usuários Linux comuns, existem usuários do SELinux. Cada usuário Linux é associado a um usuário do SELinux como parte da policy, permitindo que o sistema imponha diferentes roles e domains a diferentes contas.

Verificações rápidas:
```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
sudo -l 2>/dev/null
grep -R "ROLE=\|TYPE=" /etc/sudoers /etc/sudoers.d 2>/dev/null
```
Em muitos sistemas convencionais, os usuários são mapeados para `unconfined_u`, o que reduz o impacto prático do confinement de usuários. Em deployments hardened, no entanto, usuários confinados podem tornar `sudo`, `su`, `newrole` e `runcon` muito mais interessantes, porque **o caminho de escalation pode depender da entrada em uma role/type melhor do SELinux, e não apenas de se tornar UID 0**. Lembre-se também de que alguns usuários confinados não podem invocar `sudo`/`su` de forma alguma, a menos que a policy permita explicitamente a transição setuid subjacente. Assim, um host que use `staff_u` + `sysadm_r` pode transformar uma regra aparentemente menor de `sudo ROLE=` / `TYPE=` no verdadeiro limite de privilégios.

## SELinux em Containers

Os runtimes de containers geralmente iniciam workloads em um domain confinado, como `container_t`, e rotulam o conteúdo do container como `container_file_t`. Se um processo do container escapar, mas ainda estiver sendo executado com o label do container, as gravações no host ainda poderão falhar porque o limite de labels permaneceu intacto.

Exemplo rápido:
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
A parte `c647,c780` não é decoração. Em muitas implantações de containers, os runtimes atribuem dinamicamente categorias MCS para que dois processos executando como `container_t` ainda permaneçam separados. Se um escape levar você a um namespace do host, mas mantiver o conjunto de categorias original, incompatibilidades de categorias ainda poderão explicar por que alguns paths do host continuam sem permissão de leitura ou escrita.

Operações modernas de containers que vale observar:

- `--security-opt label=disable` pode efetivamente mover o workload para um tipo relacionado a containers e sem confinamento, como `spc_t`
- bind mounts com `:z` / `:Z` acionam o relabeling do path do host para uso compartilhado/privado por containers
- o relabeling amplo do conteúdo do host pode se tornar um security issue por si só

Esta página mantém o conteúdo sobre containers curto para evitar duplicação. Para os casos de abuso específicos de containers e exemplos de runtimes, consulte:

{{#ref}}
../containers-namespaces/container-security/protections/selinux.md
{{#endref}}

## Referências

- [Red Hat docs: Using SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [SETools: Policy analysis tools for SELinux](https://github.com/SELinuxProject/setools)
- [Managing confined and unconfined users - RHEL 9 docs](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/using_selinux/managing-confined-and-unconfined-users_using-selinux)
- [semodule(8) - Linux manual page](https://man7.org/linux/man-pages/man8/semodule.8.html)
{{#include ../../banners/hacktricks-training.md}}
