# SELinux

{{#include ../../banners/hacktricks-training.md}}

SELinux é um sistema de **Mandatory Access Control (MAC) baseado em labels**. Na prática, isso significa que, mesmo que as permissões DAC, os grupos ou as Linux capabilities pareçam suficientes para uma ação, o kernel ainda pode negá-la porque o **contexto de origem** não tem permissão para acessar o **contexto de destino** com a classe/permissão solicitada.

Um contexto geralmente se parece com:
```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```
Do ponto de vista de privesc, o `type` (domain para processos, type para objetos) geralmente é o campo mais importante:

- Um processo é executado em um **domain** como `unconfined_t`, `staff_t`, `httpd_t`, `container_t`, `sysadm_t`
- Arquivos e sockets têm um **type** como `admin_home_t`, `shadow_t`, `httpd_sys_rw_content_t`, `container_file_t`
- A policy decide se um domain pode ler/escrever/executar/fazer transition para o outro

## Enumeração rápida

Se o SELinux estiver habilitado, faça a enumeração logo no início, pois isso pode explicar por que caminhos comuns de privesc no Linux falham ou por que um wrapper privilegiado em torno de uma ferramenta "inofensiva" do SELinux é, na verdade, crítico:
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
Achados interessantes:

- O modo `Disabled` ou `Permissive` remove a maior parte do valor do SELinux como limite de segurança.
- `unconfined_t` geralmente significa que o SELinux está presente, mas não está restringindo significativamente esse processo.
- `default_t`, `file_t` ou labels obviamente incorretos em paths personalizados geralmente indicam labels incorretos ou uma implantação incompleta.
- Substituições locais em `file_contexts.local` têm precedência sobre os padrões da policy, portanto, revise-as cuidadosamente.

## Análise da Policy

O SELinux é muito mais fácil de atacar ou contornar quando você consegue responder a duas perguntas:

1. **O que o meu domain atual pode acessar?**
2. **Para quais domains eu posso fazer transition?**

As ferramentas mais úteis para isso são `sepolicy` e **SETools** (`seinfo`, `sesearch`, `sedta`):<sup>[[2]](#references)</sup>
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
Isso é especialmente útil quando um host usa **usuários confinados** em vez de mapear todos para `unconfined_u`. Nesse caso, procure por:<sup>[[3]](#references)</sup>

- mapeamentos de usuários via `semanage login -l`
- roles permitidos via `semanage user -l`
- domínios administrativos acessíveis, como `sysadm_t`, `secadm_t`, `webadm_t`
- entradas de `sudoers` usando `ROLE=` ou `TYPE=`

Se `sudo -l` contiver entradas como esta, o SELinux faz parte do limite de privilégios:
```text
linux_user ALL=(ALL) ROLE=webadm_r TYPE=webadm_t /bin/bash
```
Verifique também se `newrole` está disponível:
```bash
sudo -l
which newrole runcon
newrole -l 2>/dev/null
```
`runcon` e `newrole` não são automaticamente exploráveis, mas, se um wrapper privilegiado ou uma regra `sudoers` permitir selecionar uma role/type melhor, eles se tornam primitives de escalation de alto valor.

## Arquivos, Relabeling e Misconfigurações de Alto Valor

A diferença operacional mais importante entre as ferramentas comuns do SELinux é:<sup>[[1]](#references)</sup>

- `chcon`: alteração temporária de label em um caminho específico
- `semanage fcontext`: regra persistente de caminho para label
- `restorecon` / `setfiles`: aplica novamente o label definido pela policy/default

Isso é muito importante durante o privesc porque **relabeling não é apenas cosmético**. Ele pode transformar um arquivo de "bloqueado pela policy" em "legível/executável por um serviço privilegiado confinado".

Verifique regras locais de relabeling e drift de relabeling:
```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```
Um detalhe sutil, mas útil: um `restorecon` simples **nem sempre reverte completamente um label suspeito**. Se o tipo do alvo estiver em `customizable_types`, talvez seja necessário usar `-F` para forçar uma redefinição completa. De uma perspectiva ofensiva, isso explica por que um `chcon` incomum às vezes pode sobreviver a uma limpeza casual do tipo "já executamos o restorecon".
```bash
grep -R . /etc/selinux/*/contexts/customizable_types 2>/dev/null | head
restorecon -n -v /path/of/interest 2>/dev/null
restorecon -F -v /path/of/interest 2>/dev/null
```
Comandos de alto valor para procurar em `sudo -l`, wrappers de root, scripts de automação ou file capabilities:
```bash
which semanage restorecon chcon setfiles semodule audit2allow runcon newrole setsebool load_policy 2>/dev/null
getcap -r / 2>/dev/null | grep -E 'cap_mac_admin|cap_mac_override'
```
Se alguma das capacidades MAC aparecer, consulte também a [página de Linux capabilities](linux-capabilities.md); `cap_mac_admin` e `cap_mac_override` são incomuns, mas diretamente relevantes quando o SELinux faz parte do limite de segurança.

Especialmente interessantes:

- `semanage fcontext`: altera persistentemente o label que um caminho deve receber
- `restorecon` / `setfiles`: reaplica essas alterações em escala
- `semodule -i`: carrega um custom policy module
- `semanage permissive -a <domain_t>`: torna um domínio permissive sem alterar todo o host
- `setsebool -P`: altera permanentemente os policy booleans
- `load_policy`: recarrega a policy ativa

Geralmente, essas são **primitivas auxiliares**, não root exploits independentes. O valor delas está em permitir que você:

- torne um target domain permissive
- amplie o acesso entre seu domínio e um protected type
- altere o label de arquivos controlados pelo atacante para que um serviço privilegiado possa lê-los ou executá-los
- enfraqueça um serviço confinado o suficiente para que um bug local existente se torne explorável

Verificações de exemplo:
```bash
# If sudo exposes semanage/restorecon, think in terms of policy abuse
sudo -l | grep -E 'semanage|restorecon|setfiles|semodule|runcon|newrole|setsebool|load_policy'

# Look for places where local file-context overrides may matter
semanage fcontext -C -l 2>/dev/null
restorecon -n -v /usr/local/bin /opt /srv /var/www 2>/dev/null
```
Se você puder carregar um módulo de política como root, normalmente controlará a fronteira do SELinux:
```bash
ausearch -m AVC,USER_AVC -ts recent 2>/dev/null | audit2allow -M localfix
sudo semodule -i localfix.pp
```
É por isso que `audit2allow`, `semodule` e `semanage permissive` devem ser tratados como superfícies administrativas sensíveis durante o post-exploitation. Eles podem converter silenciosamente uma cadeia bloqueada em uma cadeia funcional sem alterar as permissões UNIX clássicas.

## Denials Ocultas e Extração de Módulos

Uma frustração ofensiva muito comum é uma cadeia que falha com um `EACCES` genérico, enquanto a AVC denial esperada nunca aparece. As regras `dontaudit` podem estar ocultando exatamente a permissão necessária. Se você puder executar `semodule` por meio de `sudo` ou de outro wrapper privilegiado, desabilitar temporariamente `dontaudit` pode transformar uma falha silenciosa em uma pista precisa da policy:<sup>[[4]](#references)</sup>
```bash
# Rebuild policy without dontaudit rules, trigger the action again, then inspect AVCs
sudo semodule -DB
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null | tail -n 50
sudo semodule -B

# Extract installed modules for offline review / diffing
semodule -lfull 2>/dev/null
semodule -E --cil <module_name> 2>/dev/null
```
Isso também é útil para revisar o que os administradores locais já alteraram. Um pequeno módulo customizado ou uma regra permissiva para um único domínio costuma ser o motivo pelo qual um serviço-alvo se comporta de forma muito mais permissiva do que a política base sugeriria.

## Pistas de Auditoria

As negações AVC geralmente são um sinal ofensivo, não apenas ruído defensivo. Elas informam:

- qual objeto/tipo-alvo você atingiu
- qual permissão foi negada
- qual domínio você controla atualmente
- se uma pequena alteração na policy faria a cadeia funcionar
```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```
Se uma exploração local ou tentativa de persistência continuar falhando com `EACCES` ou erros estranhos de "permissão negada", apesar de permissões DAC que parecem de root, geralmente vale a pena verificar o SELinux antes de descartar o vetor.

## Usuários do SELinux

Existem usuários do SELinux além dos usuários Linux comuns. Cada usuário Linux é mapeado para um usuário do SELinux como parte da policy, permitindo que o sistema imponha diferentes roles e domains a diferentes contas.<sup>[[3]](#references)</sup>

Verificações rápidas:
```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
sudo -l 2>/dev/null
grep -R "ROLE=\|TYPE=" /etc/sudoers /etc/sudoers.d 2>/dev/null
```
Em muitos sistemas convencionais, os usuários são mapeados para `unconfined_u`, o que reduz o impacto prático do confinamento de usuários. Em deployments hardened, no entanto, usuários confinados podem tornar `sudo`, `su`, `newrole` e `runcon` muito mais interessantes, porque **o caminho de escalation pode depender da entrada em uma role/type melhor do SELinux, e não apenas de se tornar UID 0**. Lembre-se também de que alguns usuários confinados não podem executar `sudo`/`su` de forma alguma, a menos que a policy permita explicitamente a transição setuid subjacente; portanto, um host que use `staff_u` + `sysadm_r` pode transformar uma regra aparentemente menor de `sudo ROLE=` / `TYPE=` no verdadeiro limite de privilégios.<sup>[[3]](#references)</sup>

## SELinux em Containers

Os runtimes de containers normalmente iniciam workloads em um domínio confinado, como `container_t`, e rotulam o conteúdo do container como `container_file_t`. Se um processo do container escapar, mas continuar executando com o label do container, as gravações no host ainda podem falhar porque o limite de labels permaneceu intacto.

Exemplo rápido:
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
A parte `c647,c780` não é decoração. Em muitas implantações de containers, os runtimes atribuem dinamicamente categorias MCS para que dois processos executados como `container_t` ainda permaneçam separados. Se um escape fizer você chegar a um namespace do host, mas mantiver o conjunto de categorias original, incompatibilidades de categorias ainda poderão explicar por que alguns caminhos do host continuam sem permissão de leitura ou escrita.

Operações modernas de containers que merecem atenção:

- `--security-opt label=disable` pode mover efetivamente a workload para um tipo relacionado a containers e sem confinamento, como `spc_t`
- bind mounts com `:z` / `:Z` acionam o relabeling do caminho do host para uso compartilhado/privado por containers
- o relabeling amplo do conteúdo do host pode se tornar um problema de segurança por si só

Esta página mantém o conteúdo sobre containers curto para evitar duplicação. Para os casos de abuso específicos de containers e exemplos de runtimes, consulte:

{{#ref}}
../containers-namespaces/container-security/protections/selinux.md
{{#endref}}

## Referências

- [1] [Documentação da Red Hat: Usando o SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [2] [SETools: Ferramentas de análise de políticas para SELinux](https://github.com/SELinuxProject/setools)
- [3] [Gerenciando usuários confinados e sem confinamento - documentação do RHEL 9](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/using_selinux/managing-confined-and-unconfined-users_using-selinux)
- [4] [semodule(8) - página de manual do Linux](https://man7.org/linux/man-pages/man8/semodule.8.html)

{{#include ../../banners/hacktricks-training.md}}
