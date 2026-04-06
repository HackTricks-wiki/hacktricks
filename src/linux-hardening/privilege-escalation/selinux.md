# SELinux

{{#include ../../banners/hacktricks-training.md}}

SELinux é um sistema de **Controle de Acesso Obrigatório baseado em rótulos (Mandatory Access Control - MAC)**. Na prática, isso significa que, mesmo que as permissões DAC, grupos ou capacidades do Linux pareçam suficientes para uma ação, o kernel ainda pode negá-la porque o **contexto de origem** não tem permissão para acessar o **contexto de destino** com a classe/permissão solicitada.

Um contexto geralmente se parece com:
```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```
Do ponto de vista de privesc, o `type` (domínio para processos, type para objetos) costuma ser o campo mais importante:

- Um processo é executado em um **domain** como `unconfined_t`, `staff_t`, `httpd_t`, `container_t`, `sysadm_t`
- Arquivos e sockets têm um **type** como `admin_home_t`, `shadow_t`, `httpd_sys_rw_content_t`, `container_file_t`
- A política decide se um **domain** pode ler/gravar/executar/transicionar para o outro

## Enumeração Rápida

Se o SELinux estiver habilitado, enumere-o cedo porque ele pode explicar por que caminhos comuns de privesc no Linux falham ou por que um wrapper privilegiado em torno de uma ferramenta SELinux "inofensiva" é, na verdade, crítico:
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
Constatações interessantes:

- `Disabled` ou `Permissive` mode remove a maior parte do valor do SELinux como fronteira.
- `unconfined_t` geralmente significa que o SELinux está presente, mas não está restringindo esse processo de forma significativa.
- `default_t`, `file_t`, ou rótulos obviamente errados em caminhos personalizados frequentemente indicam rotulagem incorreta ou implantação incompleta.
- Substituições locais em `file_contexts.local` têm precedência sobre os padrões de política, então revise-as cuidadosamente.

## Análise da Política

O SELinux é muito mais fácil de atacar ou contornar quando você consegue responder duas perguntas:

1. **O que meu domínio atual pode acessar?**
2. **Em quais domínios posso transitar?**

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
Isto é especialmente útil quando um host usa **usuários confinados** em vez de mapear todos para `unconfined_u`. Nesse caso, procure por:

- mapeamentos de usuário via `semanage login -l`
- funções permitidas via `semanage user -l`
- domínios administrativos acessíveis, como `sysadm_t`, `secadm_t`, `webadm_t`
- entradas do `sudoers` usando `ROLE=` ou `TYPE=`

Se `sudo -l` contiver entradas como esta, o SELinux faz parte da fronteira de privilégios:
```text
linux_user ALL=(ALL) ROLE=webadm_r TYPE=webadm_t /bin/bash
```
Também verifique se `newrole` está disponível:
```bash
sudo -l
which newrole runcon
newrole -l 2>/dev/null
```
`runcon` e `newrole` não são automaticamente exploráveis, mas se um wrapper privilegiado ou uma regra em `sudoers` permitir que você selecione um papel/tipo melhor, eles se tornam primitivas de escalada de alto valor.

## Arquivos, Relabeling e Misconfigurações de Alto Valor

A diferença operacional mais importante entre as ferramentas SELinux comuns é:

- `chcon`: mudança temporária de rótulo em um caminho específico
- `semanage fcontext`: regra persistente de caminho-para-rótulo
- `restorecon` / `setfiles`: aplicar novamente o rótulo padrão/da política

Isso importa muito durante privesc porque **relabeling não é apenas cosmético**. Pode transformar um arquivo de "bloqueado pela política" para "legível/executável por um serviço confinado privilegiado".

Verifique regras locais de relabel e drift de relabel:
```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```
Comandos de alto valor para procurar em `sudo -l`, root wrappers, automation scripts, ou file capabilities:
```bash
which semanage restorecon chcon setfiles semodule audit2allow runcon newrole setsebool load_policy 2>/dev/null
getcap -r / 2>/dev/null | grep -E 'cap_mac_admin|cap_mac_override'
```
Especialmente interessantes:

- `semanage fcontext`: altera de forma persistente qual rótulo um caminho deve receber
- `restorecon` / `setfiles`: reaplica essas mudanças em escala
- `semodule -i`: carrega um módulo de política customizado
- `semanage permissive -a <domain_t>`: torna um domínio permissivo sem colocar o host inteiro em permissive
- `setsebool -P`: altera permanentemente os booleans da política
- `load_policy`: recarrega a política ativa

Estes são frequentemente **helper primitives**, não root exploits independentes. Eles permitem que você:

- tornar um domínio alvo permissivo
- ampliar o acesso entre seu domínio e um tipo protegido
- rerotular arquivos controlados pelo atacante para que um serviço privilegiado possa lê-los ou executá-los
- enfraquecer um serviço confinado o suficiente para que um bug local existente se torne explorável

Checagens de exemplo:
```bash
# If sudo exposes semanage/restorecon, think in terms of policy abuse
sudo -l | grep -E 'semanage|restorecon|setfiles|semodule|runcon|newrole|setsebool|load_policy'

# Look for places where local file-context overrides may matter
semanage fcontext -C -l 2>/dev/null
restorecon -n -v /usr/local/bin /opt /srv /var/www 2>/dev/null
```
Se você consegue carregar um módulo de política como root, normalmente você controla a fronteira do SELinux:
```bash
ausearch -m AVC,USER_AVC -ts recent 2>/dev/null | audit2allow -M localfix
sudo semodule -i localfix.pp
```
Por isso `audit2allow`, `semodule` e `semanage permissive` devem ser tratados como superfícies administrativas sensíveis durante post-exploitation. Eles podem, silenciosamente, converter uma cadeia bloqueada em uma funcional sem alterar as permissões clássicas do UNIX.

## Indícios de Auditoria

Negativas de AVC são frequentemente sinais ofensivos, não apenas ruído defensivo. Elas indicam:

- qual objeto/tipo alvo você atingiu
- qual permissão foi negada
- qual domínio você controla atualmente
- se uma pequena alteração na política faria a cadeia funcionar
```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```
Se um local exploit ou persistence attempt continuar falhando com `EACCES` ou estranhos erros "permission denied" apesar de permissões DAC com aparência de root, geralmente vale a pena verificar o SELinux antes de descartar o vector.

## Usuários SELinux

Existem usuários SELinux além dos usuários Linux regulares. Cada usuário Linux é mapeado para um usuário SELinux como parte da política, o que permite ao sistema impor diferentes papéis e domínios permitidos em diferentes contas.

Verificações rápidas:
```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
```
Em muitos sistemas comuns, usuários são mapeados para `unconfined_u`, o que reduz o impacto prático do confinamento de usuários. Em implantações mais endurecidas, contudo, usuários confinados podem tornar `sudo`, `su`, `newrole`, e `runcon` muito mais interessantes porque **o caminho de escalada pode depender de entrar em um papel/tipo SELinux melhor, não apenas de se tornar UID 0**.

## SELinux em contêineres

Runtimes de container comumente iniciam cargas de trabalho em um domínio confinado, como `container_t`, e rotulam o conteúdo do container como `container_file_t`. Se um processo do container escapar mas ainda rodar com o rótulo do container, gravações no host podem ainda falhar porque a fronteira de rótulo permaneceu intacta.

Exemplo rápido:
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
Pontos a observar nas operações modernas de containers:

- `--security-opt label=disable` pode efetivamente mover a carga de trabalho para um tipo relacionado a container não confinado, como `spc_t`
- bind mounts com `:z` / `:Z` acionam o relabeling do caminho do host para uso compartilhado/privado pelo container
- relabeling amplo do conteúdo do host pode se tornar um problema de segurança por si só

Esta página mantém o conteúdo sobre containers curto para evitar duplicação. Para os casos de abuso específicos de container e exemplos em tempo de execução, consulte:

{{#ref}}
container-security/protections/selinux.md
{{#endref}}

## Referências

- [Red Hat docs: Using SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [SETools: Policy analysis tools for SELinux](https://github.com/SELinuxProject/setools)
{{#include ../../banners/hacktricks-training.md}}
