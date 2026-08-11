# SELinux

{{#include ../../banners/hacktricks-training.md}}

SELinux é um sistema de **Mandatory Access Control (MAC) baseado em labels**. Na prática, isso significa que, mesmo que as permissões DAC, os grupos ou as capabilities do Linux pareçam suficientes para uma ação, o kernel ainda poderá negá-la porque o **source context** não tem permissão para acessar o **target context** com a classe/permissão solicitada.<sup>[[1]](#references)</sup>

Um context geralmente se parece com:<sup>[[1]](#references)</sup>
```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```
De uma perspectiva de privesc, o `type` (domínio para processos, tipo para objetos) geralmente é o campo mais importante:<sup>[[1]](#references)</sup>

- Um processo é executado em um **domain**, como `unconfined_t`, `staff_t`, `httpd_t`, `container_t`, `sysadm_t`
- Arquivos e sockets têm um **type**, como `admin_home_t`, `shadow_t`, `httpd_sys_rw_content_t`, `container_file_t`
- A policy decide se um domínio pode ler/gravar/executar/fazer a transição para o outro

## Enumeração rápida

Se o SELinux estiver habilitado, faça a enumeração dele logo no início, pois isso pode explicar por que caminhos comuns de privesc no Linux falham ou por que um wrapper privilegiado em torno de uma ferramenta SELinux "inofensiva" é, na verdade, crítico:<sup>[[1]](#references)</sup>
```bash
getenforce
sestatus
id -Z
ps -eZ | head
cat /proc/self/attr/current
ls -Zd / /root /home /tmp /etc /var/www 2>/dev/null
```
Verificações úteis de acompanhamento:<sup>[[1]](#references)[[3]](#references)[[4]](#references)[[7]](#references)[[12]](#references)</sup>
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
Descobertas interessantes:<sup>[[1]](#references)[[3]](#references)[[7]](#references)[[19]](#references)</sup>

- O modo `Disabled` ou `Permissive` remove a maior parte do valor do SELinux como limite.
- `unconfined_t` geralmente significa que o SELinux está presente, mas não restringe significativamente esse processo.
- `default_t`, `file_t` ou labels obviamente incorretos em paths personalizados geralmente indicam mislabeling ou uma implantação incompleta.
- Substituições locais em `file_contexts.local` têm precedência sobre os padrões da policy, portanto, revise-as cuidadosamente.

## Análise da Policy

O SELinux é muito mais fácil de atacar ou contornar quando você consegue responder a duas perguntas:

1. **O que meu domínio atual pode acessar?**
2. **Para quais domínios posso fazer transition?**

As ferramentas mais úteis para isso são `sepolicy` e **SETools** (`seinfo`, `sesearch`, `sedta`):<sup>[[2]](#references)[[9]](#references)</sup>
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

Se `sudo -l` contiver entradas como esta, o SELinux faz parte do limite de privilégios:<sup>[[3]](#references)</sup>
```text
linux_user ALL=(ALL) ROLE=webadm_r TYPE=webadm_t /bin/bash
```
Verifique também se `newrole` está disponível:<sup>[[3]](#references)[[10]](#references)[[11]](#references)</sup>
```bash
sudo -l
which newrole runcon
newrole -l 2>/dev/null
```
`runcon` e `newrole` não são exploráveis automaticamente, mas, se um wrapper privilegiado ou uma regra `sudoers` permitir selecionar uma role/type melhor, eles se tornam primitivas de alto valor para escalada.<sup>[[3]](#references)[[10]](#references)[[11]](#references)</sup>

## Arquivos, Relabeling e Misconfigurações de Alto Valor

A diferença operacional mais importante entre as ferramentas comuns do SELinux é:<sup>[[1]](#references)[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- `chcon`: alteração temporária do label em um caminho específico
- `semanage fcontext`: regra persistente de caminho para label
- `restorecon` / `setfiles`: aplica novamente o label definido pela policy/padrão

Isso é muito importante durante o privesc porque **relabeling não é apenas cosmético**. Ele pode transformar um arquivo de "bloqueado pela policy" em "legível/executável por um serviço confinado privilegiado".<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

Verifique regras locais de relabeling e desvios de relabeling:<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>
```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```
Um detalhe sutil, mas útil: o `restorecon` simples **nem sempre reverte totalmente um label suspeito**. Se o tipo alvo estiver em `customizable_types`, talvez seja necessário usar `-F` para forçar uma redefinição completa. De uma perspectiva ofensiva, isso explica por que um `chcon` incomum às vezes pode persistir após uma limpeza superficial de "já executamos o restorecon".<sup>[[8]](#references)</sup>
```bash
grep -R . /etc/selinux/*/contexts/customizable_types 2>/dev/null | head
restorecon -n -v /path/of/interest 2>/dev/null
restorecon -F -v /path/of/interest 2>/dev/null
```
Comandos de alto valor para procurar em `sudo -l`, wrappers de root, scripts de automação ou capabilities de arquivos:<sup>[[1]](#references)[[4]](#references)[[5]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>
```bash
which semanage restorecon chcon setfiles semodule audit2allow runcon newrole setsebool load_policy 2>/dev/null
getcap -r / 2>/dev/null | grep -E 'cap_mac_admin|cap_mac_override'
```
Se qualquer uma das capacidades MAC aparecer, consulte também a [página de capacidades do Linux](linux-capabilities.md); a documentação de capacidades do Linux descreve `cap_mac_admin` e `cap_mac_override` como específicos do Smack, portanto não presuma que apenas os nomes dessas capacidades contornem o SELinux.<sup>[[5]](#references)</sup>

Especialmente interessantes:<sup>[[1]](#references)[[4]](#references)[[7]](#references)[[8]](#references)[[12]](#references)[[13]](#references)</sup>

- `semanage fcontext`: altera persistentemente o label que um caminho deve receber
- `restorecon` / `setfiles`: reaplica essas alterações em larga escala
- `semodule -i`: carrega um módulo de policy personalizado
- `semanage permissive -a <domain_t>`: torna um domínio permissivo sem alterar todo o host
- `setsebool -P`: altera permanentemente os booleanos da policy
- `load_policy`: recarrega a policy ativa

Frequentemente, essas são **primitivas auxiliares**, não root exploits independentes. O valor delas está em permitir que você:<sup>[[1]](#references)[[4]](#references)[[7]](#references)[[8]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

- torne um domínio-alvo permissivo
- amplie o acesso entre seu domínio e um tipo protegido
- altere o label de arquivos controlados pelo atacante para que um serviço privilegiado possa lê-los ou executá-los
- enfraqueça um serviço confinado o suficiente para que um bug local existente se torne explorável

Verificações de exemplo:<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>
```bash
# If sudo exposes semanage/restorecon, think in terms of policy abuse
sudo -l | grep -E 'semanage|restorecon|setfiles|semodule|runcon|newrole|setsebool|load_policy'

# Look for places where local file-context overrides may matter
semanage fcontext -C -l 2>/dev/null
restorecon -n -v /usr/local/bin /opt /srv /var/www 2>/dev/null
```
Se você puder carregar um módulo de policy como root, geralmente controlará a fronteira do SELinux:<sup>[[1]](#references)[[4]](#references)[[14]](#references)</sup>
```bash
ausearch -m AVC,USER_AVC -ts recent 2>/dev/null | audit2allow -M localfix
sudo semodule -i localfix.pp
```
É por isso que `audit2allow`, `semodule` e `semanage permissive` devem ser tratados como superfícies administrativas sensíveis durante o post-exploitation. Eles podem converter silenciosamente uma cadeia bloqueada em uma cadeia funcional sem alterar as permissões UNIX clássicas.<sup>[[1]](#references)[[4]](#references)[[12]](#references)[[14]](#references)</sup>

## Negativas Ocultas e Extração de Módulos

Uma frustração ofensiva muito comum é uma cadeia que falha com um `EACCES` genérico enquanto a negativa AVC esperada nunca aparece. As regras `dontaudit` podem estar ocultando exatamente a permissão de que você precisa. Se você puder executar `semodule` por meio de `sudo` ou de outro wrapper privilegiado, desativar temporariamente `dontaudit` pode transformar uma falha silenciosa em uma pista precisa sobre a policy:<sup>[[4]](#references)[[15]](#references)</sup>
```bash
# Rebuild policy without dontaudit rules, trigger the action again, then inspect AVCs
sudo semodule -DB
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null | tail -n 50
sudo semodule -B

# Extract installed modules for offline review / diffing
semodule -lfull 2>/dev/null
semodule -E --cil <module_name> 2>/dev/null
```
Isso também é útil para revisar o que os administradores locais já alteraram. Um pequeno módulo customizado ou uma regra permissiva para um único domínio costuma ser o motivo pelo qual um serviço-alvo se comporta de forma muito mais permissiva do que a política base sugeriria.<sup>[[1]](#references)[[4]](#references)[[12]](#references)</sup>

## Indícios de auditoria

As negações do AVC geralmente são um sinal ofensivo, não apenas ruído defensivo. Elas informam:<sup>[[1]](#references)[[15]](#references)</sup>

- qual objeto/tipo-alvo você atingiu
- qual permissão foi negada
- qual domínio você controla atualmente
- se uma pequena alteração na política faria a cadeia funcionar
```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```
Se um exploit local ou uma tentativa de persistência continuar falhando com `EACCES` ou erros estranhos de "permission denied", apesar de permissões DAC que parecem de root, geralmente vale a pena verificar o SELinux antes de descartar o vetor.<sup>[[1]](#references)</sup>

## Usuários do SELinux

Além dos usuários comuns do Linux, existem usuários do SELinux. Cada usuário do Linux é associado a um usuário do SELinux como parte da policy, permitindo que o sistema imponha diferentes roles e domains permitidos em diferentes contas.<sup>[[3]](#references)</sup>

Verificações rápidas:<sup>[[3]](#references)</sup>
```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
sudo -l 2>/dev/null
grep -R "ROLE=\|TYPE=" /etc/sudoers /etc/sudoers.d 2>/dev/null
```
Em muitos sistemas convencionais, os usuários são mapeados para `unconfined_u`, o que reduz o impacto prático do confinamento de usuários. Em implantações hardened, no entanto, usuários confinados podem tornar `sudo`, `su`, `newrole` e `runcon` muito mais interessantes, porque **o caminho de escalada pode depender da entrada em uma role/type melhor do SELinux, e não apenas de se tornar UID 0**. Lembre-se também de que alguns usuários confinados não podem executar `sudo`/`su` de forma alguma, a menos que a policy permita explicitamente a transição subjacente de setuid; portanto, um host que use `staff_u` + `sysadm_r` pode transformar uma regra aparentemente pequena de `sudo ROLE=` / `TYPE=` no verdadeiro limite de privilégio.<sup>[[3]](#references)</sup>

## SELinux em Containers

Os runtimes de containers normalmente iniciam workloads em um domínio confinado, como `container_t`, e rotulam o conteúdo do container como `container_file_t`. Se um processo do container escapar, mas ainda for executado com o label do container, as gravações no host ainda podem falhar porque o limite de labels permaneceu intacto.<sup>[[1]](#references)[[17]](#references)</sup>

Exemplo rápido:<sup>[[16]](#references)[[18]](#references)</sup>
```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```
A parte `c647,c780` não é decoração. Em muitas implantações de containers, os runtimes atribuem dinamicamente categorias MCS para que dois processos executados como `container_t` ainda permaneçam separados. Se um escape levar você a um namespace do host, mas mantiver o conjunto de categorias original, incompatibilidades de categorias ainda poderão explicar por que alguns caminhos do host continuam sem permissão de leitura ou escrita.<sup>[[17]](#references)</sup>

Operações modernas de containers que vale a pena observar:<sup>[[16]](#references)[[17]](#references)</sup>

- `--security-opt label=disable` desativa a separação por labels SELinux para o container
- bind mounts com `:z` / `:Z` acionam a reetiquetagem do caminho do host para uso compartilhado/privado por containers
- a reetiquetagem ampla do conteúdo do host pode se tornar um problema de segurança por si só

Esta página mantém o conteúdo sobre containers curto para evitar duplicação. Para os casos de abuso específicos de containers e exemplos de runtimes, consulte:

{{#ref}}
../containers-namespaces/container-security/protections/selinux.md
{{#endref}}

## References

- [1] [Documentação da Red Hat: Usando SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [2] [SETools: Ferramentas de análise de políticas para SELinux](https://github.com/SELinuxProject/setools)
- [3] [Gerenciando usuários confinados e não confinados - Documentação do RHEL 9](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/using_selinux/managing-confined-and-unconfined-users_using-selinux)
- [4] [semodule(8) - Página de manual do Linux](https://man7.org/linux/man-pages/man8/semodule.8.html)
- [5] [capabilities(7) - Página de manual do Linux](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [6] [chcon(1) - Página de manual do Linux](https://man7.org/linux/man-pages/man1/chcon.1.html)
- [7] [semanage-fcontext(8) - Página de manual do Linux](https://man7.org/linux/man-pages/man8/semanage-fcontext.8.html)
- [8] [restorecon(8) - Página de manual do Linux](https://man7.org/linux/man-pages/man8/restorecon.8.html)
- [9] [sepolicy-transition(8) - Página de manual do Linux](https://man7.org/linux/man-pages/man8/sepolicy-transition.8.html)
- [10] [runcon(1) - Página de manual do Linux](https://man7.org/linux/man-pages/man1/runcon.1.html)
- [11] [newrole(1) - Página de manual do Linux](https://man7.org/linux/man-pages/man1/newrole.1.html)
- [12] [semanage-permissive(8) - Página de manual do Linux](https://man7.org/linux/man-pages/man8/semanage-permissive.8.html)
- [13] [setsebool(8) - Página de manual do Linux](https://man7.org/linux/man-pages/man8/setsebool.8.html)
- [14] [audit2allow(1) - Página de manual do Linux](https://man7.org/linux/man-pages/man1/audit2allow.1.html)
- [15] [ausearch(8) - Página de manual do Linux](https://man7.org/linux/man-pages/man8/ausearch.8.html)
- [16] [Documentação do Podman run](https://docs.podman.io/en/latest/markdown/podman-run.1.html)
- [17] [Por que você deveria usar Multi-Category Security nos seus containers Linux](https://www.redhat.com/en/blog/why-you-should-be-using-multi-category-security-your-linux-containers)
- [18] [Documentação do Podman top](https://docs.podman.io/en/latest/markdown/podman-top.1.html)
- [19] [selinux(8) - Página de manual do Linux](https://man7.org/linux/man-pages/man8/selinux.8.html)
{{#include ../../banners/hacktricks-training.md}}
