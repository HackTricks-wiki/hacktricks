# SELinux

{{#include ../../banners/hacktricks-training.md}}

SELinux é um sistema **Mandatory Access Control (MAC)** baseado em rótulos. Na prática, isso significa que, mesmo que as permissões DAC, os grupos ou as Linux capabilities pareçam suficientes para uma ação, o kernel ainda pode negá-la porque o **contexto de origem** não tem permissão para acessar o **contexto de destino** com a classe/permissão solicitada.<sup>[[1]](#references)</sup>

Um contexto geralmente se parece com:<sup>[[1]](#references)</sup>

```text
user:role:type:level
system_u:system_r:httpd_t:s0
unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023
```

Do ponto de vista de privesc, o `type` (domínio para processos, tipo para objetos) costuma ser o campo mais importante:<sup>[[1]](#references)</sup>

- Um processo é executado em um **domínio** como `unconfined_t`, `staff_t`, `httpd_t`, `container_t`, `sysadm_t`
- Arquivos e sockets têm um **tipo** como `admin_home_t`, `shadow_t`, `httpd_sys_rw_content_t`, `container_file_t`
- A policy decide se um domínio pode ler/gravar/executar/fazer a transição para o outro

## Enumeração rápida

Se o SELinux estiver habilitado, enumere-o logo no início, pois ele pode explicar por que caminhos comuns de privesc no Linux falham ou por que um wrapper privilegiado em torno de uma ferramenta SELinux “inofensiva” é, na verdade, crucial:<sup>[[1]](#references)</sup>

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

Achados interessantes:<sup>[[1]](#references)[[3]](#references)[[7]](#references)[[19]](#references)</sup>

- Os modos `Disabled` ou `Permissive` eliminam a maior parte do valor do SELinux como limite de segurança.
- `unconfined_t` geralmente significa que o SELinux está presente, mas não restringe significativamente esse processo.
- `default_t`, `file_t` ou rótulos obviamente incorretos em caminhos personalizados geralmente indicam rotulagem incorreta ou implantação incompleta.
- As substituições locais em `file_contexts.local` têm precedência sobre os padrões da política, então revise-as com cuidado.

## Análise da política

O SELinux é muito mais fácil de atacar ou contornar quando você consegue responder a duas perguntas:

1. **O que meu domínio atual pode acessar?**
2. **Para quais domínios posso fazer a transição?**

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
- funções permitidas via `semanage user -l`
- domínios administrativos acessíveis, como `sysadm_t`, `secadm_t`, `webadm_t`
- entradas de `sudoers` que usam `ROLE=` ou `TYPE=`

Se `sudo -l` contiver entradas como esta, o SELinux faz parte do limite de privilégios:<sup>[[3]](#references)</sup>

```text
linux_user ALL=(ALL) ROLE=webadm_r TYPE=webadm_t /bin/bash
```

Verifique também se `newrole` está disponível:<sup>[[3]](#references)[[10]](#references)[[11]](#references)</sup>

```bash
sudo -l
which newrole runcon
newrole -V 2>/dev/null
```

`runcon` e `newrole` não são exploráveis automaticamente, mas, se um wrapper privilegiado ou uma regra `sudoers` permitir selecionar uma função/tipo mais vantajoso, tornam-se primitivas de escalada de alto valor.<sup>[[3]](#references)[[10]](#references)[[11]](#references)</sup>

### Auditar pontos de entrada de transição graváveis

Um grafo de transição é apenas uma pista sobre a política. Para transformá-lo em um caminho de ataque, identifique o tipo de executável que entra em um domínio mais útil e, em seguida, verifique se você pode modificar um executável com esse rótulo ou substituí-lo por meio do diretório pai.<sup>[[9]](#references)[[20]](#references)</sup> Uma transição automática de `execve` precisa de uma regra `type_transition` aplicável, acesso de execução do domínio de origem, acesso `entrypoint` do domínio de destino e permissão para fazer a transição entre os domínios.<sup>[[20]](#references)</sup> O domínio de destino pode obter acesso do SELinux, mas a execução, por si só, não altera o UID do Linux; verifique separadamente [SUID/SGID e ACLs](suid-sgid-and-acl-triage.md).<sup>[[20]](#references)[[21]](#references)</sup>

Use o tipo de ponto de entrada informado para verificar as regras subjacentes e, em seguida, inspecione o caminho e seu diretório pai em busca de acesso de gravação.<sup>[[9]](#references)[[20]](#references)[[22]](#references)</sup>

```bash
src=$(id -Z | cut -d: -f3)
sepolicy transition -s "$src"                 # Note target domain and entrypoint type
dst=target_t                                   # Substitute a domain from the report
entry=target_exec_t                            # Substitute its entrypoint type
sesearch -T -s "$src" -t "$entry" -c process
sesearch --allow -s "$src" -t "$dst" -c process -p transition
sesearch --allow -s "$src" -t "$entry" -c file -p execute
sesearch --allow -s "$dst" -t "$entry" -c file -p entrypoint
sesearch --allow -s "$src" -t "$entry" -c file -p write
ls -lZ /path/to/entrypoint
namei -l /path/to/entrypoint
getfacl -p /path/to/entrypoint
getfacl -p /path/to
```

Correlacione o tipo de entrypoint com um caminho executável real. Inspecione DAC, ACLs, a permissão de gravação do SELinux no arquivo ou diretório pai, o rótulo do arquivo e qualquer booleano condicional antes de considerar uma aresta da política alcançável.<sup>[[20]](#references)[[22]](#references)</sup> Se um caminho for substituído em vez de editado no local, verifique o contexto do novo inode: os rótulos do sistema de arquivos são armazenados como atributos estendidos, e a substituição pode não manter o tipo de entrypoint.<sup>[[21]](#references)</sup> Programas compatíveis com SELinux podem solicitar uma transição com `setexeccon`; portanto, a ausência de uma regra automática `type_transition` não descarta todas as transições.<sup>[[20]](#references)</sup>

## Arquivos, reetiquetagem e configurações incorretas de alto valor

A diferença operacional mais importante entre as ferramentas comuns do SELinux é:<sup>[[1]](#references)[[6]](#references)[[7]](#references)[[8]](#references)</sup>

- `chcon`: alteração temporária do rótulo em um caminho específico
- `semanage fcontext`: regra persistente de caminho para rótulo
- `restorecon` / `setfiles`: reaplicam o rótulo da política/padrão

Isso é muito importante durante a elevação de privilégios, porque **a reetiquetagem não é apenas cosmética**. Ela pode transformar um arquivo de "bloqueado pela política" em "legível/executável por um serviço confinado privilegiado".<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

Verifique as regras locais de reetiquetagem e desvios de rótulo:<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

```bash
grep -R . /etc/selinux/*/contexts/files/file_contexts.local 2>/dev/null
restorecon -nvr / 2>/dev/null | head -n 50
matchpathcon -V /etc/passwd /etc/shadow /usr/local/bin/* 2>/dev/null
```

Um detalhe sutil, mas útil: `restorecon` simples **nem sempre reverte totalmente um rótulo suspeito**. Se o tipo de destino estiver em `customizable_types`, talvez seja necessário usar `-F` para forçar uma redefinição completa. Do ponto de vista ofensivo, isso explica por que um `chcon` incomum às vezes pode persistir mesmo após uma limpeza casual do tipo "já executamos restorecon".<sup>[[8]](#references)</sup>

```bash
grep -R . /etc/selinux/*/contexts/customizable_types 2>/dev/null | head
restorecon -n -v /path/of/interest 2>/dev/null
restorecon -F -v /path/of/interest 2>/dev/null
```

Comandos de alto valor para procurar em `sudo -l`, wrappers de root, scripts de automação ou capabilities de arquivo:<sup>[[1]](#references)[[4]](#references)[[5]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

```bash
which semanage restorecon chcon setfiles semodule audit2allow runcon newrole setsebool load_policy 2>/dev/null
getcap -r / 2>/dev/null | grep -E 'cap_mac_admin|cap_mac_override'
```

Se qualquer uma das capacidades MAC aparecer, confira também a [página de capacidades do Linux](linux-capabilities.md); a documentação de capacidades do Linux descreve `cap_mac_admin` e `cap_mac_override` como específicas do Smack, então não presuma que apenas os nomes delas contornam o SELinux.<sup>[[5]](#references)</sup>

Especialmente interessantes:<sup>[[1]](#references)[[4]](#references)[[7]](#references)[[8]](#references)[[12]](#references)[[13]](#references)</sup>

- `semanage fcontext`: altera de forma persistente o rótulo que um caminho deve receber
- `restorecon` / `setfiles`: reaplica essas alterações em escala
- `semodule -i`: carrega um módulo de política personalizado
- `semanage permissive -a <domain_t>`: torna um domínio permissive sem alterar todo o host
- `setsebool -P`: altera permanentemente os booleanos da política
- `load_policy`: recarrega a política ativa

Esses recursos costumam ser **primitivas auxiliares**, não exploits de root autônomos. Eles são úteis porque permitem:<sup>[[1]](#references)[[4]](#references)[[7]](#references)[[8]](#references)[[12]](#references)[[13]](#references)[[14]](#references)</sup>

- tornar um domínio-alvo permissive
- ampliar o acesso entre seu domínio e um tipo protegido
- alterar os rótulos de arquivos controlados pelo atacante para que um serviço privilegiado possa lê-los ou executá-los
- enfraquecer um serviço confinado o suficiente para tornar explorável um bug local existente

Verificações de exemplo:<sup>[[1]](#references)[[7]](#references)[[8]](#references)</sup>

```bash
# If sudo exposes semanage/restorecon, think in terms of policy abuse
sudo -l | grep -E 'semanage|restorecon|setfiles|semodule|runcon|newrole|setsebool|load_policy'

# Look for places where local file-context overrides may matter
semanage fcontext -C -l 2>/dev/null
restorecon -n -v /usr/local/bin /opt /srv /var/www 2>/dev/null
```

Se você consegue carregar um módulo de política como root, geralmente controla a fronteira do SELinux:<sup>[[1]](#references)[[4]](#references)[[14]](#references)</sup>

```bash
ausearch -m AVC,USER_AVC -ts recent 2>/dev/null | audit2allow -M localfix
sudo semodule -i localfix.pp
```

É por isso que `audit2allow`, `semodule` e `semanage permissive` devem ser tratados como superfícies administrativas sensíveis durante o post-exploitation. Eles podem converter silenciosamente uma cadeia bloqueada em uma funcional sem alterar as permissões clássicas do UNIX.<sup>[[1]](#references)[[4]](#references)[[12]](#references)[[14]](#references)</sup>

## Negativas Ocultas e Extração de Módulos

Uma frustração ofensiva muito comum é uma cadeia que falha com um `EACCES` genérico, enquanto a negativa AVC esperada nunca aparece. Regras `dontaudit` podem ocultar a permissão exata de que você precisa. Se você puder executar `semodule` usando `sudo` ou outro wrapper privilegiado, desativar temporariamente `dontaudit` pode transformar uma falha silenciosa em uma pista precisa sobre a política:<sup>[[4]](#references)[[15]](#references)</sup>

```bash
# Rebuild policy without dontaudit rules, trigger the action again, then inspect AVCs
sudo semodule -DB
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null | tail -n 50
sudo semodule -B

# Extract installed modules for offline review / diffing
semodule -lfull 2>/dev/null
semodule -E --cil <module_name> 2>/dev/null
```

Isso também é útil para revisar o que os administradores locais já alteraram. Um pequeno módulo personalizado ou uma regra permissiva para um único domínio costuma ser o motivo pelo qual um serviço-alvo se comporta de forma muito mais permissiva do que a política base sugeriria.<sup>[[1]](#references)[[4]](#references)[[12]](#references)</sup>

## Pistas de auditoria

As negações AVC costumam ser um sinal ofensivo, não apenas ruído defensivo. Elas informam:<sup>[[1]](#references)[[15]](#references)</sup>

- qual objeto/tipo de destino você atingiu
- qual permissão foi negada
- qual domínio você controla atualmente
- se uma pequena alteração na política faria a cadeia funcionar

```bash
ausearch -m AVC,USER_AVC,SELINUX_ERR -ts recent 2>/dev/null
journalctl -t setroubleshoot --no-pager 2>/dev/null | tail -n 50
```

Se uma exploração local ou tentativa de persistência continuar falhando com `EACCES` ou erros estranhos de "permissão negada", apesar de permissões DAC que parecem de root, geralmente vale a pena verificar o SELinux antes de descartar o vetor.<sup>[[1]](#references)</sup>

## Usuários do SELinux

Além dos usuários Linux comuns, há usuários do SELinux. Cada usuário Linux é associado a um usuário do SELinux como parte da política, o que permite ao sistema impor diferentes funções e domínios permitidos a contas distintas.<sup>[[3]](#references)</sup>

Verificações rápidas:<sup>[[3]](#references)</sup>

```bash
id -Z
semanage login -l 2>/dev/null
semanage user -l 2>/dev/null
sudo -l 2>/dev/null
grep -R "ROLE=\|TYPE=" /etc/sudoers /etc/sudoers.d 2>/dev/null
```

Em muitos sistemas convencionais, os usuários são mapeados para `unconfined_u`, o que reduz o impacto prático do confinamento de usuários. Em implantações reforçadas, porém, usuários confinados podem tornar `sudo`, `su`, `newrole` e `runcon` muito mais interessantes, pois **o caminho de escalonamento pode depender de entrar em uma role/type SELinux mais privilegiada, e não apenas de se tornar UID 0**. Lembre-se também de que alguns usuários confinados não podem executar `sudo`/`su` a menos que a política permita explicitamente a transição setuid subjacente. Assim, um host que use `staff_u` + `sysadm_r` pode transformar uma regra aparentemente pequena de `sudo ROLE=` / `TYPE=` no verdadeiro limite de privilégio.<sup>[[3]](#references)</sup>

## SELinux em Containers

Os runtimes de containers geralmente iniciam workloads em um domínio confinado, como `container_t`, e rotulam o conteúdo dos containers como `container_file_t`. Se um processo do container escapar, mas continuar sendo executado com o rótulo do container, as gravações no host ainda poderão falhar porque o limite do rótulo permaneceu intacto.<sup>[[1]](#references)[[17]](#references)</sup>

Exemplo rápido:<sup>[[16]](#references)[[18]](#references)</sup>

```shell
$ podman run -d fedora sleep 100
d4194babf6b877c7100e79de92cd6717166f7302113018686cea650ea40bd7cb
$ podman top -l label
LABEL
system_u:system_r:container_t:s0:c647,c780
```

A parte `c647,c780` não é decorativa. Em muitas implantações de containers, os runtimes atribuem categorias MCS dinamicamente para que dois processos em execução como `container_t` continuem separados um do outro. Se um escape levar você a um namespace do host, mas mantiver o conjunto de categorias original, incompatibilidades entre categorias ainda podem explicar por que alguns caminhos do host continuam ilegíveis ou não podem ser gravados.<sup>[[17]](#references)</sup>

Operações modernas com containers que vale a pena observar:<sup>[[16]](#references)[[17]](#references)</sup>

- `--security-opt label=disable` desativa a separação de rótulos SELinux para o container
- bind mounts com `:z` / `:Z` acionam a rotulagem do caminho do host para uso compartilhado/privado pelo container
- a rotulagem ampla do conteúdo do host pode se tornar um problema de segurança por si só

Esta página mantém o conteúdo sobre containers curto para evitar duplicação. Para os casos de abuso específicos de containers e exemplos de runtimes, consulte:

{{#ref}}
../containers-namespaces/container-security/protections/selinux.md
{{#endref}}



## References

- [1] [Documentação da Red Hat: Usando SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html-single/using_selinux/index)
- [2] [SETools: Ferramentas de análise de políticas para SELinux](https://github.com/SELinuxProject/setools)
- [3] [Gerenciando usuários confinados e não confinados - documentação do RHEL 9](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/using_selinux/managing-confined-and-unconfined-users_using-selinux)
- [4] [semodule(8) - página de manual do Linux](https://man7.org/linux/man-pages/man8/semodule.8.html)
- [5] [capabilities(7) - página de manual do Linux](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [6] [chcon(1) - página de manual do Linux](https://man7.org/linux/man-pages/man1/chcon.1.html)
- [7] [semanage-fcontext(8) - página de manual do Linux](https://man7.org/linux/man-pages/man8/semanage-fcontext.8.html)
- [8] [restorecon(8) - página de manual do Linux](https://man7.org/linux/man-pages/man8/restorecon.8.html)
- [9] [sepolicy-transition(8) - página de manual do Linux](https://man7.org/linux/man-pages/man8/sepolicy-transition.8.html)
- [10] [runcon(1) - página de manual do Linux](https://man7.org/linux/man-pages/man1/runcon.1.html)
- [11] [newrole(1) - página de manual do Linux](https://man7.org/linux/man-pages/man1/newrole.1.html)
- [12] [semanage-permissive(8) - página de manual do Linux](https://man7.org/linux/man-pages/man8/semanage-permissive.8.html)
- [13] [setsebool(8) - página de manual do Linux](https://man7.org/linux/man-pages/man8/setsebool.8.html)
- [14] [audit2allow(1) - página de manual do Linux](https://man7.org/linux/man-pages/man1/audit2allow.1.html)
- [15] [ausearch(8) - página de manual do Linux](https://man7.org/linux/man-pages/man8/ausearch.8.html)
- [16] [Documentação do comando Podman run](https://docs.podman.io/en/latest/markdown/podman-run.1.html)
- [17] [Por que você deve usar Multi-Category Security nos seus containers Linux](https://www.redhat.com/en/blog/why-you-should-be-using-multi-category-security-your-linux-containers)
- [18] [Documentação do comando Podman top](https://docs.podman.io/en/latest/markdown/podman-top.1.html)
- [19] [selinux(8) - página de manual do Linux](https://man7.org/linux/man-pages/man8/selinux.8.html)
- [20] [Caderno SELinux: transições de domínio e objeto](https://github.com/SELinuxProject/selinux-notebook/blob/main/src/domain_object_transitions.md)
- [21] [Red Hat Enterprise Linux 10: Usando SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/10/html-single/using_selinux/using_selinux)
- [22] [Manual do SETools sesearch(1)](https://manpages.debian.org/testing/setools/sesearch.1.en.html)
{{#include ../../banners/hacktricks-training.md}}
