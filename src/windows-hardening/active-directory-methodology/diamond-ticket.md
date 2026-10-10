# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Wie ein golden ticket** ist ein diamond ticket ein TGT, mit dem **auf jeden Dienst als beliebiger Benutzer zugegriffen werden kann**. Ein golden ticket wird vollständig offline gefälscht, mit dem krbtgt-Hash der betreffenden Domäne verschlüsselt und anschließend zur Verwendung in eine Logon-Session eingefügt. Da Domain Controller nicht nachverfolgen, welche TGTs sie (oder andere) legitim ausgestellt haben, akzeptieren sie problemlos TGTs, die mit ihrem eigenen krbtgt-Hash verschlüsselt sind.<sup>[[1]](#references)</sup>

Es gibt zwei gängige Methoden, die Verwendung von golden tickets zu erkennen:

- Nach TGS-REQs ohne entsprechenden AS-REQ suchen.
- Nach TGTs mit auffälligen Werten suchen, etwa der standardmäßigen Laufzeit von 10 Jahren bei Mimikatz.

Ein **diamond ticket** wird erstellt, indem **die Felder eines legitimen, von einem DC ausgestellten TGT geändert werden**. Dazu wird ein **TGT angefordert**, mit dem krbtgt-Hash der Domäne **entschlüsselt**, die gewünschten Ticketfelder **geändert** und das Ticket anschließend **erneut verschlüsselt**. Dadurch werden **die beiden oben genannten Schwachstellen eines golden tickets umgangen**, denn:<sup>[[1]](#references)</sup>

- TGS-REQs haben einen vorausgehenden AS-REQ.
- Das TGT wurde von einem DC ausgestellt und enthält daher alle korrekten Details gemäß der Kerberos-Richtlinie der Domäne. Diese lassen sich zwar auch in einem golden ticket genau fälschen, doch ist das komplexer und fehleranfälliger.

### Voraussetzungen & Ablauf

- **Kryptografisches Material**: der krbtgt-AES256-Schlüssel (bevorzugt) oder der NTLM-Hash, um das TGT zu entschlüsseln und erneut zu signieren.
- **Legitimer TGT-Blob**: erhalten mit `/tgtdeleg`, `asktgt`, `s4u` oder durch Exportieren von Tickets aus dem Speicher.
- **Kontextdaten**: die RID des Zielbenutzers, Gruppen-RIDs/SIDs und (optional) aus LDAP abgeleitete PAC-Attribute.
- **Dienstschlüssel** (nur falls Diensttickets erneut erstellt werden sollen): AES-Schlüssel des zu imitierenden Dienst-SPN.

1. Ein TGT für einen beliebigen kontrollierten Benutzer per AS-REQ abrufen (Rubeus `/tgtdeleg` ist praktisch, da es den Client dazu zwingt, den Kerberos-GSS-API-Austausch ohne Anmeldedaten durchzuführen).
2. Das zurückgegebene TGT mit dem krbtgt-Schlüssel entschlüsseln und PAC-Attribute ändern (Benutzer, Gruppen, Anmeldeinformationen, SIDs, Geräteansprüche usw.).
3. Das Ticket mit demselben krbtgt-Schlüssel erneut verschlüsseln/signieren und in die aktuelle Logon-Session einfügen (`kerberos::ptt`, `Rubeus.exe ptt`...).
4. Optional den Vorgang mit einem Dienstticket wiederholen, indem ein gültiger TGT-Blob und der Schlüssel des Zieldienstes angegeben werden, um auf dem Netzwerk unauffällig zu bleiben.

### Aktualisierte Rubeus tradecraft (2024+)

Neuere Arbeiten von Huntress haben die `diamond`-Aktion in Rubeus modernisiert, indem die Verbesserungen `/ldap` und `/opsec` übernommen wurden, die zuvor nur für golden/silver tickets verfügbar waren. `/ldap` ruft nun echten PAC-Kontext ab, indem LDAP abgefragt **und** SYSVOL eingebunden wird, um Konto- und Gruppenattribute sowie Kerberos-/Passwortrichtlinien (z. B. `GptTmpl.inf`) auszulesen. `/opsec` sorgt dafür, dass der AS-REQ/AS-REP-Ablauf dem Verhalten von Windows entspricht, indem der zweistufige Preauth-Austausch durchgeführt sowie ausschließlich AES und realistische KDCOptions erzwungen werden. Dadurch werden offensichtliche Indikatoren wie fehlende PAC-Felder oder nicht zur Richtlinie passende Laufzeiten deutlich reduziert.<sup>[[3]](#references)</sup>

```powershell
# Query RID/context data (PowerView/SharpView/AD modules all work)
Get-DomainUser -Identity <username> -Properties objectsid | Select-Object samaccountname,objectsid

# Craft a high-fidelity diamond TGT and inject it
./Rubeus.exe diamond /tgtdeleg \
  /ticketuser:svc_sql /ticketuserid:1109 \
  /groups:512,519 \
  /krbkey:<KRBTGT_AES256_KEY> \
  /ldap /ldapuser:MARVEL\loki /ldappassword:Mischief$ \
  /opsec /nowrap
```

- `/ldap` (mit optionalen `/ldapuser` und `/ldappassword`) fragt AD und SYSVOL ab, um die PAC-Richtliniendaten des Zielbenutzers nachzubilden.
- `/opsec` erzwingt einen Windows-ähnlichen AS-REQ-Wiederholungsversuch, setzt auffällige Flags auf null und beschränkt die Verschlüsselung auf AES256.
- `/tgtdeleg` ermöglicht es, das Klartextpasswort oder den NTLM-/AES-Schlüssel des Opfers unangetastet zu lassen und trotzdem ein entschlüsselbares TGT zurückzugeben.

### Service-Tickets neu erstellen

Die gleiche Rubeus-Aktualisierung ergänzte die Möglichkeit, die Diamond-Technik auf TGS-Blobs anzuwenden. Indem du `diamond` ein **Base64-codiertes TGT** (von `asktgt`, `/tgtdeleg` oder ein zuvor gefälschtes TGT), den **Service-SPN** und den **AES-Schlüssel des Service** übergibst, kannst du realistische Service-Tickets erstellen, ohne den KDC zu kontaktieren – im Grunde ein unauffälligeres Silver Ticket.<sup>[[3]](#references)</sup>

```powershell
./Rubeus.exe diamond \
  /ticket:<BASE64_TGT_OR_KRB-CRED> \
  /service:cifs/dc01.lab.local \
  /servicekey:<AES256_SERVICE_KEY> \
  /ticketuser:svc_sql /ticketuserid:1109 \
  /ldap /opsec /nowrap
```

Dieser Workflow ist ideal, wenn du bereits über einen service account key verfügst (z. B. mit `lsadump::lsa /inject` oder `secretsdump.py` ausgelesen) und ein einmaliges TGS erstellen möchtest, das genau der AD-Richtlinie, den Zeitvorgaben und den PAC-Daten entspricht, ohne neuen AS/TGS-Verkehr zu erzeugen.<sup>[[3]](#references)</sup>

### Sapphire-style PAC swaps (2025)

Eine neuere Variante, manchmal **sapphire ticket** genannt, kombiniert die „real TGT“-Basis von Diamond mit **S4U2self+U2U**, um einen privilegierten PAC zu stehlen und in das eigene TGT einzufügen. Statt zusätzliche SIDs zu erfinden, forderst du ein U2U-S4U2self-Ticket für einen Benutzer mit hohen Rechten an, wobei der `sname` auf den Anfragenden mit niedrigen Rechten verweist. Der KRB_TGS_REQ enthält das TGT des Anfragenden in `additional-tickets` und setzt `ENC-TKT-IN-SKEY`, sodass sich das Service-Ticket mit dem Schlüssel dieses Benutzers entschlüsseln lässt. Anschließend extrahierst du den privilegierten PAC und fügst ihn in dein legitimes TGT ein, bevor du ihn mit dem krbtgt-Schlüssel neu signierst.<sup>[[2]](#references)[[5]](#references)</sup>

Impacket unterstützt sapphire jetzt in `ticketer.py` über `-impersonate` + `-request` (Live-KDC-Austausch):<sup>[[2]](#references)[[5]](#references)</sup>

```bash
python3 ticketer.py -request -impersonate 'DAuser' \
  -domain 'lab.local' -user 'lowpriv' -password 'Passw0rd!' \
  -aesKey '<krbtgt_aes256>' -domain-sid 'S-1-5-21-111-222-333'
# inject resulting .ccache
export KRB5CCNAME=lowpriv.ccache
python3 psexec.py lab.local/DAuser@dc.lab.local -k -no-pass
```

- `-impersonate` akzeptiert einen Benutzernamen oder eine SID; `-request` erfordert Live-Anmeldedaten eines Benutzers sowie krbtgt-Schlüsselmaterial (AES/NTLM), um Tickets zu entschlüsseln und zu patchen.

Wichtige OPSEC-Indikatoren bei Verwendung dieser Variante:<sup>[[5]](#references)</sup>

- TGS-REQ enthält `ENC-TKT-IN-SKEY` und `additional-tickets` (das TGT des Opfers) – ungewöhnlich im normalen Datenverkehr.
- `sname` entspricht häufig dem anfragenden Benutzer (Self-Service-Zugriff), und Event ID 4769 zeigt den Aufrufer und das Ziel als denselben SPN/Benutzer.
- Es sind zusammengehörige 4768/4769-Einträge mit demselben Clientcomputer, aber unterschiedlichen CNAMES zu erwarten (Anfragender mit geringen Berechtigungen vs. privilegierter PAC-Eigentümer).

### OPSEC- und Erkennungshinweise

- Die herkömmlichen Hunter-Heuristiken (TGS ohne AS, Laufzeiten von Jahrzehnten) gelten weiterhin für Golden Tickets. Diamond Tickets fallen jedoch hauptsächlich auf, wenn der **PAC-Inhalt oder die Gruppenzuordnung unmöglich erscheint**. Befülle alle PAC-Felder (Anmeldezeiten, Benutzerprofilpfade, Geräte-IDs), damit automatisierte Vergleiche die Fälschung nicht sofort erkennen.<sup>[[3]](#references)</sup>
- **Füge nicht zu viele Gruppen/RIDs hinzu**. Wenn du nur `512` (Domain Admins) und `519` (Enterprise Admins) benötigst, belasse es dabei und stelle sicher, dass das Zielkonto plausiblerweise auch an anderer Stelle in AD zu diesen Gruppen gehört. Übermäßig viele `ExtraSids` sind ein verräterisches Zeichen.
- Sapphire-artige Austausche hinterlassen U2U-Spuren: `ENC-TKT-IN-SKEY` und `additional-tickets` sowie ein `sname`, das in 4769 auf einen Benutzer (häufig den Anfragenden) verweist, und eine nachfolgende 4624-Anmeldung, die vom gefälschten Ticket stammt. Korreliere diese Felder, statt nur nach Lücken ohne AS-REQ zu suchen.<sup>[[5]](#references)</sup>
- Microsoft hat begonnen, die **Ausstellung von RC4-Service-Tickets** aufgrund von CVE-2026-20833 schrittweise einzustellen. Die Durchsetzung von AES-only-Etypes auf dem KDC härtet die Domäne und entspricht zugleich den Diamond-/Sapphire-Tools (`/opsec` erzwingt bereits AES). RC4 in gefälschten PACs zu verwenden, wird zunehmend auffallen.<sup>[[6]](#references)</sup>
- Splunks Security Content-Projekt stellt Attack-Range-Telemetrie für Diamond Tickets sowie Erkennungen wie *Windows Domain Admin Impersonation Indicator* bereit. Diese korrelieren ungewöhnliche Abfolgen von Event ID 4768/4769/4624 und Änderungen an PAC-Gruppen. Die Wiedergabe dieses Datensatzes (oder die Erstellung eines eigenen mit den obigen Befehlen) hilft dabei, die SOC-Abdeckung für T1558.001 zu überprüfen und liefert zugleich konkrete Alarmierungslogik, der du ausweichen kannst.<sup>[[4]](#references)</sup>

## References

- [1] [Palo Alto Unit 42 – Edelsteine von besonderem Wert: Die neue Generation von Kerberos-Angriffen (2022)](https://unit42.paloaltonetworks.com/next-gen-kerberos-attacks/)
- [2] [Core Security – Impacket: Wir lieben es, mit Tickets zu spielen (2023)](https://www.coresecurity.com/core-labs/articles/impacket-we-love-playing-tickets)
- [3] [Huntress – Den Kerberos Diamond Ticket neu zuschneiden (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [4] [Splunk Security Content – Angriffsdaten und Erkennungen zu Diamond Tickets (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)
- [5] [Хабр – Die Schattenseite der Edelsteine: Diamond & Sapphire Ticket (2025)](https://habr.com/ru/articles/891620/)
- [6] [Microsoft – Durchsetzung von RC4-Service-Tickets für CVE-2026-20833](https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc)
{{#include ../../banners/hacktricks-training.md}}
