# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Wie ein golden ticket** ist ein diamond ticket ein TGT, das verwendet werden kann, um **als beliebiger Benutzer auf jeden Dienst zuzugreifen**. Ein golden ticket wird vollständig offline gefälscht, mit dem krbtgt-Hash der Domäne verschlüsselt und anschließend zur Verwendung in eine Anmeldesitzung eingefügt. Da Domänencontroller nicht nachverfolgen, welche TGTs sie rechtmäßig ausgestellt haben, akzeptieren sie problemlos TGTs, die mit ihrem eigenen krbtgt-Hash verschlüsselt sind.<sup>[[1]](#references)</sup>

Es gibt zwei gängige Techniken, um die Verwendung von golden tickets zu erkennen:

- Nach TGS-REQs ohne zugehörigen AS-REQ suchen.
- Nach TGTs mit ungewöhnlichen Werten suchen, etwa der standardmäßigen Laufzeit von 10 Jahren in Mimikatz.

Ein **diamond ticket** wird erstellt, indem **die Felder eines legitimen, von einem DC ausgestellten TGT geändert werden**. Dazu wird ein **TGT angefordert**, mit dem krbtgt-Hash der Domäne **entschlüsselt**, die gewünschten Ticketfelder **geändert** und anschließend **erneut verschlüsselt**. Damit werden die beiden oben genannten Schwachstellen eines golden tickets **umgangen**, denn:<sup>[[1]](#references)</sup>

- TGS-REQs haben einen vorausgehenden AS-REQ.
- Das TGT wurde von einem DC ausgestellt und enthält daher alle korrekten Angaben aus der Kerberos-Richtlinie der Domäne. Auch wenn sich diese Angaben in einem golden ticket präzise fälschen lassen, ist das komplexer und fehleranfälliger.

### Voraussetzungen und Ablauf

- **Kryptografisches Material**: der AES256-Schlüssel von krbtgt (bevorzugt) oder der NTLM-Hash, um das TGT zu entschlüsseln und erneut zu signieren.
- **Legitimer TGT-Blob**: bezogen über `/tgtdeleg`, `asktgt`, `s4u` oder durch Exportieren von Tickets aus dem Speicher.
- **Kontextdaten**: die RID des Zielbenutzers, Gruppen-RIDs/SIDs und (optional) aus LDAP abgeleitete PAC-Attribute.
- **Dienstschlüssel** (nur wenn Diensttickets neu erstellt werden sollen): AES-Schlüssel des Dienst-SPN, der imitiert werden soll.

1. Über AS-REQ ein TGT für einen beliebigen kontrollierten Benutzer beziehen (`/tgtdeleg` von Rubeus ist praktisch, da es den Client dazu zwingt, den Kerberos-GSS-API-Ablauf ohne Anmeldedaten auszuführen).
2. Das zurückgegebene TGT mit dem krbtgt-Schlüssel entschlüsseln und PAC-Attribute anpassen (Benutzer, Gruppen, Anmeldeinformationen, SIDs, Geräte-Claims usw.).
3. Das Ticket mit demselben krbtgt-Schlüssel erneut verschlüsseln/signieren und in die aktuelle Anmeldesitzung einfügen (`kerberos::ptt`, `Rubeus.exe ptt`...).
4. Optional den Vorgang mit einem Dienstticket wiederholen, indem ein gültiger TGT-Blob und der Ziel-Dienstschlüssel angegeben werden, um auf der Leitung unauffällig zu bleiben.

### Aktualisierte Rubeus-Techniken (2024+)

Neuere Arbeiten von Huntress haben die `diamond`-Aktion in Rubeus modernisiert, indem sie die Verbesserungen `/ldap` und `/opsec` übernommen haben, die zuvor nur für golden/silver tickets verfügbar waren. `/ldap` ruft nun realen PAC-Kontext ab, indem LDAP abgefragt **und** SYSVOL eingebunden wird, um Konto- und Gruppenattribute sowie die Kerberos-/Passwortrichtlinie auszulesen (z. B. `GptTmpl.inf`). `/opsec` sorgt dafür, dass der AS-REQ/AS-REP-Ablauf dem Verhalten von Windows entspricht, indem der zweistufige Preauth-Austausch durchgeführt sowie ausschließlich AES und realistische KDCOptions erzwungen werden. Dadurch werden auffällige Indikatoren wie fehlende PAC-Felder oder nicht zur Richtlinie passende Laufzeiten deutlich reduziert.<sup>[[3]](#references)</sup>

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
- `/opsec` erzwingt einen Windows-ähnlichen AS-REQ-Wiederholungsversuch, setzt auffällige Flags auf null und beschränkt sich auf AES256.
- `/tgtdeleg` vermeidet den Zugriff auf das Klartextpasswort oder den NTLM-/AES-Schlüssel des Opfers und gibt dennoch ein entschlüsselbares TGT zurück.

### Service-Tickets neu zuschneiden

Dasselbe Rubeus-Update fügte die Möglichkeit hinzu, die Diamond-Technik auf TGS-Blobs anzuwenden. Indem du `diamond` ein **Base64-kodiertes TGT** (von `asktgt`, `/tgtdeleg` oder einem zuvor gefälschten TGT), den **Service-SPN** und den **AES-Schlüssel des Dienstes** übergibst, kannst du realistische Service-Tickets erstellen, ohne den KDC zu kontaktieren – effektiv ein unauffälligeres Silver Ticket.<sup>[[3]](#references)</sup>

```powershell
./Rubeus.exe diamond \
  /ticket:<BASE64_TGT_OR_KRB-CRED> \
  /service:cifs/dc01.lab.local \
  /servicekey:<AES256_SERVICE_KEY> \
  /ticketuser:svc_sql /ticketuserid:1109 \
  /ldap /opsec /nowrap
```

Dieser Workflow ist ideal, wenn du bereits einen Service-Account-Key kontrollierst (z. B. mit `lsadump::lsa /inject` oder `secretsdump.py` gedumpt) und ein einmaliges TGS erstellen möchtest, das exakt zu AD-Richtlinien, Zeitvorgaben und PAC-Daten passt, ohne neuen AS/TGS-Traffic zu erzeugen.<sup>[[3]](#references)</sup>

### Sapphire-artige PAC-Swaps (2025)

Eine neuere Variante, die manchmal **sapphire ticket** genannt wird, kombiniert Diamonds Basis aus einem „real TGT“ mit **S4U2self+U2U**, um einen privilegierten PAC zu stehlen und in das eigene TGT einzufügen. Statt zusätzliche SIDs zu erfinden, forderst du ein U2U-S4U2self-Ticket für einen Benutzer mit hohen Berechtigungen an, wobei `sname` auf den Benutzer mit niedrigen Berechtigungen zeigt, der die Anfrage stellt; der KRB_TGS_REQ enthält das TGT des Anfragenden in `additional-tickets` und setzt `ENC-TKT-IN-SKEY`, sodass das Service-Ticket mit dem Schlüssel dieses Benutzers entschlüsselt werden kann. Anschließend extrahierst du den privilegierten PAC und fügst ihn in dein legitimes TGT ein, bevor du ihn mit dem krbtgt-Schlüssel neu signierst.<sup>[[2]](#references)[[5]](#references)</sup>

Impacket bietet jetzt Sapphire-Unterstützung in `ticketer.py` über `-impersonate` + `-request` (Live-KDC-Austausch):<sup>[[2]](#references)[[5]](#references)</sup>

```bash
python3 ticketer.py -request -impersonate 'DAuser' \
  -domain 'lab.local' -user 'lowpriv' -password 'Passw0rd!' \
  -aesKey '<krbtgt_aes256>' -domain-sid 'S-1-5-21-111-222-333'
# inject resulting .ccache
export KRB5CCNAME=lowpriv.ccache
python3 psexec.py lab.local/DAuser@dc.lab.local -k -no-pass
```

- `-impersonate` akzeptiert einen Benutzernamen oder eine SID; `-request` erfordert aktuelle Benutzeranmeldedaten sowie `krbtgt`-Schlüsselmaterial (AES/NTLM), um Tickets zu entschlüsseln und zu patchen.

Wichtige OPSEC-Indikatoren bei dieser Variante:<sup>[[5]](#references)</sup>

- TGS-REQ enthält `ENC-TKT-IN-SKEY` und `additional-tickets` (das TGT des Opfers) – ungewöhnlich im normalen Datenverkehr.
- `sname` entspricht häufig dem anfragenden Benutzer (Self-Service-Zugriff), und Event ID 4769 zeigt den Aufrufer und das Ziel als denselben SPN/Benutzer.
- Rechnen Sie mit gepaarten 4768/4769-Einträgen mit demselben Clientcomputer, aber unterschiedlichen CNAMES (Anfragender mit geringen Berechtigungen vs. privilegierter PAC-Eigentümer).

### OPSEC- und Erkennungshinweise

- Die traditionellen Hunter-Heuristiken (TGS ohne AS, Laufzeiten von Jahrzehnten) gelten weiterhin für Golden Tickets, aber Diamond Tickets fallen hauptsächlich auf, wenn der **PAC-Inhalt oder die Gruppenzuordnung unmöglich erscheint**. Befüllen Sie alle PAC-Felder (Anmeldezeiten, Benutzerprofilpfade, Geräte-IDs), damit automatisierte Vergleiche die Fälschung nicht sofort erkennen.<sup>[[3]](#references)</sup>
- **Fügen Sie nicht zu viele Gruppen/RIDs hinzu**. Wenn Sie nur `512` (Domain Admins) und `519` (Enterprise Admins) benötigen, belassen Sie es dabei und stellen Sie sicher, dass das Zielkonto plausiblerweise auch an anderer Stelle in AD zu diesen Gruppen gehört. Übermäßige `ExtraSids` sind verräterisch.
- Sapphire-artige Austausche hinterlassen U2U-Spuren: `ENC-TKT-IN-SKEY` und `additional-tickets` sowie ein `sname`, das in 4769 auf einen Benutzer (oft den Anfragenden) verweist, und ein nachfolgender 4624-Logon aus dem gefälschten Ticket. Korrelieren Sie diese Felder, statt nur nach Lücken ohne AS-REQ zu suchen.<sup>[[5]](#references)</sup>
- Microsoft hat damit begonnen, die **Ausstellung von RC4-Service-Tickets** wegen CVE-2026-20833 schrittweise einzustellen; die Erzwingung von AES-only-Etypes auf dem KDC härtet die Domäne und entspricht zugleich den Diamond-/Sapphire-Tools (`/opsec` erzwingt bereits AES). RC4 in gefälschte PACs einzumischen, wird zunehmend auffallen.<sup>[[6]](#references)</sup>
- Splunks Projekt Security Content stellt Telemetriedaten aus einer Attack Range für Diamond Tickets sowie Erkennungsregeln wie *Windows Domain Admin Impersonation Indicator* bereit, die ungewöhnliche Sequenzen von Event ID 4768/4769/4624 und Änderungen an PAC-Gruppen korrelieren. Das erneute Abspielen dieses Datensatzes (oder das Erzeugen eigener Daten mit den obigen Befehlen) hilft dabei, die SOC-Abdeckung für T1558.001 zu validieren, und liefert gleichzeitig konkrete Alarmierungslogik, die umgangen werden kann.<sup>[[4]](#references)</sup>

## References

- [1] [Palo Alto Unit 42 – Edelsteine: Die nächste Generation von Kerberos-Angriffen (2022)](https://unit42.paloaltonetworks.com/next-gen-kerberos-attacks/)
- [2] [Core Security – Impacket: Wir spielen gerne mit Tickets (2023)](https://www.coresecurity.com/core-labs/articles/impacket-we-love-playing-tickets)
- [3] [Huntress – Den Kerberos Diamond Ticket neu zuschneiden (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [4] [Splunk Security Content – Angriffsdaten und Erkennungsregeln für Diamond Tickets (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)
- [5] [Хабр – Die Schattenseite der Edelsteine: Diamond & Sapphire Ticket (2025)](https://habr.com/ru/articles/891620/)
- [6] [Microsoft – Erzwingung von RC4-Service-Tickets für CVE-2026-20833](https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc)
{{#include ../../banners/hacktricks-training.md}}
