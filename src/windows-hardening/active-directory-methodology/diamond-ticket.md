# Diamond Ticket

{{#include ../../banners/hacktricks-training.md}}

## Diamond Ticket

**Wie ein golden ticket**, ein diamond ticket ist ein TGT, das verwendet werden kann, um **auf jeden Dienst als beliebiger Benutzer** zuzugreifen. Ein golden ticket wird komplett offline gefälscht, mit dem krbtgt-Hash dieser Domain verschlüsselt und dann in eine Logon-Session geladen. Da Domain Controller TGTs, die sie (legitim) ausgestellt haben, nicht nachverfolgen, akzeptieren sie bereitwillig TGTs, die mit ihrem eigenen krbtgt-Hash verschlüsselt sind.

Es gibt zwei gebräuchliche Techniken, um die Verwendung von golden tickets zu erkennen:

- Suche nach TGS-REQs, die keine entsprechende AS-REQ haben.
- Suche nach TGTs mit auffälligen Werten, wie der standardmäßigen 10-Jahres-Lebensdauer von Mimikatz.

Ein **diamond ticket** wird erzeugt, indem die Felder eines legitimen TGT, das von einem DC ausgestellt wurde, **modifiziert** werden. Dies wird erreicht, indem man ein **TGT anfordert**, es mit dem krbtgt-Hash der Domain **entschlüsselt**, die gewünschten Felder des Tickets **ändert** und es anschließend wieder **verschlüsselt**. Dadurch werden die beiden oben genannten Schwachstellen eines golden ticket überwunden, weil:

- TGS-REQs eine vorausgehende AS-REQ haben.
- Das TGT von einem DC ausgestellt wurde und somit alle korrekten Details gemäß der Kerberos-Policy der Domain enthält. Obwohl diese in einem golden ticket präzise gefälscht werden können, ist das komplexer und fehleranfälliger.

### Requirements & workflow

- **Cryptographic material**: der krbtgt AES256 key (bevorzugt) oder NTLM hash, um das TGT zu entschlüsseln und erneut zu signieren.
- **Legitimate TGT blob**: erhalten mit `/tgtdeleg`, `asktgt`, `s4u` oder durch Export von Tickets aus dem Speicher.
- **Context data**: die RID des Zielbenutzers, Gruppen-RIDs/SIDs und (optional) LDAP-derived PAC-Attribute.
- **Service keys** (nur falls geplant, Service-Tickets neu auszustellen): AES key des Service-SPN, den man impersonieren möchte.

1. Beschaffe ein TGT für einen beliebigen kontrollierten Benutzer via AS-REQ (Rubeus `/tgtdeleg` ist praktisch, weil es den Client zwingt, den Kerberos GSS-API-Austausch ohne Credentials durchzuführen).
2. Entschlüssele das zurückgegebene TGT mit dem krbtgt key, patch die PAC-Attribute (Benutzer, Gruppen, Logon-Info, SIDs, Device-Claims usw.).
3. Verschlüssele/signiere das Ticket erneut mit demselben krbtgt key und injiziere es in die aktuelle Logon-Session (`kerberos::ptt`, `Rubeus.exe ptt`...).
4. Optional: Wiederhole den Prozess für ein Service-Ticket, indem du ein gültiges TGT blob plus den Ziel-Service-Key bereitstellst, um auf dem Wire stealthy zu bleiben.

### Updated Rubeus tradecraft (2024+)

Jüngste Arbeit von Huntress modernisierte die `diamond`-Action in Rubeus, indem die `/ldap`- und `/opsec`-Verbesserungen, die zuvor nur für golden/silver tickets existierten, portiert wurden. `/ldap` zieht jetzt echten PAC-Kontext, indem es LDAP abfragt **und** SYSVOL mountet, um Account-/Gruppen-Attribute sowie Kerberos-/Password-Policy (z. B. `GptTmpl.inf`) zu extrahieren, während `/opsec` den AS-REQ/AS-REP-Flow Windows-gleich macht, indem es den zweistufigen Preauth-Austausch durchführt und AES-only + realistische KDCOptions erzwingt. Das reduziert deutlich offensichtliche Indikatoren wie fehlende PAC-Felder oder policy-missmatchte Lifetimes.
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
- `/ldap` (mit optionalen `/ldapuser` & `/ldappassword`) fragt AD und SYSVOL ab, um die PAC-Richtliniendaten des Zielbenutzers zu spiegeln.
- `/opsec` erzwingt eine Windows-ähnliche AS-REQ-Wiederholung, nullt störende Flags und bleibt bei AES256.
- `/tgtdeleg` hält dich vom Klartextpasswort bzw. dem NTLM/AES-Schlüssel des Opfers fern, liefert aber trotzdem ein entschlüsselbares TGT zurück.

### Service-Ticket-Neuzuschnitt

Das gleiche Rubeus-Refresh fügte die Möglichkeit hinzu, die diamond technique auf TGS blobs anzuwenden. Indem man `diamond` ein **base64-encoded TGT** (von `asktgt`, `/tgtdeleg`, oder einem zuvor gefälschten TGT), den **service SPN**, und den **service AES key** übergibt, kann man realistische Service-Tickets erstellen, ohne den KDC zu berühren — effektiv ein unauffälligerer silver ticket.
```powershell
./Rubeus.exe diamond \
/ticket:<BASE64_TGT_OR_KRB-CRED> \
/service:cifs/dc01.lab.local \
/servicekey:<AES256_SERVICE_KEY> \
/ticketuser:svc_sql /ticketuserid:1109 \
/ldap /opsec /nowrap
```
Dieser Workflow ist ideal, wenn Sie bereits einen service account key (e.g., dumped with `lsadump::lsa /inject` or `secretsdump.py`) kontrollieren und ein einmaliges TGS erstellen möchten, das perfekt zu AD policy, Zeitstempeln und PAC data passt, ohne neuen AS/TGS-Verkehr zu erzeugen.

### Sapphire-style PAC swaps (2025)

Eine neuere Variante, manchmal als **sapphire ticket** bezeichnet, kombiniert Diamond's "real TGT" base mit **S4U2self+U2U**, um einen privilegierten PAC zu stehlen und ihn in Ihr eigenes TGT zu implantieren. Anstatt zusätzliche SIDs zu erfinden, fordern Sie ein U2U S4U2self-Ticket für einen hoch privilegierten Benutzer an, bei dem das `sname` auf den niedrig-privilegierten Anforderer zielt; die KRB_TGS_REQ trägt das TGT des Anforderers in `additional-tickets` und setzt `ENC-TKT-IN-SKEY`, wodurch das service ticket mit dem Schlüssel dieses Benutzers entschlüsselt werden kann. Anschließend extrahieren Sie den privilegierten PAC und fügen ihn in Ihr legitimes TGT ein, bevor Sie es mit dem krbtgt key neu signieren.

Impacket's `ticketer.py` now ships sapphire support via `-impersonate` + `-request` (live KDC exchange):
```bash
python3 ticketer.py -request -impersonate 'DAuser' \
-domain 'lab.local' -user 'lowpriv' -password 'Passw0rd!' \
-aesKey '<krbtgt_aes256>' -domain-sid 'S-1-5-21-111-222-333'
# inject resulting .ccache
export KRB5CCNAME=lowpriv.ccache
python3 psexec.py lab.local/DAuser@dc.lab.local -k -no-pass
```
- `-impersonate` akzeptiert einen Benutzernamen oder SID; `-request` benötigt gültige Benutzer-Anmeldeinformationen plus krbtgt-Schlüsselmateriaal (AES/NTLM), um Tickets zu entschlüsseln/patchen.

Wichtige OPSEC-Indikatoren bei Verwendung dieser Variante:

- TGS-REQ wird `ENC-TKT-IN-SKEY` und `additional-tickets` (das Opfer-TGT) enthalten — selten im normalen Verkehr.
- `sname` ist oft gleich dem anfragenden Benutzer (Self-Service-Zugriff) und Event ID 4769 zeigt den Anrufer und das Ziel als denselben SPN/Benutzer.
- Erwarten Sie gepaarte 4768/4769-Einträge mit demselben Client-Computer, aber unterschiedlichen CNAMES (niedrig privilegierter Anforderer vs. privilegierter PAC-Eigentümer).

### OPSEC- & Erkennungsnotizen

- Die traditionellen Hunter-Heuristiken (TGS ohne AS, jahrzehntelange Lebensdauern) gelten weiterhin für golden tickets, aber diamond tickets treten hauptsächlich zutage, wenn der **PAC-Inhalt oder die Gruppenabbildung unmöglich aussieht**. Füllen Sie jedes PAC-Feld aus (logon hours, user profile paths, device IDs), damit automatisierte Vergleiche die Fälschung nicht sofort markieren.
- **Weisen Sie Gruppen/RIDs nicht übermäßig zu**. Wenn Sie nur `512` (Domain Admins) und `519` (Enterprise Admins) benötigen, belassen Sie es dabei und stellen Sie sicher, dass das Zielkonto plausibel anderweitig in AD zu diesen Gruppen gehört. Übermäßige `ExtraSids` verraten es.
- Sapphire-style swaps hinterlassen U2U-Fingerabdrücke: `ENC-TKT-IN-SKEY` + `additional-tickets` plus ein `sname`, das in 4769 auf einen Benutzer (oft den Anforderer) zeigt, und ein anschließender 4624-Logon, der aus dem gefälschten Ticket stammt. Korrigieren Sie diese Felder, anstatt nur nach no-AS-REQ-Lücken zu suchen.
- Microsoft begann mit dem Ausphasieren der **RC4 service ticket issuance** wegen CVE-2026-20833; das Erzwingen von AES-only etypes auf dem KDC härtet sowohl die Domain als auch stimmt mit diamond/sapphire-Tooling überein (/opsec erzwingt bereits AES). Das Mischen von RC4 in gefälschte PACs wird zunehmend auffallen.
- Splunk's Security Content project verteilt attack-range telemetry für diamond tickets sowie Erkennungen wie *Windows Domain Admin Impersonation Indicator*, das ungewöhnliche Event ID 4768/4769/4624-Sequenzen und PAC-Gruppenänderungen korreliert. Das Abspielen dieses Datensatzes (oder das Erzeugen eigener Daten mit den obigen Befehlen) hilft, die SOC-Abdeckung für T1558.001 zu validieren und gibt Ihnen konkrete Alarmlogik, die es zu umgehen gilt.

## References

- [Palo Alto Unit 42 – Precious Gemstones: The New Generation of Kerberos Attacks (2022)](https://unit42.paloaltonetworks.com/next-gen-kerberos-attacks/)
- [Core Security – Impacket: We Love Playing Tickets (2023)](https://www.coresecurity.com/core-labs/articles/impacket-we-love-playing-tickets)
- [Huntress – Recutting the Kerberos Diamond Ticket (2025)](https://www.huntress.com/blog/recutting-the-kerberos-diamond-ticket)
- [Splunk Security Content – Diamond Ticket attack data & detections (2023)](https://research.splunk.com/attack_data/be469518-9d2d-4ebb-b839-12683cd18a7c/)
- [Хабр – Теневая сторона драгоценностей: Diamond & Sapphire Ticket (2025)](https://habr.com/ru/articles/891620/)
- [Microsoft – RC4 service ticket enforcement for CVE-2026-20833](https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc)

{{#include ../../banners/hacktricks-training.md}}
