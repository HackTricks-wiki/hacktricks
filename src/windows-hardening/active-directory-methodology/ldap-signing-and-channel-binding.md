# LDAP Signing & Channel Binding Hardening

{{#include ../../banners/hacktricks-training.md}}

## Warum es wichtig ist

LDAP-Relay-/MITM-Angriffe leiten die Authentifizierung an einen Domain Controller weiter, um einen authentifizierten LDAP-Kontext zu erhalten. Die [Übersicht zu Name-Resolution-Poisoning und Relay-Angriffen](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) behandelt den umfassenderen Ablauf. Zwei verwandte Kontrollen schränken diese Angriffswege ein:

- **LDAP channel binding (CBT)** bindet die entsprechende Authentifizierung an das TLS-Serverzertifikat bzw. den TLS-Kanal, der für LDAPS verwendet wird, und erschwert so kanalübergreifende Relays.
- **LDAP signing** erfordert Integritätsschutz für SASL-LDAP-Binds. Es bietet keine Vertraulichkeit; verwenden Sie TLS, wenn LDAP-Inhalte zusätzlich verschlüsselt werden müssen.<sup>[[2]](#references)</sup>

**Schnelle Überprüfung der Konfiguration**: Tools wie `netexec ldap <dc> -u user -p pass` melden die ermittelte Signing- und Channel-Binding-Richtlinie. `(signing:None)` und `(channel binding:Never)` weisen auf fehlende Kontrollen hin. Ein erfolgreiches Relay hängt jedoch weiterhin vom erfassten Authentifizierungstyp, dem EPA-Verhalten, den Kontoberechtigungen, dem Zielprotokoll und den Relay-Schutzmaßnahmen ab. Verfügt der weitergeleitete Principal über die erforderlichen Rechte, können Tools wie KrbRelayUp `msDS-AllowedToActOnBehalfOfOtherIdentity` schreiben, ressourcenbasierte eingeschränkte Delegierung (RBCD) konfigurieren und den resultierenden Delegierungspfad verwenden, um sich als privilegierter Principal auszugeben.<sup>[[4]](#references)</sup>

**Server-2025-DCs** führen eine neue GPO (**LDAP server signing requirements Enforcement**) ein, die standardmäßig **Require Signing** verwendet, wenn sie auf **Not Configured** belassen wird. Um die Erzwingung zu vermeiden, muss diese Richtlinie explizit auf **Disabled** gesetzt werden.<sup>[[1]](#references)</sup>

## LDAP Channel Binding (nur LDAPS)

- **Voraussetzungen**:
  - Der CVE-2017-8563-Patch (2017) ergänzt die Unterstützung für Extended Protection for Authentication.<sup>[[3]](#references)</sup>
  - **KB4520412** (Server 2019/2022) ergänzt LDAPS-CBT-Telemetrie im „What-if“-Modus.<sup>[[2]](#references)</sup>
- **GPO (DCs)**: `Domain controller: LDAP server channel binding token requirements`
  - `Never` (Standardwert, kein CBT)
  - `When Supported` (teilweise Erzwingung: CBT-fähige Clients müssen ein gültiges Token bereitstellen; Clients ohne CBT-Unterstützung können weiterhin Binds durchführen, und Audit-Ereignisse werden ausgegeben)
  - `Always` (Erzwingung: LDAPS-Binds ohne gültiges CBT werden abgewiesen)<sup>[[1]](#references)</sup>
- **Audit**: Setzen Sie **When Supported**, um Folgendes sichtbar zu machen:
  - **3074** – Der LDAPS-Bind wäre bei aktivierter Erzwingung an der CBT-Validierung gescheitert.
  - **3075** – Beim LDAPS-Bind wurden keine CBT-Daten übermittelt; bei aktivierter Erzwingung würde er abgewiesen.
  - (Ereignis **3039** signalisiert bei älteren Builds weiterhin CBT-Fehler.)<sup>[[1]](#references)[[2]](#references)</sup>
- **Erzwingung**: Setzen Sie **Always**, sobald LDAPS-Clients CBTs senden; dies wirkt sich nur auf **LDAPS** aus (nicht auf rohes LDAP über Port 389).<sup>[[1]](#references)</sup>

`When Supported` dient nicht ausschließlich dem Audit: Die Einstellung validiert CBT für unterstützte Clients und lässt Clients ohne CBT-Unterstützung weiterhin zu. Die [Microsoft-Richtlinienreferenz](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding) beschreibt die versionsabhängigen Standardwerte. LDAP signing gilt für entsprechende Binds über LDAP/389; channel binding gilt für TLS-geschützte LDAP-Authentifizierung.


## LDAP Signing

- **Client-GPO**: `Network security: LDAP client signing requirements` = `Require signing` (im Gegensatz zum modernen Windows-Standardwert `Negotiate signing`).<sup>[[1]](#references)</sup>
- **DC-GPO**:
  - Ältere Versionen: `Domain controller: LDAP server signing requirements` = `Require signing` (Standardwert ist `None`).<sup>[[2]](#references)</sup>
  - **Server 2025**: Belassen Sie die ältere Richtlinie auf `None` und setzen Sie `LDAP server signing requirements Enforcement` auf `Enabled` (`Not Configured` bedeutet standardmäßig Erzwingung; setzen Sie die Richtlinie auf `Disabled`, um diese zu vermeiden).<sup>[[1]](#references)</sup>
- **Kompatibilität**: Erfassen Sie Appliances und Anwendungen, die nicht unter Windows laufen und Simple Binds oder nicht signierte SASL-Binds verwenden. Microsoft dokumentiert die Unterstützung für gewartete Windows-Versionen; Aussagen zur Kompatibilität mit älteren Clients sollten anhand des tatsächlichen Client-Stacks überprüft und nicht auf eine XP-Versionsgrenze reduziert werden.<sup>[[2]](#references)</sup>

## Relay-Angriffswege und erneute Authentifizierung mit signiertem SASL

Wenn **nur signing** erforderlich ist, kann ein Relay zu LDAPS weiterhin funktionieren, sofern channel binding nicht erzwungen wird: TLS liefert die Integrität auf Transportebene. Wenn **nur channel binding** erforderlich ist, gibt es bei einfachem LDAP keinen TLS-Kanal, an den es gebunden werden kann; ein Relay kann sich über TCP 389 authentifizieren und anschließend StartTLS für Vorgänge verwenden, die TLS erfordern, sofern die weitergeleitete Identität über die erforderlichen Rechte verfügt. Die Erzwingung beider Kontrollen schließt diese üblichen Alternativen, verhinderte jedoch nicht den folgenden Fehler auf ungepatchten Domain Controllern.<sup>[[5]](#references)</sup>

### LDAP-Operation nach einem weitergeleiteten Bind einschleusen

Stellen Sie auf betroffenen Windows-Server-2016–2025-Domain-Controllern zunächst als Identität X eine **signierte NTLM-SASL-LDAP-Verbindung** über TCP 389 her, und verwenden Sie dafür Zugangsdaten, deren Sitzungsschlüssel Sie kennen (oder einen anonymen NTLM-SASL-Kontext, sofern dieser akzeptiert wird). Bringen Sie Identität Y dazu, sich **über SMB** beim Relay zu authentifizieren. Leiten Sie Y's NTLM NEGOTIATE und die CHALLENGE des DC über GSS-SPNEGO-Bind-Requests auf X's bestehender LDAP-Verbindung weiter. Der Windows-SMB-Client setzt `NTLMSSP_NEGOTIATE_SIGN`, sodass der resultierende LDAP-Bind eine signierte SASL-Schicht erfordert; ein Austausch, der von HTTP/WebDAV ausgeht, enthält dieses Flag in der Regel nicht und ist hier nicht gleichwertig.<sup>[[5]](#references)</sup>

Wenn Y NTLM AUTHENTICATE sendet, fügen Sie **zwei unterschiedliche LDAP-Nachrichten in einen längenpräfixierten SASL-Datensatz** ein: einen BindRequest mit dieser Antwort, gefolgt von einem ModifyRequest. Signieren Sie den gesamten Datensatz mit X's bekanntem Schlüssel. Der verwundbare DC validiert den Datensatz unter X, schließt den Bind ab und wechselt die Autorisierung der Verbindung zu Y. Anschließend führt er den verbleibenden ModifyRequest als Y aus, ohne den Datensatz erneut mit Y's Schlüssel zu prüfen. Dadurch werden weder Y's Passwort noch Sitzungsschlüssel offengelegt; ein späterer, mit X signierter Datensatz schlägt fehl. Ein RBCD-Schreibvorgang in `msDS-AllowedToActOnBehalfOfOtherIdentity` oder ein Shadow-Credentials-Schreibvorgang in `msDS-KeyCredentialLink` erfordert weiterhin, dass Y über Berechtigungen für das Zielobjekt verfügt. Siehe [RBCD](resource-based-constrained-delegation.md), [Shadow Credentials](acl-persistence-abuse/shadow-credentials.md) und, für ein weitergeleitetes DC-Computerkonto, [DCSync](dcsync.md).<sup>[[5]](#references)</sup>

Dies ist ein Bypass für **einfaches LDAP**, kein Bypass für LDAPS channel binding. Bei LDAPS schützt TLS die Verbindung, und Windows richtet nicht die NTLM-SASL-Signing-Schicht mit X's Schlüssel ein, die für diesen Record-Stacking-Angriffsweg erforderlich ist. Ist TCP 389 nicht verfügbar, lässt sich die Technik nicht einfach auf TCP 636 übertragen. Die Sicherheitsupdates vom Oktober 2026 verhindern die Operation mit demselben Datensatz, indem sie verbleibende Daten verwerfen, nachdem der Bind die Verbindungsidentität geändert hat.<sup>[[5]](#references)</sup> KB5126646 ist das Update für Windows Server 2025; für andere betroffene Serverversionen gelten andere KB-Nummern.<sup>[[7]](#references)</sup>

Die [LDAP-Switcheroo](https://github.com/grayhatkiller/switcheroo) des Forschers umschließt eine modifizierte `ntlmrelayx.py` für diesen Ablauf. Sie erfordert eine **SMB**-Quelle für die Authentifizierungserzwingung, einen festgelegten Impacket-Tree mit LDAP-Signing-/Security-Context-APIs (PyPI Impacket 0.13.1 reicht nicht aus) sowie ein vom Angreifer kontrolliertes Konto für den anfänglichen signierten Bind. Geben Sie für einen RBCD-Schreibvorgang den DN des Opferobjekts und die SID eines kontrollierten delegierenden Computers an. Verwenden Sie `-attribute` mit `-value` oder `-value-hex` für einen anderen zulässigen Schreibvorgang. Überprüfen Sie den unabhängigen signierten Read-back des Tools, anstatt eine Relay-seitige `FAILED`-Meldung als Beweis dafür zu betrachten, dass der ModifyRequest fehlgeschlagen ist.<sup>[[5]](#references)[[6]](#references)</sup>

```bash
sudo PYTHONPATH=/path/to/pinned-impacket python3 switcheroo.py \
  'EXAMPLE/low@dc.example.com' -dc-ip <DC_IP> \
  -base-dn 'DC=example,DC=com' -listen-ip <ATTACKER_IP> \
  -victim 'EXAMPLE/VICTIM$' \
  -modify-dn 'CN=VICTIM,CN=Computers,DC=example,DC=com' \
  -rbcd-sid '<CONTROLLED_COMPUTER_SID>' \
  -ntlmrelayx /path/to/pinned-impacket/examples/ntlmrelayx.py
```

Trigger SMB authentication separat aus; siehe [forcing privileged NTLM authentication](printers-spooler-service-abuse.md) für eine Coercion-Angriffsfläche und den [relay overview](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) für weitere. Der Befehl und die Implementierung des Tools sind in seinem Repository dokumentiert.<sup>[[6]](#references)</sup>

## Stufenweise Einführung mit Audit zuerst (empfohlen: ca. 30 Tage)

1. Aktiviere die LDAP-Schnittstellendiagnose auf jedem DC, um nicht signierte Binds zu protokollieren (Event **2889**):<sup>[[1]](#references)</sup>

```bash
Reg Add HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Diagnostics /v "16 LDAP Interface Events" /t REG_DWORD /d 2
```

2. Setze die DC-GPO `LDAP server channel binding token requirements` auf **When Supported**, um CBT teilweise durchzusetzen und Telemetriedaten zu erfassen; prüfe zuerst die Kompatibilität mit Legacy-Clients.<sup>[[1]](#references)</sup>
3. Überwache Directory-Service-Ereignisse:<sup>[[1]](#references)[[2]](#references)</sup>
   - **2889** – Bindungen ohne Signatur bzw. mit erlaubter unsignierter Verbindung (Signierung nicht konform).
   - **3074/3075** – LDAPS-Bindungen, die fehlschlagen würden oder bei denen CBT fehlt (erfordert KB4520412 unter 2019/2022 und den obigen Schritt 2).
4. Setze die folgenden Einstellungen in separaten Änderungen durch:<sup>[[1]](#references)</sup>
   - `LDAP server channel binding token requirements` = **Always** (DCs).
   - `LDAP client signing requirements` = **Require signing** (Clients).
   - `LDAP server signing requirements` = **Require signing** (DCs) **oder** (Server 2025) `LDAP server signing requirements Enforcement` = **Enabled**.



## References

- [1] [TrustedSec - LDAP Channel Binding und LDAP-Signierung](https://trustedsec.com/blog/ldap-channel-binding-and-ldap-signing)
- [2] [Microsoft KB4520412 - Anforderungen für LDAP Channel Binding und LDAP-Signierung](https://support.microsoft.com/en-us/topic/2020-and-2023-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a)
- [3] [Microsoft CVE-2017-8563 - Update zur LDAP-Relay-Minderung](https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2017-8563)
- [4] [0xdf – HTB Bruno (LDAP-Signierung deaktiviert → Kerberos-Relay → RBCD)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [SpecterOps – Signiert, versiegelt und weitergeleitet, im NTLM-Stil](https://specterops.io/blog/2026/10/23/ldap-signing-bypass-ntlm-relay/)
- [6] [LDAP Switcheroo Proof of Concept](https://github.com/grayhatkiller/switcheroo)
- [7] [Microsoft – Informationen zu Windows-Server-Versionen](https://learn.microsoft.com/en-us/windows/release-health/windows-server-release-info)
{{#include ../../banners/hacktricks-training.md}}
