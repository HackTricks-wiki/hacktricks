# Shadow Credentials

{{#include ../../../banners/hacktricks-training.md}}

## Einleitung <a href="#3f17" id="3f17"></a>

**Lies den ursprünglichen Beitrag für [alle Informationen zu dieser Technik](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).**<sup>[[1]](#references)</sup>

Zusammengefasst kann die Kontrolle über **`msDS-KeyCredentialLink`** eines Benutzers oder Computers einem Angreifer ermöglichen, eine Key Credential hinzuzufügen, sich mit PKINIT als dieses Objekt zu authentifizieren und – wenn KDC und Account die erforderlichen Abläufe unterstützen – das resultierende Ticket mit `S4U2Self`/user-to-user zu verwenden, um den NT-Hash des Objekts wiederherzustellen.<sup>[[1]](#references)</sup>

Im Beitrag wird eine Methode beschrieben, um **Authentifizierungs-Credentials mit öffentlichen und privaten Schlüsseln** einzurichten und ein eindeutiges **Service Ticket** zu erhalten, das den NTLM-Hash des Ziels enthält. Dieser Prozess umfasst das verschlüsselte NTLM_SUPPLEMENTAL_CREDENTIAL innerhalb des Privilege Attribute Certificate (PAC), das entschlüsselt werden kann.<sup>[[1]](#references)</sup>

### Voraussetzungen

Um diese Technik anzuwenden, müssen bestimmte Bedingungen erfüllt sein:<sup>[[1]](#references)</sup>

- Mindestens ein Windows Server 2016 Domain Controller ist erforderlich.
- Auf dem Domain Controller muss ein digitales Zertifikat für die Serverauthentifizierung installiert sein.
- Das Verzeichnisschema muss `msDS-KeyCredentialLink` enthalten; ein Windows Server 2016 oder neuer DC und ein PKINIT-fähiges Zertifikat auf dem KDC sind die in der Forschung beschriebenen praktischen Plattformanforderungen. Überprüfe die Kombination aus Domänenschema und DCs, anstatt davon auszugehen, dass allein die Bezeichnung der Domänenfunktionsebene über die Ausnutzbarkeit entscheidet.
- Ein Account mit delegierten Rechten zum Ändern des Attributs `msDS-KeyCredentialLink` des Zielobjekts ist erforderlich.

## Abuse

Der Abuse von Key Trust für Computerobjekte umfasst weitere Schritte über das Erlangen eines Ticket Granting Ticket (TGT) und des NTLM-Hashs hinaus. Zu den Optionen gehören:<sup>[[1]](#references)</sup>

1. Erstellen eines **RC4 silver ticket**, um als privilegierte Benutzer auf dem vorgesehenen Host zu agieren.
2. Verwenden des TGT mit **S4U2Self** zur Impersonation von **privilegierten Benutzern**, wobei Änderungen am Service Ticket erforderlich sind, um dem Servicenamen eine Serviceklasse hinzuzufügen.

Ein wesentlicher Vorteil des Key-Trust-Abuse besteht darin, dass er auf den vom Angreifer erzeugten privaten Schlüssel beschränkt ist. Dadurch wird eine Delegation an potenziell verwundbare Accounts vermieden und die Erstellung eines Computeraccounts ist nicht erforderlich, dessen Entfernung problematisch sein könnte.<sup>[[1]](#references)</sup>

## Tools

### [**Whisker**](https://github.com/eladshamir/Whisker)

Whisker verwendet DSInternals, um `msDS-KeyCredentialLink` aus C# heraus zu manipulieren. Whisker und sein Python-Gegenstück **pyWhisker** unterstützen das Hinzufügen, Auflisten, Entfernen und Löschen von Key Credentials.<sup>[[2]](#references)[[4]](#references)</sup>

**Whisker**-Funktionen umfassen:

- **Add**: Erzeugt ein Schlüsselpaar und fügt eine Key Credential hinzu.
- **List**: Zeigt alle Key-Credential-Einträge an.
- **Remove**: Löscht eine angegebene Key Credential.
- **Clear**: Löscht alle Key Credentials, wodurch die legitime Nutzung von WHfB möglicherweise beeinträchtigt wird.
```shell
Whisker.exe add /target:computername$ /domain:constoso.local /dc:dc1.contoso.local /path:C:\path\to\file.pfx /password:P@ssword1
```
### [pyWhisker](https://github.com/ShutdownRepo/pywhisker)

pyWhisker bringt den Workflow mit Impacket und PyDSInternals auf **UNIX-ähnliche Systeme**, einschließlich list/add/remove sowie JSON-Import-/Export-Operationen.<sup>[[4]](#references)</sup>
```shell
python3 pywhisker.py -d "domain.local" -u "user1" -p "complexpassword" --target "user2" --action "list"
```
### [ShadowSpray](https://github.com/Dec0ne/ShadowSpray/)

ShadowSpray zählt Domänenobjekte auf, für die der Operator über Rechte wie `GenericWrite`/`GenericAll` verfügt, versucht, umfassend Key Credentials hinzuzufügen, und umfasst Cleanup-/rekursive Modi. Breites Spraying ist störend und auffällig; verwende explizite Ziele und bewahre jede hinzugefügte DeviceID zur präzisen Entfernung auf.<sup>[[3]](#references)</sup>

## References

- [1] [Shadow Credentials: Missbrauch der Key Trust Account Mapping-Funktion zur Account-Übernahme](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
- [2] [Whisker – Tool zur Übernahme von AD-Accounts durch Manipulation von msDS-KeyCredentialLink](https://github.com/eladshamir/Whisker)
- [3] [ShadowSpray – Tool zum Verteilen von Shadow Credentials über eine Domäne](https://github.com/Dec0ne/ShadowSpray/)
- [4] [pywhisker – Python-Version des Shadow-Credentials-Tools](https://github.com/ShutdownRepo/pywhisker)
{{#include ../../../banners/hacktricks-training.md}}
