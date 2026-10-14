# Shadow Credentials

{{#include ../../../banners/hacktricks-training.md}}

## Einführung <a href="#3f17" id="3f17"></a>

**Lies den Originalbeitrag mit [allen Informationen zu dieser Technik](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).**<sup>[[1]](#references)</sup>

Zusammengefasst kann die Kontrolle über **`msDS-KeyCredentialLink`** eines Benutzers oder Computers einem Angreifer ermöglichen, ein Key Credential hinzuzufügen, sich mit PKINIT als dieses Objekt zu authentifizieren und – sofern KDC und Konto die erforderlichen Abläufe unterstützen – das resultierende Ticket mit `S4U2Self`/user-to-user zu verwenden, um den NT-Hash des Objekts wiederherzustellen.<sup>[[1]](#references)</sup>

Im Beitrag wird eine Methode zum Einrichten von **Public-Private-Key-Authentifizierungsdaten** beschrieben, um ein eindeutiges **Service Ticket** zu erhalten, das den NTLM-Hash des Ziels enthält. Dabei wird der verschlüsselte NTLM_SUPPLEMENTAL_CREDENTIAL innerhalb des Privilege Attribute Certificate (PAC) entschlüsselt.<sup>[[1]](#references)</sup>

### Voraussetzungen

Für diese Technik müssen bestimmte Bedingungen erfüllt sein:<sup>[[1]](#references)</sup>

- Es wird mindestens ein Windows Server 2016 Domain Controller benötigt.
- Auf dem Domain Controller muss ein digitales Serverauthentifizierungszertifikat installiert sein.
- Das Verzeichnisschema muss `msDS-KeyCredentialLink` enthalten. Ein Windows Server 2016 oder neuer DC und ein PKINIT-fähiges Zertifikat auf dem KDC sind die praktischen Plattformvoraussetzungen, die in der Forschung beschrieben werden. Prüfe die Schema- und DC-Konfiguration der Domäne, anstatt davon auszugehen, dass allein die Bezeichnung der Domänenfunktionsebene über die Ausnutzbarkeit entscheidet.
- Ein Konto mit delegierten Rechten zum Ändern des Attributs msDS-KeyCredentialLink des Zielobjekts ist erforderlich.

## Missbrauch

Der Missbrauch von Key Trust bei Computerobjekten umfasst weitere Schritte, die über das Erlangen eines Ticket Granting Ticket (TGT) und des NTLM-Hashes hinausgehen. Dazu gehören:<sup>[[1]](#references)</sup>

1. Ein **RC4 silver ticket** erstellen, um als privilegierter Benutzer auf dem vorgesehenen Host zu agieren.
2. Das TGT mit **S4U2Self** zur Identitätsübernahme **privilegierter Benutzer** verwenden. Dazu muss das Service Ticket geändert werden, um dem Dienstnamen eine Serviceklasse hinzuzufügen.

Ein wesentlicher Vorteil des Key-Trust-Missbrauchs ist, dass er auf den vom Angreifer generierten privaten Schlüssel beschränkt ist. Dadurch wird eine Delegierung an potenziell verwundbare Konten vermieden, und es muss kein Computerkonto erstellt werden, dessen Entfernung schwierig sein könnte.<sup>[[1]](#references)</sup>

## Tools

### [**Whisker**](https://github.com/eladshamir/Whisker)

Whisker verwendet DSInternals, um `msDS-KeyCredentialLink` mit C# zu manipulieren. Whisker und sein Python-Pendant **pyWhisker** unterstützen das Hinzufügen, Auflisten und Entfernen von Key Credentials sowie das Löschen aller Key Credentials.<sup>[[2]](#references)[[4]](#references)</sup>

Zu den Funktionen von **Whisker** gehören:

- **Add**: Generiert ein Schlüsselpaar und fügt ein Key Credential hinzu.
- **List**: Zeigt alle Key-Credential-Einträge an.
- **Remove**: Löscht ein angegebenes Key Credential.
- **Clear**: Löscht alle Key Credentials, wodurch die legitime Nutzung von WHfB möglicherweise beeinträchtigt wird.

```shell
Whisker.exe add /target:computername$ /domain:constoso.local /dc:dc1.contoso.local /path:C:\path\to\file.pfx /password:P@ssword1
```

### [pyWhisker](https://github.com/ShutdownRepo/pywhisker)

pyWhisker bringt den Workflow mit Impacket und PyDSInternals auf **UNIX-ähnliche Systeme** und unterstützt das Auflisten, Hinzufügen und Entfernen sowie JSON-Import- und -Exportvorgänge.<sup>[[4]](#references)</sup>

```shell
python3 pywhisker.py -d "domain.local" -u "user1" -p "complexpassword" --target "user2" --action "list"
```

### [ShadowSpray](https://github.com/Dec0ne/ShadowSpray/)

ShadowSpray enumeriert Domänenobjekte, für die der Operator Rechte wie `GenericWrite`/`GenericAll` besitzt, versucht, breit gefächert Key Credentials hinzuzufügen, und bietet Bereinigungs- und rekursive Modi. Breit angelegtes Spraying ist störend und auffällig; verwende explizite Ziele und speichere jede hinzugefügte DeviceID, um sie gezielt zu entfernen.<sup>[[3]](#references)</sup>

ADWS kann den Schreibvorgang für Key Credentials übernehmen, wenn direktes LDAP gefiltert wird. Siehe den [SOAPy ADWS-Workflow](../adws-enumeration.md#shadow-credentials-over-adws).<sup>[[5]](#references)</sup>



## References

- [1] [Shadow Credentials: Missbrauch von Key Trust Account Mapping zur Kontoübernahme](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
- [2] [Whisker – Tool zur Übernahme von AD-Konten durch Manipulation von msDS-KeyCredentialLink](https://github.com/eladshamir/Whisker)
- [3] [ShadowSpray – Tool zum Spraying von Shadow Credentials über eine Domäne hinweg](https://github.com/Dec0ne/ShadowSpray/)
- [4] [pywhisker – Python-Version des Shadow Credentials-Tools](https://github.com/ShutdownRepo/pywhisker)
- [5] [SOAPy Wiki – Post-Exploitation](https://github.com/logangoins/SOAPy/wiki/Post%E2%80%90Exploitation)
{{#include ../../../banners/hacktricks-training.md}}
