# Shadow Credentials

{{#include ../../../banners/hacktricks-training.md}}

## Einleitung <a href="#3f17" id="3f17"></a>

**Prüfe den Originalbeitrag auf [alle Informationen zu dieser Technik](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab).**<sup>[[1]](#references)</sup>

**Zusammengefasst**: Wenn du in die Eigenschaft **msDS-KeyCredentialLink** eines Benutzers/Computers schreiben kannst, kannst du den **NT-Hash dieses Objekts** abrufen.<sup>[[1]](#references)</sup>

Im Beitrag wird eine Methode zum Einrichten von **Authentifizierungs-Credentials mit einem öffentlichen und privaten Schlüssel** beschrieben, um ein eindeutiges **Service Ticket** zu erhalten, das den NTLM-Hash des Ziels enthält. Dieser Prozess umfasst das verschlüsselte NTLM_SUPPLEMENTAL_CREDENTIAL innerhalb des Privilege Attribute Certificate (PAC), das entschlüsselt werden kann.<sup>[[1]](#references)</sup>

### Anforderungen

Um diese Technik anzuwenden, müssen bestimmte Bedingungen erfüllt sein:<sup>[[1]](#references)</sup>

- Es wird mindestens ein Windows Server 2016 Domain Controller benötigt.
- Auf dem Domain Controller muss ein digitales Zertifikat für die Serverauthentifizierung installiert sein.
- Das Active Directory muss sich auf dem Windows Server 2016 Functional Level befinden.
- Es wird ein Konto mit delegierten Rechten benötigt, um das Attribut msDS-KeyCredentialLink des Zielobjekts zu ändern.

## Missbrauch

Der Missbrauch von Key Trust bei Computerobjekten umfasst weitere Schritte über das Erlangen eines Ticket Granting Tickets (TGT) und des NTLM-Hashes hinaus. Zu den Optionen gehören:<sup>[[1]](#references)</sup>

1. Erstellen eines **RC4 silver ticket**, um als privilegierte Benutzer auf dem vorgesehenen Host zu agieren.
2. Verwenden des TGT mit **S4U2Self** zur Identitätsübernahme von **privilegierten Benutzern**. Dafür muss das Service Ticket geändert werden, um dem Servicenamen eine Serviceklasse hinzuzufügen.

Ein wesentlicher Vorteil des Key-Trust-Missbrauchs besteht darin, dass er auf den vom Angreifer erzeugten privaten Schlüssel beschränkt ist. Dadurch wird eine Delegierung an potenziell verwundbare Konten vermieden. Außerdem ist das Erstellen eines Computerkontos nicht erforderlich, dessen Entfernung möglicherweise schwierig wäre.<sup>[[1]](#references)</sup>

## Tools

### [**Whisker**](https://github.com/eladshamir/Whisker)

Whisker basiert auf DSInternals und stellt ein C#-Interface für diesen Angriff bereit. Whisker und sein Python-Gegenstück **pyWhisker** ermöglichen die Manipulation des Attributs `msDS-KeyCredentialLink`, um die Kontrolle über Active-Directory-Konten zu erlangen. Diese Tools unterstützen verschiedene Vorgänge wie das Hinzufügen, Auflisten, Entfernen und Löschen von Key Credentials aus dem Zielobjekt.

Zu den Funktionen von **Whisker** gehören:

- **Add**: Erzeugt ein Schlüsselpaar und fügt ein Key Credential hinzu.
- **List**: Zeigt alle Key-Credential-Einträge an.
- **Remove**: Löscht ein angegebenes Key Credential.
- **Clear**: Löscht alle Key Credentials und kann dadurch die legitime Verwendung von WHfB beeinträchtigen.
```shell
Whisker.exe add /target:computername$ /domain:constoso.local /dc:dc1.contoso.local /path:C:\path\to\file.pfx /password:P@ssword1
```
### [pyWhisker](https://github.com/ShutdownRepo/pywhisker)

Es erweitert die Whisker-Funktionalität auf **UNIX-basierte Systeme** und nutzt Impacket sowie PyDSInternals für umfassende Exploitation-Funktionen, darunter das Auflisten, Hinzufügen und Entfernen von KeyCredentials sowie deren Import und Export im JSON-Format.
```shell
python3 pywhisker.py -d "domain.local" -u "user1" -p "complexpassword" --target "user2" --action "list"
```
### [ShadowSpray](https://github.com/Dec0ne/ShadowSpray/)

ShadowSpray zielt darauf ab, **GenericWrite/GenericAll-Berechtigungen auszunutzen, die weit gefasste Benutzergruppen für Domänenobjekte besitzen können**, um ShadowCredentials umfassend anzuwenden. Dazu gehören die Anmeldung an der Domäne, die Überprüfung der Funktionsebene der Domäne, die Aufzählung von Domänenobjekten sowie der Versuch, KeyCredentials für den Erwerb von TGTs und die Offenlegung von NT-Hashes hinzuzufügen. Bereinigungsoptionen und rekursive Ausnutzungstaktiken erweitern den Nutzen.

## Referenzen

- [1] [Shadow Credentials: Ausnutzung des Key-Trust-Account-Mappings zur Kontoübernahme](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab)
- [2] [Whisker - Tool zur Übernahme von AD-Konten durch Manipulation von msDS-KeyCredentialLink](https://github.com/eladshamir/Whisker)
- [3] [ShadowSpray - Tool zum Verteilen von Shadow Credentials über eine Domäne](https://github.com/Dec0ne/ShadowSpray/)
- [4] [pywhisker - Python-Version des Shadow-Credentials-Tools](https://github.com/ShutdownRepo/pywhisker)

{{#include ../../../banners/hacktricks-training.md}}
