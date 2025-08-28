# Active Directory Methodology

{{#include ../../banners/hacktricks-training.md}}

## Basic overview

**Active Directory** dient als grundlegende Technologie, die **Netzwerkadministratoren** ermöglicht, **Domänen**, **Benutzer** und **Objekte** innerhalb eines Netzwerks effizient zu erstellen und zu verwalten. Es ist darauf ausgelegt zu skalieren und erlaubt die Organisation einer großen Anzahl von Benutzern in handhabbare **Gruppen** und **Untergruppen**, wobei **Zugriffsrechte** auf verschiedenen Ebenen gesteuert werden können.

Die Struktur von **Active Directory** besteht aus drei primären Ebenen: **Domänen**, **Domänenbäumen** und **Wäldern**. Eine **Domäne** umfasst eine Sammlung von Objekten, wie **Benutzer** oder **Geräte**, die eine gemeinsame Datenbank teilen. **Domänenbäume** sind Gruppen dieser Domänen, die durch eine gemeinsame Struktur verbunden sind, und ein **Wald** stellt die Sammlung mehrerer Domänenbäume dar, die durch **Vertrauensbeziehungen** miteinander verbunden sind und die oberste Ebene der Organisationsstruktur bilden. Spezifische **Zugriffs-** und **Kommunikationsrechte** können auf jeder dieser Ebenen festgelegt werden.

Wichtige Konzepte innerhalb von **Active Directory** umfassen:

1. **Directory** – Beherbergt alle Informationen zu Active Directory-Objekten.
2. **Object** – Bezeichnet Entitäten im Verzeichnis, einschließlich **Benutzern**, **Gruppen** oder **freigegebenen Ordnern**.
3. **Domain** – Dient als Container für Verzeichnisobjekte; mehrere Domänen können innerhalb eines **Walds** koexistieren, wobei jede ihre eigene Objektsammlungen pflegt.
4. **Tree** – Eine Gruppierung von Domänen, die eine gemeinsame Root-Domäne teilen.
5. **Forest** – Die oberste Organisationsstruktur in Active Directory, bestehend aus mehreren Domänenbäumen mit **Vertrauensbeziehungen** untereinander.

**Active Directory Domain Services (AD DS)** umfasst eine Reihe von Diensten, die für die zentrale Verwaltung und Kommunikation innerhalb eines Netzwerks entscheidend sind. Diese Dienste beinhalten:

1. **Domain Services** – Zentralisiert die Datenspeicherung und verwaltet die Interaktionen zwischen **Benutzern** und **Domänen**, einschließlich **Authentifizierung** und **Suche**.
2. **Certificate Services** – Überwacht die Erstellung, Verteilung und Verwaltung sicherer **digitaler Zertifikate**.
3. **Lightweight Directory Services** – Unterstützt directory-enabled Anwendungen über das **LDAP-Protokoll**.
4. **Directory Federation Services** – Bietet **Single-Sign-On**-Funktionalität, um Benutzer über mehrere Webanwendungen in einer Sitzung zu authentifizieren.
5. **Rights Management** – Hilft beim Schutz von urheberrechtlich geschütztem Material, indem die unautorisierte Verbreitung und Nutzung reguliert wird.
6. **DNS Service** – Entscheidend für die Auflösung von **Domainnamen**.

Für eine detailliertere Erklärung siehe: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos Authentication**

Um zu lernen, wie man ein **AD** angreift, muss man den **Kerberos-Authentifizierungsprozess** wirklich gut verstehen.\
[**Lies diese Seite, falls du noch nicht weißt, wie es funktioniert.**](kerberos-authentication.md)

## Cheat Sheet

Du kannst https://wadcoms.github.io/ verwenden, um schnell einen Überblick zu bekommen, welche Befehle du ausführen kannst, um ein AD zu enumerieren/auszunutzen.

> [!WARNING]
> Kerberos communication **requires a full qualifid name (FQDN)** for performing actions. If you try to access a machine by the IP address, **it'll use NTLM and not kerberos**.

## Recon Active Directory (No creds/sessions)

Wenn du Zugriff auf eine AD-Umgebung hast, aber keine Anmeldeinformationen/Sessions, könntest du:

- **Pentest the network:**
- Scanne das Netzwerk, finde Maschinen und offene Ports und versuche, **Vulnerabilities auszunutzen** oder **Credentials zu extrahieren** (zum Beispiel können [Printer sehr interessante Ziele sein](ad-information-in-printers.md)).
- Die Enumeration von DNS kann Informationen über Schlüsselsysteme in der Domäne liefern, wie Web, Drucker, Shares, VPN, Media, etc.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Schau dir die allgemeine [**Pentesting Methodology**](../../generic-methodologies-and-resources/pentesting-methodology.md) an, um mehr Informationen darüber zu finden, wie man das macht.
- **Check for null and Guest access on smb services** (das funktioniert nicht auf modernen Windows-Versionen):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Ein detaillierterer Leitfaden, wie man einen SMB-Server enumeriert, ist hier zu finden:


{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Ein detaillierterer Leitfaden, wie man LDAP enumeriert, ist hier zu finden (achte **besonders auf anonymen Zugriff**):


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Poison the network**
- Sammle Credentials, indem du [**Services mit Responder impersonierst**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Greife Hosts an, indem du [**den relay attack ausnutzt**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Sammle Credentials, indem du **gefälschte UPnP-Services mit evil-S** **exponierst**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856)
- [**OSINT**](https://book.hacktricks.wiki/en/generic-methodologies-and-resources/external-recon-methodology/index.html):
- Extrahiere Benutzernamen/Namen aus internen Dokumenten, Social Media, Services (hauptsächlich Web) innerhalb der Domänenumgebungen und auch aus öffentlich zugänglichen Quellen.
- Wenn du die vollständigen Namen von Mitarbeitern findest, könntest du verschiedene AD **username conventions** ausprobieren ([**lies das**](https://activedirectorypro.com/active-directory-user-naming-convention/)). Die gängigsten Konventionen sind: _NameSurname_, _Name.Surname_, _NamSur_ (3 Buchstaben von jedem), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _zufällige Buchstaben und 3 zufällige Zahlen_ (abc123).
- Tools:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### User enumeration

- **Anonymous SMB/LDAP enum:** Siehe die Seiten [**pentesting SMB**](../../network-services-pentesting/pentesting-smb/index.html) und [**pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md).
- **Kerbrute enum**: Wenn ein **ungültiger Benutzername abgefragt** wird, antwortet der Server mit dem **Kerberos-Fehlercode** _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_, was uns erlaubt zu bestimmen, dass der Benutzername ungültig ist. **Gültige Benutzernamen** werden entweder ein **TGT in einer AS-REP**-Antwort auslösen oder den Fehler _KRB5KDC_ERR_PREAUTH_REQUIRED_, was anzeigt, dass der Benutzer Pre-Authentication durchführen muss.
- **No Authentication against MS-NRPC**: Verwendung von auth-level = 1 (Keine Authentifizierung) gegen die MS-NRPC (Netlogon)-Schnittstelle auf Domain Controllern. Die Methode ruft die Funktion `DsrGetDcNameEx2` nach dem Binden der MS-NRPC-Schnittstelle auf, um zu prüfen, ob der Benutzer oder Computer ohne Anmeldeinformationen existiert. Das Tool [NauthNRPC](https://github.com/sud0Ru/NauthNRPC) implementiert diese Art der Enumeration. Die Forschung dazu ist [hier](https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2024/05/22190247/A-journey-into-forgotten-Null-Session-and-MS-RPC-interfaces.pdf) zu finden.
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
python3 nauth.py -t target -u users_file.txt #From https://github.com/sud0Ru/NauthNRPC
```
- **OWA (Outlook Web Access) Server**

Wenn Sie einen dieser Server im Netzwerk gefunden haben, können Sie auch **user enumeration against it** durchführen. Zum Beispiel können Sie das Tool [**MailSniper**](https://github.com/dafthack/MailSniper) verwenden:
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
> However, you should have the **Namen der Personen, die im Unternehmen arbeiten** from the recon step you should have performed before this. With the name and surname you could used the script [**namemash.py**](https://gist.github.com/superkojiman/11076951) to generate potential valid usernames.

### Knowing one or several usernames

Ok, so you know you have already a valid username but no passwords... Then try:

- [**ASREPRoast**](asreproast.md): Wenn ein Benutzer das Attribut _DONT_REQ_PREAUTH_ **nicht hat**, können Sie **eine AS_REP-Nachricht anfordern** für diesen Benutzer, die einige Daten enthalten wird, die mit einer Ableitung des Passworts des Benutzers verschlüsselt sind.
- [**Password Spraying**](password-spraying.md): Versuchen Sie die **häufigsten Passwörter** bei jedem der entdeckten Benutzer; vielleicht verwendet ein Benutzer ein schlechtes Passwort (denken Sie an die Passwortrichtlinie!).
- Note that you can also **spray OWA servers** to try to get access to the users mail servers.


{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

You might be able to **erhalten** some challenge **Hashes** to crack by **Poisoning** some protocols of the **Netzwerks**:


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTLM Relay

If you have managed to enumerate the active directory you will have **mehr E-Mails und ein besseres Verständnis des Netzwerks**. You might be able to to force NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)  to get access to the AD env.

### Steal NTLM Creds

If you can **auf andere PCs oder Freigaben zugreifen** with the **null or guest user** you could **place files** (like a SCF file) that if somehow accessed will **eine NTLM-Authentifizierung gegen Sie auslösen** so you can **steal** the **NTLM challenge** to crack it:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Enumerating Active Directory WITH credentials/session

For this phase you need to have **die Credentials oder eine Session eines gültigen Domain-Kontos kompromittiert**. If you have some valid credentials or a shell as a domain user, **you should remember that the options given before are still options to compromise other users**.

Before start the authenticated enumeration you should know what is the **Kerberos double hop problem.**


{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Having compromised an account is a **großer Schritt, um die gesamte Domain zu kompromittieren**, because you are going to be able to start the **Active Directory Enumeration:**

Regarding [**ASREPRoast**](asreproast.md) you can now find every possible vulnerable user, and regarding [**Password Spraying**](password-spraying.md) you can get a **Liste aller Benutzernamen** and try the password of the compromised account, empty passwords and new promising passwords.

- Sie könnten die [**CMD to perform a basic recon**](../basic-cmd-for-pentesters.md#domain-info) verwenden
- Sie können auch [**powershell for recon**](../basic-powershell-for-pentesters/index.html) verwenden, das unauffälliger ist
- Sie können auch [**use powerview**](../basic-powershell-for-pentesters/powerview.md) verwenden, um detailliertere Informationen zu extrahieren
- Ein weiteres großartiges Tool für Recon in einem Active Directory ist [**BloodHound**](bloodhound.md). Es ist **nicht sehr unauffällig** (abhängig von den von Ihnen verwendeten Collection-Methoden), aber **wenn es Ihnen egal ist**, sollten Sie es unbedingt ausprobieren. Finden Sie, wo Benutzer RDP können, finden Sie Pfade zu anderen Gruppen, usw.
- **Weitere automatisierte AD-Enumeration-Tools sind:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS records of the AD**](ad-dns-records.md) prüfen, da diese interessante Informationen enthalten könnten.
- Ein **Tool mit GUI**, das Sie zur Enumeration des Verzeichnisses verwenden können, ist **AdExplorer.exe** aus der **SysInternal**-Suite.
- Sie können auch die LDAP-Datenbank mit **ldapsearch** durchsuchen, um nach Credentials in den Feldern _userPassword_ & _unixUserPassword_ oder sogar im Feld _Description_ zu suchen. cf. [Password in AD User comment on PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) für andere Methoden.
- Wenn Sie **Linux** verwenden, können Sie die Domain auch mit [**pywerview**](https://github.com/the-useless-one/pywerview) enumerieren.
- Sie können auch automatisierte Tools wie versuchen:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Alle Domain-Benutzer extrahieren**

Es ist sehr einfach, alle Domain-Benutzernamen unter Windows zu erhalten (`net user /domain` ,`Get-DomainUser` oder `wmic useraccount get name,sid`). Unter Linux können Sie `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` oder `enum4linux -a -u "user" -p "password" <DC IP>` verwenden

> Selbst wenn dieser Enumeration-Abschnitt klein aussieht, ist dies der wichtigste Teil von allem. Rufen Sie die Links auf (hauptsächlich die zu cmd, powershell, powerview und BloodHound), lernen Sie, wie man eine Domain enumeriert, und üben Sie, bis Sie sich sicher fühlen. Während eines Assessments wird dies der entscheidende Moment sein, um Ihren Weg zu DA zu finden oder zu entscheiden, dass nichts getan werden kann.

### Kerberoast

Kerberoasting involves obtaining **TGS tickets** used by services tied to user accounts and cracking their encryption—which is based on user passwords—**offline**.

More about this in:


{{#ref}}
kerberoast.md
{{#endref}}

### Remote connexion (RDP, SSH, FTP, Win-RM, etc)

Once you have obtained some credentials you could check if you have access to any **Maschine**. For that matter, you could use **CrackMapExec** to attempt connecting on several servers with different protocols, accordingly to your ports scans.

### Local Privilege Escalation

If you have compromised credentials or a session as a regular domain user and you have **Zugriff** with this user to **any machine in the domain** you should try to find your way to **escalate privileges locally and looting for credentials**. This is because only with local administrator privileges you will be able to **dump hashes of other users** in memory (LSASS) and locally (SAM).

There is a complete page in this book about [**local privilege escalation in Windows**](../windows-local-privilege-escalation/index.html) and a [**checklist**](../checklist-windows-privilege-escalation.md). Also, don't forget to use [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite).

### Aktuelle Session-Tickets

It's very **unlikely** that you will find **tickets** in the current user **giving you permission to access** unexpected resources, but you could check:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTLM Relay

Wenn Sie es geschafft haben, Active Directory zu enumerieren, haben Sie **mehr E‑Mails und ein besseres Verständnis des Netzwerks**. Möglicherweise können Sie NTLM [**relay attacks**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)**.**

### Suche nach Creds in Computer Shares | SMB Shares

Jetzt, da Sie einige grundlegende Anmeldeinformationen haben, sollten Sie prüfen, ob Sie **interessante Dateien finden, die innerhalb des AD freigegeben sind**. Sie könnten das manuell tun, aber das ist eine sehr langweilige, sich wiederholende Aufgabe (und noch mehr, wenn Sie Hunderte von Docs finden, die Sie überprüfen müssen).

[**Folgen Sie diesem Link, um mehr über Tools zu erfahren, die Sie verwenden könnten.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### NTLM Creds stehlen

Wenn Sie **auf andere PCs oder Shares zugreifen** können, könnten Sie **Dateien ablegen** (z. B. eine SCF file), die, falls sie irgendwie geöffnet werden, eine **NTLM authentication gegen Sie auslösen**, sodass Sie die **NTLM challenge** **stehlen** können, um sie zu knacken:


{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Diese Schwachstelle ermöglichte es jedem authentifizierten Benutzer, den **Domänencontroller zu kompromittieren**.


{{#ref}}
printnightmare.md
{{#endref}}

## Privilege escalation on Active Directory WITH privileged credentials/session

**Für die folgenden Techniken reicht ein normaler Domänenbenutzer nicht aus, Sie benötigen spezielle Privilegien/Anmeldeinformationen, um diese Angriffe durchzuführen.**

### Hash extraction

Hoffentlich ist es Ihnen gelungen, **ein lokales Admin-Konto zu kompromittieren** mit [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) inklusive relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [escalating privileges locally](../windows-local-privilege-escalation/index.html).  
Dann ist es Zeit, alle Hashes im Speicher und lokal zu dumpen.  
[**Lesen Sie diese Seite über verschiedene Möglichkeiten, die Hashes zu erhalten.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Sobald Sie den Hash eines Benutzers haben**, können Sie ihn verwenden, um sich als dieser Benutzer **auszugeben**.  
Sie müssen ein **Tool** verwenden, das die **NTLM authentication mit** diesem **Hash durchführt**, **oder** Sie können ein neues **sessionlogon** erstellen und diesen **Hash** in **LSASS** injizieren, sodass bei jeder **NTLM authentication** dieser **Hash verwendet wird.** Die letzte Option ist das, was mimikatz macht.  
[**Lesen Sie diese Seite für mehr Informationen.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Dieser Angriff zielt darauf ab, **den NTLM-Hash des Benutzers zu verwenden, um Kerberos-Tickets anzufordern**, als Alternative zum üblichen Pass The Hash über das NTLM-Protokoll. Daher kann dies besonders **nützlich in Netzwerken sein, in denen das NTLM-Protokoll deaktiviert ist** und nur **Kerberos als Authentifizierungsprotokoll zugelassen** ist.


{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

Bei der **Pass The Ticket (PTT)**-Angriffsmethode stehlen Angreifer **das Authentifizierungsticket eines Benutzers** anstelle seines Passworts oder seiner Hash-Werte. Dieses gestohlene Ticket wird dann verwendet, um **sich als der Benutzer auszugeben** und sich unautorisierten Zugriff auf Ressourcen und Dienste im Netzwerk zu verschaffen.


{{#ref}}
pass-the-ticket.md
{{#endref}}

### Credentials Reuse

Wenn Sie den **Hash** oder das **Passwort** eines **lokalen Administrators** haben, sollten Sie versuchen, sich **lokal** an anderen **PCs** damit anzumelden.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Beachte, dass dies ziemlich **auffällig** ist und **LAPS** dies **mildern** würde.

### MSSQL Abuse & Trusted Links

Wenn ein Benutzer Berechtigungen hat, **MSSQL-Instanzen zuzugreifen**, könnte er diese nutzen, um **Befehle** auf dem MSSQL-Host auszuführen (wenn dieser als SA läuft), den NetNTLM **Hash** zu **stehlen** oder sogar einen **relay** **Angriff** durchzuführen.\
Außerdem, wenn eine MSSQL-Instanz von einer anderen MSSQL-Instanz vertraut wird (database link). Wenn der Benutzer Berechtigungen über die vertraute Datenbank besitzt, kann er **die Vertrauensbeziehung nutzen, um auch in der anderen Instanz Abfragen auszuführen**. Diese Vertrauensstellungen können verkettet werden und irgendwann könnte der Benutzer eine fehlkonfigurierte Datenbank finden, in der er Befehle ausführen kann.\
**Die Links zwischen Datenbanken funktionieren sogar über Forest-Trusts hinweg.**


{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### IT asset/deployment platforms abuse

Third-party Inventory- und Deployment-Suites bieten oft mächtige Pfade zu Credentials und Code-Ausführung. Siehe:

{{#ref}}
sccm-management-point-relay-sql-policy-secrets.md
{{#endref}}

{{#ref}}
lansweeper-security.md
{{#endref}}

### Unconstrained Delegation

Wenn du ein Computerobjekt mit dem Attribut [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) findest und du Domain-Berechtigungen auf dem Computer hast, kannst du TGTs aus dem Speicher aller Benutzer dumpen, die sich an dem Computer anmelden.\
Wenn sich also ein **Domain Admin an dem Computer anmeldet**, kannst du seinen TGT dumpen und ihn mithilfe von [Pass the Ticket](pass-the-ticket.md) impersonifizieren.\
Dank constrained delegation könntest du sogar **automatisch einen Print Server kompromittieren** (hoffentlich ist es ein DC).


{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Constrained Delegation

Wenn einem Benutzer oder Computer "Constrained Delegation" erlaubt ist, kann er **jeden Benutzer impersonifizieren, um auf bestimmte Dienste auf einem Computer zuzugreifen**.\
Wenn du dann den **Hash dieses Benutzers/Computers kompromittierst**, kannst du **jeden Benutzer** (auch Domain Admins) impersonifizieren, um auf diese Dienste zuzugreifen.


{{#ref}}
constrained-delegation.md
{{#endref}}

### Resourced-based Constrain Delegation

Das Besitzen von **WRITE**-Rechten an einem Active Directory-Objekt eines entfernten Computers ermöglicht die Erlangung von Codeausführung mit **erhöhten Rechten**:


{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### Permissions/ACLs Abuse

Der kompromittierte Benutzer könnte über einige **interessante Berechtigungen auf Domain-Objekten** verfügen, die es dir erlauben könnten, später lateral zu **bewegen** oder **Privilegien zu eskalieren**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Printer Spooler service abuse

Das Entdecken eines **Spool-Dienstes, der innerhalb der Domain lauscht**, kann **missbraucht** werden, um **neue Credentials zu erlangen** und **Privilegien zu eskalieren**.


{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Third party sessions abuse

Wenn **andere Benutzer** auf die **kompromittierte** Maschine **zugreifen**, ist es möglich, **Credentials aus dem Speicher zu sammeln** und sogar **Beacons in ihre Prozesse zu injizieren**, um sie zu impersonifizieren.\
Üblicherweise greifen Benutzer per RDP auf das System zu, daher hier, wie man ein paar Angriffe auf Drittparteien-RDP-Sitzungen durchführt:


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** bietet ein System zur Verwaltung des **lokalen Administratorpassworts** auf domain-joined Computern, stellt sicher, dass es **randomisiert**, einzigartig und häufig **geändert** wird. Diese Passwörter werden in Active Directory gespeichert und der Zugriff wird über ACLs nur für autorisierte Benutzer kontrolliert. Mit ausreichenden Berechtigungen zum Zugriff auf diese Passwörter wird Pivoting zu anderen Computern möglich.


{{#ref}}
laps.md
{{#endref}}

### Certificate Theft

Das **Sammeln von Zertifikaten** von der kompromittierten Maschine kann ein Weg sein, um Privilegien innerhalb der Umgebung zu eskalieren:


{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Certificate Templates Abuse

Wenn **verwundbare Templates** konfiguriert sind, ist es möglich, diese zu missbrauchen, um Privilegien zu eskalieren:


{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-exploitation with high privilege account

### Dumping Domain Credentials

Sobald du **Domain Admin** oder noch besser **Enterprise Admin**-Rechte erhältst, kannst du die **Domain-Datenbank** dumpen: _ntds.dit_.

[**More information about DCSync attack can be found here**](dcsync.md).

[**More information about how to steal the NTDS.dit can be found here**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc as Persistence

Einige der zuvor diskutierten Techniken können für Persistence genutzt werden.\
Zum Beispiel könntest du:

- Benutzer anfällig für [**Kerberoast**](kerberoast.md) machen

```bash
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Benutzer anfällig für [**ASREPRoast**](asreproast.md) machen

```bash
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- [**DCSync**](#dcsync)-Berechtigungen einem Benutzer gewähren

```bash
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

Der **Silver Ticket attack** erstellt ein **legitimes Ticket Granting Service (TGS) ticket** für einen spezifischen Dienst, indem der **NTLM hash** verwendet wird (z. B. der **Hash des PC-Accounts**). Diese Methode wird eingesetzt, um **Zugriff auf die Rechte des Dienstes** zu erhalten.


{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Ein **Golden Ticket attack** bedeutet, dass ein Angreifer Zugriff auf den **NTLM hash des krbtgt-Accounts** in einer Active Directory-Umgebung erlangt. Dieser Account ist speziell, weil er verwendet wird, um alle **Ticket Granting Tickets (TGTs)** zu signieren, die für die Authentifizierung innerhalb des AD-Netzwerks unerlässlich sind.

Sobald der Angreifer diesen Hash erhält, kann er **TGTs** für beliebige Accounts erstellen (Silver ticket attack).


{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Diese sind wie Golden Tickets, jedoch so gefälscht, dass sie **gängige Erkennungsmechanismen für Golden Tickets umgehen.**


{{#ref}}
diamond-ticket.md
{{#endref}}

### **Certificates Account Persistence**

**Zertifikate eines Accounts zu besitzen oder diese anfordern zu können** ist ein sehr guter Weg, um im Benutzerkonto persistent zu bleiben (auch wenn dieser das Passwort ändert):


{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Certificates Domain Persistence**

**Mittels Zertifikaten ist es ebenfalls möglich, mit hohen Rechten innerhalb der Domain persistent zu bleiben:**


{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder Group

Das **AdminSDHolder**-Objekt in Active Directory stellt die Sicherheit **privilegierter Gruppen** (wie Domain Admins und Enterprise Admins) sicher, indem es eine standardisierte **Access Control List (ACL)** über diese Gruppen anwendet, um unautorisierte Änderungen zu verhindern. Diese Funktion kann jedoch ausgenutzt werden; wenn ein Angreifer die ACL des AdminSDHolder ändert, um einem normalen Benutzer Vollzugriff zu geben, erhält dieser Benutzer umfassende Kontrolle über alle privilegierten Gruppen. Diese Sicherheitsmaßnahme, die schützen soll, kann somit nach hinten losgehen und unberechtigten Zugriff ermöglichen, sofern sie nicht genau überwacht wird.

[**More information about AdminDSHolder Group here.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM Credentials

In jedem **Domain Controller (DC)** existiert ein **lokaler Administrator**-Account. Durch das Erlangen von Admin-Rechten auf einer solchen Maschine kann der lokale Administrator-Hash mittels **mimikatz** extrahiert werden. Anschließend ist eine Registry-Änderung notwendig, um die **Nutzung dieses Passworts zu ermöglichen**, wodurch ein Remotezugriff auf das lokale Administrator-Konto möglich wird.


{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL Persistence

Du könntest einem **Benutzer** einige **spezielle Rechte** an bestimmten Domain-Objekten **geben**, die es dem Benutzer erlauben, **in Zukunft Privilegien zu eskalieren**.


{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Security Descriptors

Die **Security Descriptors** werden verwendet, um die **Berechtigungen** zu **speichern**, die ein **Objekt** über ein **anderes Objekt** besitzt. Wenn du nur eine **kleine Änderung** im **Security Descriptor** eines Objekts vornehmen kannst, kannst du sehr interessante Rechte über dieses Objekt erlangen, ohne Mitglied einer privilegierten Gruppe sein zu müssen.


{{#ref}}
security-descriptors.md
{{#endref}}

### Skeleton Key

Ändere **LSASS** im Speicher, um ein **universelles Passwort** zu etablieren, das Zugang zu allen Domain-Accounts gewährt.


{{#ref}}
skeleton-key.md
{{#endref}}

### Custom SSP

[Learn what is a SSP (Security Support Provider) here.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Du kannst dein **eigenes SSP** erstellen, um **Credentials im Klartext** zu **capturen**, die verwendet werden, um auf die Maschine zuzugreifen.


{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Es registriert einen **neuen Domain Controller** im AD und verwendet ihn, um **Attribute** (SIDHistory, SPNs...) auf bestimmten Objekten **zu pushen**, **ohne** Logs bezüglich der **Änderungen** zu hinterlassen. Du **brauchst DA**-Berechtigungen und musst dich innerhalb der **Root-Domain** befinden.\
Beachte, dass, wenn du falsche Daten verwendest, ziemlich unschöne Logs erscheinen werden.


{{#ref}}
dcshadow.md
{{#endref}}

### LAPS Persistence

Vorher haben wir diskutiert, wie man Privilegien eskalieren kann, wenn man **ausreichende Berechtigungen hat, um LAPS-Passwörter zu lesen**. Diese Passwörter können jedoch auch zur **Aufrechterhaltung von Persistence** verwendet werden.\
Siehe:


{{#ref}}
laps.md
{{#endref}}

## Forest Privilege Escalation - Domain Trusts

Microsoft betrachtet das **Forest** als die Sicherheitsgrenze. Das impliziert, dass **das Kompromittieren einer einzelnen Domain potenziell zum Kompromiss des gesamten Forests führen kann**.

### Basic Information

Ein [**domain trust**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) ist ein Sicherheitsmechanismus, der einem Benutzer aus einer **Domain** ermöglicht, auf Ressourcen in einer anderen **Domain** zuzugreifen. Er stellt im Wesentlichen eine Verbindung zwischen den Authentifizierungssystemen der beiden Domains her, sodass Authentifizierungsüberprüfungen nahtlos fließen können. Wenn Domains eine Trust-Beziehung einrichten, tauschen sie bestimmte **Keys** zwischen ihren **Domain Controllers (DCs)** aus und speichern diese, die für die Integrität des Trusts entscheidend sind.

In einem typischen Szenario, wenn ein Benutzer auf einen Dienst in einer **vertrauten Domain** zugreifen möchte, muss er zuerst ein spezielles Ticket, bekannt als **inter-realm TGT**, von seinem eigenen Domain-DC anfordern. Dieses TGT ist mit einem geteilten **Key** verschlüsselt, den beide Domains vereinbart haben. Der Benutzer präsentiert dieses TGT dann dem **DC der vertrauten Domain**, um ein Service-Ticket (**TGS**) zu erhalten. Nach erfolgreicher Validierung des inter-realm TGT durch den DC der vertrauten Domain stellt dieser ein TGS aus, das dem Benutzer Zugang zum Dienst gewährt.

**Schritte**:

1. Ein **Client-Computer** in **Domain 1** startet den Prozess, indem er seinen **NTLM-Hash** verwendet, um ein **Ticket Granting Ticket (TGT)** von seinem **Domain Controller (DC1)** anzufordern.
2. DC1 stellt ein neues TGT aus, wenn der Client erfolgreich authentifiziert wurde.
3. Der Client fordert anschließend ein **inter-realm TGT** von DC1 an, das benötigt wird, um auf Ressourcen in **Domain 2** zuzugreifen.
4. Das inter-realm TGT ist mit einem **Trust Key** verschlüsselt, der zwischen DC1 und DC2 als Teil des wechselseitigen Domain-Trusts geteilt wird.
5. Der Client bringt das inter-realm TGT zum **Domain Controller (DC2)** von Domain 2.
6. DC2 verifiziert das inter-realm TGT mit seinem geteilten Trust Key und stellt, falls gültig, ein **Ticket Granting Service (TGS)** für den Server in Domain 2 aus, auf den der Client zugreifen möchte.
7. Schließlich präsentiert der Client dieses TGS dem Server, das mit dem Hash des Server-Accounts verschlüsselt ist, um Zugriff auf den Dienst in Domain 2 zu erhalten.

### Different trusts

Es ist wichtig zu beachten, dass **ein Trust einseitig oder zweiseitig sein kann**. Bei der zweiseitigen Option vertrauen sich beide Domains gegenseitig, aber bei der **einseitigen** Trust-Beziehung ist eine der Domains die **trusted** und die andere die **trusting** Domain. Im letzteren Fall **kannst du nur aus der trusted Domain heraus auf Ressourcen in der trusting Domain zugreifen**.

Wenn Domain A Domain B vertraut, ist A die trusting Domain und B die trusted. Außerdem wäre dies in **Domain A** ein **Outbound trust**; und in **Domain B** ein **Inbound trust**.

**Verschiedene Vertrauensbeziehungen**

- **Parent-Child Trusts**: Dies ist eine übliche Konfiguration innerhalb desselben Forests, bei der eine Child-Domain automatisch eine zweiseitige transitive Trust mit ihrer Parent-Domain hat. Im Wesentlichen bedeutet das, dass Authentifizierungsanfragen nahtlos zwischen Parent und Child fließen können.
- **Cross-link Trusts**: Als "shortcut trusts" bezeichnet, werden diese zwischen Child-Domains eingerichtet, um Referral-Prozesse zu beschleunigen. In komplexen Forests müssen Authentifizierungs-Referrals typischerweise bis zur Forest-Root und dann hinunter zur Ziel-Domain reisen. Durch das Erstellen von Cross-Links wird die Reise verkürzt, was in geografisch verteilten Umgebungen besonders vorteilhaft ist.
- **External Trusts**: Diese werden zwischen verschiedenen, nicht verbundenen Domains eingerichtet und sind von Natur aus nicht-transitiv. Laut [Microsoft's documentation](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>) sind External Trusts nützlich für den Zugriff auf Ressourcen in einer Domain außerhalb des aktuellen Forests, die nicht durch einen Forest-Trust verbunden ist. Die Sicherheit wird durch SID-Filtering bei External Trusts verstärkt.
- **Tree-root Trusts**: Diese Trusts werden automatisch zwischen der Forest-Root-Domain und einer neu hinzugefügten Tree-Root hergestellt. Obwohl sie nicht häufig vorkommen, sind Tree-root Trusts wichtig, um neue Domain-Trees zu einem Forest hinzuzufügen, ihnen eine eindeutige Domain-Bezeichnung zu ermöglichen und die zweiseitige Transitivität sicherzustellen. Weitere Informationen sind in [Microsoft's guide](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>) verfügbar.
- **Forest Trusts**: Diese Trust-Art ist ein zweiseitiger transitive Trust zwischen zwei Forest-Root-Domains und erzwingt ebenfalls SID-Filtering, um Sicherheitsmaßnahmen zu verstärken.
- **MIT Trusts**: Diese Trusts werden mit nicht-Windows, [RFC4120-konformen](https://tools.ietf.org/html/rfc4120) Kerberos-Domains eingerichtet. MIT Trusts sind etwas spezialisierter und richten sich an Umgebungen, die eine Integration mit Kerberos-basierten Systemen außerhalb des Windows-Ökosystems erfordern.

#### Other differences in **trusting relationships**

- Eine Vertrauensbeziehung kann auch **transitiv** (A vertraut B, B vertraut C, dann vertraut A C) oder **nicht-transitiv** sein.
- Eine Vertrauensbeziehung kann als **bidirektionaler Trust** (beide vertrauen einander) oder als **einseitiger Trust** (nur einer vertraut dem anderen) eingerichtet werden.

### Attack Path

1. **Enumeriere** die Vertrauensbeziehungen
2. Prüfe, ob irgendein **Security Principal** (Benutzer/Gruppe/Computer) **Zugriff** auf Ressourcen der **anderen Domain** hat, möglicherweise durch ACE-Einträge oder durch Mitgliedschaft in Gruppen der anderen Domain. Suche nach **Beziehungen über Domains hinweg** (vermutlich wurde der Trust dafür erstellt).
1. kerberoast könnte in diesem Fall eine weitere Option sein.
3. **Kompromittiere** die **Accounts**, die durch Domains **pivotieren** können.

Angreifer können über drei primäre Mechanismen auf Ressourcen in einer anderen Domain zugreifen:

- **Lokale Gruppenmitgliedschaft**: Principals könnten zu lokalen Gruppen auf Maschinen hinzugefügt werden, wie der Gruppe “Administrators” auf einem Server, was ihnen erheblichen Zugriff auf diese Maschine gewährt.
- **Fremde Domain-Gruppenmitgliedschaft**: Principals können auch Mitglieder von Gruppen innerhalb der fremden Domain sein. Die Effektivität dieser Methode hängt jedoch von der Art des Trusts und dem Umfang der Gruppe ab.
- **Access Control Lists (ACLs)**: Principals könnten in einer **ACL** aufgeführt sein, insbesondere als Entitäten in **ACEs** innerhalb einer **DACL**, und ihnen so Zugriff auf spezifische Ressourcen gewähren. Für tiefergehende Informationen zu den Mechaniken von ACLs, DACLs und ACEs ist das Whitepaper “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” eine unschätzbare Ressource.

### Find external users/groups with permissions

Du kannst **`CN=<user_SID>,CN=ForeignSecurityPrincipals,DC=domain,DC=com`** prüfen, um fremde Security Principals in der Domain zu finden. Diese sind Benutzer/Gruppen aus **einer externen Domain/Forest**.

Du kannst dies in **Bloodhound** oder mit powerview prüfen:
```powershell
# Get users that are i groups outside of the current domain
Get-DomainForeignUser

# Get groups inside a domain with users our
Get-DomainForeignGroupMember
```
### Child-to-Parent forest privilege escalation
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
Weitere Möglichkeiten, Domänen-Vertrauensstellungen zu enumerieren:
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
> Es gibt **2 trusted keys**, einen für _Child --> Parent_ und einen weiteren für _Parent_ --> _Child_.\
> Sie können den von der aktuellen Domain verwendeten Schlüssel mit den folgenden Befehlen anzeigen:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Als Enterprise Admin in die child/parent domain eskalieren, indem die Trust-Beziehung mit SID-History Injection ausgenutzt wird:


{{#ref}}
sid-history-injection.md
{{#endref}}

#### Exploit writeable Configuration NC

Es ist entscheidend zu verstehen, wie die Configuration Naming Context (NC) ausgenutzt werden kann. Die Configuration NC dient als zentrales Repository für Konfigurationsdaten innerhalb eines AD forest. Diese Daten werden an jeden Domain Controller (DC) im Forest repliziert; writable DCs behalten eine beschreibbare Kopie der Configuration NC. Um dies auszunutzen, benötigt man **SYSTEM-Rechte auf einem DC**, vorzugsweise auf einem Child-DC.

**Link GPO to root DC site**

Der Sites-Container der Configuration NC enthält Informationen über die Sites aller domain-joined computers im AD forest. Mit SYSTEM-Rechten auf einem beliebigen DC können Angreifer GPOs mit den root DC sites verknüpfen. Diese Aktion kann das Root-Domain kompromittieren, indem Policies manipuliert werden, die auf diese Sites angewendet werden.

Für detailliertere Informationen kann man die Forschung zu [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research) heranziehen.

**Compromise any gMSA in the forest**

Ein Angriffsvektor zielt auf privilegierte gMSAs innerhalb der Domain ab. Der KDS Root key, der für die Berechnung der Passwörter von gMSAs notwendig ist, wird in der Configuration NC gespeichert. Mit SYSTEM-Rechten auf einem DC ist es möglich, auf den KDS Root key zuzugreifen und die Passwörter für beliebige gMSAs im Forest zu berechnen.

Detaillierte Analysen und Schritt-für-Schritt-Anleitungen finden sich in:


{{#ref}}
golden-dmsa-gmsa.md
{{#endref}}

Komplementärer delegated MSA-Angriff (BadSuccessor – abusing migration attributes):


{{#ref}}
badsuccessor-dmsa-migration-abuse.md
{{#endref}}

Weitere externe Forschung: [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema change attack**

Diese Methode erfordert Geduld und das Warten auf die Erstellung neuer privilegierter AD-Objekte. Mit SYSTEM-Rechten kann ein Angreifer das AD Schema ändern, um jedem Benutzer volle Kontrolle über alle Klassen zu gewähren. Das kann zu unautorisiertem Zugriff und Kontrolle über neu erstellte AD-Objekte führen.

Weiterführende Informationen sind verfügbar unter [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**From DA to EA with ADCS ESC5**

Die ADCS ESC5-Schwachstelle zielt auf die Kontrolle über PKI-Objekte ab, um ein Zertifikattemplate zu erstellen, das die Authentifizierung als beliebiger Benutzer im Forest ermöglicht. Da PKI-Objekte in der Configuration NC liegen, ermöglicht das Kompromittieren eines writable Child-DC die Durchführung von ESC5-Angriffen.

Mehr Details dazu finden sich in [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c). In Umgebungen ohne ADCS kann ein Angreifer die notwendigen Komponenten selbst einrichten, wie in [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/) erläutert.

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
In diesem Szenario wird **Ihre Domain von einer externen Domain vertraut**, wodurch Ihnen **nicht näher bestimmte Berechtigungen** darauf gewährt werden. Sie müssen herausfinden, **welche Prinzipale Ihrer Domain welche Zugriffsrechte auf die externe Domain haben**, und dann versuchen, diese auszunutzen:

{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Externe Forest-Domain - Einseitig (Outbound)
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
In diesem Szenario vertraut **deine Domäne** einigen **Privilegien** an einen **principal** aus **einer anderen Domäne**.

Allerdings, wenn eine **Domäne vom vertrauenden Domäne** vertraut wird, erstellt die vertrauende Domäne einen **Benutzer** mit einem **vorhersehbaren Namen**, der als **Passwort das Trusted Password** verwendet. Das bedeutet, dass es möglich ist, **einen Benutzer aus der vertrauenden Domäne zu verwenden, um in die vertraute Domäne zu gelangen**, diese zu enumerieren und zu versuchen, weitere Privilegien zu eskalieren:


{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Eine andere Möglichkeit, die vertraute Domäne zu kompromittieren, besteht darin, einen [**SQL trusted link**](abusing-ad-mssql.md#mssql-trusted-links) zu finden, der in die **entgegengesetzte Richtung** des Domain-Trusts erstellt wurde (was nicht sehr häufig vorkommt).

Eine weitere Möglichkeit, die vertraute Domäne zu kompromittieren, besteht darin, auf einem Rechner zu warten, auf dem ein **Benutzer aus der vertrauten Domäne** per **RDP** zugreifen kann. Dann könnte der Angreifer Code in den RDP-Session-Prozess injizieren und von dort auf die **ursprüngliche Domäne des Opfers** zugreifen.\
Außerdem, wenn das **Opfer seine Festplatte eingebunden** hat, könnte der Angreifer vom **RDP-Session**-Prozess aus **Backdoors** im **Autostart-Ordner der Festplatte** ablegen. Diese Technik wird **RDPInception** genannt.


{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Missbrauch von Domain-Trusts — Gegenmaßnahmen

### **SID Filtering:**

- Das Risiko von Angriffen, die das SID-History-Attribut über Forest-Trusts ausnutzen, wird durch SID Filtering gemindert, das standardmäßig bei allen Inter-Forest-Trusts aktiviert ist. Dies basiert auf der Annahme, dass Intra-Forest-Trusts sicher sind, wobei der Forest und nicht die Domäne als Sicherheitsgrenze betrachtet wird, gemäß der Sichtweise von Microsoft.
- Es gibt jedoch einen Haken: SID Filtering kann Anwendungen und Benutzerzugriffe stören, was dazu führt, dass es gelegentlich deaktiviert wird.

### **Selective Authentication:**

- Für Inter-Forest-Trusts stellt Selective Authentication sicher, dass Benutzer aus den beiden Forests nicht automatisch authentifiziert werden. Stattdessen sind explizite Berechtigungen erforderlich, damit Benutzer auf Domänen und Server innerhalb der vertrauenden Domäne oder des Forests zugreifen können.
- Es ist wichtig zu beachten, dass diese Maßnahmen nicht vor der Ausnutzung des beschreibbaren Configuration Naming Context (NC) oder vor Angriffen auf das Trust-Konto schützen.

[**More information about domain trusts in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## AD -> Azure & Azure -> AD


{{#ref}}
https://cloud.hacktricks.wiki/en/pentesting-cloud/azure-security/az-lateral-movement-cloud-on-prem/azure-ad-connect-hybrid-identity/index.html
{{#endref}}

## Allgemeine Verteidigungsmaßnahmen

[**Learn more about how to protect credentials here.**](../stealing-credentials/credentials-protections.md)

### **Verteidigungsmaßnahmen zum Schutz von Anmeldeinformationen**

- **Einschränkungen für Domain Admins**: Es wird empfohlen, dass Domain Admins sich nur an Domain Controllers anmelden dürfen und nicht auf anderen Hosts verwendet werden.
- **Bereiche für Service Accounts**: Dienste sollten nicht mit Domain Admin (DA) Privilegien ausgeführt werden, um die Sicherheit zu wahren.
- **Zeitliche Einschränkung von Privilegien**: Für Aufgaben, die DA-Privilegien erfordern, sollte deren Dauer begrenzt werden. Dies kann z. B. erreicht werden durch: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### **Implementierung von Deception-Techniken**

- Die Implementierung von Deception umfasst das Stellen von Fallen, wie Decoy-User oder -Computer, mit Eigenschaften wie Passwörtern, die nicht ablaufen, oder die als Trusted for Delegation markiert sind. Ein detaillierter Ansatz umfasst das Erstellen von Benutzern mit spezifischen Rechten oder das Hinzufügen zu hochprivilegierten Gruppen.
- Ein praktisches Beispiel beinhaltet die Verwendung von Tools wie: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Mehr zur Implementierung von Deception-Techniken findet sich bei [Deploy-Deception on GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identifizierung von Deception**

- **Für Benutzerobjekte**: Verdächtige Indikatoren sind untypische ObjectSID, seltene Logons, Erstellungsdaten und geringe Counts für falsche Passworteingaben.
- **Allgemeine Indikatoren**: Das Vergleichen von Attributen potenzieller Decoy-Objekte mit echten Objekten kann Inkonsistenzen aufdecken. Tools wie [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) können bei der Identifizierung solcher Deceptions helfen.

### **Umgehung von Erkennungssystemen**

- **Microsoft ATA Detection Bypass**:
- **User Enumeration**: Vermeidung der Session-Enumeration auf Domain Controllers, um ATA-Detektion zu verhindern.
- **Ticket Impersonation**: Die Verwendung von **aes**-Schlüsseln zur Erstellung von Tickets hilft, die Detektion zu umgehen, indem kein Downgrade auf NTLM erfolgt.
- **DCSync Angriffe**: Ausführung von einem Nicht-Domain Controller wird empfohlen, um ATA-Detektion zu vermeiden, da direkte Ausführung von einem Domain Controller Alarme auslöst.

## References

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

{{#include ../../banners/hacktricks-training.md}}
