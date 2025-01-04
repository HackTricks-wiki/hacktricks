# Active Directory Methodology

{{#include ../../banners/hacktricks-training.md}}

## Grundüberblick

**Active Directory** dient als grundlegende Technologie, die **Netzwerkadministratoren** ermöglicht, **Domänen**, **Benutzer** und **Objekte** innerhalb eines Netzwerks effizient zu erstellen und zu verwalten. Es ist darauf ausgelegt, skalierbar zu sein, und erleichtert die Organisation einer umfangreichen Anzahl von Benutzern in verwaltbare **Gruppen** und **Untergruppen**, während **Zugriffsrechte** auf verschiedenen Ebenen kontrolliert werden.

Die Struktur von **Active Directory** besteht aus drei primären Ebenen: **Domänen**, **Bäume** und **Wälder**. Eine **Domäne** umfasst eine Sammlung von Objekten, wie **Benutzern** oder **Geräten**, die eine gemeinsame Datenbank teilen. **Bäume** sind Gruppen dieser Domänen, die durch eine gemeinsame Struktur verbunden sind, und ein **Wald** stellt die Sammlung mehrerer Bäume dar, die durch **Vertrauensverhältnisse** miteinander verbunden sind und die oberste Ebene der Organisationsstruktur bilden. Bestimmte **Zugriffs-** und **Kommunikationsrechte** können auf jeder dieser Ebenen festgelegt werden.

Wichtige Konzepte innerhalb von **Active Directory** umfassen:

1. **Verzeichnis** – Beherbergt alle Informationen zu Active Directory-Objekten.
2. **Objekt** – Bezeichnet Entitäten im Verzeichnis, einschließlich **Benutzern**, **Gruppen** oder **freigegebenen Ordnern**.
3. **Domäne** – Dient als Container für Verzeichnisobjekte, wobei mehrere Domänen innerhalb eines **Walds** koexistieren können, jede mit ihrer eigenen Objektsammlungen.
4. **Baum** – Eine Gruppierung von Domänen, die eine gemeinsame Stammdomäne teilen.
5. **Wald** – Der Höhepunkt der Organisationsstruktur in Active Directory, bestehend aus mehreren Bäumen mit **Vertrauensverhältnissen** untereinander.

**Active Directory Domain Services (AD DS)** umfasst eine Reihe von Diensten, die für das zentrale Management und die Kommunikation innerhalb eines Netzwerks entscheidend sind. Diese Dienste umfassen:

1. **Domänendienste** – Zentralisiert die Datenspeicherung und verwaltet die Interaktionen zwischen **Benutzern** und **Domänen**, einschließlich **Authentifizierung** und **Suchfunktionen**.
2. **Zertifikatsdienste** – Überwacht die Erstellung, Verteilung und Verwaltung sicherer **digitaler Zertifikate**.
3. **Leichtgewichtige Verzeichnisdienste** – Unterstützt verzeichnisfähige Anwendungen über das **LDAP-Protokoll**.
4. **Verzeichnis-Federationsdienste** – Bietet **Single-Sign-On**-Funktionen zur Authentifizierung von Benutzern über mehrere Webanwendungen in einer einzigen Sitzung.
5. **Rechtsverwaltung** – Hilft beim Schutz urheberrechtlich geschützter Materialien, indem die unbefugte Verbreitung und Nutzung reguliert wird.
6. **DNS-Dienst** – Entscheidend für die Auflösung von **Domänennamen**.

Für eine detailliertere Erklärung siehe: [**TechTerms - Active Directory Definition**](https://techterms.com/definition/active_directory)

### **Kerberos-Authentifizierung**

Um zu lernen, wie man **ein AD angreift**, müssen Sie den **Kerberos-Authentifizierungsprozess** wirklich gut **verstehen**.\
[**Lesen Sie diese Seite, wenn Sie noch nicht wissen, wie es funktioniert.**](kerberos-authentication.md)

## Cheat Sheet

Sie können viel auf [https://wadcoms.github.io/](https://wadcoms.github.io) nehmen, um einen schnellen Überblick darüber zu erhalten, welche Befehle Sie ausführen können, um ein AD zu enumerieren/exploiten.

## Recon Active Directory (Keine Anmeldeinformationen/Sitzungen)

Wenn Sie nur Zugriff auf eine AD-Umgebung haben, aber keine Anmeldeinformationen/Sitzungen besitzen, könnten Sie:

- **Das Netzwerk testen:**
- Scannen Sie das Netzwerk, finden Sie Maschinen und offene Ports und versuchen Sie, **Schwachstellen auszunutzen** oder **Anmeldeinformationen** von ihnen zu **extrahieren** (zum Beispiel könnten [Drucker sehr interessante Ziele sein](ad-information-in-printers.md)).
- Die Enumeration von DNS könnte Informationen über wichtige Server in der Domäne wie Web, Drucker, Freigaben, VPN, Medien usw. liefern.
- `gobuster dns -d domain.local -t 25 -w /opt/Seclist/Discovery/DNS/subdomain-top2000.txt`
- Werfen Sie einen Blick auf die allgemeine [**Pentesting-Methodologie**](../../generic-methodologies-and-resources/pentesting-methodology.md), um weitere Informationen darüber zu finden, wie man dies macht.
- **Überprüfen Sie auf Null- und Gastzugriff auf SMB-Dienste** (dies funktioniert nicht auf modernen Windows-Versionen):
- `enum4linux -a -u "" -p "" <DC IP> && enum4linux -a -u "guest" -p "" <DC IP>`
- `smbmap -u "" -p "" -P 445 -H <DC IP> && smbmap -u "guest" -p "" -P 445 -H <DC IP>`
- `smbclient -U '%' -L //<DC IP> && smbclient -U 'guest%' -L //`
- Eine detailliertere Anleitung zur Enumeration eines SMB-Servers finden Sie hier:

{{#ref}}
../../network-services-pentesting/pentesting-smb/
{{#endref}}

- **Enumerate Ldap**
- `nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP>`
- Eine detailliertere Anleitung zur Enumeration von LDAP finden Sie hier (achten Sie **besonders auf den anonymen Zugriff**):

{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

- **Das Netzwerk vergiften**
- Anmeldeinformationen sammeln [**indem Sie Dienste mit Responder impersonieren**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md)
- Auf Hosts zugreifen, indem Sie [**den Relay-Angriff ausnutzen**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)
- Anmeldeinformationen sammeln, indem Sie [**falsche UPnP-Dienste mit evil-S**](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md)[**SDP**](https://medium.com/@nickvangilder/exploiting-multifunction-printers-during-a-penetration-test-engagement-28d3840d8856) **exponieren**
- [**OSINT**](https://book.hacktricks.xyz/external-recon-methodology):
- Benutzernamen/Namen aus internen Dokumenten, sozialen Medien, Diensten (hauptsächlich Web) innerhalb der Domänenumgebungen und auch aus öffentlich verfügbaren Quellen extrahieren.
- Wenn Sie die vollständigen Namen von Unternehmensmitarbeitern finden, könnten Sie verschiedene AD **Benutzernamenskonventionen** ausprobieren (**[lesen Sie dies](https://activedirectorypro.com/active-directory-user-naming-convention/)**). Die häufigsten Konventionen sind: _NameSurname_, _Name.Surname_, _NamSur_ (3 Buchstaben von jedem), _Nam.Sur_, _NSurname_, _N.Surname_, _SurnameName_, _Surname.Name_, _SurnameN_, _Surname.N_, 3 _zufällige Buchstaben und 3 zufällige Zahlen_ (abc123).
- Werkzeuge:
- [w0Tx/generate-ad-username](https://github.com/w0Tx/generate-ad-username)
- [urbanadventurer/username-anarchy](https://github.com/urbanadventurer/username-anarchy)

### Benutzerenumeration

- **Anonymer SMB/LDAP enum:** Überprüfen Sie die [**Pentesting SMB**](../../network-services-pentesting/pentesting-smb/) und [**Pentesting LDAP**](../../network-services-pentesting/pentesting-ldap.md) Seiten.
- **Kerbrute enum**: Wenn ein **ungültiger Benutzername angefordert wird**, wird der Server mit dem **Kerberos-Fehler**-Code _KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN_ antworten, was uns ermöglicht festzustellen, dass der Benutzername ungültig war. **Gültige Benutzernamen** werden entweder die **TGT in einer AS-REP**-Antwort hervorrufen oder den Fehler _KRB5KDC_ERR_PREAUTH_REQUIRED_, was darauf hinweist, dass der Benutzer eine Vor-Authentifizierung durchführen muss.
```bash
./kerbrute_linux_amd64 userenum -d lab.ropnop.com --dc 10.10.10.10 usernames.txt #From https://github.com/ropnop/kerbrute/releases

nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='DOMAIN'" <IP>
Nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<domain>',userdb=/root/Desktop/usernames.txt <IP>

msf> use auxiliary/gather/kerberos_enumusers

crackmapexec smb dominio.es  -u '' -p '' --users | awk '{print $4}' | uniq
```
- **OWA (Outlook Web Access) Server**

Wenn Sie einen dieser Server im Netzwerk gefunden haben, können Sie auch **Benutzerdaten gegen ihn auflisten**. Zum Beispiel könnten Sie das Tool [**MailSniper**](https://github.com/dafthack/MailSniper) verwenden:
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
> Sie finden Listen von Benutzernamen in [**diesem GitHub-Repo**](https://github.com/danielmiessler/SecLists/tree/master/Usernames/Names) \*\*\*\* und diesem hier ([**statistisch wahrscheinliche Benutzernamen**](https://github.com/insidetrust/statistically-likely-usernames)).
>
> Sie sollten jedoch den **Namen der Personen, die im Unternehmen arbeiten**, aus dem Recon-Schritt haben, den Sie zuvor durchgeführt haben sollten. Mit dem Vorname und Nachname könnten Sie das Skript [**namemash.py**](https://gist.github.com/superkojiman/11076951) verwenden, um potenziell gültige Benutzernamen zu generieren.

### Kenntnis von einem oder mehreren Benutzernamen

Okay, Sie wissen also, dass Sie bereits einen gültigen Benutzernamen haben, aber keine Passwörter... Dann versuchen Sie:

- [**ASREPRoast**](asreproast.md): Wenn ein Benutzer **nicht** das Attribut _DONT_REQ_PREAUTH_ hat, können Sie **eine AS_REP-Nachricht** für diesen Benutzer anfordern, die einige Daten enthält, die mit einer Ableitung des Passworts des Benutzers verschlüsselt sind.
- [**Password Spraying**](password-spraying.md): Lassen Sie uns die **häufigsten Passwörter** mit jedem der entdeckten Benutzer ausprobieren, vielleicht verwendet ein Benutzer ein schlechtes Passwort (denken Sie an die Passwort-Richtlinie!).
- Beachten Sie, dass Sie auch **OWA-Server sprühen** können, um zu versuchen, Zugriff auf die Mail-Server der Benutzer zu erhalten.

{{#ref}}
password-spraying.md
{{#endref}}

### LLMNR/NBT-NS Poisoning

Sie könnten in der Lage sein, einige Challenge-**Hashes** zu erhalten, um **Protokolle** des **Netzwerks** zu cracken:

{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

### NTML Relay

Wenn Sie es geschafft haben, das Active Directory zu enumerieren, haben Sie **mehr E-Mails und ein besseres Verständnis des Netzwerks**. Sie könnten in der Lage sein, NTML [**Relay-Angriffe**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack) \*\*\*\* zu erzwingen, um Zugriff auf die AD-Umgebung zu erhalten.

### NTLM-Creds stehlen

Wenn Sie **auf andere PCs oder Freigaben** mit dem **null- oder Gastbenutzer** zugreifen können, könnten Sie **Dateien** (wie eine SCF-Datei) platzieren, die, wenn sie irgendwie aufgerufen werden, eine **NTML-Authentifizierung gegen Sie auslösen**, sodass Sie die **NTLM-Herausforderung** stehlen können, um sie zu cracken:

{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

## Enumerierung des Active Directory MIT Anmeldeinformationen/Sitzung

Für diese Phase müssen Sie **die Anmeldeinformationen oder eine Sitzung eines gültigen Domänenkontos kompromittiert haben.** Wenn Sie einige gültige Anmeldeinformationen oder eine Shell als Domänenbenutzer haben, **sollten Sie sich daran erinnern, dass die zuvor genannten Optionen weiterhin Möglichkeiten sind, andere Benutzer zu kompromittieren**.

Bevor Sie mit der authentifizierten Enumeration beginnen, sollten Sie wissen, was das **Kerberos-Doppelhop-Problem** ist.

{{#ref}}
kerberos-double-hop-problem.md
{{#endref}}

### Enumeration

Ein kompromittiertes Konto zu haben, ist ein **großer Schritt, um die gesamte Domäne zu kompromittieren**, da Sie mit der **Active Directory Enumeration** beginnen können:

Bezüglich [**ASREPRoast**](asreproast.md) können Sie jetzt jeden möglichen verwundbaren Benutzer finden, und bezüglich [**Password Spraying**](password-spraying.md) können Sie eine **Liste aller Benutzernamen** erhalten und das Passwort des kompromittierten Kontos, leere Passwörter und neue vielversprechende Passwörter ausprobieren.

- Sie könnten die [**CMD verwenden, um eine grundlegende Recon durchzuführen**](../basic-cmd-for-pentesters.md#domain-info)
- Sie können auch [**PowerShell für Recon verwenden**](../basic-powershell-for-pentesters/), was stealthier sein wird
- Sie können auch [**PowerView verwenden**](../basic-powershell-for-pentesters/powerview.md), um detailliertere Informationen zu extrahieren
- Ein weiteres erstaunliches Tool für Recon in einem Active Directory ist [**BloodHound**](bloodhound.md). Es ist **nicht sehr stealthy** (je nach den verwendeten Sammlungsmethoden), aber **wenn es Ihnen egal ist**, sollten Sie es auf jeden Fall ausprobieren. Finden Sie heraus, wo Benutzer RDP nutzen können, finden Sie den Weg zu anderen Gruppen usw.
- **Andere automatisierte AD-Enumerationstools sind:** [**AD Explorer**](bloodhound.md#ad-explorer)**,** [**ADRecon**](bloodhound.md#adrecon)**,** [**Group3r**](bloodhound.md#group3r)**,** [**PingCastle**](bloodhound.md#pingcastle)**.**
- [**DNS-Einträge des AD**](ad-dns-records.md), da sie interessante Informationen enthalten könnten.
- Ein **Tool mit GUI**, das Sie zur Enumeration des Verzeichnisses verwenden können, ist **AdExplorer.exe** aus der **SysInternal** Suite.
- Sie können auch in der LDAP-Datenbank mit **ldapsearch** nach Anmeldeinformationen in den Feldern _userPassword_ & _unixUserPassword_ suchen oder sogar nach _Description_. Siehe [Passwort im AD-Benutzerkommentar auf PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Active%20Directory%20Attack.md#password-in-ad-user-comment) für andere Methoden.
- Wenn Sie **Linux** verwenden, könnten Sie auch die Domäne mit [**pywerview**](https://github.com/the-useless-one/pywerview) enumerieren.
- Sie könnten auch automatisierte Tools wie:
- [**tomcarver16/ADSearch**](https://github.com/tomcarver16/ADSearch)
- [**61106960/adPEAS**](https://github.com/61106960/adPEAS)
- **Alle Domänenbenutzer extrahieren**

Es ist sehr einfach, alle Benutzernamen der Domäne von Windows zu erhalten (`net user /domain`, `Get-DomainUser` oder `wmic useraccount get name,sid`). In Linux können Sie verwenden: `GetADUsers.py -all -dc-ip 10.10.10.110 domain.com/username` oder `enum4linux -a -u "user" -p "password" <DC IP>`

> Auch wenn dieser Abschnitt zur Enumeration klein aussieht, ist dies der wichtigste Teil von allem. Greifen Sie auf die Links zu (hauptsächlich auf den zur CMD, PowerShell, PowerView und BloodHound), lernen Sie, wie man eine Domäne enumeriert, und üben Sie, bis Sie sich wohlfühlen. Während einer Bewertung wird dies der entscheidende Moment sein, um Ihren Weg zu DA zu finden oder zu entscheiden, dass nichts getan werden kann.

### Kerberoast

Kerberoasting beinhaltet das Erhalten von **TGS-Tickets**, die von Diensten verwendet werden, die an Benutzerkonten gebunden sind, und das Knacken ihrer Verschlüsselung – die auf Benutzerpasswörtern basiert – **offline**.

Mehr dazu in:

{{#ref}}
kerberoast.md
{{#endref}}

### Remote-Verbindung (RDP, SSH, FTP, Win-RM usw.)

Sobald Sie einige Anmeldeinformationen erhalten haben, könnten Sie überprüfen, ob Sie auf irgendeine **Maschine** zugreifen können. Zu diesem Zweck könnten Sie **CrackMapExec** verwenden, um zu versuchen, sich auf mehreren Servern mit verschiedenen Protokollen entsprechend Ihren Port-Scans zu verbinden.

### Lokale Privilegieneskalation

Wenn Sie Anmeldeinformationen oder eine Sitzung als regulärer Domänenbenutzer kompromittiert haben und Sie mit diesem Benutzer **Zugriff** auf **irgendeine Maschine in der Domäne** haben, sollten Sie versuchen, Ihren Weg zur **lokalen Eskalation von Privilegien und zum Ausspähen von Anmeldeinformationen** zu finden. Dies liegt daran, dass Sie nur mit lokalen Administratorrechten in der Lage sind, **Hashes anderer Benutzer** im Speicher (LSASS) und lokal (SAM) zu dumpen.

Es gibt eine komplette Seite in diesem Buch über [**lokale Privilegieneskalation in Windows**](../windows-local-privilege-escalation/) und eine [**Checkliste**](../checklist-windows-privilege-escalation.md). Vergessen Sie auch nicht, [**WinPEAS**](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite) zu verwenden.

### Aktuelle Sitzungstickets

Es ist sehr **unwahrscheinlich**, dass Sie **Tickets** im aktuellen Benutzer finden, die Ihnen die Berechtigung geben, auf unerwartete Ressourcen zuzugreifen, aber Sie könnten überprüfen:
```bash
## List all tickets (if not admin, only current user tickets)
.\Rubeus.exe triage
## Dump the interesting one by luid
.\Rubeus.exe dump /service:krbtgt /luid:<luid> /nowrap
[IO.File]::WriteAllBytes("ticket.kirbi", [Convert]::FromBase64String("<BASE64_TICKET>"))
```
### NTML Relay

Wenn Sie es geschafft haben, das Active Directory zu enumerieren, haben Sie **mehr E-Mails und ein besseres Verständnis des Netzwerks**. Möglicherweise können Sie NTML [**Relay-Angriffe**](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md#relay-attack)** erzwingen.**

### **Suchen Sie nach Anmeldeinformationen in Computerfreigaben**

Jetzt, da Sie einige grundlegende Anmeldeinformationen haben, sollten Sie überprüfen, ob Sie **interessante Dateien finden können, die im AD geteilt werden**. Sie könnten das manuell tun, aber es ist eine sehr langweilige, sich wiederholende Aufgabe (und noch mehr, wenn Sie Hunderte von Dokumenten finden, die Sie überprüfen müssen).

[**Folgen Sie diesem Link, um mehr über die Tools zu erfahren, die Sie verwenden könnten.**](../../network-services-pentesting/pentesting-smb/index.html#domain-shared-folders-search)

### NTLM-Anmeldeinformationen stehlen

Wenn Sie **auf andere PCs oder Freigaben zugreifen können**, könnten Sie **Dateien platzieren** (wie eine SCF-Datei), die, wenn sie irgendwie aufgerufen werden, **eine NTML-Authentifizierung gegen Sie auslösen**, sodass Sie die **NTLM-Herausforderung** stehlen können, um sie zu knacken:

{{#ref}}
../ntlm/places-to-steal-ntlm-creds.md
{{#endref}}

### CVE-2021-1675/CVE-2021-34527 PrintNightmare

Diese Schwachstelle ermöglichte es jedem authentifizierten Benutzer, **den Domänencontroller zu kompromittieren**.

{{#ref}}
printnightmare.md
{{#endref}}

## Privilegieneskalation im Active Directory MIT privilegierten Anmeldeinformationen/Sitzung

**Für die folgenden Techniken reicht ein regulärer Domänenbenutzer nicht aus, Sie benötigen spezielle Berechtigungen/Anmeldeinformationen, um diese Angriffe durchzuführen.**

### Hash-Extraktion

Hoffentlich ist es Ihnen gelungen, **einige lokale Administrator**-Konten mit [AsRepRoast](asreproast.md), [Password Spraying](password-spraying.md), [Kerberoast](kerberoast.md), [Responder](../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md) einschließlich Relaying, [EvilSSDP](../../generic-methodologies-and-resources/pentesting-network/spoofing-ssdp-and-upnp-devices.md), [lokale Privilegien zu eskalieren](../windows-local-privilege-escalation/).\
Dann ist es Zeit, alle Hashes im Speicher und lokal zu dumpen.\
[**Lesen Sie diese Seite über verschiedene Möglichkeiten, die Hashes zu erhalten.**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Pass the Hash

**Sobald Sie den Hash eines Benutzers haben**, können Sie ihn verwenden, um **ihn zu impersonieren**.\
Sie müssen ein **Tool** verwenden, das die **NTLM-Authentifizierung mit** diesem **Hash** **durchführt**, **oder** Sie könnten eine neue **Sitzungsanmeldung** erstellen und diesen **Hash** in die **LSASS** **einspeisen**, sodass bei jeder **NTLM-Authentifizierung** dieser **Hash verwendet wird.** Die letzte Option ist das, was Mimikatz tut.\
[**Lesen Sie diese Seite für weitere Informationen.**](../ntlm/index.html#pass-the-hash)

### Over Pass the Hash/Pass the Key

Dieser Angriff zielt darauf ab, **den NTLM-Hash des Benutzers zu verwenden, um Kerberos-Tickets anzufordern**, als Alternative zum gängigen Pass The Hash über das NTLM-Protokoll. Daher könnte dies besonders **nützlich in Netzwerken sein, in denen das NTLM-Protokoll deaktiviert ist** und nur **Kerberos als Authentifizierungsprotokoll erlaubt ist**.

{{#ref}}
over-pass-the-hash-pass-the-key.md
{{#endref}}

### Pass the Ticket

Im **Pass The Ticket (PTT)**-Angriffsverfahren stehlen Angreifer **das Authentifizierungsticket eines Benutzers** anstelle seines Passworts oder seiner Hash-Werte. Dieses gestohlene Ticket wird dann verwendet, um **den Benutzer zu impersonieren** und unbefugten Zugriff auf Ressourcen und Dienste innerhalb eines Netzwerks zu erhalten.

{{#ref}}
pass-the-ticket.md
{{#endref}}

### Wiederverwendung von Anmeldeinformationen

Wenn Sie den **Hash** oder das **Passwort** eines **lokalen Administrators** haben, sollten Sie versuchen, sich damit **lokal** an anderen **PCs** anzumelden.
```bash
# Local Auth Spray (once you found some local admin pass or hash)
## --local-auth flag indicate to only try 1 time per machine
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
```
> [!WARNING]
> Beachten Sie, dass dies ziemlich **laut** ist und **LAPS** es **mildern** würde.

### MSSQL-Missbrauch & Vertrauenswürdige Links

Wenn ein Benutzer Berechtigungen hat, um **auf MSSQL-Instanzen zuzugreifen**, könnte er in der Lage sein, es zu **benutzen, um Befehle** auf dem MSSQL-Host auszuführen (wenn er als SA läuft), den NetNTLM **Hash** zu **stehlen** oder sogar einen **Relay**-**Angriff** durchzuführen.\
Außerdem, wenn eine MSSQL-Instanz von einer anderen MSSQL-Instanz als vertrauenswürdig (Datenbanklink) betrachtet wird. Wenn der Benutzer Berechtigungen über die vertrauenswürdige Datenbank hat, wird er in der Lage sein, **die Vertrauensbeziehung zu nutzen, um auch in der anderen Instanz Abfragen auszuführen**. Diese Vertrauensstellungen können verkettet werden, und irgendwann könnte der Benutzer in der Lage sein, eine falsch konfigurierte Datenbank zu finden, in der er Befehle ausführen kann.\
**Die Links zwischen Datenbanken funktionieren sogar über Waldvertrauensstellungen hinweg.**

{{#ref}}
abusing-ad-mssql.md
{{#endref}}

### Unbeschränkte Delegation

Wenn Sie ein Computerobjekt mit dem Attribut [ADS_UF_TRUSTED_FOR_DELEGATION](<https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx>) finden und Sie über Domain-Berechtigungen auf dem Computer verfügen, können Sie TGTs aus dem Speicher jedes Benutzers, der sich am Computer anmeldet, dumpen.\
Wenn sich also ein **Domain Admin am Computer anmeldet**, können Sie sein TGT dumpen und ihn mit [Pass the Ticket](pass-the-ticket.md) impersonieren.\
Dank der eingeschränkten Delegation könnten Sie sogar **automatisch einen Druckserver kompromittieren** (hoffentlich wird es ein DC sein).

{{#ref}}
unconstrained-delegation.md
{{#endref}}

### Eingeschränkte Delegation

Wenn ein Benutzer oder Computer für "Eingeschränkte Delegation" zugelassen ist, kann er **jeden Benutzer impersonieren, um auf einige Dienste auf einem Computer zuzugreifen**.\
Wenn Sie dann den **Hash** dieses Benutzers/Computers **kompromittieren**, können Sie **jeden Benutzer** (sogar Domain-Admins) impersonieren, um auf einige Dienste zuzugreifen.

{{#ref}}
constrained-delegation.md
{{#endref}}

### Ressourcenbasierte Eingeschränkte Delegation

Das Vorhandensein von **WRITE**-Berechtigungen auf einem Active Directory-Objekt eines Remote-Computers ermöglicht die Erlangung von Codeausführung mit **erhöhten Berechtigungen**:

{{#ref}}
resource-based-constrained-delegation.md
{{#endref}}

### ACLs-Missbrauch

Der kompromittierte Benutzer könnte einige **interessante Berechtigungen über einige Domänenobjekte** haben, die es Ihnen ermöglichen könnten, **seitlich zu bewegen**/**Berechtigungen zu eskalieren**.

{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Missbrauch des Druckerspooler-Dienstes

Das Entdecken eines **Spool-Dienstes, der im Domänenbereich lauscht**, kann **ausgenutzt** werden, um **neue Anmeldeinformationen zu erwerben** und **Berechtigungen zu eskalieren**.

{{#ref}}
printers-spooler-service-abuse.md
{{#endref}}

### Missbrauch von Drittanbieter-Sitzungen

Wenn **andere Benutzer** die **kompromittierte** Maschine **zugreifen**, ist es möglich, **Anmeldeinformationen aus dem Speicher zu sammeln** und sogar **Beacons in ihren Prozessen zu injizieren**, um sie zu impersonieren.\
In der Regel greifen Benutzer über RDP auf das System zu, daher hier, wie man ein paar Angriffe über Drittanbieter-RDP-Sitzungen durchführt:

{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### LAPS

**LAPS** bietet ein System zur Verwaltung des **lokalen Administratorpassworts** auf domänenverbundenen Computern, um sicherzustellen, dass es **randomisiert**, einzigartig und häufig **geändert** wird. Diese Passwörter werden im Active Directory gespeichert und der Zugriff wird über ACLs nur für autorisierte Benutzer kontrolliert. Mit ausreichenden Berechtigungen zum Zugriff auf diese Passwörter wird das Pivotieren zu anderen Computern möglich.

{{#ref}}
laps.md
{{#endref}}

### Zertifikatsdiebstahl

**Zertifikate** von der kompromittierten Maschine zu **sammeln** könnte ein Weg sein, um Berechtigungen innerhalb der Umgebung zu eskalieren:

{{#ref}}
ad-certificates/certificate-theft.md
{{#endref}}

### Missbrauch von Zertifikatvorlagen

Wenn **anfällige Vorlagen** konfiguriert sind, ist es möglich, sie auszunutzen, um Berechtigungen zu eskalieren:

{{#ref}}
ad-certificates/domain-escalation.md
{{#endref}}

## Post-Exploitation mit hochprivilegiertem Konto

### Dumping von Domain-Anmeldeinformationen

Sobald Sie **Domain Admin** oder noch besser **Enterprise Admin**-Berechtigungen erhalten, können Sie die **Domänendatenbank** dumpen: _ntds.dit_.

[**Weitere Informationen über den DCSync-Angriff finden Sie hier**](dcsync.md).

[**Weitere Informationen darüber, wie man die NTDS.dit stiehlt, finden Sie hier**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/active-directory-methodology/broken-reference/README.md)

### Privesc als Persistenz

Einige der zuvor besprochenen Techniken können für Persistenz verwendet werden.\
Zum Beispiel könnten Sie:

- Benutzer anfällig für [**Kerberoast**](kerberoast.md) machen

```powershell
Set-DomainObject -Identity <username> -Set @{serviceprincipalname="fake/NOTHING"}r
```

- Benutzer anfällig für [**ASREPRoast**](asreproast.md) machen

```powershell
Set-DomainObject -Identity <username> -XOR @{UserAccountControl=4194304}
```

- [**DCSync**](#dcsync) Berechtigungen an einen Benutzer gewähren

```powershell
Add-DomainObjectAcl -TargetIdentity "DC=SUB,DC=DOMAIN,DC=LOCAL" -PrincipalIdentity bfarmer -Rights DCSync
```

### Silver Ticket

Der **Silver Ticket-Angriff** erstellt ein **legitimes Ticket Granting Service (TGS)-Ticket** für einen bestimmten Dienst, indem der **NTLM-Hash** (zum Beispiel der **Hash des PC-Kontos**) verwendet wird. Diese Methode wird verwendet, um **auf die Dienstberechtigungen** zuzugreifen.

{{#ref}}
silver-ticket.md
{{#endref}}

### Golden Ticket

Ein **Golden Ticket-Angriff** beinhaltet, dass ein Angreifer Zugriff auf den **NTLM-Hash des krbtgt-Kontos** in einer Active Directory (AD)-Umgebung erhält. Dieses Konto ist besonders, da es verwendet wird, um alle **Ticket Granting Tickets (TGTs)** zu signieren, die für die Authentifizierung im AD-Netzwerk unerlässlich sind.

Sobald der Angreifer diesen Hash erhält, kann er **TGTs** für jedes Konto erstellen, das er wählt (Silver Ticket-Angriff).

{{#ref}}
golden-ticket.md
{{#endref}}

### Diamond Ticket

Diese sind wie goldene Tickets, die so gefälscht sind, dass sie **gemeinsame Erkennungsmechanismen für goldene Tickets umgehen**.

{{#ref}}
diamond-ticket.md
{{#endref}}

### **Zertifikatskonto-Persistenz**

**Zertifikate eines Kontos zu haben oder in der Lage zu sein, sie anzufordern**, ist eine sehr gute Möglichkeit, um in dem Benutzerkonto persistieren zu können (auch wenn er das Passwort ändert):

{{#ref}}
ad-certificates/account-persistence.md
{{#endref}}

### **Zertifikatsdomänen-Persistenz**

**Die Verwendung von Zertifikaten ist auch möglich, um mit hohen Berechtigungen innerhalb der Domäne zu persistieren:**

{{#ref}}
ad-certificates/domain-persistence.md
{{#endref}}

### AdminSDHolder-Gruppe

Das **AdminSDHolder**-Objekt in Active Directory gewährleistet die Sicherheit von **privilegierten Gruppen** (wie Domain Admins und Enterprise Admins), indem es eine standardisierte **Zugriffskontrollliste (ACL)** auf diese Gruppen anwendet, um unbefugte Änderungen zu verhindern. Diese Funktion kann jedoch ausgenutzt werden; wenn ein Angreifer die ACL des AdminSDHolder so ändert, dass ein regulärer Benutzer vollen Zugriff erhält, gewinnt dieser Benutzer umfangreiche Kontrolle über alle privilegierten Gruppen. Diese Sicherheitsmaßnahme, die zum Schutz gedacht ist, kann somit nach hinten losgehen und unbefugten Zugriff ermöglichen, es sei denn, sie wird genau überwacht.

[**Weitere Informationen zur AdminDSHolder-Gruppe finden Sie hier.**](privileged-groups-and-token-privileges.md#adminsdholder-group)

### DSRM-Anmeldeinformationen

Innerhalb jedes **Domain Controllers (DC)** existiert ein **lokales Administratorkonto**. Durch den Erwerb von Admin-Rechten auf einem solchen Computer kann der Hash des lokalen Administrators mit **mimikatz** extrahiert werden. Danach ist eine Registrierungänderung erforderlich, um **die Verwendung dieses Passworts zu aktivieren**, was den Remote-Zugriff auf das lokale Administratorkonto ermöglicht.

{{#ref}}
dsrm-credentials.md
{{#endref}}

### ACL-Persistenz

Sie könnten einem **Benutzer** einige **besondere Berechtigungen** über einige spezifische Domänenobjekte geben, die es dem Benutzer ermöglichen, **zukünftig Berechtigungen zu eskalieren**.

{{#ref}}
acl-persistence-abuse/
{{#endref}}

### Sicherheitsbeschreibungen

Die **Sicherheitsbeschreibungen** werden verwendet, um die **Berechtigungen** zu **speichern**, die ein **Objekt** über ein **Objekt** hat. Wenn Sie nur **eine kleine Änderung** in der **Sicherheitsbeschreibung** eines Objekts vornehmen können, können Sie sehr interessante Berechtigungen über dieses Objekt erhalten, ohne Mitglied einer privilegierten Gruppe sein zu müssen.

{{#ref}}
security-descriptors.md
{{#endref}}

### Skeleton Key

Ändern Sie **LSASS** im Speicher, um ein **universelles Passwort** festzulegen, das den Zugriff auf alle Domänenkonten gewährt.

{{#ref}}
skeleton-key.md
{{#endref}}

### Benutzerdefinierter SSP

[Erfahren Sie hier, was ein SSP (Security Support Provider) ist.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Sie können Ihr **eigenes SSP** erstellen, um die **Anmeldeinformationen**, die zum Zugriff auf die Maschine verwendet werden, in **klarem Text** zu **erfassen**.\\

{{#ref}}
custom-ssp.md
{{#endref}}

### DCShadow

Es registriert einen **neuen Domain Controller** im AD und verwendet ihn, um **Attribute** (SIDHistory, SPNs...) auf bestimmten Objekten **ohne** das Hinterlassen von **Protokollen** bezüglich der **Änderungen** zu **pushen**. Sie **benötigen DA**-Berechtigungen und müssen sich im **Root-Domain** befinden.\
Beachten Sie, dass bei Verwendung falscher Daten ziemlich hässliche Protokolle erscheinen werden.

{{#ref}}
dcshadow.md
{{#endref}}

### LAPS-Persistenz

Zuvor haben wir darüber gesprochen, wie man Berechtigungen eskalieren kann, wenn man **genug Berechtigungen hat, um LAPS-Passwörter zu lesen**. Diese Passwörter können jedoch auch verwendet werden, um **Persistenz aufrechtzuerhalten**.\
Überprüfen Sie:

{{#ref}}
laps.md
{{#endref}}

## Wald-Berechtigungseskalation - Domänenvertrauensstellungen

Microsoft betrachtet den **Wald** als die Sicherheitsgrenze. Dies impliziert, dass **die Kompromittierung einer einzelnen Domäne potenziell zur Kompromittierung des gesamten Waldes führen könnte**.

### Grundlegende Informationen

Eine [**Domänenvertrauensstellung**](<http://technet.microsoft.com/en-us/library/cc759554(v=ws.10).aspx>) ist ein Sicherheitsmechanismus, der es einem Benutzer aus einer **Domäne** ermöglicht, auf Ressourcen in einer anderen **Domäne** zuzugreifen. Es schafft im Wesentlichen eine Verbindung zwischen den Authentifizierungssystemen der beiden Domänen, die es ermöglicht, dass Authentifizierungsüberprüfungen nahtlos fließen. Wenn Domänen eine Vertrauensstellung einrichten, tauschen sie spezifische **Schlüssel** innerhalb ihrer **Domain Controllers (DCs)** aus und behalten diese, was für die Integrität der Vertrauensstellung entscheidend ist.

In einem typischen Szenario, wenn ein Benutzer beabsichtigt, auf einen Dienst in einer **vertrauenswürdigen Domäne** zuzugreifen, muss er zunächst ein spezielles Ticket anfordern, das als **inter-realm TGT** bekannt ist, von dem DC seiner eigenen Domäne. Dieses TGT ist mit einem gemeinsamen **Schlüssel** verschlüsselt, auf den sich beide Domänen geeinigt haben. Der Benutzer präsentiert dann dieses TGT dem **DC der vertrauenswürdigen Domäne**, um ein Dienstticket (**TGS**) zu erhalten. Nach erfolgreicher Validierung des inter-realm TGT durch den DC der vertrauenswürdigen Domäne gibt dieser ein TGS aus, das dem Benutzer den Zugriff auf den Dienst gewährt.

**Schritte**:

1. Ein **Client-Computer** in **Domäne 1** beginnt den Prozess, indem er seinen **NTLM-Hash** verwendet, um ein **Ticket Granting Ticket (TGT)** von seinem **Domain Controller (DC1)** anzufordern.
2. DC1 gibt ein neues TGT aus, wenn der Client erfolgreich authentifiziert wird.
3. Der Client fordert dann ein **inter-realm TGT** von DC1 an, das benötigt wird, um auf Ressourcen in **Domäne 2** zuzugreifen.
4. Das inter-realm TGT ist mit einem **Vertrauensschlüssel** verschlüsselt, der zwischen DC1 und DC2 als Teil der zweiseitigen Domänenvertrauensstellung geteilt wird.
5. Der Client bringt das inter-realm TGT zu **Domain 2's Domain Controller (DC2)**.
6. DC2 überprüft das inter-realm TGT mit seinem gemeinsamen Vertrauensschlüssel und gibt, wenn es gültig ist, ein **Ticket Granting Service (TGS)** für den Server in Domäne 2 aus, auf den der Client zugreifen möchte.
7. Schließlich präsentiert der Client dieses TGS dem Server, das mit dem Hash des Serverkontos verschlüsselt ist, um Zugriff auf den Dienst in Domäne 2 zu erhalten.

### Verschiedene Vertrauensstellungen

Es ist wichtig zu beachten, dass **eine Vertrauensstellung einseitig oder zweiseitig sein kann**. Bei der zweiseitigen Option vertrauen sich beide Domänen gegenseitig, aber in der **einseitigen** Vertrauensbeziehung ist eine der Domänen die **vertrauenswürdige** und die andere die **vertrauende** Domäne. Im letzteren Fall **können Sie nur auf Ressourcen innerhalb der vertrauenden Domäne von der vertrauenswürdigen zugreifen**.

Wenn Domäne A Domäne B vertraut, ist A die vertrauende Domäne und B die vertrauenswürdige. Darüber hinaus wäre dies in **Domäne A** eine **Outbound-Vertrauensstellung**; und in **Domäne B** wäre dies eine **Inbound-Vertrauensstellung**.

**Verschiedene vertrauende Beziehungen**

- **Eltern-Kind-Vertrauensstellungen**: Dies ist eine gängige Konfiguration innerhalb desselben Waldes, bei der eine Kinddomäne automatisch eine zweiseitige transitive Vertrauensstellung mit ihrer Elterndomäne hat. Im Wesentlichen bedeutet dies, dass Authentifizierungsanfragen nahtlos zwischen der Eltern- und der Kinddomäne fließen können.
- **Kreuzverbindungen**: Auch als "Shortcut-Vertrauensstellungen" bezeichnet, werden diese zwischen Kinddomänen eingerichtet, um die Verweisprozesse zu beschleunigen. In komplexen Wäldern müssen Authentifizierungsreferenzen typischerweise bis zum Wurzelwald reisen und dann zur Zieldomäne. Durch die Erstellung von Kreuzverbindungen wird die Reise verkürzt, was besonders vorteilhaft in geografisch verteilten Umgebungen ist.
- **Externe Vertrauensstellungen**: Diese werden zwischen verschiedenen, nicht verwandten Domänen eingerichtet und sind von Natur aus nicht-transitiv. Laut [Microsofts Dokumentation](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>) sind externe Vertrauensstellungen nützlich, um auf Ressourcen in einer Domäne außerhalb des aktuellen Waldes zuzugreifen, die nicht über eine Waldvertrauensstellung verbunden ist. Die Sicherheit wird durch SID-Filterung bei externen Vertrauensstellungen erhöht.
- **Baumwurzel-Vertrauensstellungen**: Diese Vertrauensstellungen werden automatisch zwischen der Wurzel-Domäne des Waldes und einer neu hinzugefügten Baumwurzel eingerichtet. Obwohl sie nicht häufig vorkommen, sind Baumwurzel-Vertrauensstellungen wichtig, um neue Domänenbäume zu einem Wald hinzuzufügen, damit sie einen einzigartigen Domänennamen beibehalten und eine zweiseitige Transitivität gewährleisten können. Weitere Informationen finden Sie in [Microsofts Anleitung](<https://technet.microsoft.com/en-us/library/cc773178(v=ws.10).aspx>).
- **Waldvertrauensstellungen**: Diese Art von Vertrauensstellung ist eine zweiseitige transitive Vertrauensstellung zwischen zwei Wurzel-Domänen des Waldes, die ebenfalls SID-Filterung durchsetzt, um Sicherheitsmaßnahmen zu verbessern.
- **MIT-Vertrauensstellungen**: Diese Vertrauensstellungen werden mit nicht-Windows, [RFC4120-konformen](https://tools.ietf.org/html/rfc4120) Kerberos-Domänen eingerichtet. MIT-Vertrauensstellungen sind etwas spezialisierter und richten sich an Umgebungen, die eine Integration mit Kerberos-basierten Systemen außerhalb des Windows-Ökosystems erfordern.

#### Weitere Unterschiede in **vertrauenden Beziehungen**

- Eine Vertrauensbeziehung kann auch **transitiv** sein (A vertraut B, B vertraut C, dann vertraut A C) oder **nicht-transitiv**.
- Eine Vertrauensbeziehung kann als **bidirektionale Vertrauensstellung** (beide vertrauen sich gegenseitig) oder als **einseitige Vertrauensstellung** (nur einer von ihnen vertraut dem anderen) eingerichtet werden.

### Angriffsweg

1. **Enumerieren** Sie die vertrauenden Beziehungen
2. Überprüfen Sie, ob ein **Sicherheitsprinzipal** (Benutzer/Gruppe/Computer) **Zugriff** auf Ressourcen der **anderen Domäne** hat, möglicherweise durch ACE-Einträge oder durch Mitgliedschaft in Gruppen der anderen Domäne. Suchen Sie nach **Beziehungen über Domänen hinweg** (die Vertrauensstellung wurde wahrscheinlich dafür erstellt).
1. Kerberoast könnte in diesem Fall eine weitere Option sein.
3. **Kompromittieren** Sie die **Konten**, die durch Domänen **pivotieren** können.

Angreifer könnten über drei Hauptmechanismen auf Ressourcen in einer anderen Domäne zugreifen:

- **Lokale Gruppenmitgliedschaft**: Prinzipale könnten zu lokalen Gruppen auf Maschinen hinzugefügt werden, wie der "Administratoren"-Gruppe auf einem Server, was ihnen erhebliche Kontrolle über diese Maschine gewährt.
- **Mitgliedschaft in Gruppen der Fremddomäne**: Prinzipale können auch Mitglieder von Gruppen innerhalb der Fremddomäne sein. Die Wirksamkeit dieser Methode hängt jedoch von der Art der Vertrauensstellung und dem Umfang der Gruppe ab.
- **Zugriffskontrolllisten (ACLs)**: Prinzipale könnten in einer **ACL** angegeben sein, insbesondere als Entitäten in **ACEs** innerhalb einer **DACL**, die ihnen Zugriff auf spezifische Ressourcen gewährt. Für diejenigen, die tiefer in die Mechanik von ACLs, DACLs und ACEs eintauchen möchten, ist das Whitepaper mit dem Titel “[An ACE Up The Sleeve](https://specterops.io/assets/resources/an_ace_up_the_sleeve.pdf)” eine wertvolle Ressource.

### Kind-zu-Eltern-Wald-Berechtigungseskalation
```
Get-DomainTrust

SourceName      : sub.domain.local    --> current domain
TargetName      : domain.local        --> foreign domain
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : WITHIN_FOREST       --> WITHIN_FOREST: Both in the same forest
TrustDirection  : Bidirectional       --> Trust direction (2ways in this case)
WhenCreated     : 2/19/2021 1:28:00 PM
WhenChanged     : 2/19/2021 1:28:00 PM
```
> [!WARNING]
> Es gibt **2 vertrauenswürdige Schlüssel**, einen für _Child --> Parent_ und einen weiteren für _Parent_ --> _Child_.\
> Sie können den aktuellen Schlüssel des aktuellen Domäne mit folgendem Befehl abrufen:
>
> ```bash
> Invoke-Mimikatz -Command '"lsadump::trust /patch"' -ComputerName dc.my.domain.local
> Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\mcorp$"'
> ```

#### SID-History Injection

Erhöhen Sie die Berechtigungen als Enterprise-Administrator zur Child/Parent-Domäne, indem Sie das Vertrauen mit SID-History-Injection ausnutzen:

{{#ref}}
sid-history-injection.md
{{#endref}}

#### Ausnutzen des beschreibbaren Configuration NC

Das Verständnis, wie der Configuration Naming Context (NC) ausgenutzt werden kann, ist entscheidend. Der Configuration NC dient als zentrales Repository für Konfigurationsdaten in einer Active Directory (AD)-Umgebung. Diese Daten werden auf jeden Domain Controller (DC) innerhalb des Waldes repliziert, wobei beschreibbare DCs eine beschreibbare Kopie des Configuration NC führen. Um dies auszunutzen, muss man **SYSTEM-Rechte auf einem DC** haben, vorzugsweise auf einem Child DC.

**Link GPO zum Root DC-Standort**

Der Sites-Container des Configuration NC enthält Informationen über alle domänenverbundenen Computerstandorte innerhalb des AD-Waldes. Durch das Arbeiten mit SYSTEM-Rechten auf einem DC können Angreifer GPOs mit den Root DC-Standorten verknüpfen. Diese Aktion könnte die Root-Domäne gefährden, indem die auf diese Standorte angewendeten Richtlinien manipuliert werden.

Für detaillierte Informationen könnte man die Forschung zu [Bypassing SID Filtering](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-4-bypass-sid-filtering-research) erkunden.

**Kompromittierung eines gMSA im Wald**

Ein Angriffsvektor besteht darin, privilegierte gMSAs innerhalb der Domäne ins Visier zu nehmen. Der KDS Root-Schlüssel, der für die Berechnung der gMSA-Passwörter erforderlich ist, wird im Configuration NC gespeichert. Mit SYSTEM-Rechten auf einem DC ist es möglich, auf den KDS Root-Schlüssel zuzugreifen und die Passwörter für jeden gMSA im Wald zu berechnen.

Eine detaillierte Analyse findet sich in der Diskussion über [Golden gMSA Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-5-golden-gmsa-trust-attack-from-child-to-parent).

**Schema-Änderungsangriff**

Diese Methode erfordert Geduld, da auf die Erstellung neuer privilegierter AD-Objekte gewartet werden muss. Mit SYSTEM-Rechten kann ein Angreifer das AD-Schema ändern, um jedem Benutzer die vollständige Kontrolle über alle Klassen zu gewähren. Dies könnte zu unbefugtem Zugriff und Kontrolle über neu erstellte AD-Objekte führen.

Weiterführende Informationen sind verfügbar zu [Schema Change Trust Attacks](https://improsec.com/tech-blog/sid-filter-as-security-boundary-between-domains-part-6-schema-change-trust-attack-from-child-to-parent).

**Von DA zu EA mit ADCS ESC5**

Die ADCS ESC5-Schwachstelle zielt darauf ab, die Kontrolle über Public Key Infrastructure (PKI)-Objekte zu erlangen, um eine Zertifikatvorlage zu erstellen, die die Authentifizierung als beliebiger Benutzer im Wald ermöglicht. Da PKI-Objekte im Configuration NC gespeichert sind, ermöglicht die Kompromittierung eines beschreibbaren Child DC die Durchführung von ESC5-Angriffen.

Weitere Details dazu können in [From DA to EA with ESC5](https://posts.specterops.io/from-da-to-ea-with-esc5-f9f045aa105c) nachgelesen werden. In Szenarien ohne ADCS hat der Angreifer die Möglichkeit, die erforderlichen Komponenten einzurichten, wie in [Escalating from Child Domain Admins to Enterprise Admins](https://www.pkisolutions.com/escalating-from-child-domains-admins-to-enterprise-admins-in-5-minutes-by-abusing-ad-cs-a-follow-up/) besprochen.

### Externer Wald-Domäne - Einweg (Inbound) oder bidirektional
```powershell
Get-DomainTrust
SourceName      : a.domain.local   --> Current domain
TargetName      : domain.external  --> Destination domain
TrustType       : WINDOWS-ACTIVE_DIRECTORY
TrustAttributes :
TrustDirection  : Inbound          --> Inboud trust
WhenCreated     : 2/19/2021 10:50:56 PM
WhenChanged     : 2/19/2021 10:50:56 PM
```
In diesem Szenario **wird Ihre Domäne von einer externen vertraut** und gibt Ihnen **unbestimmte Berechtigungen** über sie. Sie müssen herausfinden, **welche Prinzipale Ihrer Domäne welchen Zugriff auf die externe Domäne haben** und dann versuchen, dies auszunutzen:

{{#ref}}
external-forest-domain-oneway-inbound.md
{{#endref}}

### Externer Wald-Domäne - Einweg (Ausgehend)
```powershell
Get-DomainTrust -Domain current.local

SourceName      : current.local   --> Current domain
TargetName      : external.local  --> Destination domain
TrustType       : WINDOWS_ACTIVE_DIRECTORY
TrustAttributes : FOREST_TRANSITIVE
TrustDirection  : Outbound        --> Outbound trust
WhenCreated     : 2/19/2021 10:15:24 PM
WhenChanged     : 2/19/2021 10:15:24 PM
```
In diesem Szenario **vertraut Ihre Domäne** einigen **Befugnissen** einem Principal aus **anderen Domänen**.

Wenn jedoch eine **Domäne vertraut** wird von der vertrauenden Domäne, **erstellt die vertrauenswürdige Domäne einen Benutzer** mit einem **vorhersehbaren Namen**, der als **Passwort das vertrauenswürdige Passwort** verwendet. Das bedeutet, dass es möglich ist, **auf einen Benutzer aus der vertrauenden Domäne zuzugreifen, um in die vertrauenswürdige zu gelangen**, um sie zu enumerieren und zu versuchen, weitere Berechtigungen zu eskalieren:

{{#ref}}
external-forest-domain-one-way-outbound.md
{{#endref}}

Eine weitere Möglichkeit, die vertrauenswürdige Domäne zu kompromittieren, besteht darin, einen [**SQL vertrauenswürdigen Link**](abusing-ad-mssql.md#mssql-trusted-links) zu finden, der in die **entgegengesetzte Richtung** des Domänenvertrauens erstellt wurde (was nicht sehr häufig vorkommt).

Eine weitere Möglichkeit, die vertrauenswürdige Domäne zu kompromittieren, besteht darin, auf einem Rechner zu warten, auf den ein **Benutzer aus der vertrauenswürdigen Domäne zugreifen kann**, um sich über **RDP** anzumelden. Dann könnte der Angreifer Code in den RDP-Sitzungsprozess injizieren und **auf die Ursprungsdomäne des Opfers** von dort aus zugreifen.\
Darüber hinaus, wenn das **Opfer seine Festplatte eingebunden hat**, könnte der Angreifer über den **RDP-Sitzungsprozess** **Backdoors** im **Autostart-Ordner der Festplatte** speichern. Diese Technik wird als **RDPInception** bezeichnet.

{{#ref}}
rdp-sessions-abuse.md
{{#endref}}

### Minderung des Missbrauchs von Domänenvertrauen

### **SID-Filterung:**

- Das Risiko von Angriffen, die das SID-Historienattribut über Waldvertrauen ausnutzen, wird durch SID-Filterung gemindert, die standardmäßig bei allen inter-waldlichen Vertrauensstellungen aktiviert ist. Dies basiert auf der Annahme, dass intra-waldliche Vertrauensstellungen sicher sind, wobei der Wald, nicht die Domäne, als Sicherheitsgrenze gemäß Microsofts Auffassung betrachtet wird.
- Es gibt jedoch einen Haken: Die SID-Filterung könnte Anwendungen und den Benutzerzugang stören, was gelegentlich zu ihrer Deaktivierung führt.

### **Selektive Authentifizierung:**

- Bei inter-waldlichen Vertrauensstellungen stellt die Verwendung selektiver Authentifizierung sicher, dass Benutzer aus den beiden Wäldern nicht automatisch authentifiziert werden. Stattdessen sind explizite Berechtigungen erforderlich, damit Benutzer auf Domänen und Server innerhalb der vertrauenden Domäne oder des Waldes zugreifen können.
- Es ist wichtig zu beachten, dass diese Maßnahmen nicht vor der Ausnutzung des beschreibbaren Configuration Naming Context (NC) oder Angriffen auf das Vertrauenskonto schützen.

[**Weitere Informationen zu Domänenvertrauten in ired.team.**](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

## AD -> Azure & Azure -> AD

{{#ref}}
https://cloud.hacktricks.xyz/pentesting-cloud/azure-security/az-lateral-movements/azure-ad-connect-hybrid-identity
{{#endref}}

## Einige allgemeine Abwehrmaßnahmen

[**Erfahren Sie hier mehr darüber, wie Sie Anmeldeinformationen schützen können.**](../stealing-credentials/credentials-protections.md)\\

### **Abwehrmaßnahmen zum Schutz von Anmeldeinformationen**

- **Einschränkungen für Domänenadministratoren**: Es wird empfohlen, dass Domänenadministratoren nur auf Domänencontrollern anmelden dürfen, um ihre Verwendung auf anderen Hosts zu vermeiden.
- **Befugnisse von Dienstkonten**: Dienste sollten nicht mit Domänenadministrator (DA)-Befugnissen ausgeführt werden, um die Sicherheit zu gewährleisten.
- **Temporäre Einschränkung von Berechtigungen**: Für Aufgaben, die DA-Befugnisse erfordern, sollte deren Dauer begrenzt werden. Dies kann erreicht werden durch: `Add-ADGroupMember -Identity ‘Domain Admins’ -Members newDA -MemberTimeToLive (New-TimeSpan -Minutes 20)`

### **Implementierung von Täuschungstechniken**

- Die Implementierung von Täuschung umfasst das Setzen von Fallen, wie z.B. Lockvogelbenutzern oder -computern, mit Funktionen wie Passwörtern, die nicht ablaufen oder als vertrauenswürdig für Delegation gekennzeichnet sind. Ein detaillierter Ansatz umfasst die Erstellung von Benutzern mit spezifischen Rechten oder deren Hinzufügung zu hochprivilegierten Gruppen.
- Ein praktisches Beispiel umfasst die Verwendung von Tools wie: `Create-DecoyUser -UserFirstName user -UserLastName manager-uncommon -Password Pass@123 | DeployUserDeception -UserFlag PasswordNeverExpires -GUID d07da11f-8a3d-42b6-b0aa-76c962be719a -Verbose`
- Weitere Informationen zur Bereitstellung von Täuschungstechniken finden Sie unter [Deploy-Deception auf GitHub](https://github.com/samratashok/Deploy-Deception).

### **Identifizierung von Täuschung**

- **Für Benutzerobjekte**: Verdächtige Indikatoren sind atypische ObjectSID, seltene Anmeldungen, Erstellungsdaten und niedrige Anzahl an falschen Passwörtern.
- **Allgemeine Indikatoren**: Der Vergleich von Attributen potenzieller Lockvogelobjekte mit denen echter Objekte kann Inkonsistenzen aufdecken. Tools wie [HoneypotBuster](https://github.com/JavelinNetworks/HoneypotBuster) können bei der Identifizierung solcher Täuschungen helfen.

### **Umgehung von Erkennungssystemen**

- **Umgehung der Microsoft ATA-Erkennung**:
- **Benutzerenumeration**: Vermeidung der Sitzungsenumeration auf Domänencontrollern, um die ATA-Erkennung zu verhindern.
- **Ticket-Impersonation**: Die Verwendung von **aes**-Schlüsseln zur Ticket-Erstellung hilft, die Erkennung zu umgehen, indem nicht auf NTLM herabgestuft wird.
- **DCSync-Angriffe**: Es wird empfohlen, von einem Nicht-Domänencontroller aus auszuführen, um die ATA-Erkennung zu vermeiden, da die direkte Ausführung von einem Domänencontroller aus Warnungen auslösen wird.

## Referenzen

- [http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/](http://www.harmj0y.net/blog/redteaming/a-guide-to-attacking-domain-trusts/)
- [https://www.labofapenetrationtester.com/2018/10/deploy-deception.html](https://www.labofapenetrationtester.com/2018/10/deploy-deception.html)
- [https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain](https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/child-domain-da-to-ea-in-parent-domain)

{{#include ../../banners/hacktricks-training.md}}
