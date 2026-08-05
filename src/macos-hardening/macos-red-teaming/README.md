# macOS Red Teaming

{{#include ../../banners/hacktricks-training.md}}


## Zloupotreba MDM-ova

- JAMF Pro: `jamf checkJSSConnection`
- Kandji

Ako uspete da **kompromitujete administratorske kredencijale** za pristup management platformi, možete **potencijalno kompromitovati sve računare** distribucijom svog malware-a na njih.

Za red teaming u MacOS okruženjima veoma je preporučljivo razumeti kako MDM-ovi funkcionišu:


{{#ref}}
macos-mdm/
{{#endref}}

### Korišćenje MDM-a kao C2

MDM će imati dozvole za instaliranje, upite ili uklanjanje profila, instaliranje aplikacija, kreiranje lokalnih administratorskih naloga, postavljanje firmware lozinke, promenu FileVault ključa...

Da biste pokrenuli sopstveni MDM, potrebno je da **vaš CSR bude potpisan od strane vendora**, što možete pokušati da dobijete na [**https://mdmcert.download/**](https://mdmcert.download/). Za pokretanje sopstvenog MDM-a za Apple uređaje možete koristiti [**MicroMDM**](https://github.com/micromdm/micromdm).

Međutim, da biste instalirali aplikaciju na enrolled uređaju, ona i dalje mora biti potpisana developerskim nalogom... međutim, prilikom MDM enrolmenta **uređaj dodaje SSL cert MDM-a kao trusted CA**, tako da sada možete potpisati bilo šta.<sup>[4]</sup>

Da biste enrolovali uređaj u MDM, potrebno je da instalirate **`mobileconfig`** fajl kao root, što može biti isporučeno putem **pkg** fajla (možete ga kompresovati u zip, a kada se preuzme iz Safarija, biće dekompresovan).

**Mythic agent Orthrus** koristi ovu tehniku.

### Zloupotreba JAMF PRO

JAMF može pokretati **custom scripts** (skripte koje je razvio sysadmin), **native payloads** (kreiranje lokalnih naloga, postavljanje EFI lozinke, monitoring fajlova/procesa...) i **MDM** (konfiguracije uređaja, certifikati uređaja...).<sup>[5]</sup>

#### JAMF self-enrolment

Idite na stranicu kao što je `https://<company-name>.jamfcloud.com/enroll/` da biste proverili da li je omogućen **self-enrolment**. Ako jeste, možda će **zatražiti kredencijale za pristup**.

Možete koristiti skriptu [**JamfSniper.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfSniper.py) za izvođenje password spraying napada.

Pored toga, nakon pronalaženja ispravnih kredencijala možda ćete moći da izvršite brute-force nad drugim korisničkim imenima pomoću sledeće forme:

![Zloupotreba JAMF PRO - JAMF self-enrolment: Pored toga, nakon pronalaženja ispravnih kredencijala možda ćete moći da izvršite brute-force nad drugim korisničkim imenima pomoću sledeće forme](<../../images/image (107).png>)

#### JAMF device Authentication

<figure><img src="../../images/image (167).png" alt=""><figcaption></figcaption></figure>

**`jamf`** binary je sadržao secret za otvaranje keychain-a koji je u vreme otkrića bio **shared** među svima i glasio je: **`jk23ucnq91jfu9aj`**.<sup>[5]</sup>\
Pored toga, jamf **persist** kao **LaunchDaemon** u **`/Library/LaunchAgents/com.jamf.management.agent.plist`**

#### JAMF Device Takeover

**JSS** (Jamf Software Server) **URL** koji će **`jamf`** koristiti nalazi se u **`/Library/Preferences/com.jamfsoftware.jamf.plist`**.\
Ovaj fajl u osnovi sadrži URL:
```bash
plutil -convert xml1 -o - /Library/Preferences/com.jamfsoftware.jamf.plist

[...]
<key>is_virtual_machine</key>
<false/>
<key>jss_url</key>
<string>https://subdomain-company.jamfcloud.com/</string>
<key>last_management_framework_change_id</key>
<integer>4</integer>
[...]
```
Dakle, napadač bi mogao da ubaci zlonamerni paket (`pkg`) koji bi **prepisao ovu datoteku** prilikom instalacije, postavljajući **URL ka Mythic C2 listeneru iz Typhon agenta**, čime bi mogao da zloupotrebi JAMF kao C2.
```bash
# After changing the URL you could wait for it to be reloaded or execute:
sudo jamf policy -id 0

# TODO: There is an ID, maybe it's possible to have the real jamf connection and another one to the C2
```
#### JAMF Impersonation

Da biste **impersonate komunikaciju** između uređaja i JMF-a, potrebno vam je:

- **UUID** uređaja: `ioreg -d2 -c IOPlatformExpertDevice | awk -F" '/IOPlatformUUID/{print $(NF-1)}'`
- **JAMF keychain** sa lokacije: `/Library/Application\ Support/Jamf/JAMF.keychain`, koji sadrži sertifikat uređaja

Sa ovim informacijama, **kreirajte VM** sa **ukradenim** Hardware **UUID-om** i sa **onemogućenim SIP-om**, ubacite **JAMF keychain**, uradite **hook** Jamf **agent-a** i ukradite njegove informacije.

#### Krađa secrets

<figure><img src="../../images/image (1025).png" alt=""><figcaption><p>a</p></figcaption></figure>

Takođe možete pratiti lokaciju `/Library/Application Support/Jamf/tmp/` za **custom scripts** koje administratori mogu želeti da izvrše putem Jamf-a, pošto se oni **ovde postavljaju, izvršavaju i uklanjaju**. Ove skripte mogu sadržati **credentials**.

Međutim, **credentials** se mogu proslediti ovim skriptama kao **parameters**, pa bi bilo potrebno pratiti `ps aux | grep -i jamf` (čak i bez root privilegija).

Skripta [**JamfExplorer.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfExplorer.py) može da osluškuje dodavanje novih fajlova i nove argumente procesa.

### macOS Remote Access

Takođe, u vezi sa "posebnim" **network** **protocols** sistema **MacOS**:


{{#ref}}
../macos-security-and-privilege-escalation/macos-protocols.md
{{#endref}}

## Active Directory

U nekim slučajevima ćete otkriti da je **MacOS računar povezan na AD**. U ovom scenariju trebalo bi da pokušate da **enumerate** active directory na način na koji ste navikli. Pronađite **pomoć** na sledećim stranicama:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}


{{#ref}}
../../windows-hardening/active-directory-methodology/
{{#endref}}


{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/
{{#endref}}

Neki **lokalni MacOS alat** koji vam takođe može pomoći jeste `dscl`:
```bash
dscl "/Active Directory/[Domain]/All Domains" ls /
```
Takođe postoje neki alati pripremljeni za MacOS koji automatski enumerišu AD i omogućavaju rad sa kerberosom:

- [**Machound**](https://github.com/XMCyber/MacHound): MacHound je proširenje alata Bloodhound za auditing, koje omogućava prikupljanje i unos informacija o odnosima u Active Directory-ju sa MacOS hostova.<sup>[2]</sup>
- [**Bifrost**](https://github.com/its-a-feature/bifrost): Bifrost je Objective-C projekat dizajniran za interakciju sa Heimdal krb5 API-jima na macOS-u. Cilj projekta je omogućavanje kvalitetnijeg security testinga Kerberosa na macOS uređajima korišćenjem izvornih API-ja, bez potrebe za bilo kojim drugim frameworkom ili paketima na targetu.
- [**Orchard**](https://github.com/its-a-feature/Orchard): JavaScript for Automation (JXA) alat za enumeraciju Active Directory-ja.

### Informacije o domenu
```bash
echo show com.apple.opendirectoryd.ActiveDirectory | scutil
```
### Korisnici

Tri vrste MacOS korisnika su:

- **Lokalni korisnici** — Njima upravlja lokalni OpenDirectory servis i nisu ni na koji način povezani sa Active Directory-jem.
- **Mrežni korisnici** — Privremeni Active Directory korisnici kojima je potrebna veza sa DC serverom radi autentifikacije.
- **Mobilni korisnici** — Active Directory korisnici sa lokalnom rezervnom kopijom svojih akreditiva i datoteka.

Lokalne informacije o korisnicima i grupama čuvaju se u fascikli _/var/db/dslocal/nodes/Default._\
Na primer, informacije o korisniku pod imenom _mark_ čuvaju se u _/var/db/dslocal/nodes/Default/users/mark.plist_, a informacije o grupi _admin_ nalaze se u _/var/db/dslocal/nodes/Default/groups/admin.plist_.

Pored korišćenja HasSession i AdminTo edges, **MacHound dodaje tri nova edge-a** u Bloodhound bazu podataka:<sup>[2]</sup>

- **CanSSH** - entitetu je dozvoljeno da koristi SSH za pristup hostu
- **CanVNC** - entitetu je dozvoljeno da koristi VNC za pristup hostu
- **CanAE** - entitetu je dozvoljeno da izvršava AppleEvent skripte na hostu
```bash
#User enumeration
dscl . ls /Users
dscl . read /Users/[username]
dscl "/Active Directory/TEST/All Domains" ls /Users
dscl "/Active Directory/TEST/All Domains" read /Users/[username]
dscacheutil -q user

#Computer enumeration
dscl "/Active Directory/TEST/All Domains" ls /Computers
dscl "/Active Directory/TEST/All Domains" read "/Computers/[compname]$"

#Group enumeration
dscl . ls /Groups
dscl . read "/Groups/[groupname]"
dscl "/Active Directory/TEST/All Domains" ls /Groups
dscl "/Active Directory/TEST/All Domains" read "/Groups/[groupname]"

#Domain Information
dsconfigad -show
```
Više informacija na [https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/)

### Computer$ lozinka

Preuzmite lozinke pomoću:
```bash
bifrost --action askhash --username [name] --password [password] --domain [domain]
```
Moguce je pristupiti lozinki **`Computer$`** unutar System keychain-a.

### Over-Pass-The-Hash

Dobijte TGT za odredenog user-a i service:
```bash
bifrost --action asktgt --username [user] --domain [domain.com] \
--hash [hash] --enctype [enctype] --keytab [/path/to/keytab]
```
Kada se TGT prikupi, moguće je injectovati ga u trenutnu sesiju pomoću:
```bash
bifrost --action asktgt --username test_lab_admin \
--hash CF59D3256B62EE655F6430B0F80701EE05A0885B8B52E9C2480154AFA62E78 \
--enctype aes256 --domain test.lab.local
```
### Kerberoasting
```bash
bifrost --action asktgs --spn [service] --domain [domain.com] \
--username [user] --hash [hash] --enctype [enctype]
```
Sa pribavljenim service tickets moguće je pokušati da se pristupi deljenim resursima na drugim računarima:
```bash
smbutil view //computer.fqdn
mount -t smbfs //server/folder /local/mount/point
```
## Pristupanje Keychain-u

Keychain vrlo verovatno sadrži osetljive informacije koje bi, ako im se pristupi bez generisanja prompt-a, mogle pomoći u napredovanju red team vežbe:


{{#ref}}
macos-keychain.md
{{#endref}}

## Eksterne usluge

MacOS Red Teaming se razlikuje od uobičajenog Windows Red Teaming-a jer je **MacOS obično direktno integrisan sa nekoliko eksternih platformi**. Uobičajena konfiguracija MacOS-a omogućava pristup računaru pomoću **OneLogin sinhronizovanih kredencijala i pristup različitim eksternim uslugama** (kao što su github, aws...) putem OneLogin-a.

## Razne Red Team tehnike

### Safari

Kada se datoteka preuzme u Safari-ju, ako je to "bezbedna" datoteka, biće **automatski otvorena**. Na primer, ako **preuzmete zip**, on će biti automatski dekompresovan:

<figure><img src="../../images/image (226).png" alt=""><figcaption></figcaption></figure>

## Reference

- [1] [Gone Apple Pickin': Red Teaming MacOS Environments in 2021 - Cedric Owens (DEF CON 29)](https://www.youtube.com/watch?v=IiMladUbL6E)
- [2] [Introducing MacHound: A Solution to macOS Active Directory Based Attacks](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)
- [3] [its-a-feature - Domain Enumeration Commands (dscl / net / ldapsearch equivalents)](https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0)
- [4] [Come to the Dark Side, We Have Apples: Turning macOS Management Evil](https://www.youtube.com/watch?v=pOQOh07eMxY)
- [5] [OBTS v3.0: "An Attackers Perspective on Jamf Configurations" - Luke Roberts / Calum Hall](https://www.youtube.com/watch?v=ju1IYWUv4ZA)


{{#include ../../banners/hacktricks-training.md}}
