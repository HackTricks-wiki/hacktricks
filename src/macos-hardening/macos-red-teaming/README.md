# macOS Red Teaming

{{#include ../../banners/hacktricks-training.md}}


## Zloupotreba MDM-ova

- JAMF Pro: `jamf checkJSSConnection`
- Kandji

Ako uspete da **kompromitujete administratorske kredencijale** za pristup management platformi, možete **potencijalno kompromitovati sve računare** distribucijom malware-a na njima.

Za red teaming u MacOS okruženjima veoma se preporučuje razumevanje načina rada MDM-ova:


{{#ref}}
macos-mdm/
{{#endref}}

### Korišćenje MDM-a kao C2

MDM ima dozvole za instaliranje, ispitivanje ili uklanjanje profila, instaliranje aplikacija, kreiranje lokalnih administratorskih naloga, postavljanje firmware lozinke, promenu FileVault ključa...

Da biste pokrenuli sopstveni MDM, potreban vam je **CSR potpisan od strane vendora**, što možete pokušati da dobijete putem [**https://mdmcert.download/**](https://mdmcert.download/). Za pokretanje sopstvenog MDM-a za Apple uređaje možete koristiti [**MicroMDM**](https://github.com/micromdm/micromdm).

Međutim, da biste instalirali aplikaciju na enrolled uređaj, ona i dalje mora biti potpisana developerskim nalogom... međutim, prilikom MDM enrollment-a **uređaj dodaje SSL sertifikat MDM-a kao trusted CA**, tako da sada možete potpisati bilo šta.<sup>[[4]](#references)</sup>

Da biste enrolovali uređaj u MDM, potrebno je da kao root instalirate **`mobileconfig`** fajl, koji se može isporučiti putem **pkg** fajla (možete ga kompresovati u zip, a kada se preuzme iz Safarija, biće dekompresovan).

**Mythic agent Orthrus** koristi ovu tehniku.

### Zloupotreba JAMF PRO

JAMF može da pokreće **custom scripts** (skripte koje razvija sysadmin), **native payloads** (kreiranje lokalnog naloga, postavljanje EFI lozinke, nadgledanje fajlova/procesa...) i **MDM** (konfiguracije uređaja, sertifikati uređaja...).<sup>[[5]](#references)</sup>

#### JAMF self-enrolment

Posetite stranicu kao što je `https://<company-name>.jamfcloud.com/enroll/` da biste proverili da li je omogućen **self-enrolment**. Ako jeste, stranica može **zahtevati kredencijale za pristup**.

Možete koristiti skriptu [**JamfSniper.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfSniper.py) za izvođenje password spraying napada.

Pored toga, nakon pronalaženja ispravnih kredencijala, možda ćete moći da brute-force-ujete druga korisnička imena pomoću sledeće forme:

![Zloupotreba JAMF PRO - JAMF self-enrolment: Pored toga, nakon pronalaženja ispravnih kredencijala, možda ćete moći da brute-force-ujete druga korisnička imena pomoću sledeće forme](<../../images/image (107).png>)

#### JAMF device Authentication

<figure><img src="../../images/image (167).png" alt=""><figcaption></figcaption></figure>

Binarni fajl **`jamf`** sadržao je tajnu vrednost za otvaranje keychain-a, koja je u vreme otkrića bila **deljena** među svima i glasila je: **`jk23ucnq91jfu9aj`**.<sup>[[5]](#references)</sup>\
Pored toga, jamf se **perzistira** kao **LaunchDaemon** u **`/Library/LaunchAgents/com.jamf.management.agent.plist`**

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
Dakle, napadač bi mogao da ubaci zlonamerni paket (`pkg`) koji bi **prepisao ovu datoteku** prilikom instalacije, postavljajući **URL na Mythic C2 listener iz Typhon agenta**, čime bi mogao da zloupotrebi JAMF kao C2.
```bash
# After changing the URL you could wait for it to be reloaded or execute:
sudo jamf policy -id 0

# TODO: There is an ID, maybe it's possible to have the real jamf connection and another one to the C2
```
#### JAMF Impersonation

Da biste **impersonirali komunikaciju** između uređaja i JMF-a potrebno je:

- **UUID** uređaja: `ioreg -d2 -c IOPlatformExpertDevice | awk -F" '/IOPlatformUUID/{print $(NF-1)}'`
- **JAMF keychain** sa lokacije: `/Library/Application\ Support/Jamf/JAMF.keychain`, koji sadrži sertifikat uređaja

Koristeći ove informacije, **kreirajte VM** sa **ukradenim** Hardware **UUID-om** i sa **isključenim SIP-om**, ubacite **JAMF keychain**, izvršite **hook** Jamf **agenta** i ukradite njegove informacije.

#### Secrets stealing

<figure><img src="../../images/image (1025).png" alt=""><figcaption><p>a</p></figcaption></figure>

Takođe možete nadgledati lokaciju `/Library/Application Support/Jamf/tmp/` u potrazi za **custom scripts** koje administratori mogu želeti da izvrše putem Jamf-a, pošto se oni **postavljaju ovde, izvršavaju i uklanjaju**. Ove skripte **mogu sadržati credentials**.

Međutim, **credentials** mogu biti prosleđeni ovim skriptama kao **parametri**, pa bi bilo potrebno nadgledati `ps aux | grep -i jamf` (čak i bez root privilegija).

Skripta [**JamfExplorer.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfExplorer.py) može osluškivati dodavanje novih fajlova i nove arguments procesa.

### macOS Remote Access

Takođe, u vezi sa "posebnim" **mrežnim** **protokolima** sistema **MacOS**:


{{#ref}}
../macos-security-and-privilege-escalation/macos-protocols.md
{{#endref}}

## Active Directory

U nekim slučajevima otkrićete da je **MacOS računar povezan sa AD-om**. U ovom scenariju trebalo bi da pokušate da **enumerišete** active directory na način na koji ste navikli. Dodatnu **pomoć** možete pronaći na sledećim stranicama:


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
Takođe postoje neke alatke pripremljene za MacOS za automatsko enumerisanje AD-a i rad sa kerberosom:

- [**Machound**](https://github.com/XMCyber/MacHound): MacHound je proširenje alatke Bloodhound audting koje omogućava prikupljanje i unos odnosa Active Directory-ja na MacOS hostovima.<sup>[[2]](#references)</sup>
- [**Bifrost**](https://github.com/its-a-feature/bifrost): Bifrost je Objective-C projekat dizajniran za interakciju sa Heimdal krb5 API-jima na macOS-u. Cilj projekta je omogućavanje boljeg security testiranja u vezi sa Kerberosom na macOS uređajima, korišćenjem nativnih API-ja bez potrebe za bilo kojim drugim framework-om ili paketima na targetu.
- [**Orchard**](https://github.com/its-a-feature/Orchard): JavaScript for Automation (JXA) alatka za enumerisanje Active Directory-ja.

### Informacije o domenu
```bash
echo show com.apple.opendirectoryd.ActiveDirectory | scutil
```
### Korisnici

Tri tipa MacOS korisnika su:

- **Lokalni korisnici** — Njima upravlja lokalna OpenDirectory usluga i ni na koji način nisu povezani sa Active Directory.
- **Mrežni korisnici** — Privremeni Active Directory korisnici kojima je potrebna veza sa DC serverom radi autentifikacije.
- **Mobilni korisnici** — Active Directory korisnici sa lokalnom rezervnom kopijom svojih akreditiva i datoteka.

Lokalne informacije o korisnicima i grupama čuvaju se u folderu _/var/db/dslocal/nodes/Default._\
Na primer, informacije o korisniku pod nazivom _mark_ čuvaju se u _/var/db/dslocal/nodes/Default/users/mark.plist_, a informacije o grupi _admin_ nalaze se u _/var/db/dslocal/nodes/Default/groups/admin.plist_.

Pored korišćenja veza HasSession i AdminTo, **MacHound dodaje tri nove veze** u Bloodhound bazu podataka:<sup>[[2]](#references)</sup>

- **CanSSH** - entitet kojem je dozvoljeno da koristi SSH za povezivanje sa hostom
- **CanVNC** - entitet kojem je dozvoljeno da koristi VNC za povezivanje sa hostom
- **CanAE** - entitet kojem je dozvoljeno da izvršava AppleEvent skripte na hostu
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
Moguce je pristupiti lozinci **`Computer$`** unutar System keychain-a.

### Over-Pass-The-Hash

Preuzmite TGT za odredenog korisnika i servis:
```bash
bifrost --action asktgt --username [user] --domain [domain.com] \
--hash [hash] --enctype [enctype] --keytab [/path/to/keytab]
```
Kada je TGT prikupljen, moguće je inject-ovati ga u trenutnu sesiju pomoću:
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
Sa pribavljenim service tickets moguće je pokušati pristup share-ovima na drugim računarima:
```bash
smbutil view //computer.fqdn
mount -t smbfs //server/folder /local/mount/point
```
## Pristup Keychain-u

Keychain vrlo verovatno sadrži osetljive informacije koje bi, ako im se pristupi bez generisanja prompta, mogle pomoći u napredovanju Red Team vežbe:


{{#ref}}
macos-keychain.md
{{#endref}}

## Eksterne usluge

MacOS Red Teaming se razlikuje od uobičajenog Windows Red Teaming-a, jer je **MacOS obično direktno integrisan sa nekoliko eksternih platformi**. Uobičajena konfiguracija MacOS-a je pristup računaru pomoću **OneLogin sinhronizovanih kredencijala i pristupanje različitim eksternim uslugama** (kao što su github, aws...) putem OneLogin-a.

## Razne Red Team tehnike

### Safari

Kada se datoteka preuzme u Safariju, ako je to "bezbedna" datoteka, ona će biti **automatski otvorena**. Na primer, ako **preuzmete zip**, on će biti automatski dekompresovan:

<figure><img src="../../images/image (226).png" alt=""><figcaption></figcaption></figure>

## Reference

- [1] [Gone Apple Pickin': Red Teaming MacOS Environments in 2021 - Cedric Owens (DEF CON 29)](https://www.youtube.com/watch?v=IiMladUbL6E)
- [2] [Introducing MacHound: A Solution to macOS Active Directory Based Attacks](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)
- [3] [its-a-feature - Domain Enumeration Commands (dscl / net / ldapsearch equivalents)](https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0)
- [4] [Come to the Dark Side, We Have Apples: Turning macOS Management Evil](https://www.youtube.com/watch?v=pOQOh07eMxY)
- [5] [OBTS v3.0: "An Attackers Perspective on Jamf Configurations" - Luke Roberts / Calum Hall](https://www.youtube.com/watch?v=ju1IYWUv4ZA)


{{#include ../../banners/hacktricks-training.md}}
