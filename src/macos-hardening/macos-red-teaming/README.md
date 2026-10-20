# macOS Red Teaming

{{#include ../../banners/hacktricks-training.md}}


## Misbruik van MDM's

- JAMF Pro: `jamf checkJSSConnection`
- Kandji

As jy daarin slaag om **admin-aanmeldbewyse te kompromitteer** om toegang tot die bestuursplatform te kry, kan jy **potensieel al die rekenaars kompromitteer** deur jou malware op die rekenaars te versprei.

Vir Red Teaming in MacOS-omgewings word dit sterk aanbeveel om te verstaan hoe MDM's werk:


{{#ref}}
macos-mdm/
{{#endref}}

### Gebruik MDM as 'n C2

'n MDM sal toestemming hê om profiele te installeer, navraag daaroor te doen of dit te verwyder, toepassings te installeer, plaaslike admin-rekeninge te skep, die firmware-wagwoord in te stel, die FileVault-sleutel te verander...

Om jou eie MDM te gebruik, moet jy **jou CSR deur 'n verskaffer laat onderteken**. Jy kan probeer om dit via [**https://mdmcert.download/**](https://mdmcert.download/) te kry. Om jou eie MDM vir Apple-toestelle te gebruik, kan jy [**MicroMDM**](https://github.com/micromdm/micromdm) gebruik.

MDM-inskrywing maak nie **outomaties** die bestuurbediener se TLS-sertifikaat 'n vertroude CA nie en verleen ook nie 'n programondertekeningsidentiteit nie. As die bediener 'n private CA gebruik, moet sy wortel- en intermediêre sertifikate in die inskrywingsprofiel of 'n afsonderlike vertrouensprofiel voorsien word. Die kliëntidentiteitsertifikaat wat vir MDM-verifikasie gebruik word, is 'n ander sertifikaat.<sup>[[7]](#references)</sup>

'n Afgelaaide MDM-inskrywingsprofiel (`.mobileconfig`) moet oopgemaak en goedgekeur word in **Stelselinstellings → Algemeen → Toestelbestuur**. Om dit bloot in 'n as root geïnstalleerde `.pkg` of 'n ZIP-lêer wat in Safari oopgemaak is te plaas, skryf nie 'n huidige Mac stilweg in nie. Sien [gedrag van konfigurasieprofiele](../macos-auto-start-locations.md#configuration-profiles-mobileconfig).<sup>[[8]](#references)</sup>

Outomatiese toestेलinskrywing tydens Setup Assistant is 'n afsonderlike proses. Sien [skelm inskrywing van 'n ander organisasie se toestel](macos-mdm/enrolling-devices-in-other-organisations.md) vir die verskillende voorvereistes.<sup>[[9]](#references)</sup>

**Mythic-agent Orthrus** gebruik hierdie tegniek.

### Ontplooiing van 'n pakket deur 'n beheerde MDM

Op 'n **Mac onder toesig wat macOS 26 of later gebruik**, laat beheer oor die MDM-diens toe dat 'n `com.apple.configuration.package`-verklaring in die stelselomvang gebruik word.<sup>[[10]](#references)</sup> Die toestel moet die pakkethandtekening kan verifieer, maar die toepassing daarvan het nie 'n afsonderlike Developer ID-handtekening nodig nie: Gatekeeper kontroleer nie toepassings wat deur toestelbestuur geïnstalleer word nie.<sup>[[11]](#references)</sup> 'n Vertroude TLS-sertifikaat vir die bediener gee die operateur op sigself nie die private sleutel of ondertekeningsgebruik wat vir daardie pakkethandtekening nodig is nie.<sup>[[11]](#references)[[12]](#references)</sup>

Bou 'n ondertekende toetspakket, bereken die digest daarvan en publiseer die pakket en 'n `ManifestURL`-plist oor HTTPS. Die manifest benodig een `software-package`-bate met sy URL en SHA-256, plus 'n unieke `bundle-identifier` en `bundle-version`.<sup>[[11]](#references)</sup> Stuur dan 'n pakketverklaring met daardie manifest-URL en stel `InstallBehavior.Install` op `Required`; kyk na die `package.list`-statusitem vir installasie-inligting of foute.<sup>[[10]](#references)[[11]](#references)</sup>

```bash
pkgbuild --component ./Test.app --install-location /Applications --sign "Package Signing Certificate" ./Test.pkg
shasum -a 256 ./Test.pkg
```

’n Minimale verklaring vir ’n vereiste installasie, wat via die MDM-diens ingedien word, lyk so (vervang die URL en albei UUID’s).<sup>[[10]](#references)</sup>

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

### Misbruik van JAMF PRO

JAMF kan **pasgemaakte scripts** (scripts wat deur die sysadmin ontwikkel is), **native payloads** (die skep van plaaslike rekeninge, die instel van ’n EFI-wagwoord, lêer-/prosesmonitering...) en **MDM** (toestelkonfigurasies, toestelsertifikate...) uitvoer.<sup>[[5]](#references)</sup>

#### JAMF self-inskrywing

Gaan na ’n bladsy soos `https://<company-name>.jamfcloud.com/enroll/` om te sien of hulle **self-inskrywing geaktiveer het**. As dit geaktiveer is, kan dit **aanmeldbesonderhede vereis**.

Jy kan die script [**JamfSniper.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfSniper.py) gebruik om ’n password spraying-aanval uit te voer.

Nadat jy geldige aanmeldbesonderhede gevind het, kan jy ook ander gebruikersname brute-force met die volgende vorm:

![Misbruik van JAMF PRO - JAMF self-inskrywing: Nadat jy geldige aanmeldbesonderhede gevind het, kan jy ook ander gebruikersname brute-force met die volgende vorm](<../../images/image (107).png>)

#### JAMF-toestelverifikasie

<figure><img src="../../images/image (167).png" alt=""><figcaption></figcaption></figure>

Die **`jamf`**-binêre lêer het die geheim bevat waarmee die keychain oopgemaak kon word. Ten tyde van die ontdekking is dit **met almal gedeel** en was dit: **`jk23ucnq91jfu9aj`**.<sup>[[5]](#references)</sup>\
Daarbenewens handhaaf jamf volharding as ’n **LaunchDaemon** in **`/Library/LaunchAgents/com.jamf.management.agent.plist`**

#### Oorneem van ’n JAMF-toestel

Die **JSS**- (Jamf Software Server-)**URL** wat **`jamf`** sal gebruik, is geleë in **`/Library/Preferences/com.jamfsoftware.jamf.plist`**.\
Hierdie lêer bevat basies die URL:

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

Dus kan ’n aanvaller ’n kwaadwillige pakket (`pkg`) plaas wat hierdie lêer **by installering oorskryf** en die **URL na ’n Mythic C2-listener van ’n Typhon-agent** instel, sodat JAMF as C2 misbruik kan word.

```bash
# After changing the URL you could wait for it to be reloaded or execute:
sudo jamf policy -id 0

# TODO: There is an ID, maybe it's possible to have the real jamf connection and another one to the C2
```

#### JAMF Impersonation

Om die **kommunikasie** tussen ’n toestel en JMF **na te boots**, benodig jy:

- Die toestel se **UUID**: `ioreg -d2 -c IOPlatformExpertDevice | awk -F" '/IOPlatformUUID/{print $(NF-1)}'`
- Die **JAMF-sleutelhanger** vanaf: `/Library/Application\ Support/Jamf/JAMF.keychain`, wat die toestelsertifikaat bevat

Met hierdie inligting **skep jy ’n VM** met die **gesteelde** Hardware **UUID** en met **SIP gedeaktiveer**, plaas die **JAMF-sleutelhanger** daarop, **hook** die Jamf-**agent** en steel sy inligting.

#### Geheime steel

<figure><img src="../../images/image (1025).png" alt=""><figcaption><p>a</p></figcaption></figure>

Jy kan ook die ligging `/Library/Application Support/Jamf/tmp/` monitor vir **pasgemaakte scripts** wat admins dalk via Jamf wil uitvoer, aangesien dit hier **geplaas, uitgevoer en verwyder** word. Hierdie scripts **kan geloofsbriewe bevat**.

**Geloofsbriewe** kan egter as **parameters** aan hierdie scripts deurgegee word, dus moet jy `ps aux | grep -i jamf` monitor (selfs sonder root-regte).

Die script [**JamfExplorer.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfExplorer.py) kan luister vir nuwe lêers wat bygevoeg word en nuwe prosesargumente.

### macOS-afstandstoegang

En ook oor **MacOS** se "spesiale" **netwerk**-**protokolle**:


{{#ref}}
../macos-security-and-privilege-escalation/macos-protocols.md
{{#endref}}

## Active Directory

Soms sal jy vind dat die **MacOS-rekenaar aan ’n AD gekoppel is**. In hierdie scenario moet jy probeer om die active directory te **enumereer**, soos jy gewoond is om te doen. Kry **hulp** op die volgende bladsye:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}


{{#ref}}
../../windows-hardening/active-directory-methodology/
{{#endref}}


{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/
{{#endref}}

’n **Plaaslike MacOS-nutsding** wat jou dalk ook kan help, is `dscl`:

```bash
dscl "/Active Directory/[Domain]/All Domains" ls /
```

Ook is daar 'n paar tools vir MacOS beskikbaar om die AD outomaties te enumerate en met kerberos te werk:

- [**Machound**](https://github.com/XMCyber/MacHound): MacHound is 'n uitbreiding vir die Bloodhound-ouditinstrument waarmee Active Directory-verhoudings op MacOS-gashere versamel en ingeneem kan word.<sup>[[2]](#references)</sup>
- [**Bifrost**](https://github.com/its-a-feature/bifrost): Bifrost is 'n Objective-C-projek wat ontwerp is om met die Heimdal krb5-API's op macOS te werk. Die doel van die projek is om beter sekuriteitstoetsing rondom Kerberos op macOS-toestelle moontlik te maak met behulp van native API's, sonder dat enige ander framework of pakkette op die teiken benodig word.
- [**Orchard**](https://github.com/its-a-feature/Orchard): JavaScript for Automation (JXA)-tool vir Active Directory-enumerasie.

### Domeininligting

```bash
echo show com.apple.opendirectoryd.ActiveDirectory | scutil
```

### Gebruikers

Die drie tipes MacOS-gebruikers is:

- **Plaaslike gebruikers** — Word deur die plaaslike OpenDirectory-diens bestuur en is op geen manier aan die Active Directory gekoppel nie.
- **Netwerkgebruikers** — Vlugtige Active Directory-gebruikers wat ’n verbinding met die DC-bediener benodig om te staaf.
- **Mobiele gebruikers** — Active Directory-gebruikers met ’n plaaslike rugsteun van hul geloofsbriewe en lêers.

Die plaaslike inligting oor gebruikers en groepe word in die vouer _/var/db/dslocal/nodes/Default._ gestoor.\
Byvoorbeeld, die inligting oor die gebruiker genaamd _mark_ word in _/var/db/dslocal/nodes/Default/users/mark.plist_ gestoor, en die inligting oor die groep _admin_ is in _/var/db/dslocal/nodes/Default/groups/admin.plist_.

Benewens die gebruik van die HasSession- en AdminTo-randverbindings, voeg **MacHound drie nuwe randverbindings** by die Bloodhound-databasis:<sup>[[2]](#references)</sup>

- **CanSSH** - entiteit wat toegelaat word om via SSH aan die gasheer te koppel
- **CanVNC** - entiteit wat toegelaat word om via VNC aan die gasheer te koppel
- **CanAE** - entiteit wat toegelaat word om AppleEvent-skripte op die gasheer uit te voer

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

Meer inligting by [https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/)<sup>[[3]](#references)[[6]](#references)</sup>

### Computer$-wagwoord

Kry wagwoorde met:

```bash
bifrost --action askhash --username [name] --password [password] --domain [domain]
```

Dit is moontlik om toegang te kry tot die **`Computer$`**-wagwoord binne die System keychain.

### Over-Pass-The-Hash

Kry 'n TGT vir 'n spesifieke gebruiker en diens:

```bash
bifrost --action asktgt --username [user] --domain [domain.com] \
       --hash [hash] --enctype [enctype] --keytab [/path/to/keytab]
```

Sodra die TGT ingesamel is, is dit moontlik om dit in die huidige sessie in te spuit met:

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

Met verkrygde service tickets is dit moontlik om toegang tot shares op ander rekenaars te probeer verkry:

```bash
smbutil view //computer.fqdn
mount -t smbfs //server/folder /local/mount/point
```

## Toegang tot die Keychain

Die Keychain bevat waarskynlik sensitiewe inligting wat kan help om ’n red team-oefening voort te sit as dit verkry word sonder om ’n prompt te laat verskyn:


{{#ref}}
macos-keychain.md
{{#endref}}

## Eksterne dienste

MacOS Red Teaming verskil van gewone Windows Red Teaming, aangesien **MacOS gewoonlik direk met verskeie eksterne platforms geïntegreer is**. ’n Algemene MacOS-opstelling gebruik **OneLogin-gesinchroniseerde aanmeldbewyse om toegang tot die rekenaar te verkry, en om toegang tot verskeie eksterne dienste** (soos github, aws...) via OneLogin te kry.

## Diverse Red Team-tegnieke

### Safari

Wanneer ’n lêer in Safari afgelaai word, word dit **outomaties oopgemaak** as dit ’n "veilige" lêer is. As jy byvoorbeeld **’n zip-lêer aflaai**, word dit outomaties gedecomprimeer:<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (226).png" alt=""><figcaption></figcaption></figure>



## References

- [1] [Appels pluk: Red Teaming van MacOS-omgewings in 2021 - Cedric Owens (DEF CON 29)](https://www.youtube.com/watch?v=IiMladUbL6E)
- [2] [Bekendstelling van MacHound: ’n oplossing vir macOS-aanvalle gebaseer op Active Directory](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)
- [3] [its-a-feature - Domein-enumerasie-opdragte (dscl / net / ldapsearch-ekwivalente)](https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0)
- [4] [Kom na die Donker Kant, ons het appels: Maak macOS-bestuur boos](https://www.youtube.com/watch?v=pOQOh07eMxY)
- [5] [OBTS v3.0: "’n aanvallerperspektief op Jamf-konfigurasies" - Luke Roberts / Calum Hall](https://www.youtube.com/watch?v=ju1IYWUv4ZA)
- [6] [Active Directory-ontdekking met ’n Mac - its-a-feature](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/)
- [7] [Apple — Bestuur van sertifikate vir toestelbestuurdienste en -toestelle](https://developer.apple.com/documentation/devicemanagement/managing-certificates-for-device-management-services-and-devices)
- [8] [Apple — Gebruik konfigurasieprofiele op Mac](https://support.apple.com/en-gb/guide/mac-help/mh35561/mac)
- [9] [Apple — Ontplooiing van toestelbestuur-inskrywingsprofiele](https://developer.apple.com/documentation/devicemanagement/deploying-device-management-enrollment-profiles)
- [10] [Apple — Pakketverklaring](https://developer.apple.com/documentation/devicemanagement/package)
- [11] [Apple — Installeer pakkette](https://developer.apple.com/documentation/devicemanagement/installing-packages)
- [12] [Apple — Identiteite](https://developer.apple.com/documentation/security/identities)
{{#include ../../banners/hacktricks-training.md}}
