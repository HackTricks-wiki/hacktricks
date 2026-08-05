# macOS Red Teaming

{{#include ../../banners/hacktricks-training.md}}


## Misbruik van MDMs

- JAMF Pro: `jamf checkJSSConnection`
- Kandji

As jy daarin slaag om **admin-geloofsbriewe te kompromitteer** om toegang tot die bestuursplatform te verkry, kan jy **potensieel al die rekenaars kompromitteer** deur jou malware na die masjiene te versprei.

Vir red teaming in MacOS-omgewings word dit sterk aanbeveel om ’n mate van begrip te hê van hoe die MDMs werk:


{{#ref}}
macos-mdm/
{{#endref}}

### Gebruik van MDM as ’n C2

’n MDM sal toestemming hê om profiele te installeer, navraag daaroor te doen of dit te verwyder, toepassings te installeer, plaaslike admin-rekeninge te skep, firmware-wagwoorde op te stel, die FileVault-sleutel te verander...

Om jou eie MDM te bedryf, moet jy **jou CSR deur ’n vendor laat onderteken**, wat jy kan probeer verkry by [**https://mdmcert.download/**](https://mdmcert.download/). Om jou eie MDM vir Apple-toestelle te bedryf, kan jy **[MicroMDM](https://github.com/micromdm/micromdm)** gebruik.

Om ’n toepassing op ’n ingeskrewe toestel te installeer, moet dit egter steeds deur ’n developer account onderteken wees... tydens MDM-enrolment voeg die **toestel die SSL-cert van die MDM as ’n trusted CA by**, sodat jy nou enigiets kan onderteken.<sup>[[4]](#references)</sup>

Om die toestel by ’n MDM in te skryf, moet jy ’n **`mobileconfig`**-lêer as root installeer, wat via ’n **pkg**-lêer afgelewer kan word (jy kan dit in zip saamdruk en wanneer dit vanaf Safari afgelaai word, sal dit gedekomprimeer word).

**Mythic agent Orthrus** gebruik hierdie tegniek.

### Misbruik van JAMF PRO

JAMF kan **custom scripts** (scripts wat deur die sysadmin ontwikkel is), **native payloads** (skepping van plaaslike rekeninge, opstel van EFI-wagwoorde, lêer-/prosesmonitering...) en **MDM** (toestelkonfigurasies, toestelsertifikate...) uitvoer.<sup>[[5]](#references)</sup>

#### JAMF self-enrolment

Gaan na ’n bladsy soos `https://<company-name>.jamfcloud.com/enroll/` om te sien of hulle **self-enrolment geaktiveer het**. As dit geaktiveer is, kan dit **geloofsbriewe versoek om toegang te verkry**.

Jy kan die script [**JamfSniper.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfSniper.py) gebruik om ’n password spraying-aanval uit te voer.

Verder, nadat jy geldige geloofsbriewe gevind het, kan jy moontlik ander gebruikersname met die volgende vorm brute-force:

![Misbruik van JAMF PRO - JAMF self-enrolment: Verder, nadat jy geldige geloofsbriewe gevind het, kan jy moontlik ander gebruikersname met die volgende vorm brute-force](<../../images/image (107).png>)

#### JAMF device Authentication

<figure><img src="../../images/image (167).png" alt=""><figcaption></figcaption></figure>

Die **`jamf`**-binary het die geheim bevat om die keychain oop te maak wat tydens die ontdekking met almal **gedeel** is, naamlik: **`jk23ucnq91jfu9aj`**.<sup>[[5]](#references)</sup>\
Verder **persist** jamf as ’n **LaunchDaemon** in **`/Library/LaunchAgents/com.jamf.management.agent.plist`**

#### JAMF Device Takeover

Die **JSS** (Jamf Software Server) **URL** wat **`jamf`** sal gebruik, is geleë in **`/Library/Preferences/com.jamfsoftware.jamf.plist`**.\
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
Dus kan 'n aanvaller 'n kwaadwillige pakket (`pkg`) plaas wat **hierdie lêer oorskryf** wanneer dit geïnstalleer word, en die **URL na 'n Mythic C2-listener vanaf 'n Typhon-agent stel**, sodat JAMF nou as C2 misbruik kan word.
```bash
# After changing the URL you could wait for it to be reloaded or execute:
sudo jamf policy -id 0

# TODO: There is an ID, maybe it's possible to have the real jamf connection and another one to the C2
```
#### JAMF Impersonation

Om die **kommunikasie** tussen ’n toestel en JMF te **impersonate**, benodig jy:

- Die toestel se **UUID**: `ioreg -d2 -c IOPlatformExpertDevice | awk -F" '/IOPlatformUUID/{print $(NF-1)}'`
- Die **JAMF keychain** vanaf: `/Library/Application\ Support/Jamf/JAMF.keychain`, wat die toestelsertifikaat bevat

Met hierdie inligting, **skep ’n VM** met die **gesteelde** Hardware **UUID** en met **SIP disabled**, plaas die **JAMF keychain**, **hook** die Jamf **agent** en steel sy inligting.

#### Secrets stealing

<figure><img src="../../images/image (1025).png" alt=""><figcaption><p>a</p></figcaption></figure>

Jy kan ook die ligging `/Library/Application Support/Jamf/tmp/` monitor vir die **custom scripts** wat admins moontlik via Jamf wil uitvoer, aangesien hulle **hier geplaas, uitgevoer en verwyder word**. Hierdie scripts **kan credentials bevat**.

**Credentials** kan egter as **parameters** aan hierdie scripts deurgegee word, dus sal jy `ps aux | grep -i jamf` moet monitor (selfs sonder om root te wees).

Die script [**JamfExplorer.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfExplorer.py) kan luister vir nuwe lêers wat bygevoeg word en nuwe prosesargumente.

### macOS Remote Access

En ook oor MacOS se "spesiale" **network** **protocols**:


{{#ref}}
../macos-security-and-privilege-escalation/macos-protocols.md
{{#endref}}

## Active Directory

By sommige geleenthede sal jy vind dat die **MacOS-rekenaar aan ’n AD gekoppel is**. In hierdie scenario moet jy probeer om die active directory te **enumerate**, soos jy gewoond is om te doen. Vind ’n bietjie **hulp** op die volgende bladsye:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}


{{#ref}}
../../windows-hardening/active-directory-methodology/
{{#endref}}


{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/
{{#endref}}

’n **Local MacOS tool** wat jou ook kan help, is `dscl`:
```bash
dscl "/Active Directory/[Domain]/All Domains" ls /
```
Daar is ook sommige tools wat vir MacOS voorberei is om die AD outomaties te enumerate en met kerberos te werk:

- [**Machound**](https://github.com/XMCyber/MacHound): MacHound is ’n uitbreiding vir die Bloodhound-auditingtool waarmee Active Directory-verhoudings op MacOS-hosts versamel en ingeneem kan word.<sup>[[2]](#references)</sup>
- [**Bifrost**](https://github.com/its-a-feature/bifrost): Bifrost is ’n Objective-C-projek wat ontwerp is om met die Heimdal krb5 APIs op macOS te kommunikeer. Die doel van die projek is om beter security testing rondom Kerberos op macOS-toestelle moontlik te maak deur native APIs te gebruik, sonder dat enige ander framework of packages op die target benodig word.
- [**Orchard**](https://github.com/its-a-feature/Orchard): JavaScript for Automation (JXA)-tool om Active Directory te enumerate.

### Domeininligting
```bash
echo show com.apple.opendirectoryd.ActiveDirectory | scutil
```
### Gebruikers

Die drie tipes MacOS-gebruikers is:

- **Local Users** — Word deur die plaaslike OpenDirectory-diens bestuur; hulle is op geen manier aan die Active Directory gekoppel nie.
- **Network Users** — Vlugtige Active Directory-gebruikers wat ’n verbinding met die DC-bediener benodig om te authenticate.
- **Mobile Users** — Active Directory-gebruikers met ’n plaaslike rugsteun van hul credentials en lêers.

Die plaaslike inligting oor gebruikers en groepe word in die vouer _/var/db/dslocal/nodes/Default._\
gestoor.\
Byvoorbeeld, die inligting oor die gebruiker genaamd _mark_ word in _/var/db/dslocal/nodes/Default/users/mark.plist_ gestoor, en die inligting oor die groep _admin_ is in _/var/db/dslocal/nodes/Default/groups/admin.plist_.

Benewens die gebruik van die HasSession- en AdminTo-edges, **voeg MacHound drie nuwe edges** by die Bloodhound-databasis:<sup>[[2]](#references)</sup>

- **CanSSH** - entiteit wat toegelaat word om via SSH aan host te koppel
- **CanVNC** - entiteit wat toegelaat word om via VNC aan host te koppel
- **CanAE** - entiteit wat toegelaat word om AppleEvent-scripts op host uit te voer
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
Meer inligting by [https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/)

### Computer$-wagwoord

Kry wagwoorde met behulp van:
```bash
bifrost --action askhash --username [name] --password [password] --domain [domain]
```
Dit is moontlik om die **`Computer$`**-wagwoord binne die System-sleutelhanger te bekom.

### Over-Pass-The-Hash

Kry 'n TGT vir 'n spesifieke gebruiker en diens:
```bash
bifrost --action asktgt --username [user] --domain [domain.com] \
--hash [hash] --enctype [enctype] --keytab [/path/to/keytab]
```
Sodra die TGT verkry is, kan dit met die volgende in die huidige sessie ge-inject word:
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

Die Keychain bevat heel waarskynlik sensitiewe inligting wat, indien dit verkry word sonder om 'n prompt te genereer, kan help om met 'n red team-oefening voort te gaan:


{{#ref}}
macos-keychain.md
{{#endref}}

## Eksterne Dienste

MacOS Red Teaming verskil van gewone Windows Red Teaming, aangesien **MacOS gewoonlik direk met verskeie eksterne platforms geïntegreer is**. 'n Algemene konfigurasie van MacOS is om toegang tot die rekenaar te verkry met **OneLogin-gesinchroniseerde geloofsbriewe, en om toegang tot verskeie eksterne dienste** (soos github, aws...) via OneLogin te verkry.

## Diverse Red Team-tegnieke

### Safari

Wanneer 'n lêer in Safari afgelaai word, sal dit, indien dit 'n "veilige" lêer is, **outomaties oopgemaak word**. As jy byvoorbeeld **'n zip aflaai**, sal dit outomaties gedekomprimeer word:

<figure><img src="../../images/image (226).png" alt=""><figcaption></figcaption></figure>

## Verwysings

- [1] [Gone Apple Pickin': Red Teaming MacOS Environments in 2021 - Cedric Owens (DEF CON 29)](https://www.youtube.com/watch?v=IiMladUbL6E)
- [2] [Introducing MacHound: A Solution to macOS Active Directory Based Attacks](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)
- [3] [its-a-feature - Domain Enumeration Commands (dscl / net / ldapsearch equivalents)](https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0)
- [4] [Come to the Dark Side, We Have Apples: Turning macOS Management Evil](https://www.youtube.com/watch?v=pOQOh07eMxY)
- [5] [OBTS v3.0: "An Attackers Perspective on Jamf Configurations" - Luke Roberts / Calum Hall](https://www.youtube.com/watch?v=ju1IYWUv4ZA)


{{#include ../../banners/hacktricks-training.md}}
