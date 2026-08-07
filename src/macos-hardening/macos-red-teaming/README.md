# macOS Red Teaming

{{#include ../../banners/hacktricks-training.md}}


## Kutumia Vibaya MDMs

- JAMF Pro: `jamf checkJSSConnection`
- Kandji

Ikiwa utaweza **kuathiri credentials za admin** ili kufikia management platform, unaweza **kuathiri kompyuta zote** kwa kusambaza malware yako kwenye mashine hizo.

Kwa red teaming katika mazingira ya MacOS, inapendekezwa sana kuwa na uelewa fulani wa jinsi MDMs zinavyofanya kazi:


{{#ref}}
macos-mdm/
{{#endref}}

### Kutumia MDM kama C2

MDM itakuwa na ruhusa ya kusakinisha, kuuliza au kuondoa profiles, kusakinisha applications, kuunda local admin accounts, kuweka firmware password, kubadilisha FileVault key...

Ili kuendesha MDM yako mwenyewe, unahitaji **CSR yako isainiwe na vendor**, jambo ambalo unaweza kujaribu kupata kupitia [**https://mdmcert.download/**](https://mdmcert.download/). Na ili kuendesha MDM yako mwenyewe kwa vifaa vya Apple, unaweza kutumia [**MicroMDM**](https://github.com/micromdm/micromdm).

Hata hivyo, ili kusakinisha application kwenye device iliyosajiliwa, bado inahitajika isainiwe na developer account... hata hivyo, wakati wa MDM enrolment **device huongeza SSL cert ya MDM kama trusted CA**, kwa hiyo sasa unaweza kusaini chochote.<sup>[[4]](#references)</sup>

Ili kusajili device kwenye MDM, unahitaji kusakinisha **`mobileconfig`** file kama root, ambayo inaweza kuwasilishwa kupitia **pkg** file (unaweza kuibana kwenye zip na inapopakuliwa kutoka Safari itafunguliwa kutoka kwenye compression).

**Mythic agent Orthrus** hutumia technique hii.

### Kutumia Vibaya JAMF PRO

JAMF inaweza kuendesha **custom scripts** (scripts zilizotengenezwa na sysadmin), **native payloads** (uundaji wa local account, kuweka EFI password, file/process monitoring...) na **MDM** (device configurations, device certificates...).<sup>[[5]](#references)</sup>

#### JAMF self-enrolment

Nenda kwenye ukurasa kama `https://<company-name>.jamfcloud.com/enroll/` ili kuona kama wana **self-enrolment imewezeshwa**. Ikiwa wameiwezesha, inaweza **kuomba credentials za kufikia**.

Unaweza kutumia script [**JamfSniper.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfSniper.py) kutekeleza password spraying attack.

Zaidi ya hayo, baada ya kupata credentials sahihi, unaweza kuwa na uwezo wa kufanya brute-force dhidi ya usernames nyingine kwa kutumia form ifuatayo:

![Kutumia Vibaya JAMF PRO - JAMF self-enrolment: Zaidi ya hayo, baada ya kupata credentials sahihi, unaweza kuwa na uwezo wa kufanya brute-force dhidi ya usernames nyingine kwa kutumia form ifuatayo](<../../images/image (107).png>)

#### JAMF device Authentication

<figure><img src="../../images/image (167).png" alt=""><figcaption></figcaption></figure>

Binary ya **`jamf`** ilikuwa na secret ya kufungua keychain ambayo wakati wa ugunduzi ilikuwa **shared** miongoni mwa kila mtu na ilikuwa: **`jk23ucnq91jfu9aj`**.<sup>[[5]](#references)</sup>\
Zaidi ya hayo, jamf **huendelea kuwepo** kama **LaunchDaemon** kwenye **`/Library/LaunchAgents/com.jamf.management.agent.plist`**

#### JAMF Device Takeover

**URL** ya **JSS** (Jamf Software Server) ambayo **`jamf`** itatumia iko kwenye **`/Library/Preferences/com.jamfsoftware.jamf.plist`**.\
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
Kwa hivyo, mshambuliaji anaweza kuweka package (`pkg`) hasidi ambayo **inaandika juu ya faili hii** inapowekwa, na kuweka **URL kuwa ya Mythic C2 listener kutoka kwa Typhon agent**, hivyo sasa kuweza kutumia vibaya JAMF kama C2.
```bash
# After changing the URL you could wait for it to be reloaded or execute:
sudo jamf policy -id 0

# TODO: There is an ID, maybe it's possible to have the real jamf connection and another one to the C2
```
#### JAMF Impersonation

Ili **kuiga mawasiliano** kati ya kifaa na JMF unahitaji:

- **UUID** ya kifaa: `ioreg -d2 -c IOPlatformExpertDevice | awk -F" '/IOPlatformUUID/{print $(NF-1)}'`
- **JAMF keychain** kutoka: `/Library/Application\ Support/Jamf/JAMF.keychain` ambayo ina certificate ya kifaa

Kwa maelezo haya, **unda VM** yenye **UUID** ya Hardware **iliyoibiwa** na **SIP ikiwa imezimwa**, weka **JAMF keychain**, **hook** Jamf **agent** na uibe taarifa zake.

#### Kuiba secrets

<figure><img src="../../images/image (1025).png" alt=""><figcaption><p>a</p></figcaption></figure>

Unaweza pia kufuatilia eneo `/Library/Application Support/Jamf/tmp/` kwa ajili ya **custom scripts** ambazo admins wanaweza kutaka kutekeleza kupitia Jamf, kwa kuwa **zinawekwa hapa, zinatekelezwa na kuondolewa**. Scripts hizi **zinaweza kuwa na credentials**.

Hata hivyo, **credentials** zinaweza kupitishwa kwa scripts hizi kama **parameters**, kwa hivyo utahitaji kufuatilia `ps aux | grep -i jamf` (hata bila kuwa root).

Script [**JamfExplorer.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfExplorer.py) inaweza kusikiliza files mpya zinapoongezwa na arguments mpya za processes.

### Remote Access ya macOS

Na pia kuhusu **protocols** "maalum" za **network** za **MacOS**:


{{#ref}}
../macos-security-and-privilege-escalation/macos-protocols.md
{{#endref}}

## Active Directory

Katika baadhi ya matukio utagundua kuwa **MacOS computer imeunganishwa kwenye AD**. Katika hali hii unapaswa kujaribu **ku-enumerate** active directory kama ulivyozoea. Pata **msaada** katika kurasa zifuatazo:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}


{{#ref}}
../../windows-hardening/active-directory-methodology/
{{#endref}}


{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/
{{#endref}}

Baadhi ya **local MacOS tool** zinazoweza pia kukusaidia ni `dscl`:
```bash
dscl "/Active Directory/[Domain]/All Domains" ls /
```
Pia kuna baadhi ya tools zilizotayarishwa kwa MacOS ili ku-enumerate AD kiotomatiki na kufanya majaribio na Kerberos:

- [**Machound**](https://github.com/XMCyber/MacHound): MacHound ni extension ya BloodHound auditing tool inayowezesha kukusanya na kuingiza mahusiano ya Active Directory kwenye hosts za MacOS.<sup>[[2]](#references)</sup>
- [**Bifrost**](https://github.com/its-a-feature/bifrost): Bifrost ni project ya Objective-C iliyoundwa kuingiliana na Heimdal krb5 APIs kwenye macOS. Lengo la project hii ni kuwezesha security testing bora zaidi kuhusu Kerberos kwenye vifaa vya macOS kwa kutumia native APIs bila kuhitaji framework au packages nyingine kwenye target.
- [**Orchard**](https://github.com/its-a-feature/Orchard): Tool ya JavaScript for Automation (JXA) ya kufanya Active Directory enumeration.

### Taarifa za Domain
```bash
echo show com.apple.opendirectoryd.ActiveDirectory | scutil
```
### Watumiaji

Aina tatu za watumiaji wa MacOS ni:

- **Local Users** — Husimamiwa na huduma ya ndani ya OpenDirectory; hawajaunganishwa kwa njia yoyote na Active Directory.
- **Network Users** — Watumiaji wa Active Directory wa muda wanaohitaji muunganisho kwenye DC server ili kufanya authentication.
- **Mobile Users** — Watumiaji wa Active Directory walio na backup ya ndani ya credentials na files zao.

Taarifa za ndani kuhusu watumiaji na groups huhifadhiwa kwenye folder _/var/db/dslocal/nodes/Default._\
Kwa mfano, taarifa kuhusu mtumiaji anayeitwa _mark_ huhifadhiwa kwenye _/var/db/dslocal/nodes/Default/users/mark.plist_, na taarifa kuhusu group _admin_ iko kwenye _/var/db/dslocal/nodes/Default/groups/admin.plist_.

Mbali na kutumia edges za HasSession na AdminTo, **MacHound huongeza edges tatu mpya** kwenye Bloodhound database:<sup>[[2]](#references)</sup>

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
Maelezo zaidi katika [https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/)<sup>[[3]](#references)[[6]](#references)</sup>

### Computer$ password

Pata passwords kwa kutumia:
```bash
bifrost --action askhash --username [name] --password [password] --domain [domain]
```
Inawezekana kufikia password ya **`Computer$`** ndani ya System keychain.

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

Keychain ina uwezekano mkubwa wa kuwa na taarifa nyeti ambazo, zikifikwa bila kutengeneza prompt, zinaweza kusaidia kuendeleza zoezi la red team:


{{#ref}}
macos-keychain.md
{{#endref}}

## Huduma za Nje

MacOS Red Teaming ni tofauti na Windows Red Teaming ya kawaida kwa sababu kwa kawaida **MacOS imeunganishwa moja kwa moja na platforms kadhaa za nje**. Configuration ya kawaida ya MacOS ni kufikia computer kwa kutumia **credentials zilizosawazishwa za OneLogin, na kufikia huduma kadhaa za nje** (kama github, aws...) kupitia OneLogin.

## Mbinu Mbalimbali za Red Team

### Safari

Faili inapopakuliwa katika Safari, ikiwa ni faili "salama", **itafunguliwa automatically**. Kwa mfano, ukifanya **download ya zip**, itafunguliwa automatically:<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (226).png" alt=""><figcaption></figcaption></figure>

## Marejeleo

- [1] [Gone Apple Pickin': Red Teaming MacOS Environments in 2021 - Cedric Owens (DEF CON 29)](https://www.youtube.com/watch?v=IiMladUbL6E)
- [2] [Introducing MacHound: A Solution to macOS Active Directory Based Attacks](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)
- [3] [its-a-feature - Domain Enumeration Commands (dscl / net / ldapsearch equivalents)](https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0)
- [4] [Come to the Dark Side, We Have Apples: Turning macOS Management Evil](https://www.youtube.com/watch?v=pOQOh07eMxY)
- [5] [OBTS v3.0: "An Attackers Perspective on Jamf Configurations" - Luke Roberts / Calum Hall](https://www.youtube.com/watch?v=ju1IYWUv4ZA)
- [6] [Active Directory Discovery with a Mac - its-a-feature](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/)


{{#include ../../banners/hacktricks-training.md}}
