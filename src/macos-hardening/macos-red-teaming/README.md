# macOS Red Teaming

{{#include ../../banners/hacktricks-training.md}}


## MDMs का दुरुपयोग

- JAMF Pro: `jamf checkJSSConnection`
- Kandji

यदि आप management platform तक पहुंचने के लिए **admin credentials को compromise** कर लेते हैं, तो आप **संभावित रूप से सभी computers को compromise** कर सकते हैं, क्योंकि आप machines में अपना malware वितरित कर सकते हैं।

MacOS environments में red teaming के लिए यह समझना अत्यधिक recommended है कि MDMs कैसे काम करते हैं:


{{#ref}}
macos-mdm/
{{#endref}}

### MDM को C2 के रूप में उपयोग करना

एक MDM के पास profiles को install, query या remove करने, applications install करने, local admin accounts बनाने, firmware password set करने और FileVault key बदलने की permission होगी...

अपना MDM चलाने के लिए आपको **अपने CSR को किसी vendor से signed करवाना होगा**, जिसे आप [**https://mdmcert.download/**](https://mdmcert.download/) से प्राप्त करने का प्रयास कर सकते हैं। Apple devices के लिए अपना MDM चलाने हेतु आप [**MicroMDM**](https://github.com/micromdm/micromdm) का उपयोग कर सकते हैं।

हालांकि, किसी enrolled device में application install करने के लिए उसे अभी भी developer account से signed होना आवश्यक है... लेकिन MDM enrolment के दौरान **device MDM का SSL cert एक trusted CA के रूप में जोड़ देता है**, इसलिए अब आप किसी भी चीज़ को sign कर सकते हैं।<sup>[4]</sup>

Device को MDM में enrol करने के लिए आपको root के रूप में एक **`mobileconfig`** file install करनी होगी, जिसे **pkg** file के माध्यम से deliver किया जा सकता है (आप इसे zip में compress कर सकते हैं और Safari से download किए जाने पर यह decompress हो जाएगी)।

**Mythic agent Orthrus** इस technique का उपयोग करता है।

### JAMF PRO का दुरुपयोग

JAMF **custom scripts** (sysadmin द्वारा विकसित scripts), **native payloads** (local account creation, EFI password set करना, file/process monitoring...) और **MDM** (device configurations, device certificates...) चला सकता है।<sup>[5]</sup>

#### JAMF self-enrolment

`https://<company-name>.jamfcloud.com/enroll/` जैसे page पर जाकर देखें कि क्या उन्होंने **self-enrolment enabled** किया है। यदि enabled है, तो यह **access करने के लिए credentials मांग सकता है**।

Password spraying attack करने के लिए आप [**JamfSniper.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfSniper.py) script का उपयोग कर सकते हैं।

इसके अलावा, उचित credentials मिलने के बाद आप निम्न form के माध्यम से अन्य usernames को brute-force कर सकते हैं:

![Abusing JAMF PRO - JAMF self-enrolment: Moreover, after finding proper credentials you could be able to brute-force other usernames with the next form](<../../images/image (107).png>)

#### JAMF device Authentication

<figure><img src="../../images/image (167).png" alt=""><figcaption></figcaption></figure>

**`jamf`** binary में keychain खोलने के लिए secret मौजूद था, जो discovery के समय **सभी के बीच shared** था और यह था: **`jk23ucnq91jfu9aj`**।<sup>[5]</sup>\
इसके अलावा, jamf **`/Library/LaunchAgents/com.jamf.management.agent.plist`** में **LaunchDaemon** के रूप में **persist** करता है।

#### JAMF Device Takeover

**JSS** (Jamf Software Server) का **URL**, जिसे **`jamf`** उपयोग करेगा, **`/Library/Preferences/com.jamfsoftware.jamf.plist`** में स्थित है।\
यह file मूल रूप से URL रखती है:
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
इसलिए, एक attacker ऐसा malicious package (`pkg`) drop कर सकता है जो install होने पर **इस file को overwrite कर दे** और **Typhon agent से Mythic C2 listener का URL सेट कर दे**, जिससे अब JAMF को C2 के रूप में abuse किया जा सके।
```bash
# After changing the URL you could wait for it to be reloaded or execute:
sudo jamf policy -id 0

# TODO: There is an ID, maybe it's possible to have the real jamf connection and another one to the C2
```
#### JAMF Impersonation

किसी device और JMF के बीच **communication को impersonate** करने के लिए आपको चाहिए:

- device का **UUID**: `ioreg -d2 -c IOPlatformExpertDevice | awk -F" '/IOPlatformUUID/{print $(NF-1)}'`
- `/Library/Application\ Support/Jamf/JAMF.keychain` से **JAMF keychain**, जिसमें device certificate होता है

इस जानकारी के साथ, **stolen** Hardware **UUID** वाली और **SIP disabled** **VM create करें**, **JAMF keychain drop करें**, Jamf **agent को hook करें** और उसकी information चुरा लें।

#### Secrets stealing

<figure><img src="../../images/image (1025).png" alt=""><figcaption><p>a</p></figcaption></figure>

आप `/Library/Application Support/Jamf/tmp/` location को **custom scripts** के लिए भी monitor कर सकते हैं, जिन्हें admins Jamf के ज़रिए execute करना चाह सकते हैं, क्योंकि वे **यहाँ place, execute और remove** की जाती हैं। इन scripts में **credentials हो सकते हैं**।

हालाँकि, **credentials** इन scripts को **parameters** के रूप में pass किए जा सकते हैं, इसलिए आपको `ps aux | grep -i jamf` monitor करना होगा (बिना root हुए भी)।

[**JamfExplorer.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfExplorer.py) script नए add किए गए files और नए process arguments को listen कर सकती है।

### macOS Remote Access

और MacOS के "special" **network** **protocols** के बारे में भी:


{{#ref}}
../macos-security-and-privilege-escalation/macos-protocols.md
{{#endref}}

## Active Directory

कुछ अवसरों पर आपको पता चलेगा कि **MacOS computer किसी AD से connected है**। इस scenario में आपको active directory को उसी तरह **enumerate** करने का प्रयास करना चाहिए, जैसा आप सामान्यतः करते हैं। निम्नलिखित pages में कुछ **help** प्राप्त करें:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}


{{#ref}}
../../windows-hardening/active-directory-methodology/
{{#endref}}


{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/
{{#endref}}

कुछ **local MacOS tools**, जो आपकी मदद कर सकते हैं, `dscl` हैं:
```bash
dscl "/Active Directory/[Domain]/All Domains" ls /
```
MacOS के लिए कुछ tools भी तैयार किए गए हैं, जो AD को automatically enumerate करने और Kerberos के साथ काम करने में सहायता करते हैं:

- [**Machound**](https://github.com/XMCyber/MacHound): MacHound, BloodHound auditing tool का एक extension है, जो MacOS hosts पर Active Directory relationships को collect और ingest करने की सुविधा देता है।<sup>[2]</sup>
- [**Bifrost**](https://github.com/its-a-feature/bifrost): Bifrost एक Objective-C project है, जिसे macOS पर Heimdal krb5 APIs के साथ interact करने के लिए बनाया गया है। इस project का लक्ष्य target पर किसी अन्य framework या packages की आवश्यकता के बिना native APIs का उपयोग करके macOS devices पर Kerberos से संबंधित बेहतर security testing सक्षम करना है।
- [**Orchard**](https://github.com/its-a-feature/Orchard): Active Directory enumeration करने के लिए JavaScript for Automation (JXA) tool।

### Domain Information
```bash
echo show com.apple.opendirectoryd.ActiveDirectory | scutil
```
### उपयोगकर्ता

MacOS users के तीन प्रकार हैं:

- **Local Users** — Local OpenDirectory service द्वारा managed, ये किसी भी तरह Active Directory से connected नहीं होते।
- **Network Users** — Volatile Active Directory users, जिन्हें authenticate होने के लिए DC server से connection की आवश्यकता होती है।
- **Mobile Users** — Active Directory users, जिनके credentials और files का local backup होता है।

Users और groups की local information _/var/db/dslocal/nodes/Default._ folder में stored होती है।\
उदाहरण के लिए, _mark_ नामक user की information _/var/db/dslocal/nodes/Default/users/mark.plist_ में और _admin_ group की information _/var/db/dslocal/nodes/Default/groups/admin.plist_ में stored होती है।

HasSession और AdminTo edges के अतिरिक्त, **MacHound Bloodhound database में तीन नए edges जोड़ता है**:<sup>[2]</sup>

- **CanSSH** - host पर SSH करने की अनुमति वाली entity
- **CanVNC** - host पर VNC करने की अनुमति वाली entity
- **CanAE** - host पर AppleEvent scripts execute करने की अनुमति वाली entity
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
अधिक जानकारी [https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/)

### Computer$ password

इसका उपयोग करके passwords प्राप्त करें:
```bash
bifrost --action askhash --username [name] --password [password] --domain [domain]
```
**`Computer$`** password को System keychain के अंदर access करना संभव है।

### Over-Pass-The-Hash

किसी specific user और service के लिए TGT प्राप्त करें:
```bash
bifrost --action asktgt --username [user] --domain [domain.com] \
--hash [hash] --enctype [enctype] --keytab [/path/to/keytab]
```
TGT gather हो जाने के बाद, इसे current session में inject करना संभव है:
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
प्राप्त किए गए service tickets के साथ अन्य कंप्यूटरों में shares तक पहुंचने का प्रयास करना संभव है:
```bash
smbutil view //computer.fqdn
mount -t smbfs //server/folder /local/mount/point
```
## Keychain तक पहुंच

Keychain में अत्यधिक संभावना है कि संवेदनशील जानकारी मौजूद हो, जिसे बिना prompt उत्पन्न किए access करने पर red team exercise को आगे बढ़ाने में मदद मिल सकती है:


{{#ref}}
macos-keychain.md
{{#endref}}

## External Services

MacOS Red Teaming नियमित Windows Red Teaming से अलग है, क्योंकि आमतौर पर **MacOS कई external platforms के साथ सीधे integrated होता है**। MacOS का एक सामान्य configuration कंप्यूटर तक पहुंचने के लिए **OneLogin synchronised credentials का उपयोग करना और OneLogin के माध्यम से कई external services** (जैसे github, aws...) को access करना है।

## Misc Red Team techniques

### Safari

जब Safari में कोई file download की जाती है और वह एक "safe" file होती है, तो वह **automatically open हो जाती है**। उदाहरण के लिए, यदि आप **एक zip download करते हैं**, तो वह automatically decompressed हो जाएगी:

<figure><img src="../../images/image (226).png" alt=""><figcaption></figcaption></figure>

## References

- [1] [Gone Apple Pickin': Red Teaming MacOS Environments in 2021 - Cedric Owens (DEF CON 29)](https://www.youtube.com/watch?v=IiMladUbL6E)
- [2] [Introducing MacHound: A Solution to macOS Active Directory Based Attacks](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)
- [3] [its-a-feature - Domain Enumeration Commands (dscl / net / ldapsearch equivalents)](https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0)
- [4] [Come to the Dark Side, We Have Apples: Turning macOS Management Evil](https://www.youtube.com/watch?v=pOQOh07eMxY)
- [5] [OBTS v3.0: "An Attackers Perspective on Jamf Configurations" - Luke Roberts / Calum Hall](https://www.youtube.com/watch?v=ju1IYWUv4ZA)


{{#include ../../banners/hacktricks-training.md}}
