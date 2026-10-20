# macOS Red Teaming

{{#include ../../banners/hacktricks-training.md}}


## MDMs का दुरुपयोग

- JAMF Pro: `jamf checkJSSConnection`
- Kandji

अगर आप management platform तक पहुँचने के लिए **admin credentials से समझौता करने** में सफल होते हैं, तो आप अपनी malware मशीनों पर वितरित करके **संभावित रूप से सभी कंप्यूटरों से समझौता कर सकते हैं**।

MacOS environments में Red Teaming के लिए, MDMs कैसे काम करते हैं इसकी कुछ समझ होना अत्यधिक अनुशंसित है:


{{#ref}}
macos-mdm/
{{#endref}}

### MDM को C2 के रूप में उपयोग करना

MDM को profiles install, query या remove करने, applications install करने, local admin accounts बनाने, firmware password सेट करने, FileVault key बदलने की अनुमति होगी...

अपना MDM चलाने के लिए आपको **अपने CSR पर किसी vendor के हस्ताक्षर करवाने होंगे**। इसके लिए आप [**https://mdmcert.download/**](https://mdmcert.download/) आज़मा सकते हैं। Apple devices के लिए अपना MDM चलाने हेतु आप [**MicroMDM**](https://github.com/micromdm/micromdm) का उपयोग कर सकते हैं।

MDM enrollment से management server का TLS certificate अपने-आप trusted CA नहीं बन जाता और न ही app-signing identity मिलती है। यदि server private CA का उपयोग करता है, तो उसके root और intermediate certificates को enrollment profile या अलग trust profile में देना होगा। MDM authentication के लिए इस्तेमाल होने वाली client identity एक अलग certificate होती है।<sup>[[7]](#references)</sup>

डाउनलोड की गई MDM enrollment profile (`.mobileconfig`) को खोलकर **System Settings → General → Device Management** में approve करना होगा। इसे root-installed `.pkg` में रखना या Safari से खोली गई ZIP में रखना, मौजूदा Mac को चुपचाप enroll नहीं करता। देखें [configuration profile behavior](../macos-auto-start-locations.md#configuration-profiles-mobileconfig)।<sup>[[8]](#references)</sup>

Setup Assistant के दौरान Automated Device Enrollment एक अलग प्रक्रिया है। इसकी अलग prerequisites के लिए देखें [rogue enrollment of another organization's device](macos-mdm/enrolling-devices-in-other-organisations.md)।<sup>[[9]](#references)</sup>

**Mythic agent Orthrus** इस technique का उपयोग करता है।

### नियंत्रित MDM के ज़रिए package deploy करना

**macOS 26 या उसके बाद के संस्करण पर चल रहे supervised Mac** पर, MDM service का नियंत्रण system scope में `com.apple.configuration.package` declaration की अनुमति देता है।<sup>[[10]](#references)</sup> Package पर ऐसा signature होना चाहिए जिसे device verify कर सके, लेकिन इसके app को अलग Developer ID signature की आवश्यकता नहीं होती: Gatekeeper device management के ज़रिए install किए गए apps की जाँच नहीं करता।<sup>[[11]](#references)</sup> केवल trusted server TLS certificate होने से operator को उस package signature के लिए ज़रूरी private key या signing usage नहीं मिलता।<sup>[[11]](#references)[[12]](#references)</sup>

हस्ताक्षरित test package बनाएँ, उसका digest निकालें और package तथा `ManifestURL` plist—दोनों को HTTPS पर publish करें। Manifest में URL और SHA-256 वाला एक `software-package` asset, साथ ही एक unique `bundle-identifier` और `bundle-version` होना चाहिए।<sup>[[11]](#references)</sup> फिर उस manifest URL के साथ package declaration भेजें और `InstallBehavior.Install` को `Required` पर सेट करें; installation या errors की जाँच के लिए `package.list` status item देखें।<sup>[[10]](#references)[[11]](#references)</sup>

```bash
pkgbuild --component ./Test.app --install-location /Applications --sign "Package Signing Certificate" ./Test.pkg
shasum -a 256 ./Test.pkg
```

MDM service के माध्यम से सबमिट की गई न्यूनतम आवश्यक-इंस्टॉल घोषणा इस तरह दिखती है (URL और दोनों UUID बदलें)।<sup>[[10]](#references)</sup>

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

### JAMF PRO का दुरुपयोग

JAMF **custom scripts** (sysadmin द्वारा विकसित scripts), **native payloads** (local account बनाना, EFI password सेट करना, file/process monitoring...) और **MDM** (device configurations, device certificates...) चला सकता है।<sup>[[5]](#references)</sup>

#### JAMF self-enrolment

यह देखने के लिए कि **self-enrolment enabled** है या नहीं, `https://<company-name>.jamfcloud.com/enroll/` जैसे page पर जाएँ। अगर enabled है, तो **access के लिए credentials माँगे जा सकते हैं**।

Password spraying attack करने के लिए [**JamfSniper.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfSniper.py) script का उपयोग किया जा सकता है।

इसके अलावा, सही credentials मिलने के बाद, अगले form से दूसरे usernames को brute-force किया जा सकता है:

![JAMF PRO का दुरुपयोग - JAMF self-enrolment: इसके अलावा, सही credentials मिलने के बाद, अगले form से दूसरे usernames को brute-force किया जा सकता है](<../../images/image (107).png>)

#### JAMF device Authentication

<figure><img src="../../images/image (167).png" alt=""><figcaption></figcaption></figure>

**`jamf`** binary में keychain खोलने का secret था, जो discovery के समय **सबके साथ साझा** था। वह secret था: **`jk23ucnq91jfu9aj`**।<sup>[[5]](#references)</sup>\
इसके अलावा, jamf **`/Library/LaunchAgents/com.jamf.management.agent.plist`** में **LaunchDaemon** के रूप में persist करता है।

#### JAMF Device Takeover

**JSS** (Jamf Software Server) का **URL**, जिसका उपयोग **`jamf`** करेगा, **`/Library/Preferences/com.jamfsoftware.jamf.plist`** में मौजूद है।\
इस file में मूल रूप से URL होता है:

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

इसलिए, attacker एक malicious package (`pkg`) छोड़ सकता है, जो इंस्टॉल होने पर **इस फ़ाइल को overwrite करता है** और **Typhon agent से Mythic C2 listener का URL सेट करता है**, ताकि JAMF को C2 के रूप में abuse किया जा सके।

```bash
# After changing the URL you could wait for it to be reloaded or execute:
sudo jamf policy -id 0

# TODO: There is an ID, maybe it's possible to have the real jamf connection and another one to the C2
```

#### JAMF Impersonation

किसी device और JMF के बीच **communication की नकल करने** के लिए आपको चाहिए:

- device का **UUID**: `ioreg -d2 -c IOPlatformExpertDevice | awk -F" '/IOPlatformUUID/{print $(NF-1)}'`
- `/Library/Application\ Support/Jamf/JAMF.keychain` से **JAMF keychain**, जिसमें device certificate होता है

इस जानकारी का उपयोग करके, **चुराए गए** Hardware **UUID** और **disabled SIP** के साथ एक **VM बनाएँ**, **JAMF keychain डालें**, Jamf **agent को hook करें** और उसकी जानकारी चुरा लें।

#### Secrets चुराना

<figure><img src="../../images/image (1025).png" alt=""><figcaption><p>a</p></figcaption></figure>

आप `/Library/Application Support/Jamf/tmp/` location पर भी नज़र रख सकते हैं। Admins जिन **custom scripts** को Jamf के माध्यम से चलाना चाहते हैं, वे यहाँ **रखी जाती हैं, चलाई जाती हैं और हटा दी जाती हैं**। इन scripts में **credentials हो सकते हैं**।

हालाँकि, इन scripts को **parameters** के रूप में **credentials** दिए जा सकते हैं, इसलिए आपको `ps aux | grep -i jamf` पर नज़र रखनी होगी (इसके लिए root होना भी ज़रूरी नहीं है)।

[**JamfExplorer.py**](https://github.com/WithSecureLabs/Jamf-Attack-Toolkit/blob/master/JamfExplorer.py) script नए जोड़े गए files और नए process arguments को सुन सकती है।

### macOS Remote Access

और **MacOS** के "special" **network** **protocols** के बारे में भी:


{{#ref}}
../macos-security-and-privilege-escalation/macos-protocols.md
{{#endref}}

## Active Directory

कुछ मामलों में आपको पता चलेगा कि **MacOS computer किसी AD से जुड़ा है**। इस स्थिति में, Active Directory को उसी तरह **enumerate** करने की कोशिश करें, जैसा आप आम तौर पर करते हैं। नीचे दिए गए pages पर कुछ **मदद** पाएँ:


{{#ref}}
../../network-services-pentesting/pentesting-ldap.md
{{#endref}}


{{#ref}}
../../windows-hardening/active-directory-methodology/
{{#endref}}


{{#ref}}
../../network-services-pentesting/pentesting-kerberos-88/
{{#endref}}

कुछ **local MacOS tools** जो आपकी मदद कर सकते हैं, उनमें `dscl` भी शामिल है:

```bash
dscl "/Active Directory/[Domain]/All Domains" ls /
```

MacOS के लिए कुछ ऐसे tools भी तैयार किए गए हैं जो AD को अपने आप enumerate करने और kerberos के साथ काम करने की सुविधा देते हैं:

- [**Machound**](https://github.com/XMCyber/MacHound): MacHound, Bloodhound auditing tool का एक extension है, जो MacOS hosts पर Active Directory relationships को collect और ingest करने की सुविधा देता है।<sup>[[2]](#references)</sup>
- [**Bifrost**](https://github.com/its-a-feature/bifrost): Bifrost, macOS पर Heimdal krb5 APIs के साथ interact करने के लिए बनाया गया एक Objective-C project है। इस project का उद्देश्य target पर किसी अन्य framework या package की आवश्यकता के बिना, native APIs का उपयोग करके macOS devices पर Kerberos की बेहतर security testing करना है।
- [**Orchard**](https://github.com/its-a-feature/Orchard): Active Directory enumeration करने के लिए JavaScript for Automation (JXA) tool।

### Domain Information

```bash
echo show com.apple.opendirectoryd.ActiveDirectory | scutil
```

### Users

MacOS users के तीन प्रकार हैं:

- **Local Users** — इन्हें local OpenDirectory service द्वारा manage किया जाता है; ये किसी भी तरह Active Directory से जुड़े नहीं होते।
- **Network Users** — ये अस्थायी Active Directory users हैं, जिन्हें authenticate करने के लिए DC server से connection की आवश्यकता होती है।
- **Mobile Users** — ये Active Directory users हैं, जिनके credentials और files का local backup होता है।

Users और groups की local जानकारी _/var/db/dslocal/nodes/Default._ folder में stored होती है।\
उदाहरण के लिए, _mark_ नाम के user की जानकारी _/var/db/dslocal/nodes/Default/users/mark.plist_ में stored होती है और _admin_ group की जानकारी _/var/db/dslocal/nodes/Default/groups/admin.plist_ में होती है।

HasSession और AdminTo edges का उपयोग करने के अलावा, **MacHound Bloodhound database में तीन नए edges जोड़ता है**:<sup>[[2]](#references)</sup>

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

[https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/) पर अधिक जानकारी <sup>[[3]](#references)[[6]](#references)</sup>

### Computer$ पासवर्ड

इसका उपयोग करके पासवर्ड प्राप्त करें:

```bash
bifrost --action askhash --username [name] --password [password] --domain [domain]
```

System keychain के अंदर **`Computer$`** password को access करना संभव है।

### Over-Pass-The-Hash

किसी विशिष्ट user और service के लिए TGT प्राप्त करें:

```bash
bifrost --action asktgt --username [user] --domain [domain.com] \
       --hash [hash] --enctype [enctype] --keytab [/path/to/keytab]
```

TGT प्राप्त होने के बाद, इसे निम्न कमांड से current session में inject किया जा सकता है:

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

प्राप्त service tickets के साथ दूसरे कंप्यूटरों पर shares तक पहुँचने की कोशिश करना संभव है:

```bash
smbutil view //computer.fqdn
mount -t smbfs //server/folder /local/mount/point
```

## Keychain तक पहुंचना

Keychain में बहुत संभव है कि संवेदनशील जानकारी हो, जिसे बिना prompt जनरेट किए access करने पर red team exercise को आगे बढ़ाने में मदद मिल सकती है:


{{#ref}}
macos-keychain.md
{{#endref}}

## External Services

MacOS Red Teaming, नियमित Windows Red Teaming से अलग है, क्योंकि आम तौर पर **MacOS सीधे कई external platforms के साथ integrated होता है**। MacOS का एक आम configuration है कि **OneLogin synchronised credentials का उपयोग करके computer access किया जाए, और OneLogin के ज़रिए कई external services** (जैसे github, aws...) access की जाएं।

## Misc Red Team techniques

### Safari

Safari में कोई file download होने पर, अगर वह "safe" file है, तो वह **automatically खुल जाती है**। उदाहरण के लिए, अगर आप **zip download करते हैं**, तो वह अपने आप decompress हो जाती है:<sup>[[1]](#references)</sup>

<figure><img src="../../images/image (226).png" alt=""><figcaption></figcaption></figure>



## References

- [1] [Gone Apple Pickin': 2021 में MacOS वातावरणों की Red Teaming - Cedric Owens (DEF CON 29)](https://www.youtube.com/watch?v=IiMladUbL6E)
- [2] [MacHound का परिचय: macOS Active Directory आधारित हमलों के लिए एक समाधान](https://medium.com/xm-cyber/introducing-machound-a-solution-to-macos-active-directory-based-attacks-2a425f0a22b6)
- [3] [its-a-feature - Domain Enumeration Commands (dscl / net / ldapsearch के समकक्ष)](https://gist.github.com/its-a-feature/1a34f597fb30985a2742bb16116e74e0)
- [4] [Dark Side में आइए, हमारे पास Apples हैं: macOS Management को दुर्भावनापूर्ण बनाना](https://www.youtube.com/watch?v=pOQOh07eMxY)
- [5] [OBTS v3.0: "Jamf Configurations पर हमलावर का दृष्टिकोण" - Luke Roberts / Calum Hall](https://www.youtube.com/watch?v=ju1IYWUv4ZA)
- [6] [Mac से Active Directory की खोज - its-a-feature](https://its-a-feature.github.io/posts/2018/01/Active-Directory-Discovery-with-a-Mac/)
- [7] [Apple — device management services और devices के लिए certificates का प्रबंधन](https://developer.apple.com/documentation/devicemanagement/managing-certificates-for-device-management-services-and-devices)
- [8] [Apple — Mac पर configuration profiles का उपयोग](https://support.apple.com/en-gb/guide/mac-help/mh35561/mac)
- [9] [Apple — device management enrollment profiles deploy करना](https://developer.apple.com/documentation/devicemanagement/deploying-device-management-enrollment-profiles)
- [10] [Apple — Package declaration](https://developer.apple.com/documentation/devicemanagement/package)
- [11] [Apple — packages install करना](https://developer.apple.com/documentation/devicemanagement/installing-packages)
- [12] [Apple — Identities](https://developer.apple.com/documentation/security/identities)
{{#include ../../banners/hacktricks-training.md}}
