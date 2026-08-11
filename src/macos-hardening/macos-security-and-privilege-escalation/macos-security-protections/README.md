# macOS Security Protections

{{#include ../../../banners/hacktricks-training.md}}

## Gatekeeper

Gatekeeper का उपयोग आमतौर पर **Quarantine + Gatekeeper + XProtect** के संयोजन के लिए किया जाता है, जो macOS के 3 security modules हैं और **users को downloaded संभावित रूप से malicious software execute करने से रोकने** का प्रयास करते हैं।

अधिक जानकारी:


{{#ref}}
macos-gatekeeper.md
{{#endref}}

## Process Limitations

### MACF

### SIP - System Integrity Protection


{{#ref}}
macos-sip.md
{{#endref}}

### Sandbox

MacOS Sandbox, sandbox के अंदर चलने वाली **applications को उन allowed actions तक सीमित करता है**, जो app के साथ चल रहे **Sandbox profile में specified** हैं। इससे यह सुनिश्चित करने में मदद मिलती है कि **application केवल expected resources तक ही access करेगी**।


{{#ref}}
macos-sandbox/
{{#endref}}

### TCC - **Transparency, Consent, and Control**

**TCC (Transparency, Consent, and Control)** एक security framework है। इसे applications की **permissions manage करने** के लिए design किया गया है, विशेष रूप से sensitive features तक उनकी access को regulate करने के लिए। इसमें **location services, contacts, photos, microphone, camera, accessibility, और full disk access** जैसी चीजें शामिल हैं। TCC यह सुनिश्चित करता है कि apps इन features तक access केवल explicit user consent प्राप्त करने के बाद ही कर सकें, जिससे personal data की privacy और control मजबूत होता है।


{{#ref}}
macos-tcc/
{{#endref}}

### Launch/Environment Constraints & Trust Cache

macOS में launch constraints एक security feature हैं, जो **कौन process launch कर सकता है**, **कैसे**, और **कहां से**—इन बातों को define करके **process initiation को regulate** करते हैं। macOS Ventura में introduced, ये **trust cache** के अंदर system binaries को constraint categories में categorize करते हैं। प्रत्येक executable binary के **launch** के लिए **self**, **parent**, और **responsible** constraints सहित कुछ **rules** निर्धारित होते हैं। macOS Sonoma में third-party apps तक **Environment Constraints** के रूप में extended, ये features process launching conditions को govern करके potential system exploitations को mitigate करने में मदद करते हैं।


{{#ref}}
macos-launch-environment-constraints.md
{{#endref}}

## MRT - Malware Removal Tool

Malware Removal Tool (MRT), macOS के security infrastructure का एक अन्य हिस्सा है। जैसा कि इसके नाम से पता चलता है, MRT का मुख्य function **infected systems से known malware को remove करना** है।

एक बार जब Mac पर malware detect हो जाता है (चाहे XProtect द्वारा या किसी अन्य माध्यम से), MRT का उपयोग **malware को automatically remove करने** के लिए किया जा सकता है। MRT background में silently operate करता है और आमतौर पर system update होने पर या नई malware definition download होने पर run होता है (ऐसा लगता है कि MRT को malware detect करने के लिए आवश्यक rules binary के अंदर हैं)।

हालांकि XProtect और MRT दोनों macOS के security measures का हिस्सा हैं, लेकिन इनके functions अलग-अलग हैं:

- **XProtect** एक preventative tool है। यह **files के download होते समय उन्हें check करता है** (कुछ applications के माध्यम से), और यदि यह किसी known type के malware को detect करता है, तो यह **file को open होने से रोक देता है**, जिससे malware को शुरुआत में ही आपके system को infect करने से रोका जा सकता है।
- दूसरी ओर, **MRT** एक **reactive tool** है। यह system पर malware detect होने के बाद operate करता है और इसका उद्देश्य offending software को remove करके system को clean करना है।

MRT application **`/Library/Apple/System/Library/CoreServices/MRT.app`** में स्थित है।

## Background Tasks Management

**macOS** अब हर बार **alert** करता है, जब कोई tool **code execution को persist करने के लिए किसी well known technique** (जैसे Login Items, Daemons...) का उपयोग करता है, ताकि user को बेहतर पता हो कि **कौन सा software persist कर रहा है**।<sup>[[3]](#references)</sup>

<figure><img src="../../../images/image (1183).png" alt=""><figcaption></figcaption></figure>

यह `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/backgroundtaskmanagementd` में स्थित एक **daemon** और `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Support/BackgroundTaskManagementAgent.app` में स्थित **agent** के साथ run होता है।<sup>[[1]](#references)</sup>

**`backgroundtaskmanagementd`** को यह पता चलता है कि कोई चीज persistent folder में install हुई है, क्योंकि यह **FSEvents प्राप्त करता है** और उनके लिए कुछ **handlers create करता है**।<sup>[[1]](#references)</sup>

इसके अलावा, एक plist file है जिसमें **well known applications** शामिल हैं, जो अक्सर persist करती हैं। इसे Apple द्वारा maintain किया जाता है और यह यहां स्थित है: `/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/attributions.plist`<sup>[[3]](#references)</sup>
```json
[...]
"us.zoom.ZoomDaemon" => {
"AssociatedBundleIdentifiers" => [
0 => "us.zoom.xos"
]
"Attribution" => "Zoom"
"Program" => "/Library/PrivilegedHelperTools/us.zoom.ZoomDaemon"
"ProgramArguments" => [
0 => "/Library/PrivilegedHelperTools/us.zoom.ZoomDaemon"
]
"TeamIdentifier" => "BJ4HAAB9B3"
}
[...]
```
### Enumeration

Apple cli tool का उपयोग करके चल रहे **सभी** configured background items को **enumerate** करना संभव है:<sup>[[3]](#references)</sup>
```bash
# The tool will always ask for the users password
sfltool dumpbtm
```
इसके अलावा, [**DumpBTM**](https://github.com/objective-see/DumpBTM) के साथ इस जानकारी को सूचीबद्ध करना भी संभव है।<sup>[[2]](#references)</sup>
```bash
# You need to grant the Terminal Full Disk Access for this to work
chmod +x dumpBTM
xattr -rc dumpBTM # Remove quarantine attr
./dumpBTM
```
यह जानकारी **`/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v4.btm`** में store की जा रही है और Terminal को FDA की आवश्यकता होती है।<sup>[[2]](#references)</sup>

### BTM के साथ छेड़छाड़

जब कोई नई persistence मिलती है, तो **`ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD`** प्रकार का एक event उत्पन्न होता है। इसलिए, इस **event** को भेजे जाने से रोकने या **agent को user को alert करने से रोकने** का कोई भी तरीका attacker को BTM को _**bypass**_ करने में मदद करेगा।<sup>[[1]](#references)</sup>

- **Database reset करना**: निम्न command चलाने से database reset हो जाता है (जिसे इसे शुरुआत से फिर से build करना चाहिए)। हालांकि, ऐसा करने के बाद, system reboot होने तक कोई नया persistence alert दिखाई नहीं देता।<sup>[[1]](#references)</sup>
- **root** आवश्यक है।
```bash
# Reset the database
sfltool resettbtm
```
- **Agent को रोकना**: Agent को stop signal भेजना संभव है, ताकि नई detections मिलने पर यह **user को alert न करे**।<sup>[[1]](#references)</sup>
```bash
# Get PID
pgrep BackgroundTaskManagementAgent
1011

# Stop it
kill -SIGSTOP 1011

# Check it's stopped (a T means it's stopped)
ps -o state 1011
T
```
- **Bug**: यदि **persistence बनाने वाला process तुरंत बाद exit हो जाता है**, तो daemon उसके बारे में **information प्राप्त करने** का प्रयास करता है, **विफल रहता है**, और यह दर्शाने वाला **event भेज नहीं पाता** कि नया item persist हो रहा है।<sup>[[1]](#references)</sup>

## References

- [1] [OBTS v6.0: "macOS के Background Task Management को समझना (& Bypass करना)" - Patrick Wardle & Chris Lopez](https://youtu.be/9hjUmT031tc?t=26481)
- [2] [नया (Developer) Tool: "DumpBTM" - Patrick Wardle (Patreon)](https://www.patreon.com/posts/new-developer-77420730?l=fr)
- [3] [Mac पर login items और background tasks manage करें - Apple Platform Deployment](https://support.apple.com/en-gb/guide/deployment/depdca572563/web)
{{#include ../../../banners/hacktricks-training.md}}
