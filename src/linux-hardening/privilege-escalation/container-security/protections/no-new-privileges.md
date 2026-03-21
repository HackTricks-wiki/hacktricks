# `no_new_privs`

{{#include ../../../../banners/hacktricks-training.md}}

`no_new_privs` bir kernel sertleştirme özelliğidir ve bir işlemin `execve()` üzerinden daha fazla ayrıcalık kazanmasını engeller. Pratikte, bu bayrak ayarlandığında bir setuid binary, bir setgid binary veya Linux file capabilities içeren bir dosyanın çalıştırılması, işlemin zaten sahip olduğu ayrıcalıkların ötesinde ekstra yetki vermez. Konteynerleştirilmiş ortamlarda bu önemlidir çünkü birçok privilege-escalation zinciri, başlatıldığında ayrıcalığı değiştiren bir çalıştırılabilir dosyayı image içinde bulmaya dayanır.

Savunma açısından, `no_new_privs` namespaces, seccomp veya capability dropping yerine geçmez. Bir takviye katmanıdır. Kod yürütülmesi zaten elde edildikten sonra ortaya çıkan belirli bir sınıftaki takip yükseltmelerini engeller. Bu, image'larda yardımcı binary'ler, package-manager artifacts veya aksi takdirde kısmi compromise ile birleştiğinde tehlikeli olabilecek legacy araçlar bulunan ortamlarda özellikle değerlidir.

## İşleyiş

Bu davranışın arkasındaki kernel bayrağı `PR_SET_NO_NEW_PRIVS`'dir. Bir işlem için ayarlandığında, sonraki `execve()` çağrıları ayrıcalığı artıramaz. Önemli nokta, işlemin hala binary'leri çalıştırabilmesidir; sadece bu binary'leri kernel'in aksi takdirde onaylayacağı bir ayrıcalık sınırını aşmak için kullanamaz.

Kubernetes odaklı ortamlarda, `allowPrivilegeEscalation: false` container işlemi için bu davranışa karşılık gelir. Docker ve Podman tarzı runtime'larda eşdeğeri genellikle bir security option aracılığıyla açıkça etkinleştirilir.

## Laboratuvar

Mevcut işlem durumunu inceleyin:
```bash
grep NoNewPrivs /proc/self/status
```
Bunu, runtime'ın bayrağı etkinleştirdiği bir konteynerle karşılaştırın:
```bash
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'grep NoNewPrivs /proc/self/status'
```
Sertleştirilmiş bir iş yükünde, sonuç `NoNewPrivs: 1` göstermelidir.

## Güvenlik Etkisi

Eğer `no_new_privs` yoksa, konteyner içindeki bir foothold hâlâ setuid helper'lar veya file capabilities'a sahip ikili dosyalar aracılığıyla yükseltilebilir. Eğer etkinse, bu çalıştırma sonrası (post-exec) ayrıcalık değişiklikleri engellenir. Bu etki, uygulamanın aslında hiç ihtiyacı olmayan birçok yardımcıyı içeren geniş tabanlı imajlarda özellikle önemlidir.

## Yanlış Yapılandırmalar

En yaygın sorun, kontrolün uyumlu olduğu ortamlarda basitçe etkinleştirilmemesidir. Kubernetes'te `allowPrivilegeEscalation`'ı açık bırakmak genellikle varsayılan operasyonel hatadır. Docker ve Podman'da ilgili güvenlik seçeneğinin atlanması aynı etkiyi verir. Tekrar eden başka bir başarısızlık modu ise bir konteyner "not privileged" olduğu için exec-zamanı ayrıcalık geçişlerinin otomatik olarak alakasız olduğunu varsaymaktır.

## Kötüye Kullanım

Eğer `no_new_privs` ayarlı değilse, ilk soru imajın hâlâ ayrıcalık yükseltebilecek ikili dosyalar içerip içermediğidir:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 50
getcap -r / 2>/dev/null | head -n 50
```
İlginç sonuçlar şunlardır:

- `NoNewPrivs: 0`
- setuid yardımcıları (ör. `su`, `mount`, `passwd` veya dağıtıma özgü yönetici araçları)
- file capabilities içeren ve ağ ya da dosya sistemi ayrıcalıkları veren ikili dosyalar

Gerçek bir değerlendirmede, bu bulgular tek başlarına çalışan bir yükseltme olduğunu kanıtlamaz, ancak bir sonraki adımda test edilmesi gereken ikili dosyaları tam olarak belirler.

### Tam Örnek: In-Container Privilege Escalation Through setuid

Bu kontrol genellikle doğrudan host escape yerine **in-container privilege escalation**'ı engeller. Eğer `NoNewPrivs` `0` ise ve bir setuid helper mevcutsa, bunu açıkça test edin:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 20
/usr/bin/passwd -S root 2>/dev/null
```
Bilinen bir setuid ikili dosyası mevcut ve işlevselse, ayrıcalık geçişini koruyacak şekilde başlatmayı deneyin:
```bash
/bin/su -c id 2>/dev/null
```
Bu tek başına container'dan kaçış sağlamaz, ancak container içinde düşük ayrıcalıklı bir foothold'u container-root'a dönüştürebilir; bu da genellikle mounts, runtime sockets veya kernel-facing interfaces aracılığıyla daha sonra host escape için önkoşul olur.

## Kontroller

Bu kontrollerin amacı, exec-time privilege gain'in engellenip engellenmediğini ve image'ın, engellenmemesi durumunda önemli olabilecek helpers içerip içermediğini belirlemektir.
```bash
grep NoNewPrivs /proc/self/status      # Whether exec-time privilege gain is blocked
find / -perm -4000 -type f 2>/dev/null | head -n 50   # setuid files
getcap -r / 2>/dev/null | head -n 50   # files with Linux capabilities
```
Burada ilginç olan:

- `NoNewPrivs: 1` genellikle daha güvenli sonuçtur.
- `NoNewPrivs: 0` setuid ve file-cap tabanlı yükseltme yollarının hâlâ geçerli olduğu anlamına gelir.
- Az sayıda veya hiç setuid/file-cap ikili dosyası içeren minimal bir image, `no_new_privs` eksik olsa bile saldırganın post-exploitation seçeneklerini azaltır.

## Çalışma Zamanı Varsayılanları

| Runtime / platform | Varsayılan durum | Varsayılan davranış | Yaygın manuel zayıflatma |
| --- | --- | --- | --- |
| Docker Engine | Not enabled by default | Enabled explicitly with `--security-opt no-new-privileges=true` | bayrağın belirtilmemesi, `--privileged` |
| Podman | Not enabled by default | Enabled explicitly with `--security-opt no-new-privileges` or equivalent security configuration | seçeneğin belirtilmemesi, `--privileged` |
| Kubernetes | Controlled by workload policy | `allowPrivilegeEscalation: false` enables the effect; many workloads still leave it enabled | `allowPrivilegeEscalation: true`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Follows Kubernetes workload settings | Usually inherited from the Pod security context | same as Kubernetes row |

Bu koruma çoğunlukla runtime'ın desteğinin olmamasından değil, kimsenin bunu etkinleştirmemiş olmasından dolayı eksiktir.
