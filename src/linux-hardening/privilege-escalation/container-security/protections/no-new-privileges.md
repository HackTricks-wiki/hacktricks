# `no_new_privs`

{{#include ../../../../banners/hacktricks-training.md}}

`no_new_privs` çekirdek sertleştirme özelliğidir ve bir işlemin `execve()` ile daha fazla ayrıcalık kazanmasını engeller. Pratikte, bayrak bir kez ayarlandığında, bir setuid binary'sini, setgid binary'sini veya Linux file capabilities içeren bir dosyayı çalıştırmak, işlemin zaten sahip olduğu ayrıcalıkların ötesinde ek ayrıcalık vermez. Konteynerleştirilmiş ortamlarda bu önemlidir çünkü birçok privilege-escalation zinciri, başlatıldığında ayrıcalığı değiştiren bir yürütülebilir dosyayı image içinde bulmaya dayanır.

Defansif bakış açısından, `no_new_privs` namespaces, seccomp veya capability dropping'in yerine geçmez. Bu bir takviye katmanıdır. Kod çalıştırma elde edildikten sonra takip eden belirli bir sınıf yükseltmeyi engeller. Bu, imajların helper binaries, package-manager artifacts veya legacy tools içerdiği ve kısmi ele geçirme ile birleştiğinde aksi halde tehlikeli olabilecek ortamlarda özellikle değerli kılar.

## İşleyiş

Bu davranışın arkasındaki çekirdek bayrağı `PR_SET_NO_NEW_PRIVS`'tır. Bir işlem için ayarlandıktan sonra, sonraki `execve()` çağrıları ayrıcalıkları arttıramaz. Önemli detay, işlemin hâlâ binary'leri çalıştırabilmesi; sadece bu binary'leri çekirdeğin aksi halde kabul edeceği bir ayrıcalık sınırını aşmak için kullanamamasıdır.

Kubernetes-odaklı ortamlarda, `allowPrivilegeEscalation: false` container process için bu davranışa karşılık gelir. Docker ve Podman tarzı runtimelarda, eşdeğeri genellikle bir güvenlik seçeneği aracılığıyla açıkça etkinleştirilir.

## Laboratuvar

Mevcut işlem durumunu inceleyin:
```bash
grep NoNewPrivs /proc/self/status
```
Bunu, runtime'ın flag'ı etkinleştirdiği bir container ile karşılaştırın:
```bash
docker run --rm --security-opt no-new-privileges:true debian:stable-slim sh -c 'grep NoNewPrivs /proc/self/status'
```
Sertleştirilmiş bir iş yükünde, sonuç `NoNewPrivs: 1` göstermelidir.

## Güvenlik Etkisi

Eğer `no_new_privs` yoksa, konteyner içindeki bir ayak izi setuid yardımcıları veya file capabilities içeren ikili dosyalar aracılığıyla hâlâ yükseltilebilir. Eğer mevcutsa, bu post-exec ayrıcalık değişiklikleri engellenir. Etki, uygulamanın aslında hiç ihtiyaç duymadığı birçok yardımcı programla birlikte gelen geniş temel imajlarda özellikle önemlidir.

## Yanlış Yapılandırmalar

En yaygın sorun, kontrolün uyumlu olacağı ortamlarda basitçe etkinleştirilmemesidir. Kubernetes'te `allowPrivilegeEscalation`'ı etkin bırakmak sıklıkla varsayılan operasyonel hatadır. Docker ve Podman'da ilgili güvenlik seçeneğini atlamak aynı etkiye sahiptir. Tekrarlayan bir başka hata modu, bir konteynerin "not privileged" olduğu varsayılarak exec-time privilege transitions'ın otomatik olarak alakasız olduğunu düşünmektir.

## Kötüye Kullanım

Eğer `no_new_privs` ayarlı değilse, ilk soru imajın hâlâ ayrıcalıkları yükseltebilecek ikili dosyalar içerip içermediğidir:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 50
getcap -r / 2>/dev/null | head -n 50
```
İlginç bulgular şunları içerir:

- `NoNewPrivs: 0`
- setuid yardımcıları, ör. `su`, `mount`, `passwd` veya dağıtıma özgü yönetici araçları
- network veya filesystem ayrıcalıkları veren file capabilities içeren binaries

Gerçek bir değerlendirmede, bu bulgular kendi başlarına çalışan bir escalation kanıtlamaz, ancak sıradaki test edilmeye değer binaries'leri tam olarak belirler.

### Tam Örnek: In-Container Privilege Escalation Through setuid

Bu kontrol genellikle doğrudan host escape'i engellemekten ziyade **in-container privilege escalation**'ı önler. Eğer `NoNewPrivs` `0` ise ve bir setuid yardımcı mevcutsa, bunu açıkça test edin:
```bash
grep NoNewPrivs /proc/self/status
find / -perm -4000 -type f 2>/dev/null | head -n 20
/usr/bin/passwd -S root 2>/dev/null
```
Eğer bilinen bir setuid binary mevcut ve çalışır durumdaysa, ayrıcalık geçişini koruyacak şekilde başlatmayı deneyin:
```bash
/bin/su -c id 2>/dev/null
```
Bu tek başına container'dan kaçış sağlamaz, ancak container içindeki düşük ayrıcalıklı bir foothold'u container-root'a dönüştürebilir; bu da genellikle mounts, runtime sockets veya kernel-facing interfaces üzerinden sonraki host escape için bir ön koşul haline gelir.

## Kontroller

Bu kontrollerin amacı, exec-time privilege gain'in engellenip engellenmediğini ve eğer engellenmemişse imajın hala önemli olacak yardımcılar içerip içermediğini belirlemektir.
```bash
grep NoNewPrivs /proc/self/status      # Whether exec-time privilege gain is blocked
find / -perm -4000 -type f 2>/dev/null | head -n 50   # setuid files
getcap -r / 2>/dev/null | head -n 50   # files with Linux capabilities
```
What is interesting here:

- `NoNewPrivs: 1` is usually the safer result.
- `NoNewPrivs: 0` means setuid and file-cap based escalation paths remain relevant.
- A minimal image with few or no setuid/file-cap binaries gives an attacker fewer post-exploitation options even when `no_new_privs` is missing.

## Çalışma Zamanı Varsayılanları

| Runtime / platform | Varsayılan durum | Varsayılan davranış | Yaygın manuel zayıflatma |
| --- | --- | --- | --- |
| Docker Engine | Varsayılan olarak etkin değil | Açıkça `--security-opt no-new-privileges=true` ile etkinleştirilir | bayrağın belirtilmemesi, `--privileged` |
| Podman | Varsayılan olarak etkin değil | Açıkça `--security-opt no-new-privileges` veya eşdeğer bir güvenlik yapılandırması ile etkinleştirilir | seçeneğin belirtilmemesi, `--privileged` |
| Kubernetes | İş yükü politikası tarafından kontrol edilir | `allowPrivilegeEscalation: false` etkisini sağlar; birçok iş yükü hala bunu etkin bırakıyor | `allowPrivilegeEscalation: true`, `privileged: true` |
| containerd / CRI-O under Kubernetes | Kubernetes iş yükü ayarlarını takip eder | Genellikle Pod security context'ten miras alınır | Kubernetes satırı ile aynı |

This protection is often absent simply because nobody turned it on, not because the runtime lacks support for it.
{{#include ../../../../banners/hacktricks-training.md}}
