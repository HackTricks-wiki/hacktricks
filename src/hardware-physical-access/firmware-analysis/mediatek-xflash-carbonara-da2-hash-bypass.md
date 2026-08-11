# MediaTek XFlash Carbonara DA2 Hash Bypass

{{#include ../../banners/hacktricks-training.md}}

## Özet

"Carbonara", MediaTek'in XFlash download path'ini kullanarak DA1 integrity checks işlemlerini aşmasına rağmen değiştirilmiş bir Download Agent stage 2 (DA2) çalıştırır. DA1, DA2'nin beklenen SHA-256 değerini RAM'de saklar ve dallanma yapmadan önce bunu karşılaştırır. Birçok loader'da host, DA2 load address/size değerlerini tamamen kontrol eder; bu da bellekteki hash değerinin üzerine yazıp yürütmeyi rastgele payload'lara yönlendirebilen, unchecked bir memory write sağlar (DA tarafından cache invalidation işlemi yapılmış pre-OS context).<sup>[[1]](#references)[[2]](#references)</sup>

## XFlash'te trust boundary (DA1 → DA2)

- **DA1**, BootROM/Preloader tarafından imzalanır/yüklenir. Download Agent Authorization (DAA) etkin olduğunda yalnızca imzalı DA1 çalışmalıdır.
- **DA2**, USB üzerinden gönderilir. DA1 **size**, **load address** ve **SHA-256** değerlerini alır, alınan DA2'yi hash'ler ve bunu DA1 içine gömülü, RAM'e kopyalanmış bir **expected hash** ile karşılaştırır.
- **Weakness:** Patched olmayan loader'larda DA1, DA2 load address/size değerlerini sanitize etmez ve expected hash'i bellekte writable olarak bırakır; bu da host'un check işlemine müdahale etmesini sağlar.<sup>[[1]](#references)[[2]](#references)</sup>

## Carbonara flow ("two BOOT_TO" trick)

1. **İlk `BOOT_TO`:** DA1→DA2 staging flow işlemine girilir (DA1 allocation yapar, DRAM'i hazırlar ve expected-hash buffer'ını RAM'de erişilebilir duruma getirir).
2. **Hash-slot overwrite:** DA1 belleğini tarayarak saklanan DA2-expected hash'i bulan ve bunu attacker-modified DA2'nin SHA-256 değeriyle değiştiren küçük bir payload gönderilir. Bu işlem, payload'u hash'in bulunduğu konuma yerleştirmek için user-controlled load özelliğinden yararlanır.
3. **İkinci `BOOT_TO` + digest:** Patched DA2 metadata ile başka bir `BOOT_TO` tetiklenir ve modified DA2 ile eşleşen raw 32-byte digest gönderilir. DA1, alınan DA2 üzerinde SHA-256'yı yeniden hesaplar, bunu artık patched olan expected hash ile karşılaştırır ve jump işlemi başarılı olarak attacker code'a geçer.

Etkilenen loader'larda unchecked address ve size, hash slot'unun ötesinde attacker-selected bir pre-OS memory-write primitive sağlayabilir. SoC memory map'ine ve sonraki verification stage'lerine bağlı olarak bu; early-boot implant'larını, secure-boot-bypass helper'larını veya rootkit-style payload'ları destekleyebilir. DA code execution tek başına otomatik olarak persistence veya eksiksiz bir secure-boot bypass sağlamaz; ayrıca ayrı bir persistence mechanism ve uyumlu bir verification chain gerekir.<sup>[[1]](#references)[[2]](#references)</sup>

## Minimal PoC pattern (mtkclient-style)
```python
if self.xsend(self.Cmd.BOOT_TO):
payload = bytes.fromhex("a4de2200000000002000000000000000")
if self.xsend(payload) and self.status() == 0:
import hashlib
da_hash = hashlib.sha256(self.daconfig.da2).digest()
if self.xsend(da_hash):
self.status()
self.info("All good!")
```
- 16-byte `payload`, ücretli-tool workflow içinde gözlemlenen ve yayımlanmış implementation tarafından beklenen-hash buffer'ını patch etmek için kullanılan blob'u yeniden üretir. Bu, loader'a özgüdür; her SoC veya DA için taşınabilir bir hash-slot patch'i değildir.<sup>[[1]](#references)[[2]](#references)</sup>
- `sha256(...).digest()` ham byte'lar gönderir (hex değil); böylece DA1 patch'lenmiş buffer ile karşılaştırma yapar.
- Vulnerable ve eşleşen bir loader üzerinde DA2, attacker tarafından oluşturulmuş bir image olabilir ve seçilen load metadata, bellekteki yerleşimini kontrol eder. Gönderimden önce DA/SoC kombinasyonunu doğrulayın; yanlış adresler target'ın takılmasına veya zarar görmesine neden olabilir.<sup>[[3]](#references)</sup>

## Patch ortamı (hardened loader'lar)

- **Gözlemlenen mitigation**: Araştırmacılar tarafından incelenen hardened DA'ler, DA2 load address değerini `0x40000000` olarak zorlar ve host tarafından sağlanan adresi yok sayar; böylece gözlemlenen ve `0x200000` civarında bulunan DA1 hash region'ına yazılması engellenir. Her iki adresi de architectural constant değil, implementation-specific değerler olarak değerlendirin.
- **Patched DA'leri tespit etme**: mtkclient/penumbra, address-hardening'i belirten pattern'ler için DA1'i tarar; bu pattern'ler bulunursa Carbonara atlanır. Eski DA'ler writable hash slot'larını (V5 DA1'de genellikle `0x22dea4` gibi offset'ler civarında) açığa çıkarır ve exploitable olmaya devam eder.
- **V5 ve V6**: Bazı V6 (XML) loader'lar hâlâ user-supplied address değerlerini kabul eder; daha yeni V6 binary'leri genellikle fixed address'i zorlar ve downgrade edilmedikleri sürece Carbonara'ya karşı immune'dur.<sup>[[2]](#references)[[3]](#references)</sup>

## Post-Carbonara (heapb8) notu

MediaTek Carbonara'yı patch'ledi; daha yeni bir vulnerability olan **heapb8**, patched V6 loader'larındaki DA2 USB file download handler'ını hedefler ve `boot_to` hardened olsa bile code execution sağlar. Chunked file transfer'lar sırasında gerçekleşen bir heap overflow'u kötüye kullanarak DA2 control flow'unu ele geçirir. Exploit, Penumbra/mtk-payloads içinde public durumdadır ve Carbonara fix'lerinin tüm DA attack surface'ünü kapatmadığını gösterir.<sup>[[4]](#references)</sup>

## Triage ve hardening için notlar

- DA2 address/size değerlerinin unchecked olduğu ve DA1'in expected hash'i writable tuttuğu cihazlar vulnerable'dır. Daha sonraki bir Preloader/DA address bounds uygular veya hash'i immutable tutarsa Carbonara mitigate edilir.
- DAA'yı etkinleştirmek ve DA1/Preloader'ın BOOT_TO parametrelerini (bounds + DA2'nin authenticity'si) validate etmesini sağlamak primitive'i kapatır. Yalnızca hash patch'ini kapatmak, load'u bounds ile sınırlamadan bırakırsa arbitrary write riski devam eder.

## References

- [1] [Carbonara: Kimsenin servis etmediği MediaTek exploit'i](https://shomy.is-a.dev/blog/article/serving-carbonara)
- [2] [Carbonara exploit dokümantasyonu](https://shomy.is-a.dev/penumbra/Mediatek/Exploits/Carbonara)
- [3] [Penumbra Carbonara source code'u](https://github.com/shomykohai/penumbra/blob/main/core/src/exploit/carbonara.rs)
- [4] [heapb8: patched V6 Download Agent'larını exploit etme](https://blog.r0rt1z2.com/posts/exploiting-mediatek-datwo/)
{{#include ../../banners/hacktricks-training.md}}
