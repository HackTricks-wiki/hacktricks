# MediaTek XFlash Carbonara DA2 Hash Bypass

{{#include ../../banners/hacktricks-training.md}}

## Summary

"Carbonara", MediaTek'in XFlash download path'ini kötüye kullanarak DA1 integrity kontrollerine rağmen değiştirilmiş bir Download Agent stage 2'yi (DA2) çalıştırır. DA1, DA2'nin beklenen SHA-256 hash'ini RAM'de saklar ve dallanma gerçekleştirmeden önce karşılaştırır. Birçok loader'da host, DA2 load address/size değerlerini tamamen kontrol eder; bu da bellekteki hash'i overwrite edebilen ve execution'ı rastgele payload'lara yönlendirebilen, kontrol edilmeyen bir memory write sağlar (DA tarafından cache invalidation işlemi gerçekleştirilmiş pre-OS context).<sup>[[1]](#references)[[2]](#references)</sup>

## Trust boundary in XFlash (DA1 → DA2)

- **DA1**, BootROM/Preloader tarafından signed/loaded edilir. Download Agent Authorization (DAA) etkin olduğunda yalnızca signed DA1 çalışmalıdır.
- **DA2**, USB üzerinden gönderilir. DA1 **size**, **load address** ve **SHA-256** değerlerini alır; alınan DA2'yi hash'ler ve sonucu DA1 içine embedded edilmiş, RAM'e kopyalanan bir **expected hash** ile karşılaştırır.
- **Weakness:** Unpatched loader'larda DA1, DA2 load address/size değerlerini sanitize etmez ve expected hash'i memory'de writable olarak bırakır; bu da host'un check'i değiştirmesine olanak tanır.<sup>[[1]](#references)[[2]](#references)</sup>

## Carbonara flow ("two BOOT_TO" trick)

1. **First `BOOT_TO`:** DA1→DA2 staging flow'a girin (DA1 allocation yapar, DRAM'i hazırlar ve RAM'deki expected-hash buffer'ını açığa çıkarır).
2. **Hash-slot overwrite:** DA1 memory'sini tarayan ve stored DA2-expected hash'i attacker-modified DA2'nin SHA-256 hash'iyle overwrite eden küçük bir payload gönderin. Bu işlem, payload'ı hash'in bulunduğu yere yerleştirmek için user-controlled load özelliğinden yararlanır.
3. **Second `BOOT_TO` + digest:** Patched DA2 metadata ile başka bir `BOOT_TO` tetikleyin ve modified DA2 ile eşleşen raw 32-byte digest'i gönderin. DA1, alınan DA2 üzerinde SHA-256'yı yeniden hesaplar, sonucu artık patched olan expected hash ile karşılaştırır ve jump başarılı olarak attacker code'a gerçekleştirilir.

Load address/size attacker-controlled olduğundan, aynı primitive memory'nin herhangi bir yerine write edebilir (yalnızca hash buffer'ına değil); bu da early-boot implants, secure-boot bypass helpers veya malicious rootkits kullanımını mümkün kılar.<sup>[[1]](#references)[[2]](#references)</sup>

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
- `payload`, DA1 içindeki beklenen hash buffer'ını patch'leyen paid-tool blob'unu taklit eder.
- `sha256(...).digest()`, DA1'in patch'lenmiş buffer ile karşılaştırma yapabilmesi için hex yerine ham byte gönderir.
- DA2, attacker tarafından oluşturulmuş herhangi bir image olabilir; load address/size seçilerek, cache invalidation işlemi DA tarafından gerçekleştirilecek şekilde arbitrary memory placement sağlanabilir.<sup>[[3]](#references)</sup>

## Patch landscape (hardened loaders)

- **Mitigation**: Güncellenmiş DA'ler, DA2 load address değerini `0x40000000` olarak hardcode eder ve host tarafından sağlanan adresi yok sayar; böylece yazmalar DA1 hash slot'una (~`0x200000` aralığı) ulaşamaz. Hash hesaplanmaya devam eder, ancak artık attacker tarafından yazılabilir değildir.
- **Patched DA'leri tespit etme**: mtkclient/penumbra, address-hardening uygulandığını gösteren pattern'ler için DA1'i tarar; pattern bulunursa Carbonara atlanır. Eski DA'ler yazılabilir hash slot'larını (V5 DA1'de genellikle `0x22dea4` gibi offset'ler civarında) açığa çıkarır ve exploitable olmaya devam eder.
- **V5 vs V6**: Bazı V6 (XML) loader'lar hâlâ user-supplied address değerlerini kabul eder; daha yeni V6 binary'leri genellikle fixed address uygular ve downgraded olmadıkları sürece Carbonara'ya karşı immune'dur.<sup>[[2]](#references)[[3]](#references)</sup>

## Post-Carbonara (heapb8) note

MediaTek, Carbonara'yı patch'ledi; daha yeni bir vulnerability olan **heapb8**, patched V6 loader'larındaki DA2 USB file download handler'ını hedef alır ve `boot_to` hardened olsa bile code execution sağlar. Chunked file transfer sırasında oluşan bir heap overflow'u abuse ederek DA2 control flow'unu ele geçirir. Exploit, Penumbra/mtk-payloads içinde public durumdadır ve Carbonara fix'lerinin tüm DA attack surface'ini kapatmadığını gösterir.<sup>[[4]](#references)</sup>

## Notes for triage and hardening

- DA2 address/size değerlerinin unchecked olduğu ve DA1'in expected hash değerini writable tuttuğu cihazlar vulnerable'dır. Daha sonraki Preloader/DA address bounds uygular veya hash'i immutable tutarsa Carbonara mitigated olur.
- DAA'yı etkinleştirmek ve DA1/Preloader'ın BOOT_TO parametrelerini (bounds + DA2'nin authenticity'si) validate etmesini sağlamak primitive'i kapatır. Yalnızca hash patch'ini kapatmak, load değerini bounds ile sınırlandırmadan bırakırsa arbitrary write riskini sürdürür.

## References

- [1] [Carbonara: The MediaTek exploit nobody served](https://shomy.is-a.dev/blog/article/serving-carbonara)
- [2] [Carbonara exploit documentation](https://shomy.is-a.dev/penumbra/Mediatek/Exploits/Carbonara)
- [3] [Penumbra Carbonara source code](https://github.com/shomykohai/penumbra/blob/main/core/src/exploit/carbonara.rs)
- [4] [heapb8: exploiting patched V6 Download Agents](https://blog.r0rt1z2.com/posts/exploiting-mediatek-datwo/)

{{#include ../../banners/hacktricks-training.md}}
