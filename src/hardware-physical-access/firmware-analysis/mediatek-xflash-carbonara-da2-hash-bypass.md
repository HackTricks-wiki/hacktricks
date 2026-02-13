# MediaTek XFlash Carbonara DA2 Hash Bypass

{{#include ../../banners/hacktricks-training.md}}

## Summary

"Carbonara", DA1'in bütünlük kontrollerine rağmen değiştirilmiş bir Download Agent stage 2 (DA2)'yi çalıştırmak için MediaTek'in XFlash indirme yolunu kötüye kullanır. DA1, DA2 için beklenen SHA-256 değerini RAM'de saklar ve dallanmadan önce bunu karşılaştırır. Birçok loaders'da host, DA2'nin yükleme adresi/size'ını tamamen kontrol eder; bu da kontrolsüz bir bellek yazma imkanı vererek RAM'deki hash'i üzerine yazıp yürütmeyi rastgele payload'lara yönlendirebilir (pre-OS context, cache invalidation DA tarafından ele alınır).

## Trust boundary in XFlash (DA1 → DA2)

- **DA1** BootROM/Preloader tarafından imzalanır/yüklenir. When Download Agent Authorization (DAA) etkin olduğunda yalnızca imzalanmış DA1 çalışmalıdır.
- **DA2** USB üzerinden gönderilir. DA1, **size**, **load address**, ve **SHA-256**'yi alır ve alınan DA2'yi hash'leyip bunu DA1'e gömülü **beklenen hash** ile (RAM'e kopyalanmış) karşılaştırır.
- **Weakness:** Yaması uygulanmamış loaders'da DA1, DA2'nin load address/size bilgilerini sanitize etmez ve beklenen hash'i bellekte yazılabilir tutar; bu, host'un doğrulamayı manipüle etmesine imkan verir.

## Carbonara flow ("two BOOT_TO" trick)

1. **First `BOOT_TO`:** DA1→DA2 staging akışına girilir (DA1 DRAM ayırır, hazırlar ve beklenen-hash buffer'ını RAM'de açığa çıkarır).
2. **Hash-slot overwrite:** DA1 belleğini tarayan ve depolanan DA2-beklenen hash'ini bulan küçük bir payload gönderin; bunu saldırgan tarafından değiştirilmiş DA2'nin SHA-256'si ile üzerine yazın. Bu, kullanıcı kontrollü yüklemeyi kullanarak payload'un hash'in bulunduğu yere inmesini sağlar.
3. **Second `BOOT_TO` + digest:** Yamalanmış DA2 metadata'sı ile ikinci bir `BOOT_TO` tetikleyin ve değiştirilmiş DA2 ile eşleşen ham 32-baytlık digest'i gönderin. DA1, alınan DA2 üzerinde SHA-256'yı yeniden hesaplar, şimdi yamalanmış beklenen hash ile karşılaştırır ve kontrol saldırgan koduna geçer.

Load address/size saldırgan tarafından kontrol edildiği için aynı primitive belleğin herhangi bir yerine (sadece hash buffer'ına değil) yazabilir; bu da early-boot implantları, secure-boot bypass yardımcıları veya kötü amaçlı rootkit'ler için imkan sağlar.

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
- `payload` DA1 içinde expected-hash buffer'ını yama yapan paid-tool blob'unu taklit eder.
- `sha256(...).digest()` ham baytlar (hex değil) gönderir, böylece DA1 bunu patched buffer ile karşılaştırır.
- DA2 herhangi bir attacker-built image olabilir; yükleme adresi/boyutu seçmek, cache invalidation DA tarafından halledilerek rastgele bellek yerleşimine izin verir.

## Triage ve sertleştirme için notlar

- DA2 adresi/boyutu kontrol edilmez ve DA1 expected hash'i yazılabilir tuttuğu cihazlar savunmasızdır. Daha sonraki bir Preloader/DA adres sınırlarını uygular veya hash'i değiştirilemez tutarsa, Carbonara hafifletilmiş olur.
- DAA'yı etkinleştirip DA1/Preloader'ın BOOT_TO parametrelerini (sınırlar + DA2'nin doğruluğu) doğruladığından emin olmak primitive'i kapatır. Yüklemeyi sınırlandırmadan sadece hash yamasını kapatmak hâlâ arbitrary write riskini bırakır.

## References

- [Carbonara: The MediaTek exploit nobody served](https://shomy.is-a.dev/blog/article/serving-carbonara)
- [Carbonara exploit documentation](https://shomy.is-a.dev/penumbra/Mediatek/Exploits/Carbonara)
- [Penumbra Carbonara source code](https://github.com/shomykohai/penumbra/blob/main/core/src/exploit/carbonara.rs)

{{#include ../../banners/hacktricks-training.md}}
