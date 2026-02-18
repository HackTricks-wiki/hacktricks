# MediaTek XFlash Carbonara DA2 Hash Bypass

{{#include ../../banners/hacktricks-training.md}}

## Özet

"Carbonara", DA1 bütünlük kontrollerine rağmen değiştirilmiş bir Download Agent stage 2 (DA2)'yi çalıştırmak için MediaTek'in XFlash indirme yolunu suistimal eder. DA1, DA2 için beklenen SHA-256 değerini RAM'de tutar ve dallanmadan önce bunu karşılaştırır. Birçok loader'da host, DA2'nin yükleme adresi/boyutu üzerinde tam kontrole sahiptir; bu, denetlenmeyen bir bellek yazma işlemi sağlayarak RAM'deki bu hash'i üzerine yazabilir ve yürütmeyi rastgele payload'lara yönlendirebilir (pre-OS bağlamı; cache invalidation DA tarafından yönetilir).

## XFlash'teki güven sınırı (DA1 → DA2)

- **DA1** BootROM/Preloader tarafından imzalanır/yüklenir. Download Agent Authorization (DAA) etkinleştirildiğinde, sadece imzalanmış DA1 çalıştırılmalıdır.
- **DA2** USB üzerinden gönderilir. DA1, **boyut**, **yükleme adresi** ve **SHA-256** alır; alınan DA2'nin SHA-256'sını hesaplar ve bunu DA1 içine gömülü (RAM'e kopyalanmış) **beklenen hash** ile karşılaştırır.
- **Zayıflık:** Yaması yapılmamış loader'larda DA1, DA2'nin yükleme adresi/boyutunu temizlemez ve beklenen hash'i bellek içinde yazılabilir tutar; bu da host'un kontrolüyle kontrole müdahale edilmesine olanak verir.

## Carbonara flow ("two BOOT_TO" trick)

1. **First `BOOT_TO`:** DA1→DA2 hazırlık akışına girin (DA1 DRAM'i ayırır, hazırlar ve beklenen-hash tamponunu RAM'de açığa çıkarır).
2. **Hash-slot overwrite:** DA1 belleğini tarayan ve depolanmış DA2 beklenen hash'ini bulan, onu saldırgan tarafından değiştirilmiş DA2'nin SHA-256'si ile üstüne yazan küçük bir payload gönderin. Bu, kullanıcı tarafından kontrol edilen yüklemeyi kullanarak payload'u hash'in bulunduğu yere yerleştirir.
3. **Second `BOOT_TO` + digest:** Yama uygulanmış DA2 meta verileriyle başka bir `BOOT_TO` tetikleyin ve değiştirilmiş DA2 ile eşleşen ham 32 baytlık digest'i gönderin. DA1, alınan DA2 üzerinde SHA-256'yı yeniden hesaplar, şimdi yamanmış beklenen hash ile karşılaştırır ve atlama saldırgan koduna başarılı şekilde yönlenir.

Yükleme adresi/boyutu saldırgan tarafından kontrol edildiği için aynı primitif, bellekte her yere (sadece hash tamponuna değil) yazabilir; bu da erken-boot implantlarına, secure-boot atlatma yardımcılarına veya kötü amaçlı rootkit'lere olanak tanır.

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
- `payload` DA1 içindeki expected-hash buffer'ını yamalayan ücretli araç blob'unu taklit eder.
- `sha256(...).digest()` ham baytlar (hex değil) gönderir, böylece DA1 yamalanmış tamponla karşılaştırır.
- DA2, saldırgan tarafından oluşturulmuş herhangi bir imaj olabilir; yükleme adresi/ boyutu seçimi rastgele bellek yerleştirmesine izin verir ve cache invalidation DA tarafından halledilir.

## Yama manzarası (sertleştirilmiş yükleyiciler)

- **Önlem**: Güncellenmiş DA'lar DA2 yükleme adresini `0x40000000` olarak hardcode eder ve host'un sağladığı adresi göz ardı eder, bu nedenle yazmalar DA1 hash slot'una (~0x200000 aralığı) ulaşamaz. Hash hesaplanmaya devam eder fakat artık saldırgan tarafından yazılabilir değildir.
- **Yama uygulanmış DA'ların tespiti**: mtkclient/penumbra, adres-sertleştirmesini gösteren desenler için DA1'i tarar; bulunursa Carbonara atlanır. Eski DA'lar yazılabilir hash slot'larını açığa çıkarır (genellikle V5 DA1'de `0x22dea4` gibi offset'lerde) ve kullanılabilir kalır.
- **V5 vs V6**: Bazı V6 (XML) yükleyiciler hala kullanıcı kaynaklı adresleri kabul eder; daha yeni V6 ikilileri genellikle sabit adresi zorunlu kılar ve downgrade edilmedikçe Carbonara'ya bağışıktır.

## Carbonara sonrası (heapb8) notu

MediaTek Carbonara'yı yamadı; daha yeni bir zafiyet olan **heapb8**, yama uygulanmış V6 loader'larda DA2 USB dosya indirme handler'ını hedef alır ve `boot_to` sertleştirilmiş olsa bile kod yürütmesi sağlar. Parçalı dosya transferleri sırasında bir heap taşmasını suistimal ederek DA2 kontrol akışını ele geçirir. Exploit Penumbra/mtk-payloads'ta açıktır ve Carbonara düzeltmelerinin tüm DA saldırı yüzeyini kapatmadığını gösterir.

## Triage ve sertleştirme için notlar

- DA2 adresi/ boyutu kontrol edilmeyen ve DA1 expected hash'i yazılabilir tutan cihazlar savunmasızdır. Daha sonraki bir Preloader/DA adres sınırlarını uygular veya hash'i değişmez kılarsa Carbonara hafifletilir.
- DAA'yı etkinleştirmek ve DA1/Preloader'ın BOOT_TO parametrelerini (sınırlar + DA2'nin orjinalliği) doğruladığından emin olmak primitive'i kapatır. Yalnızca hash yamayı kapatmak, yükleme sınırlandırılmadan bırakılırsa hâlâ rastgele yazma riski bırakır.

## Referanslar

- [Carbonara: The MediaTek exploit nobody served](https://shomy.is-a.dev/blog/article/serving-carbonara)
- [Carbonara exploit documentation](https://shomy.is-a.dev/penumbra/Mediatek/Exploits/Carbonara)
- [Penumbra Carbonara source code](https://github.com/shomykohai/penumbra/blob/main/core/src/exploit/carbonara.rs)
- [heapb8: exploiting patched V6 Download Agents](https://blog.r0rt1z2.com/posts/exploiting-mediatek-datwo/)

{{#include ../../banners/hacktricks-training.md}}
