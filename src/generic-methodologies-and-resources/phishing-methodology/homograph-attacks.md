# Homograf / Homoglif Saldırıları Phishing'de

{{#include ../../banners/hacktricks-training.md}}

## Genel Bakış

Bir homograf (diğer adıyla homoglif) saldırısı, birçok **Unicode kod noktası, Latin alfabesi dışındaki yazı sistemlerinden görsel olarak aynı veya son derece benzer ASCII karakterleri** istismar eder. Bir veya daha fazla Latin karakterini, görünüşte benzer karşılıklarıyla değiştiren bir saldırgan, aşağıdakileri oluşturabilir:

* İnsan gözüne meşru görünen ancak anahtar kelime tabanlı tespitleri atlatan görüntüleme adları, konular veya mesaj metinleri.
* Kurbanların güvenilir bir siteyi ziyaret ettiklerini düşünmelerine neden olan alan adları, alt alan adları veya URL yolları.

Her glif, içsel olarak **Unicode kod noktası** ile tanımlandığı için, tek bir değiştirilmiş karakter, saf string karşılaştırmalarını (örneğin, `"Παypal.com"` vs. `"Paypal.com"`) yenmek için yeterlidir.

## Tipik Phishing İş Akışı

1. **Mesaj içeriğini oluşturun** – Taklit edilen marka / anahtar kelimede belirli Latin harflerini, başka bir yazı sisteminden (Yunanca, Kiril, Ermeni, Cherokee vb.) görsel olarak ayırt edilemeyen karakterlerle değiştirin.
2. **Destekleyici altyapıyı kaydedin** – İsteğe bağlı olarak bir homoglif alan adı kaydedin ve bir TLS sertifikası alın (çoğu CA görsel benzerlik kontrolleri yapmaz).
3. **E-posta / SMS gönderin** – Mesaj, aşağıdaki yerlerden birinde veya daha fazlasında homoglifler içerir:
* Gönderen görüntüleme adı (örneğin, `Ηеlрdеѕk`)
* Konu satırı (`Urgеnt Аctіon Rеquіrеd`)
* Bağlantı metni veya tam nitelikli alan adı
4. **Yönlendirme zinciri** – Kurban, kimlik bilgilerini toplayan / kötü amaçlı yazılım gönderen kötü niyetli ana bilgisayara ulaşmadan önce görünüşte zararsız web siteleri veya URL kısaltıcıları aracılığıyla yönlendirilir.

## Sıklıkla İstismar Edilen Unicode Aralıkları

| Yazı Sistemi | Aralık | Örnek glif | Görünüşte |
|--------------|--------|------------|-----------|
| Yunanca      | U+0370-03FF | `Η` (U+0397) | Latin `H` |
| Yunanca      | U+0370-03FF | `ρ` (U+03C1) | Latin `p` |
| Kiril        | U+0400-04FF | `а` (U+0430) | Latin `a` |
| Kiril        | U+0400-04FF | `е` (U+0435) | Latin `e` |
| Ermeni       | U+0530-058F | `օ` (U+0585) | Latin `o` |
| Cherokee     | U+13A0-13FF | `Ꭲ` (U+13A2) | Latin `T` |

> İpucu: Tam Unicode tabloları [unicode.org](https://home.unicode.org/) adresinde mevcuttur.

## Tespit Teknikleri

### 1. Karışık Yazı Sistemi İncelemesi

İngilizce konuşan bir kuruluşa yönelik phishing e-postaları nadiren birden fazla yazı sisteminden karakterleri karıştırmalıdır. Basit ama etkili bir sezgi, şunları yapmaktır:

1. İncelenen stringin her karakterini yineleyin.
2. Kod noktasını Unicode bloğuna eşleyin.
3. Birden fazla yazı sistemi mevcutsa **veya** beklenmeyen yerlerde (görüntüleme adı, alan, konu, URL vb.) Latin dışı yazı sistemleri görünüyorsa bir uyarı verin.

Python kanıtı:
```python
import unicodedata as ud
from collections import defaultdict

SUSPECT_FIELDS = {
"display_name": "Ηоmоgraph Illusion",     # example data
"subject": "Finаnꮯiаl Տtatеmеnt",
"url": "https://xn--messageconnecton-2kb.blob.core.windows.net"  # punycode
}

for field, value in SUSPECT_FIELDS.items():
blocks = defaultdict(int)
for ch in value:
if ch.isascii():
blocks['Latin'] += 1
else:
name = ud.name(ch, 'UNKNOWN')
block = name.split(' ')[0]     # e.g., 'CYRILLIC'
blocks[block] += 1
if len(blocks) > 1:
print(f"[!] Mixed scripts in {field}: {dict(blocks)} -> {value}")
```
### 2. Punycode Normalizasyonu (Alan Adları)

Uluslararasılaştırılmış Alan Adları (IDN'ler) **punycode** (`xn--`) ile kodlanmıştır. Her alan adını punycode'a dönüştürmek ve ardından Unicode'a geri dönüştürmek, dize normalleştirildikten sonra beyaz listeye karşı eşleştirme veya benzerlik kontrolleri (örneğin, Levenshtein mesafesi) yapmayı sağlar.
```python
import idna
hostname = "Ρаypal.com"   # Greek Rho + Cyrillic a
puny = idna.encode(hostname).decode()
print(puny)  # xn--yl8hpyal.com
```
### 3. Homoglyph Sözlükleri / Algoritmalar

**dnstwist** (`--homoglyph`) veya **urlcrazy** gibi araçlar, görsel olarak benzer alan permütasyonlarını sıralayabilir ve proaktif kaldırma / izleme için faydalıdır.

## Önleme & Azaltma

* Katı DMARC/DKIM/SPF politikalarını uygulayın – yetkisiz alanlardan sahteciliği önleyin.
* Yukarıdaki tespit mantığını **Secure Email Gateways** ve **SIEM/XSOAR** oyun kitaplarında uygulayın.
* Görüntü adı alanı ≠ gönderici alanı olan mesajları işaretleyin veya karantinaya alın.
* Kullanıcıları eğitin: şüpheli metni bir Unicode denetleyicisine kopyala-yapıştır yapın, bağlantılara üzerine gelin, URL kısaltıcılarına asla güvenmeyin.

## Gerçek Dünya Örnekleri

* Görüntü adı: `Сonfidеntiаl Ꭲiꮯkеt` (Kiril `С`, `е`, `а`; Cherokee `Ꭲ`; Latin küçük büyük `ꮯ`).
* Alan zinciri: `bestseoservices.com` ➜ belediye `/templates` dizini ➜ `kig.skyvaulyt.ru` ➜ özel OTP CAPTCHA ile korunan sahte Microsoft girişi `mlcorsftpsswddprotcct.approaches.it.com`.
* Spotify taklidi: `Sρօtifւ` göndereni ile `redirects.ca` arkasında gizli bağlantı.

Bu örnekler, homograf istismarının URL yönlendirmesi ve CAPTCHA kaçışı ile nasıl birleştirildiğini gösteren Unit 42 araştırmasından (Temmuz 2025) gelmektedir.

## Referanslar

- [The Homograph Illusion: Not Everything Is As It Seems](https://unit42.paloaltonetworks.com/homograph-attacks/)
- [Unicode Character Database](https://home.unicode.org/)
- [dnstwist – domain permutation engine](https://github.com/elceef/dnstwist)

{{#include ../../banners/hacktricks-training.md}}
