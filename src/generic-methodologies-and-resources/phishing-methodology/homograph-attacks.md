# Phishing'de Homograph / Homoglyph Saldırıları

{{#include ../../banners/hacktricks-training.md}}

## Genel Bakış

Bir homograph (diğer adıyla homoglyph) saldırısı, birçok **Latin dışı komut dosyasındaki Unicode code point'lerinin görsel olarak ASCII karakterleriyle aynı veya son derece benzer olması** gerçeğini kötüye kullanır. Bir veya daha fazla Latin karakterini benzer görünümlü karşılıklarıyla değiştirerek saldırgan şunları oluşturabilir:

* İnsan gözüne meşru görünen ancak keyword tabanlı tespitleri atlatan görüntüleme adları, konu satırları veya mesaj gövdeleri.
* Kurbanları güvenilir bir siteyi ziyaret ettiklerine inandıran domain'ler, alt domain'ler veya URL yolları.<sup>[[1]](#references)</sup>

Her glyph dahili olarak kendi **Unicode code point'i** ile tanımlandığından, tek bir değiştirilmiş karakter, naif string karşılaştırmalarını etkisiz hâle getirmek için yeterlidir (ör. `"Παypal.com"` ile `"Paypal.com"`).<sup>[[1]](#references)[[3]](#references)</sup>

## Tipik Phishing İş Akışı

1. **Mesaj içeriği oluşturma** – Taklit edilen brand / keyword içindeki belirli Latin harflerini başka bir script'ten görsel olarak ayırt edilemeyen karakterlerle değiştirin (Greek, Cyrillic, Armenian, Cherokee vb.).
2. **Destekleyici altyapıyı kaydetme** – İsteğe bağlı olarak bir homoglyph domain'i kaydedin ve TLS certificate edinin (çoğu CA görsel benzerlik denetimi yapmaz).
3. **Email / SMS gönderme** – Mesaj, aşağıdaki konumlardan bir veya daha fazlasında homoglyph içerir:
* Gönderen görüntüleme adı (ör. `Ηеlрdеѕk`)
* Konu satırı (`Urgеnt Аctіon Rеquіrеd`)
* Hyperlink metni veya fully qualified domain name
4. **Redirect zinciri** – Kurban, credentials toplayan / malware dağıtan malicious host'a ulaşmadan önce görünüşte zararsız web siteleri veya URL kısaltıcılar üzerinden yönlendirilir.<sup>[[1]](#references)</sup>

## Yaygın Olarak Kötüye Kullanılan Unicode Aralıkları

Aşağıdaki örnekler, script'ler arası benzer görünümler oluşturmak için yaygın olarak kullanılan karakterleri içeren Unicode bloklarıdır.<sup>[[2]](#references)[[3]](#references)</sup>

| Script | Aralık | Örnek glyph | Şuna benzer |
|--------|-------|---------------|------------|
| Greek  | U+0370-03FF | `Η` (U+0397) | Latin `H` |
| Greek  | U+0370-03FF | `ρ` (U+03C1) | Latin `p` |
| Cyrillic | U+0400-04FF | `а` (U+0430) | Latin `a` |
| Cyrillic | U+0400-04FF | `е` (U+0435) | Latin `e` |
| Armenian | U+0530-058F | `օ` (U+0585) | Latin `o` |
| Cherokee | U+13A0-13FF | `Ꭲ` (U+13A2) | Latin `T` |

> İpucu: Blokları ve code point'leri aramak için Unicode code chart'larını kullanın.

## Tespit Teknikleri

### 1. Mixed-Script İncelemesi

English konuşan bir organisation'ı hedefleyen Phishing email'lerinin birden fazla script'ten karakterleri nadiren karıştırması gerekir. Basit ancak etkili bir heuristic şudur:

1. İncelenen string'in her karakterini yineleyin.
2. Code point'i script adına veya Unicode block'una eşleyin.
3. Birden fazla script mevcutsa **veya** beklenmeyen yerlerde (görüntüleme adı, domain, konu, URL vb.) Latin dışı script'ler görünüyorsa alert oluşturun.<sup>[[3]](#references)</sup>

Python proof-of-concept:
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
### 2. Punycode Normalisation (Domains)

Internationalised Domain Names (IDN'ler) bir Unicode biçimine ve `xn--` ön ekiyle başlayan ASCII uyumlu **Punycode** biçimine sahiptir. İzin verilenler listesine eklemeden veya karşılaştırmadan önce host adlarını IDNA/Punycode biçimine dönüştürün; görüntüleme için Unicode biçimini koruyun.<sup>[[6]](#references)</sup>
```python
import idna
hostname = "ρаypal.com"   # Greek small rho + Cyrillic small a
puny = idna.encode(hostname).decode()
print(puny)  # xn--ypal-9nd08d.com
```
### 3. Homoglyph Sözlükleri / Algoritmaları

**dnstwist** (`--fuzzers homoglyph`) veya **urlcrazy** gibi araçlar, görsel olarak benzer domain permütasyonlarını listeleyebilir ve proaktif takedown / monitoring için kullanışlıdır.<sup>[[4]](#references)[[5]](#references)</sup>

## Prevention & Mitigation

* Sıkı DMARC/DKIM/SPF politikaları uygulayın – yetkisiz domainlerden spoofing yapılmasını önleyin.
* Yukarıdaki detection logic'i **Secure Email Gateways** ve **SIEM/XSOAR** playbook'larında uygulayın.
* Display name domain ≠ sender domain olan mesajları işaretleyin veya quarantine'e alın.
* Kullanıcıları eğitin: şüpheli metni bir Unicode inspector'a copy-paste edin, bağlantıların üzerine gelin ve URL shortener'larına asla güvenmeyin.

## Real-World Examples

* Display name: `Сonfidеntiаl Ꭲiꮯkеt` (Cyrillic `С`, `е`, `а`; Cherokee `Ꭲ`; Latin small capital `ꮯ`).
* Domain chain: `bestseoservices.com` ➜ municipal `/templates` directory ➜ `kig.skyvaulyt.ru` ➜ custom OTP CAPTCHA ile korunan `mlcorsftpsswddprotcct.approaches.it.com` adresindeki fake Microsoft login.
* Spotify impersonation: `redirects.ca` arkasında gizlenmiş bağlantıya sahip `Sρօtifս` sender.

Bu örnekler Unit 42 araştırmasından (Temmuz 2025) alınmıştır ve homograph abuse'ın URL redirection ve CAPTCHA evasion ile birleştirilerek automated analysis'i nasıl atlattığını göstermektedir.<sup>[[1]](#references)</sup>

## References

- [1] [The Homograph Illusion: Not Everything Is As It Seems](https://unit42.paloaltonetworks.com/homograph-attacks/)
- [2] [Unicode Character Code Charts](https://www.unicode.org/charts/)
- [3] [Unicode Technical Standard #39: Unicode Security Mechanisms](https://unicode.org/reports/tr39/)
- [4] [dnstwist – domain permutation engine](https://github.com/elceef/dnstwist)
- [5] [URLCrazy – domain typo and variation generator](https://github.com/urbanadventurer/urlcrazy)
- [6] [RFC 5890: Internationalized Domain Names for Applications (IDNA): Definitions and Document Framework](https://www.rfc-editor.org/rfc/rfc5890)
{{#include ../../banners/hacktricks-training.md}}
