# Phishing'de Homograph / Homoglyph Attacks

{{#include ../../banners/hacktricks-training.md}}

## Genel Bakış

Bir homograph (diğer adıyla homoglyph) attack, birçok **Latin alfabesi dışındaki script'e ait Unicode code point'lerinin görsel olarak ASCII karakterleriyle aynı veya son derece benzer olması** gerçeğinden yararlanır. Bir veya daha fazla Latin karakteri, benzer görünen karşılıklarıyla değiştirerek saldırgan şunları oluşturabilir:

* İnsan gözüne meşru görünen ancak keyword tabanlı tespitleri atlatan görüntü adları, konu satırları veya mesaj gövdeleri.
* Kurbanları güvenilir bir siteyi ziyaret ettiklerine inandıran domain'ler, sub-domain'ler veya URL path'leri.

Her glyph dahili olarak kendi **Unicode code point'i** ile tanımlandığından, tek bir değiştirilmiş karakter bile naif string karşılaştırmalarını etkisiz kılmak için yeterlidir (ör. `"Παypal.com"` ve `"Paypal.com"`).

## Tipik Phishing Workflow'u

1. **Mesaj içeriği oluşturma** – Taklit edilen brand / keyword içindeki belirli Latin harflerini, başka bir script'teki (Greek, Cyrillic, Armenian, Cherokee vb.) görsel olarak ayırt edilemeyen karakterlerle değiştirin.
2. **Destekleyici infrastructure'ı kaydetme** – İsteğe bağlı olarak bir homoglyph domain'i kaydedin ve bir TLS certificate edinin (CA'lerin çoğu görsel benzerlik kontrolü yapmaz).
3. **Email / SMS gönderme** – Mesaj, aşağıdaki konumlardan birinde veya birkaçında homoglyph'ler içerir:
* Sender display name (ör. `Ηеlрdеѕk`)
* Subject line (`Urgеnt Аctіon Rеquіrеd`)
* Hyperlink text veya fully qualified domain name
4. **Redirect chain** – Kurban, credential'ları toplayan / malware dağıtan malicious host'a ulaşmadan önce görünüşte zararsız web siteleri veya URL shortener'lar üzerinden yönlendirilir.

## Yaygın Olarak Kötüye Kullanılan Unicode Ranges

| Script | Range | Example glyph | Looks like |
|--------|-------|---------------|------------|
| Greek  | U+0370-03FF | `Η` (U+0397) | Latin `H` |
| Greek  | U+0370-03FF | `ρ` (U+03C1) | Latin `p` |
| Cyrillic | U+0400-04FF | `а` (U+0430) | Latin `a` |
| Cyrillic | U+0400-04FF | `е` (U+0435) | Latin `e` |
| Armenian | U+0530-058F | `օ` (U+0585) | Latin `o` |
| Cherokee | U+13A0-13FF | `Ꭲ` (U+13A2) | Latin `T` |

> İpucu: Tam Unicode charts şu adreste mevcuttur: [unicode.org](https://home.unicode.org/).<sup>[[2]](#references)</sup>

## Detection Techniques

### 1. Mixed-Script Inspection

English konuşan bir organisation'ı hedefleyen phishing email'leri birden fazla script'i nadiren karıştırmalıdır. Basit ancak etkili bir heuristic şu adımları izler:

1. İncelenen string'in her karakterini iterate edin.
2. Code point'i Unicode block'a map edin.
3. Birden fazla script mevcutsa **veya** beklenmeyen yerlerde (display name, domain, subject, URL vb.) non-Latin script'ler görülüyorsa alert oluşturun.

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

Internationalised Domain Names (IDN'ler) **punycode** (`xn--`) ile kodlanır. Her hostname'i punycode'a ve ardından tekrar Unicode'a dönüştürmek, string normalize edildikten **sonra** bir whitelist ile eşleştirme veya benzerlik kontrolleri (ör. Levenshtein distance) gerçekleştirme olanağı sağlar.
```python
import idna
hostname = "Ρаypal.com"   # Greek Rho + Cyrillic a
puny = idna.encode(hostname).decode()
print(puny)  # xn--yl8hpyal.com
```
### 3. Homoglyph Sözlükleri / Algoritmaları

**dnstwist** (`--homoglyph`) veya **urlcrazy** gibi araçlar, görsel olarak benzer domain permütasyonlarını sıralayabilir ve proaktif kaldırma / izleme için kullanışlıdır.<sup>[[3]](#references)</sup>

## Önleme ve Azaltma

* Katı DMARC/DKIM/SPF politikaları uygulayın – yetkisiz domainlerden spoofing yapılmasını önleyin.
* Yukarıdaki detection logic'i **Secure Email Gateways** ve **SIEM/XSOAR** playbook'larında uygulayın.
* Görünen ad domain'i ≠ gönderen domain'i olan mesajları işaretleyin veya karantinaya alın.
* Kullanıcıları eğitin: şüpheli metni bir Unicode inspector'a copy-paste edin, linklerin üzerine gelin ve URL shortener'lara asla güvenmeyin.

## Gerçek Dünya Örnekleri

* Görünen ad: `Сonfidеntiаl Ꭲiꮯkеt` (Cyrillic `С`, `е`, `а`; Cherokee `Ꭲ`; Latin small capital `ꮯ`).
* Domain chain: `bestseoservices.com` ➜ municipal `/templates` directory ➜ `kig.skyvaulyt.ru` ➜ custom OTP CAPTCHA ile korunan `mlcorsftpsswddprotcct.approaches.it.com` adresindeki sahte Microsoft login sayfası.
* Spotify taklidi: `redirects.ca` arkasına gizlenmiş link içeren `Sρօtifս` göndereni.

Bu örnekler Unit 42 araştırmasından (Temmuz 2025) alınmıştır ve homograph abuse'un, automated analysis'i atlatmak için URL redirection ve CAPTCHA evasion ile nasıl birleştirildiğini göstermektedir.<sup>[[1]](#references)</sup>

## Referanslar

- [1] [The Homograph Illusion: Not Everything Is As It Seems](https://unit42.paloaltonetworks.com/homograph-attacks/)
- [2] [Unicode Character Database](https://home.unicode.org/)
- [3] [dnstwist – domain permutation engine](https://github.com/elceef/dnstwist)

{{#include ../../banners/hacktricks-training.md}}
