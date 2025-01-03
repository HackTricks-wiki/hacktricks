# Sertifikalar

{{#include ../banners/hacktricks-training.md}}

## Sertifika Nedir

Bir **açık anahtar sertifikası**, birinin bir açık anahtara sahip olduğunu kanıtlamak için kriptografide kullanılan dijital bir kimliktir. Anahtarın detaylarını, sahibinin kimliğini (konu) ve güvenilir bir otoriteden (verici) dijital bir imzayı içerir. Yazılım vericiyi güvenilir buluyorsa ve imza geçerliyse, anahtarın sahibiyle güvenli iletişim mümkündür.

Sertifikalar genellikle [sertifika otoriteleri](https://en.wikipedia.org/wiki/Certificate_authority) (CA'lar) tarafından [açık anahtar altyapısı](https://en.wikipedia.org/wiki/Public-key_infrastructure) (PKI) kurulumunda verilir. Diğer bir yöntem ise [güven ağı](https://en.wikipedia.org/wiki/Web_of_trust)dır; burada kullanıcılar birbirlerinin anahtarlarını doğrudan doğrular. Sertifikalar için yaygın format [X.509](https://en.wikipedia.org/wiki/X.509) olup, RFC 5280'de belirtildiği gibi belirli ihtiyaçlara uyarlanabilir.

## x509 Ortak Alanlar

### **x509 Sertifikalarında Ortak Alanlar**

x509 sertifikalarında, sertifikanın geçerliliğini ve güvenliğini sağlamak için birkaç **alan** kritik roller oynar. Bu alanların bir dökümü:

- **Sürüm Numarası**, x509 formatının sürümünü belirtir.
- **Seri Numarası**, sertifikayı bir Sertifika Otoritesi (CA) sisteminde benzersiz olarak tanımlar, esasen iptal takibi için kullanılır.
- **Konu** alanı, sertifikanın sahibini temsil eder; bu bir makine, birey veya organizasyon olabilir. Detaylı kimlik bilgilerini içerir:
- **Ortak İsim (CN)**: Sertifika tarafından kapsanan alanlar.
- **Ülke (C)**, **Yer (L)**, **Eyalet veya İl (ST, S veya P)**, **Organizasyon (O)** ve **Organizasyon Birimi (OU)** coğrafi ve organizasyonel detaylar sağlar.
- **Ayrıcalıklı İsim (DN)**, tam konu kimliğini kapsar.
- **Verici**, sertifikayı kimlerin doğruladığını ve imzaladığını detaylandırır; CA için Konu ile benzer alt alanlar içerir.
- **Geçerlilik Süresi**, sertifikanın belirli bir tarihten önce veya sonra kullanılmadığını sağlamak için **Not Before** ve **Not After** zaman damgaları ile işaretlenir.
- **Açık Anahtar** bölümü, sertifikanın güvenliği için kritik olup, açık anahtarın algoritmasını, boyutunu ve diğer teknik detaylarını belirtir.
- **x509v3 uzantıları**, sertifikanın işlevselliğini artırır; **Anahtar Kullanımı**, **Genişletilmiş Anahtar Kullanımı**, **Konu Alternatif Adı** ve sertifikanın uygulamasını ince ayar yapmak için diğer özellikleri belirtir.

#### **Anahtar Kullanımı ve Uzantılar**

- **Anahtar Kullanımı**, açık anahtarın kriptografik uygulamalarını tanımlar; örneğin dijital imza veya anahtar şifreleme.
- **Genişletilmiş Anahtar Kullanımı**, sertifikanın kullanım durumlarını daha da daraltır; örneğin, TLS sunucu kimlik doğrulaması için.
- **Konu Alternatif Adı** ve **Temel Kısıtlama**, sertifika tarafından kapsanan ek ana bilgisayar adlarını ve bunun bir CA veya son varlık sertifikası olup olmadığını tanımlar.
- **Konu Anahtar Tanımlayıcı** ve **Otorite Anahtar Tanımlayıcı** gibi tanımlayıcılar, anahtarların benzersizliğini ve izlenebilirliğini sağlar.
- **Otorite Bilgi Erişimi** ve **CRL Dağıtım Noktaları**, verici CA'yı doğrulamak ve sertifika iptal durumunu kontrol etmek için yollar sağlar.
- **CT Ön Sertifika SCT'leri**, sertifikaya kamu güveni için kritik olan şeffaflık günlükleri sunar.
```python
# Example of accessing and using x509 certificate fields programmatically:
from cryptography import x509
from cryptography.hazmat.backends import default_backend

# Load an x509 certificate (assuming cert.pem is a certificate file)
with open("cert.pem", "rb") as file:
cert_data = file.read()
certificate = x509.load_pem_x509_certificate(cert_data, default_backend())

# Accessing fields
serial_number = certificate.serial_number
issuer = certificate.issuer
subject = certificate.subject
public_key = certificate.public_key()

print(f"Serial Number: {serial_number}")
print(f"Issuer: {issuer}")
print(f"Subject: {subject}")
print(f"Public Key: {public_key}")
```
### **OCSP ve CRL Dağıtım Noktaları Arasındaki Fark**

**OCSP** (**RFC 2560**), bir istemci ve bir yanıtlayıcının, tam **CRL** indirmeye gerek kalmadan dijital kamu anahtar sertifikasının iptal edilip edilmediğini kontrol etmek için birlikte çalışmasını içerir. Bu yöntem, iptal edilen sertifika seri numaralarının bir listesini sağlayan ancak potansiyel olarak büyük bir dosyanın indirilmesini gerektiren geleneksel **CRL**'den daha verimlidir. CRL'ler en fazla 512 giriş içerebilir. Daha fazla ayrıntı [burada](https://www.arubanetworks.com/techdocs/ArubaOS%206_3_1_Web_Help/Content/ArubaFrameStyles/CertRevocation/About_OCSP_and_CRL.htm) mevcuttur.

### **Sertifika Şeffaflığı Nedir**

Sertifika Şeffaflığı, SSL sertifikalarının verilmesi ve varlığının alan adı sahipleri, CA'lar ve kullanıcılar tarafından görünür olmasını sağlayarak sertifika ile ilgili tehditlerle mücadele etmeye yardımcı olur. Hedefleri şunlardır:

- CA'ların, alan adı sahibinin bilgisi olmadan bir alan için SSL sertifikası vermesini önlemek.
- Yanlış veya kötü niyetle verilmiş sertifikaların izlenmesi için açık bir denetim sistemi kurmak.
- Kullanıcıları sahte sertifikalardan korumak.

#### **Sertifika Kayıtları**

Sertifika kayıtları, ağ hizmetleri tarafından tutulan, kamuya açık denetlenebilir, yalnızca ekleme yapılabilen sertifika kayıtlarıdır. Bu kayıtlar, denetim amaçları için kriptografik kanıtlar sağlar. Hem verme otoriteleri hem de kamu, bu kayıtlara sertifika gönderebilir veya doğrulama için sorgulayabilir. Kayıt sunucularının kesin sayısı sabit olmamakla birlikte, dünya genelinde binin altında olması beklenmektedir. Bu sunucular, CA'lar, ISP'ler veya herhangi bir ilgilenen taraf tarafından bağımsız olarak yönetilebilir.

#### **Sorgu**

Herhangi bir alan için Sertifika Şeffaflığı kayıtlarını keşfetmek için [https://crt.sh/](https://crt.sh) adresini ziyaret edin.

Sertifikaları depolamak için farklı formatlar mevcuttur, her birinin kendi kullanım durumları ve uyumluluğu vardır. Bu özet, ana formatları kapsar ve bunlar arasında dönüştürme konusunda rehberlik sağlar.

## **Formatlar**

### **PEM Formatı**

- Sertifikalar için en yaygın kullanılan formattır.
- Sertifikalar ve özel anahtarlar için ayrı dosyalar gerektirir, Base64 ASCII ile kodlanmıştır.
- Yaygın uzantılar: .cer, .crt, .pem, .key.
- Öncelikle Apache ve benzeri sunucular tarafından kullanılır.

### **DER Formatı**

- Sertifikaların ikili formatıdır.
- PEM dosyalarında bulunan "BEGIN/END CERTIFICATE" ifadelerini içermez.
- Yaygın uzantılar: .cer, .der.
- Genellikle Java platformları ile kullanılır.

### **P7B/PKCS#7 Formatı**

- Base64 ASCII formatında depolanır, uzantıları .p7b veya .p7c'dir.
- Sadece sertifikaları ve zincir sertifikalarını içerir, özel anahtarı hariç tutar.
- Microsoft Windows ve Java Tomcat tarafından desteklenir.

### **PFX/P12/PKCS#12 Formatı**

- Sunucu sertifikalarını, ara sertifikaları ve özel anahtarları tek bir dosyada kapsayan ikili bir formattır.
- Uzantılar: .pfx, .p12.
- Sertifika içe aktarma ve dışa aktarma için öncelikle Windows'ta kullanılır.

### **Format Dönüştürme**

**PEM dönüşümleri**, uyumluluk için gereklidir:

- **x509'dan PEM'e**
```bash
openssl x509 -in certificatename.cer -outform PEM -out certificatename.pem
```
- **PEM'den DER'e**
```bash
openssl x509 -outform der -in certificatename.pem -out certificatename.der
```
- **DER'den PEM'e**
```bash
openssl x509 -inform der -in certificatename.der -out certificatename.pem
```
- **PEM'den P7B'ye**
```bash
openssl crl2pkcs7 -nocrl -certfile certificatename.pem -out certificatename.p7b -certfile CACert.cer
```
- **PKCS7'den PEM'e**
```bash
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.pem
```
**PFX dönüşümleri**, Windows'ta sertifikaları yönetmek için çok önemlidir:

- **PFX'ten PEM'e**
```bash
openssl pkcs12 -in certificatename.pfx -out certificatename.pem
```
- **PFX'ten PKCS#8'e** iki adım içerir:
1. PFX'i PEM'e dönüştür
```bash
openssl pkcs12 -in certificatename.pfx -nocerts -nodes -out certificatename.pem
```
2. PEM'i PKCS8'e Dönüştür
```bash
openSSL pkcs8 -in certificatename.pem -topk8 -nocrypt -out certificatename.pk8
```
- **P7B'den PFX'e** geçmek için de iki komut gereklidir:
1. P7B'yi CER'ye dönüştür
```bash
openssl pkcs7 -print_certs -in certificatename.p7b -out certificatename.cer
```
2. CER ve Özel Anahtarı PFX'e Dönüştür
```bash
openssl pkcs12 -export -in certificatename.cer -inkey privateKey.key -out certificatename.pfx -certfile cacert.cer
```
- **ASN.1 (DER/PEM) düzenleme** (sertifikalar veya neredeyse herhangi bir ASN.1 yapısıyla çalışır):
1. [asn1template](https://github.com/wllm-rbnt/asn1template/) klonlayın
```bash
git clone https://github.com/wllm-rbnt/asn1template.git
```
2. DER/PEM'i OpenSSL'in üretim formatına dönüştürün
```bash
asn1template/asn1template.pl certificatename.der > certificatename.tpl
asn1template/asn1template.pl -p certificatename.pem > certificatename.tpl
```
3. İhtiyaçlarınıza göre certificatename.tpl dosyasını düzenleyin
```bash
vim certificatename.tpl
```
4. Değiştirilmiş sertifikayı yeniden oluşturun
```bash
openssl asn1parse -genconf certificatename.tpl -out certificatename_new.der
openssl asn1parse -genconf certificatename.tpl -outform PEM -out certificatename_new.pem
```
--- 

{{#include ../banners/hacktricks-training.md}}
