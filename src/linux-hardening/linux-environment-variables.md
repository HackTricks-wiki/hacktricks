# Linux Ortam Değişkenleri

{{#include ../banners/hacktricks-training.md}}

## Küresel değişkenler

Küresel değişkenler **çocuk süreçler** tarafından **devralınacaktır**.

Mevcut oturumunuz için bir küresel değişken oluşturmak için:
```bash
export MYGLOBAL="hello world"
echo $MYGLOBAL #Prints: hello world
```
Bu değişken, mevcut oturumlarınız ve onların alt süreçleri tarafından erişilebilir olacaktır.

Bir değişkeni **kaldırmak** için:
```bash
unset MYGLOBAL
```
## Yerel değişkenler

**Yerel değişkenler** yalnızca **geçerli shell/script** tarafından **erişilebilir**.
```bash
LOCAL="my local"
echo $LOCAL
unset LOCAL
```
## Mevcut değişkenleri listele
```bash
set
env
printenv
cat /proc/$$/environ
cat /proc/`python -c "import os; print(os.getppid())"`/environ
```
## Ortak değişkenler

From: [https://geek-university.com/linux/common-environment-variables/](https://geek-university.com/linux/common-environment-variables/)

- **DISPLAY** – **X** tarafından kullanılan ekran. Bu değişken genellikle **:0.0** olarak ayarlanır, bu da mevcut bilgisayardaki ilk ekranı ifade eder.
- **EDITOR** – kullanıcının tercih ettiği metin düzenleyici.
- **HISTFILESIZE** – geçmiş dosyasında bulunan maksimum satır sayısı.
- **HISTSIZE** – Kullanıcı oturumunu bitirdiğinde geçmiş dosyasına eklenen satır sayısı.
- **HOME** – ev dizininiz.
- **HOSTNAME** – bilgisayarın ana bilgisayar adı.
- **LANG** – mevcut diliniz.
- **MAIL** – kullanıcının posta kuyruğunun yeri. Genellikle **/var/spool/mail/USER**.
- **MANPATH** – kılavuz sayfalarını aramak için dizinlerin listesi.
- **OSTYPE** – işletim sisteminin türü.
- **PS1** – bash'deki varsayılan istem.
- **PATH** – yalnızca dosya adını belirterek çalıştırmak istediğiniz ikili dosyaların bulunduğu tüm dizinlerin yolunu saklar, göreli veya mutlak yol ile değil.
- **PWD** – mevcut çalışma dizini.
- **SHELL** – mevcut komut kabuğunun yolu (örneğin, **/bin/bash**).
- **TERM** – mevcut terminal türü (örneğin, **xterm**).
- **TZ** – zaman diliminiz.
- **USER** – mevcut kullanıcı adınız.

## Hackleme için ilginç değişkenler

### **HISTFILESIZE**

Bu değişkenin **değerini 0 olarak değiştirin**, böylece **oturumunuzu sonlandırdığınızda** **geçmiş dosyası** (\~/.bash_history) **silinecektir**.
```bash
export HISTFILESIZE=0
```
### **HISTSIZE**

Bu **değişkenin değerini 0 olarak değiştirin**, böylece **oturumunuzu sonlandırdığınızda** herhangi bir komut **tarih dosyasına** (\~/.bash_history) eklenecektir.
```bash
export HISTSIZE=0
```
### http_proxy & https_proxy

İşlemler, **http veya https** üzerinden internete bağlanmak için burada belirtilen **proxy**'yi kullanacaktır.
```bash
export http_proxy="http://10.10.10.10:8080"
export https_proxy="http://10.10.10.10:8080"
```
### SSL_CERT_FILE & SSL_CERT_DIR

Bu **env değişkenlerinde** belirtilen sertifikalara süreçler güvenecektir.
```bash
export SSL_CERT_FILE=/path/to/ca-bundle.pem
export SSL_CERT_DIR=/path/to/ca-certificates
```
### PS1

İstediğiniz istemci görünümünü değiştirin.

[**Bu bir örnektir**](https://gist.github.com/carlospolop/43f7cd50f3deea972439af3222b68808)

Root:

![](<../images/image (897).png>)

Normal kullanıcı:

![](<../images/image (740).png>)

Bir, iki ve üç arka planda çalışan iş:

![](<../images/image (145).png>)

Bir arka planda çalışan iş, bir durdurulmuş ve son komut doğru şekilde bitmedi:

![](<../images/image (715).png>)

{{#include ../banners/hacktricks-training.md}}
