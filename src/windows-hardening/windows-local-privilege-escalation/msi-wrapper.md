# MSI Wrapper

{{#include ../../banners/hacktricks-training.md}}

MSI Wrapper, bir çalıştırılabilir dosyayı veya script'i Windows Installer (`.msi`) dosyası olarak paketleyebilir. Ücretsiz sürümü indirip başlatın, ardından paketlenecek çalıştırılabilir dosyayı seçin.<sup>[[3]](#references)</sup> Bir komut dizisi çalıştırmak için `cmd.exe`'yi paketlemek yerine girdi olarak bir `.bat` dosyası seçin.<sup>[[1]](#references)</sup>

![MSI Wrapper'da kaynak çalıştırılabilir dosyanın veya batch script'in seçilmesi](<../../images/image (417).png>)

Çalıştırma bağlamını ve diğer installer özelliklerini dikkatlice yapılandırın:

![MSI Wrapper'da uygulama kimliğinin ve güvenlik bağlamının yapılandırılması](<../../images/image (312).png>)

![MSI Wrapper'da installer özelliklerinin yapılandırılması](<../../images/image (346).png>)

![MSI Wrapper derleme ayarlarının gözden geçirilmesi](<../../images/image (1072).png>)

Özel bir binary paketlenirken bu değerler değiştirilebilir.

Sihirbazın kalan sayfalarında ilerleyin ve installer'ı oluşturmak için **Build**'i seçin.<sup>[[1]](#references)</sup>

## Sarılmış komutun çalıştırılma bağlamını doğrulayın

Bir test paketi için, MSI'ın yükseltme ayarının alt sürece uygulandığını varsaymak yerine token'ını kaydeden bir `.bat` dosyasını sarın.<sup>[[4]](#references)</sup> Sihirbazda **User** yerine **System** güvenlik bağlamını seçin ve amaçlanan yöntem buysa makine başına, yükseltilmiş bir kurulum seçin.<sup>[[5]](#references)</sup> **System** seçeneği yetkilendirmeyi atlamaz: yönetici olmayan bir kullanıcının, [iki ilkeyle yapılan `AlwaysInstallElevated` yanlış yapılandırması](index.html#alwaysinstallelevated) veya ayrıcalıklı bir installer iş akışı gibi, yükseltilmiş bir kurulum yoluna yine de ihtiyacı vardır.<sup>[[2]](#references)</sup> Bunun yerine **User** seçeneği, sarılmış komutu kurulumu yapan kullanıcının bağlamında çalıştırır; bu, kullanıcıya özgü kaynaklar veya ağ kaynakları için gerekli olabilir.<sup>[[5]](#references)</sup>

```bat
@echo off
whoami /all > "C:\Users\Public\msi-wrapper-context.txt"
exit /b 0
```

MSI'yi bu batch dosyasını girdi olarak kullanarak oluşturun, ardından test ana makinesinde çalıştırıp kaydedilen kimliği ve ayrıcalıkları inceleyin.<sup>[[4]](#references)</sup> MSI Wrapper, sıfır olmayan bir batch çıkış kodunu 1603 kurulum hatasına dönüştürür; bu nedenle açıkça sıfır döndürmek, başarılı bir testin ardından yanlış hata oluşmasını önler.<sup>[[4]](#references)</sup> Çıktı dosyası bir test artefaktıdır; yalnızca başarılı bir `msiexec` çıkış koduna veya sessiz kuruluma dayanarak SYSTEM yetkisiyle çalıştırıldığı sonucuna varmayın.<sup>[[5]](#references)[[6]](#references)</sup>

```cmd
msiexec.exe /i "C:\Users\Public\context-test.msi" /qn /norestart /L*V "C:\Users\Public\context-test.log"
type "C:\Users\Public\msi-wrapper-context.txt"
```

`/qn`, MSI arayüzünü susturur; ancak sarmalanan yürütülebilir dosyanın kendi arayüzünü susturması şart değildir.<sup>[[6]](#references)[[7]](#references)</sup> Sarmalanmış bir yükleyici için, sihirbazda desteklenen sessiz argümanlarını ayarlayın; MSI Wrapper'ın dinamik `WRAPPED_ARGUMENTS` özelliği bir PRO özelliğidir.<sup>[[1]](#references)[[7]](#references)</sup> Özel eylemlerin sıralamasını ve impersonation'ı doğrudan kontrol etmeniz gerekiyorsa [WiX özel eylem yaklaşımına](create-msi-with-wix.md) bakın.

> [!WARNING]
> MSI oluşturmak tek başına yükseltilmiş ayrıcalıklar vermez. Yüklemenin yükseltilmiş ayrıcalıklarla yapılıp yapılmayacağı; Windows Installer ilkesine, paket bağlamına ve kullanıcı yetkilendirmesine bağlıdır. Microsoft, hem kullanıcı hem de bilgisayar için `AlwaysInstallElevated` etkinleştirildiğinde, yönetici olmayan kullanıcıların paketleri sistem ayrıcalıklarıyla yükleyebileceği konusunda uyarır.<sup>[[2]](#references)</sup>



## References

- [1] [MSI Wrapper belgeleri - Başlarken](https://www.exemsi.com/documentation/getting-started/)
- [2] [Microsoft Learn - Yönetici olmayan bir kullanıcı için yükseltilmiş ayrıcalıklarla paket yükleme](https://learn.microsoft.com/en-us/windows/win32/msi/installing-a-package-with-elevated-privileges-for-a-non-admin)
- [3] [MSI Wrapper - İndirme](https://www.exemsi.com/download/)
- [4] [MSI Wrapper - Bir batch dosyasından MSI oluşturma](https://www.exemsi.com/documentation/create-msi-from-batch-file/)
- [5] [MSI Wrapper - Sihirbaz sayfaları](https://www.exemsi.com/documentation/wizard-pages/)
- [6] [Microsoft Learn - Komut satırı seçenekleri](https://learn.microsoft.com/en-us/windows/win32/msi/command-line-options)
- [7] [MSI Wrapper - Komut satırı argümanları](https://www.exemsi.com/documentation/command-line-arguments/)
{{#include ../../banners/hacktricks-training.md}}
