# MSI Wrapper

{{#include ../../banners/hacktricks-training.md}}

MSI Wrapper, bir executable veya script'i Windows Installer (`.msi`) dosyası olarak paketleyebilir. Ücretsiz sürümü indirip başlatın, ardından paketlenecek executable'ı seçin. Bir komut dizisini çalıştırmak için `cmd.exe`'yi paketlemek yerine girdi olarak bir `.bat` dosyası seçin.<sup>[[1]](#references)</sup>

![MSI Wrapper'da kaynak executable veya batch script'in seçilmesi](<../../images/image (417).png>)

Çalıştırma bağlamını ve diğer installer özelliklerini dikkatlice yapılandırın:

![MSI Wrapper'da application ID ve security context'in yapılandırılması](<../../images/image (312).png>)

![MSI Wrapper'da installer özelliklerinin yapılandırılması](<../../images/image (346).png>)

![MSI Wrapper build ayarlarının incelenmesi](<../../images/image (1072).png>)

Bu değerler, custom binary paketlenirken değiştirilebilir.

Kalan wizard sayfalarında ilerleyin ve installer'ı oluşturmak için **Build** seçeneğini belirleyin.<sup>[[1]](#references)</sup>

> [!WARNING]
> Bir MSI oluşturmak, tek başına elevated privileges sağlamaz. Installation işleminin elevated olup olmadığı Windows Installer policy'sine, package context'e ve user authorization'a bağlıdır. Microsoft, `AlwaysInstallElevated` seçeneğinin hem user hem de computer için etkinleştirilmesinin, administrator olmayan kullanıcıların system privileges ile package install etmesine olanak tanıdığı konusunda uyarır.<sup>[[2]](#references)</sup>

## References

- [1] [MSI Wrapper documentation - Başlarken](https://www.exemsi.com/documentation/getting-started/)
- [2] [Microsoft Learn - Administrator olmayan bir kullanıcı için elevated privileges ile package installation'ı](https://learn.microsoft.com/en-us/windows/win32/msi/installing-a-package-with-elevated-privileges-for-a-non-admin)
{{#include ../../banners/hacktricks-training.md}}
