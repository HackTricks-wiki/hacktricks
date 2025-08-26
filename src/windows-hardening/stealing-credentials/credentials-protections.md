# Ochrona poświadczeń Windows

{{#include ../../banners/hacktricks-training.md}}

## WDigest

The [WDigest](<https://technet.microsoft.com/pt-pt/library/cc778868(v=ws.10).aspx?f=255&MSPPError=-2147217396>) protocol, introduced with Windows XP, is designed for authentication via the HTTP Protocol and is **enabled by default on Windows XP through Windows 8.0 and Windows Server 2003 to Windows Server 2012**. This default setting results in **plain-text password storage in LSASS** (Local Security Authority Subsystem Service). An attacker can use Mimikatz to **extract these credentials** by executing:
```bash
sekurlsa::wdigest
```
Aby **włączyć lub wyłączyć tę funkcję**, klucze rejestru _**UseLogonCredential**_ i _**Negotiate**_ w _**HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest**_ muszą być ustawione na "1". Jeśli te klucze są **nieobecne lub ustawione na "0"**, WDigest jest **wyłączony**:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
```
## LSA Protection (PP & PPL protected processes)

**Protected Process (PP)** i **Protected Process Light (PPL)** to **ochrony na poziomie jądra Windows** zaprojektowane, by uniemożliwić nieautoryzowany dostęp do wrażliwych procesów, takich jak **LSASS**. Wprowadzone w **Windows Vista**, **PP** pierwotnie powstał dla egzekwowania **DRM** i tylko binaria podpisane specjalnym certyfikatem medialnym mogły być chronione. Proces oznaczony jako **PP** może być dostępny jedynie przez inne procesy, które również są **PP** i mają **równy lub wyższy poziom ochrony**, i nawet wtedy **tylko z ograniczonymi prawami dostępu**, chyba że zezwolono inaczej.

**PPL**, wprowadzony w **Windows 8.1**, to bardziej elastyczna wersja PP. Pozwala na **szersze scenariusze zastosowań** (np. LSASS, Defender) przez wprowadzenie **„poziomów ochrony”** opartych na polu **EKU (Enhanced Key Usage)** w podpisie cyfrowym. Poziom ochrony jest przechowywany w polu `EPROCESS.Protection`, które jest strukturą `PS_PROTECTION` zawierającą:
- **Type** (`Protected` or `ProtectedLight`)
- **Signer** (np. `WinTcb`, `Lsa`, `Antimalware`, itd.)

Struktura ta jest zapakowana w pojedynczy bajt i determinuje **kto może kogo uzyskać**:
- **Higher signer values can access lower ones**
- **PPLs can’t access PPs**
- **Unprotected processes can't access any PPL/PP**

### What you need to know from an offensive perspective

- Gdy **LSASS działa jako PPL**, próby otwarcia go za pomocą `OpenProcess(PROCESS_VM_READ | QUERY_INFORMATION)` z normalnego kontekstu admina **zakończą się niepowodzeniem z `0x5 (Access Denied)`**, nawet jeśli `SeDebugPrivilege` jest włączone.
- Możesz **sprawdzić poziom ochrony LSASS** używając narzędzi takich jak Process Hacker lub programowo czytając wartość `EPROCESS.Protection`.
- LSASS będzie zwykle miał `PsProtectedSignerLsa-Light` (`0x41`), do którego dostęp mają **jedynie procesy podpisane sygnatorem wyższego poziomu**, takim jak `WinTcb` (`0x61` lub `0x62`).
- PPL to **ograniczenie tylko w Userland**; **kod działający w kernelu może je całkowicie obejść**.
- Fakt, że LSASS jest PPL, **nie zapobiega zrzutowi poświadczeń jeśli możesz wykonać kernel shellcode** lub **wykorzystać proces o wysokich uprawnieniach z odpowiednim dostępem**.
- **Ustawienie lub usunięcie PPL** wymaga rebootu lub ustawień **Secure Boot/UEFI**, które mogą utrzymać ustawienie PPL nawet po odwróceniu zmian w rejestrze.

### Create a PPL process at launch (documented API)

Windows udostępnia udokumentowany sposób żądania poziomu Protected Process Light dla procesu potomnego podczas tworzenia, używając rozszerzonej listy atrybutów startup. To nie omija wymagań dotyczących podpisu — docelowy obraz musi być podpisany dla żądanej klasy signera.

Minimalny przebieg w C/C++:
```c
// Request a PPL protection level for the child process at creation time
// Requires Windows 8.1+ and a properly signed image for the selected level
#include <windows.h>

int wmain(int argc, wchar_t **argv) {
STARTUPINFOEXW si = {0};
PROCESS_INFORMATION pi = {0};
si.StartupInfo.cb = sizeof(si);

SIZE_T attrSize = 0;
InitializeProcThreadAttributeList(NULL, 1, 0, &attrSize);
si.lpAttributeList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attrSize);
if (!si.lpAttributeList) return 1;

if (!InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &attrSize)) return 1;

DWORD level = PROTECTION_LEVEL_ANTIMALWARE_LIGHT; // or WINDOWS_LIGHT/LSA_LIGHT/WINTCB_LIGHT
if (!UpdateProcThreadAttribute(
si.lpAttributeList, 0,
PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL,
&level, sizeof(level), NULL, NULL)) {
return 1;
}

DWORD flags = EXTENDED_STARTUPINFO_PRESENT;
if (!CreateProcessW(L"C\\Windows\\System32\\notepad.exe", NULL, NULL, NULL, FALSE,
flags, NULL, NULL, &si.StartupInfo, &pi)) {
// If the image isn't signed appropriately for the requested level,
// CreateProcess will fail with ERROR_INVALID_IMAGE_HASH (577).
return 1;
}

// cleanup
DeleteProcThreadAttributeList(si.lpAttributeList);
HeapFree(GetProcessHeap(), 0, si.lpAttributeList);
CloseHandle(pi.hThread);
CloseHandle(pi.hProcess);
return 0;
}
```
Uwagi i ograniczenia:
- Użyj `STARTUPINFOEX` z `InitializeProcThreadAttributeList` i `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL, ...)`, następnie przekaż `EXTENDED_STARTUPINFO_PRESENT` do `CreateProcess*`.
- Wartość ochrony `DWORD` można ustawić na stałe takie jak `PROTECTION_LEVEL_WINTCB_LIGHT`, `PROTECTION_LEVEL_WINDOWS`, `PROTECTION_LEVEL_WINDOWS_LIGHT`, `PROTECTION_LEVEL_ANTIMALWARE_LIGHT`, lub `PROTECTION_LEVEL_LSA_LIGHT`.
- Proces potomny uruchomi się jako PPL tylko jeśli jego obraz jest podpisany dla tej klasy podpisującej; w przeciwnym razie tworzenie procesu zakończy się niepowodzeniem, zwykle z `ERROR_INVALID_IMAGE_HASH (577)` / `STATUS_INVALID_IMAGE_HASH (0xC0000428)`.
- To nie jest bypass — to wspierane API przeznaczone dla odpowiednio podpisanych obrazów. Przydatne do utwardzania narzędzi lub weryfikacji konfiguracji chronionych przez PPL.

Example CLI using a minimal loader:
- Antimalware signer: `CreateProcessAsPPL.exe 3 C:\Tools\agent.exe --svc`
- LSA-light signer: `CreateProcessAsPPL.exe 4 C:\Windows\System32\notepad.exe`

**Opcje obejścia ochrony PPL:**

Jeśli chcesz zrzucić LSASS pomimo PPL, masz 3 główne opcje:
1. **Użyj podpisanego sterownika jądra (e.g., Mimikatz + mimidrv.sys)** aby **usunąć flagę ochrony LSASS**:

![](../../images/mimidrv.png)

2. **Bring Your Own Vulnerable Driver (BYOVD)** aby uruchomić niestandardowy kod w kernelu i wyłączyć ochronę. Narzędzia takie jak **PPLKiller**, **gdrv-loader**, lub **kdmapper** to umożliwiają.
3. **Ukradnij istniejący uchwyt LSASS** z innego procesu, który ma go otwartego (np. proces AV), następnie **sduplikuj go** w swoim procesie. To jest podstawa techniki `pypykatz live lsa --method handledup`.
4. **Wykorzystaj pewien uprzywilejowany proces**, który pozwoli ci załadować dowolny kod do jego przestrzeni adresowej lub do innego uprzywilejowanego procesu, skutecznie obejmując ograniczenia PPL. Możesz sprawdzić przykład tego w [bypassing-lsa-protection-in-userland](https://blog.scrt.ch/2021/04/22/bypassing-lsa-protection-in-userland/) lub [https://github.com/itm4n/PPLdump](https://github.com/itm4n/PPLdump).

**Sprawdź aktualny status ochrony LSA (PPL/PP) dla LSASS**:
```bash
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL
```
When you running **`mimikatz privilege::debug sekurlsa::logonpasswords`** it'll probably fail with the error code `0x00000005` becasue of this.

- Więcej informacji na temat tej kontroli [https://itm4n.github.io/lsass-runasppl/](https://itm4n.github.io/lsass-runasppl/)


## Credential Guard

**Credential Guard**, funkcja dostępna wyłącznie w **Windows 10 (wydania Enterprise i Education)**, zwiększa bezpieczeństwo poświadczeń maszyny, wykorzystując **Virtual Secure Mode (VSM)** i **Virtualization Based Security (VBS)**. Wykorzystuje rozszerzenia wirtualizacji CPU do izolowania kluczowych procesów w chronionej przestrzeni pamięciowej, poza zasięgiem głównego systemu operacyjnego. Ta izolacja sprawia, że nawet kernel nie ma dostępu do pamięci w VSM, skutecznie chroniąc poświadczenia przed atakami takimi jak **pass-the-hash**. **Local Security Authority (LSA)** działa w tym bezpiecznym środowisku jako trustlet, podczas gdy proces **LSASS** w głównym systemie pełni jedynie rolę komunikatora z LSA w VSM.

Domyślnie **Credential Guard** nie jest aktywny i wymaga ręcznej aktywacji w organizacji. Ma to duże znaczenie dla zwiększenia ochrony przed narzędziami takimi jak **Mimikatz**, które mają utrudnioną możliwość wyciągania poświadczeń. Niemniej jednak luki mogą być nadal wykorzystywane poprzez dodanie niestandardowych **Security Support Providers (SSP)** do przechwytywania poświadczeń w postaci jawnej podczas prób logowania.

Aby sprawdzić stan aktywacji **Credential Guard**, można przejrzeć klucz rejestru _**LsaCfgFlags**_ pod _**HKLM\System\CurrentControlSet\Control\LSA**_. Wartość "**1**" wskazuje aktywację z blokadą **UEFI**, "**2**" bez blokady, a "**0**" oznacza, że nie jest włączona. Ten wpis rejestru, choć jest silnym wskaźnikiem, nie jest jedynym krokiem wymaganym do włączenia Credential Guard. Szczegółowe instrukcje oraz skrypt PowerShell do włączenia tej funkcji są dostępne online.
```bash
reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags
```
Aby uzyskać kompleksowe informacje i instrukcje dotyczące włączenia **Credential Guard** w Windows 10 oraz jego automatycznej aktywacji w zgodnych systemach **Windows 11 Enterprise and Education (version 22H2)**, odwiedź [Microsoft's documentation](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage).

Dalsze informacje na temat implementacji custom SSPs do przechwytywania poświadczeń znajdują się w [this guide](../active-directory-methodology/custom-ssp.md).

## Tryb Restricted Admin dla RDP

**Windows 8.1 and Windows Server 2012 R2** wprowadziły kilka nowych funkcji zabezpieczeń, w tym _**Restricted Admin mode for RDP**_. Ten tryb został zaprojektowany, aby zwiększyć bezpieczeństwo przez zmniejszenie ryzyka związanego z atakami [**pass the hash**](https://blog.ahasayen.com/pass-the-hash/).

Tradycyjnie, podczas łączenia się z zdalnym komputerem przez RDP, Twoje poświadczenia są przechowywane na maszynie docelowej. Stanowi to poważne ryzyko bezpieczeństwa, zwłaszcza przy używaniu kont o podwyższonych uprawnieniach. Jednak wraz z wprowadzeniem _**Restricted Admin mode**_ to ryzyko jest znacznie zredukowane.

Podczas inicjowania połączenia RDP przy użyciu polecenia **mstsc.exe /RestrictedAdmin**, uwierzytelnianie do komputera zdalnego odbywa się bez przechowywania Twoich poświadczeń na nim. To podejście zapewnia, że w przypadku infekcji malware lub gdy złośliwy użytkownik uzyska dostęp do serwera zdalnego, Twoje poświadczenia nie zostaną ujawnione, ponieważ nie są przechowywane na serwerze.

Warto zauważyć, że w **Restricted Admin mode** próby dostępu do zasobów sieciowych z sesji RDP nie będą używać Twoich osobistych poświadczeń; zamiast tego używana jest **tożsamość maszyny**.

Funkcja ta stanowi istotny krok naprzód w zabezpieczaniu połączeń pulpitu zdalnego i ochronie wrażliwych informacji przed ujawnieniem w przypadku naruszenia bezpieczeństwa.

![](../../images/RAM.png)

Po więcej szczegółów odwiedź [this resource](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/).

## Buforowane poświadczenia

Windows zabezpiecza **domain credentials** za pomocą **Local Security Authority (LSA)**, obsługując procesy logowania protokołami bezpieczeństwa takimi jak **Kerberos** i **NTLM**. Kluczową cechą Windows jest możliwość buforowania **ostatnich dziesięciu logowań w domenie**, co pozwala użytkownikom nadal uzyskiwać dostęp do swoich komputerów, nawet jeśli **kontroler domeny jest niedostępny** — przydatne dla użytkowników laptopów często będących poza siecią firmową.

Liczbę buforowanych logowań można dostosować za pomocą określonego **klucza rejestru lub zasad grupy**. Aby wyświetlić lub zmienić to ustawienie, użyj następującego polecenia:
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
Dostęp do tych buforowanych danych uwierzytelniających jest ściśle kontrolowany — tylko konto **SYSTEM** ma wymagane uprawnienia do ich przeglądania. Administratorzy, którzy potrzebują dostępu do tych informacji, muszą działać z uprawnieniami użytkownika SYSTEM. Dane uwierzytelniające są przechowywane pod adresem: `HKEY_LOCAL_MACHINE\SECURITY\Cache`

**Mimikatz** można użyć do wyodrębnienia tych buforowanych danych uwierzytelniających poleceniem `lsadump::cache`.

Szczegółowe informacje znajdują się w oryginalnym [source](http://juggernaut.wikidot.com/cached-credentials).

## Protected Users

Członkostwo w **Protected Users group** wprowadza kilka ulepszeń bezpieczeństwa dla użytkowników, zapewniając wyższy poziom ochrony przed kradzieżą i niewłaściwym użyciem poświadczeń:

- **Credential Delegation (CredSSP)**: Nawet jeśli ustawienie Group Policy **Allow delegating default credentials** jest włączone, poświadczenia w postaci tekstu jawnego użytkowników Protected Users nie będą buforowane.
- **Windows Digest**: Począwszy od **Windows 8.1 and Windows Server 2012 R2**, system nie będzie buforował poświadczeń w postaci tekstu jawnego użytkowników Protected Users, niezależnie od stanu Windows Digest.
- **NTLM**: System nie będzie buforował poświadczeń w postaci tekstu jawnego ani jednokierunkowych funkcji NT (NTOWF) użytkowników Protected Users.
- **Kerberos**: Dla użytkowników Protected Users uwierzytelnianie Kerberos nie wygeneruje **DES** ani **RC4 keys**, ani nie będzie buforować poświadczeń w postaci tekstu jawnego czy kluczy długoterminowych poza początkowym uzyskaniem Ticket-Granting Ticket (TGT).
- **Offline Sign-In**: Dla użytkowników Protected Users nie zostanie utworzony buforowany weryfikator podczas logowania lub odblokowywania, co oznacza, że logowanie offline nie jest obsługiwane dla tych kont.

Te zabezpieczenia są aktywowane w momencie, gdy użytkownik będący członkiem **Protected Users group** loguje się na urządzenie. Zapewnia to wdrożenie krytycznych środków bezpieczeństwa chroniących przed różnymi metodami kompromitacji poświadczeń.

Szczegółowe informacje znajdziesz w oficjalnej [documentation](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group).

**Table from** [**the docs**](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)**.**

| Windows Server 2003 RTM | Windows Server 2003 SP1+ | <p>Windows Server 2012,<br>Windows Server 2008 R2,<br>Windows Server 2008</p> | Windows Server 2016          |
| ----------------------- | ------------------------ | ----------------------------------------------------------------------------- | ---------------------------- |
| Account Operators       | Account Operators        | Account Operators                                                             | Account Operators            |
| Administrator           | Administrator            | Administrator                                                                 | Administrator                |
| Administrators          | Administrators           | Administrators                                                                | Administrators               |
| Backup Operators        | Backup Operators         | Backup Operators                                                              | Backup Operators             |
| Cert Publishers         |                          |                                                                               |                              |
| Domain Admins           | Domain Admins            | Domain Admins                                                                 | Domain Admins                |
| Domain Controllers      | Domain Controllers       | Domain Controllers                                                            | Domain Controllers           |
| Enterprise Admins       | Enterprise Admins        | Enterprise Admins                                                             | Enterprise Admins            |
|                         |                          |                                                                               | Enterprise Key Admins        |
|                         |                          |                                                                               | Key Admins                   |
| Krbtgt                  | Krbtgt                   | Krbtgt                                                                        | Krbtgt                       |
| Print Operators         | Print Operators          | Print Operators                                                               | Print Operators              |
|                         |                          | Read-only Domain Controllers                                                  | Read-only Domain Controllers |
| Replicator              | Replicator               | Replicator                                                                    | Replicator                   |
| Schema Admins           | Schema Admins            | Schema Admins                                                                 | Schema Admins                |
| Server Operators        | Server Operators         | Server Operators                                                              | Server Operators             |

## Referencje

- [CreateProcessAsPPL – minimal PPL process launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [STARTUPINFOEX structure (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-startupinfoexw)
- [InitializeProcThreadAttributeList (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-initializeprocthreadattributelist)
- [UpdateProcThreadAttribute (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute)
- [LSASS RunAsPPL – background and internals](https://itm4n.github.io/lsass-runasppl/)

{{#include ../../banners/hacktricks-training.md}}
