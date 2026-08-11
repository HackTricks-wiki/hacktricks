# Ochrona poświadczeń systemu Windows

{{#include ../../banners/hacktricks-training.md}}

## WDigest

Protokół [WDigest](<https://technet.microsoft.com/pt-pt/library/cc778868(v=ws.10).aspx?f=255&MSPPError=-2147217396>), wprowadzony wraz z systemem Windows XP, został zaprojektowany do uwierzytelniania za pośrednictwem protokołu HTTP i jest **domyślnie włączony w systemach Windows XP do Windows 8.0 oraz Windows Server 2003 do Windows Server 2012**. To ustawienie domyślne skutkuje **przechowywaniem haseł w postaci zwykłego tekstu w LSASS** (usłudze podsystemu lokalnego organu zabezpieczeń). Atakujący może użyć Mimikatz do **wyodrębnienia tych poświadczeń**, wykonując:<sup>[[8]](#references)</sup>
```bash
sekurlsa::wdigest
```
Aby **włączyć lub wyłączyć tę funkcję**, klucze rejestru _**UseLogonCredential**_ i _**Negotiate**_ w _**HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest**_ muszą mieć wartość „1”. Jeśli tych kluczy **brakuje lub mają wartość „0”**, WDigest jest **wyłączony**:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
```
## LSA Protection (procesy chronione przez PP i PPL)

**Protected Process (PP)** oraz **Protected Process Light (PPL)** to **ochrony na poziomie jądra Windows**, zaprojektowane w celu zapobiegania nieautoryzowanemu dostępowi do wrażliwych procesów, takich jak **LSASS**. Wprowadzone w **Windows Vista**, **model PP** został pierwotnie stworzony do egzekwowania zasad **DRM** i umożliwiał ochronę wyłącznie plikom binarnym podpisanym **specjalnym certyfikatem medialnym**. Dostęp do procesu oznaczonego jako **PP** mogą uzyskać tylko inne procesy, które również są **PP** i mają **równy lub wyższy poziom ochrony**; nawet wtedy jest to możliwe **wyłącznie z ograniczonymi prawami dostępu**, chyba że wyraźnie na to zezwolono.

**PPL**, wprowadzone w **Windows 8.1**, jest bardziej elastyczną wersją PP. Umożliwia **szerszy zakres zastosowań** (np. LSASS, Defender), wprowadzając **„poziomy ochrony”** oparte na polu **EKU (Enhanced Key Usage)** podpisu cyfrowego. Poziom ochrony jest przechowywany w polu `EPROCESS.Protection`, które jest strukturą `PS_PROTECTION` zawierającą:
- **Type** (`Protected` lub `ProtectedLight`)
- **Signer** (np. `WinTcb`, `Lsa`, `Antimalware` itd.)

Ta struktura jest upakowana w pojedynczym bajcie i określa, **kto może uzyskać dostęp do kogo**:
- **Wyższe wartości signera mogą uzyskiwać dostęp do niższych**
- **PPL nie mogą uzyskiwać dostępu do PP**
- **Niezabezpieczone procesy nie mogą uzyskiwać dostępu do żadnych PPL/PP**

### Co należy wiedzieć z perspektywy offensive

- Gdy **LSASS działa jako PPL**, próby otwarcia go za pomocą `OpenProcess(PROCESS_VM_READ | QUERY_INFORMATION)` ze zwykłego kontekstu administratora **kończą się niepowodzeniem z `0x5 (Access Denied)`**, nawet jeśli `SeDebugPrivilege` jest włączone.
- **Poziom ochrony LSASS** można sprawdzić za pomocą narzędzi takich jak Process Hacker lub programowo, odczytując wartość `EPROCESS.Protection`.
- LSASS zwykle ma `PsProtectedSignerLsa-Light` (`0x41`), do którego dostęp mogą uzyskać **wyłącznie procesy podpisane signerem wyższego poziomu**, takim jak `WinTcb` (`0x61` lub `0x62`).
- PPL jest ograniczeniem obowiązującym **wyłącznie w Userland**; kod działający na poziomie jądra może je całkowicie ominąć.
- Fakt, że LSASS działa jako PPL, **nie uniemożliwia credential dumping**, jeśli można wykonać kernel shellcode lub **wykorzystać proces o wysokich uprawnieniach z odpowiednim dostępem**.
- **Ustawienie lub usunięcie PPL** wymaga ponownego uruchomienia systemu albo ustawień **Secure Boot/UEFI**, które mogą zachować ustawienie PPL nawet po cofnięciu zmian w rejestrze.

### Utworzenie procesu PPL podczas uruchamiania (udokumentowane API)

Windows udostępnia udokumentowany sposób zażądania poziomu Protected Process Light dla procesu potomnego podczas jego tworzenia, z użyciem rozszerzonej listy atrybutów uruchamiania. Nie omija to wymagań dotyczących podpisu — obraz docelowy musi być podpisany dla żądanej klasy signera.

Minimalny przepływ w C/C++:
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
- Użyj `STARTUPINFOEX` z `InitializeProcThreadAttributeList` i `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL, ...)`, a następnie przekaż `EXTENDED_STARTUPINFO_PRESENT` do `CreateProcess*`.<sup>[[2]](#references)[[3]](#references)[[4]](#references)</sup>
- Poziom ochrony `DWORD` można ustawić na stałe, takie jak `PROTECTION_LEVEL_WINTCB_LIGHT`, `PROTECTION_LEVEL_WINDOWS`, `PROTECTION_LEVEL_WINDOWS_LIGHT`, `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` lub `PROTECTION_LEVEL_LSA_LIGHT`.
- Proces potomny zostanie uruchomiony jako PPL tylko wtedy, gdy jego obraz jest podpisany dla danej klasy signera; w przeciwnym razie tworzenie procesu zakończy się niepowodzeniem, zwykle z błędem `ERROR_INVALID_IMAGE_HASH (577)` / `STATUS_INVALID_IMAGE_HASH (0xC0000428)`.
- Nie jest to bypass — to obsługiwane API przeznaczone dla odpowiednio podpisanych obrazów. Przydatne do hardeningu narzędzi lub weryfikowania konfiguracji chronionych przez PPL.

Przykład CLI używający minimalnego loadera:<sup>[[1]](#references)</sup>
- Antimalware signer: `CreateProcessAsPPL.exe 3 C:\Tools\agent.exe --svc`
- LSA-light signer: `CreateProcessAsPPL.exe 4 C:\Windows\System32\notepad.exe`

**Opcje bypassu ochrony PPL:**

Jeśli chcesz zrzucić LSASS pomimo PPL, masz 3 główne opcje:
1. **Użyj podpisanego sterownika kernel (np. Mimikatz + mimidrv.sys)**, aby **usunąć flagę ochrony LSASS**:

![Dane wyjściowe sterownika Mimikatz mimidrv pokazujące interakcję z ochroną poświadczeń](../../images/mimidrv.png)

2. **Bring Your Own Vulnerable Driver (BYOVD)**, aby uruchomić własny kod kernel i wyłączyć ochronę. Narzędzia takie jak **PPLKiller**, **gdrv-loader** lub **kdmapper** ułatwiają wykonanie tego podejścia.
3. **Wykradnij istniejący uchwyt LSASS** z innego procesu, który ma go otwarty (np. procesu AV), a następnie **zduplikuj go** do swojego procesu. Na tym opiera się technika `pypykatz live lsa --method handledup`.
4. **Wykorzystaj uprzywilejowany proces**, który pozwoli załadować dowolny kod do swojej przestrzeni adresowej lub do wnętrza innego uprzywilejowanego procesu, skutecznie omijając ograniczenia PPL. Przykład znajdziesz w [bypassing-lsa-protection-in-userland](https://blog.scrt.ch/2021/04/22/bypassing-lsa-protection-in-userland/) lub [https://github.com/itm4n/PPLdump](https://github.com/itm4n/PPLdump).

**Sprawdź bieżący status ochrony LSA (PPL/PP) dla LSASS**:
```bash
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL
```
Uruchomienie **`mimikatz privilege::debug sekurlsa::logonpasswords`** prawdopodobnie zakończy się niepowodzeniem z kodem błędu `0x00000005` z powodu tej ochrony.

- Więcej informacji na temat tego mechanizmu kontroli: [https://itm4n.github.io/lsass-runasppl/](https://itm4n.github.io/lsass-runasppl/)<sup>[[5]](#references)</sup>


## Credential Guard

**Credential Guard**, funkcja dostępna wyłącznie w **Windows 10 (edycje Enterprise i Education)**, zwiększa bezpieczeństwo poświadczeń maszyn za pomocą **Virtual Secure Mode (VSM)** i **Virtualization Based Security (VBS)**. Wykorzystuje rozszerzenia wirtualizacji procesora do odizolowania kluczowych procesów w chronionej przestrzeni pamięci, poza zasięgiem głównego systemu operacyjnego. Ta izolacja gwarantuje, że nawet kernel nie może uzyskać dostępu do pamięci w VSM, skutecznie chroniąc poświadczenia przed atakami takimi jak **pass-the-hash**. **Local Security Authority (LSA)** działa w tym bezpiecznym środowisku jako trustlet, podczas gdy proces **LSASS** w głównym systemie operacyjnym pełni jedynie funkcję komunikatora z LSA systemu VSM.

Domyślnie **Credential Guard** nie jest aktywny i wymaga ręcznego włączenia w organizacji. Ma kluczowe znaczenie dla zwiększenia bezpieczeństwa przed narzędziami takimi jak **Mimikatz**, które mają ograniczoną możliwość wyodrębniania poświadczeń. Nadal można jednak wykorzystywać luki poprzez dodanie niestandardowych **Security Support Providers (SSP)** do przechwytywania poświadczeń w postaci jawnego tekstu podczas prób logowania.

Aby sprawdzić stan aktywacji **Credential Guard**, można przeanalizować klucz rejestru _**LsaCfgFlags**_ w _**HKLM\System\CurrentControlSet\Control\LSA**_. Wartość "**1**" wskazuje aktywację z **UEFI lock**, "**2**" aktywację bez blokady, a "**0**" oznacza, że funkcja nie jest włączona. To sprawdzenie rejestru, choć stanowi silną przesłankę, nie jest jedynym krokiem wymaganym do włączenia Credential Guard. Szczegółowe instrukcje oraz skrypt PowerShell do włączenia tej funkcji są dostępne online.
```bash
reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags
```
Aby uzyskać kompleksowe informacje i instrukcje dotyczące włączania funkcji **Credential Guard** w Windows 10 oraz jej automatycznej aktywacji w kompatybilnych systemach **Windows 11 Enterprise i Education (wersja 22H2)**, odwiedź [dokumentację Microsoft](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage).<sup>[[9]](#references)</sup>

Więcej informacji na temat implementowania niestandardowych SSPs do przechwytywania credentials znajduje się [w tym poradniku](../active-directory-methodology/custom-ssp.md).

## Tryb RDP RestrictedAdmin

**Windows 8.1 i Windows Server 2012 R2** wprowadziły kilka nowych funkcji bezpieczeństwa, w tym _**tryb Restricted Admin dla RDP**_. Tryb ten został zaprojektowany w celu zwiększenia bezpieczeństwa poprzez ograniczenie zagrożeń związanych z atakami [**pass the hash**](https://blog.ahasayen.com/pass-the-hash/).

Tradycyjnie podczas łączenia się ze zdalnym komputerem za pośrednictwem RDP credentials są przechowywane na komputerze docelowym. Stanowi to poważne zagrożenie dla bezpieczeństwa, szczególnie w przypadku korzystania z kont z podwyższonymi uprawnieniami. Jednak wraz z wprowadzeniem _**trybu Restricted Admin**_ ryzyko to zostało znacznie ograniczone.

Podczas nawiązywania połączenia RDP za pomocą polecenia **mstsc.exe /RestrictedAdmin** uwierzytelnianie na komputerze zdalnym odbywa się bez przechowywania credentials na tym komputerze. Takie podejście gwarantuje, że w przypadku infekcji malware lub uzyskania dostępu do serwera zdalnego przez złośliwego użytkownika credentials nie zostaną naruszone, ponieważ nie są przechowywane na serwerze.

Należy pamiętać, że w **trybie Restricted Admin** próby uzyskania dostępu do zasobów sieciowych z sesji RDP nie będą korzystać z osobistych credentials użytkownika; zamiast tego używana jest **tożsamość komputera**.

Funkcja ta stanowi istotny krok naprzód w zabezpieczaniu połączeń zdalnego pulpitu i ochronie poufnych informacji przed ujawnieniem w przypadku naruszenia bezpieczeństwa.

![Diagram pamięci RAM systemu Windows w kontekście ekstrakcji credentials](../../images/RAM.png)

Więcej szczegółowych informacji można znaleźć [w tym materiale](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/).<sup>[[6]](#references)</sup>

## Cached Credentials

Windows zabezpiecza **credentials domenowe** za pośrednictwem **Local Security Authority (LSA)**, obsługując procesy logowania przy użyciu protokołów bezpieczeństwa, takich jak **Kerberos** i **NTLM**. Jedną z kluczowych funkcji systemu Windows jest możliwość buforowania **dziesięciu ostatnich logowań domenowych**, aby użytkownicy nadal mogli uzyskiwać dostęp do swoich komputerów nawet wtedy, gdy **domain controller jest offline** — jest to szczególnie przydatne dla użytkowników laptopów, którzy często przebywają poza siecią swojej firmy.

Liczbę buforowanych logowań można dostosować za pomocą określonego **klucza rejestru lub group policy**. Aby wyświetlić lub zmienić to ustawienie, używa się następującego polecenia:
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
Dostęp do tych buforowanych poświadczeń jest ściśle kontrolowany — tylko konto **SYSTEM** ma wymagane uprawnienia do ich wyświetlania. Administratorzy potrzebujący dostępu do tych informacji muszą korzystać z uprawnień użytkownika SYSTEM. Poświadczenia są przechowywane w: `HKEY_LOCAL_MACHINE\SECURITY\Cache`

**Mimikatz** może zostać użyty do wyodrębnienia tych buforowanych poświadczeń za pomocą polecenia `lsadump::cache`.

Więcej informacji zawiera oryginalne [źródło](http://juggernaut.wikidot.com/cached-credentials).<sup>[[7]](#references)</sup>

## Protected Users

Członkostwo w **Protected Users group** wprowadza kilka ulepszeń zabezpieczeń dla użytkowników, zapewniając wyższy poziom ochrony przed kradzieżą i niewłaściwym użyciem poświadczeń:

- **Credential Delegation (CredSSP)**: Nawet jeśli ustawienie Group Policy **Allow delegating default credentials** jest włączone, poświadczenia w postaci zwykłego tekstu użytkowników Protected Users nie będą buforowane.
- **Windows Digest**: Począwszy od **Windows 8.1 i Windows Server 2012 R2**, system nie będzie buforować poświadczeń w postaci zwykłego tekstu użytkowników Protected Users, niezależnie od stanu Windows Digest.
- **NTLM**: System nie będzie buforować poświadczeń użytkowników Protected Users w postaci zwykłego tekstu ani funkcji jednokierunkowych NT (NTOWF).
- **Kerberos**: W przypadku Protected Users uwierzytelnianie Kerberos nie wygeneruje kluczy **DES** ani **RC4**, a także nie będzie buforować poświadczeń w postaci zwykłego tekstu ani kluczy długoterminowych poza początkowym uzyskaniem Ticket-Granting Ticket (TGT).
- **Offline Sign-In**: Dla użytkowników Protected Users podczas logowania lub odblokowywania nie zostanie utworzony buforowany weryfikator, co oznacza, że logowanie offline nie jest obsługiwane dla tych kont.

Te zabezpieczenia są aktywowane w chwili, gdy użytkownik należący do **Protected Users group** loguje się do urządzenia. Zapewnia to zastosowanie kluczowych środków bezpieczeństwa chroniących przed różnymi metodami przejęcia poświadczeń.

Więcej szczegółowych informacji można znaleźć w oficjalnej [dokumentacji](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group).<sup>[[10]](#references)</sup>

**Tabela z** [**dokumentacji**](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)**.**<sup>[[11]](#references)</sup>

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

## References

- [1] [CreateProcessAsPPL – minimalny launcher procesu PPL](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [2] [Struktura STARTUPINFOEX (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-startupinfoexw)
- [3] [InitializeProcThreadAttributeList (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-initializeprocthreadattributelist)
- [4] [UpdateProcThreadAttribute (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute)
- [5] [LSASS RunAsPPL – tło i elementy wewnętrzne](https://itm4n.github.io/lsass-runasppl/)
- [6] [Restricted Admin Mode dla RDP](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/)
- [7] [Buforowane poświadczenia - Juggernaut AppSec Wiki](http://juggernaut.wikidot.com/cached-credentials)
- [8] [Uwierzytelnianie WDigest (Microsoft TechNet)](<https://technet.microsoft.com/pt-pt/library/cc778868(v=ws.10).aspx?f=255&MSPPError=-2147217396>)
- [9] [Zarządzanie Windows Defender Credential Guard (Microsoft Learn)](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage)
- [10] [Grupa zabezpieczeń Protected Users (Microsoft Learn)](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group)
- [11] [Dodatek C: Chronione konta i grupy w Active Directory (Microsoft Learn)](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)
{{#include ../../banners/hacktricks-training.md}}
