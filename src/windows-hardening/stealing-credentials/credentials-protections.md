# Zabezpieczenia poświadczeń systemu Windows

{{#include ../../banners/hacktricks-training.md}}

## WDigest

Protokół [WDigest](<https://technet.microsoft.com/pt-pt/library/cc778868(v=ws.10).aspx?f=255&MSPPError=-2147217396>), wprowadzony wraz z systemem Windows XP, jest przeznaczony do uwierzytelniania za pośrednictwem protokołu HTTP i jest **domyślnie włączony w systemach Windows XP do Windows 8.0 oraz Windows Server 2003 do Windows Server 2012**. To domyślne ustawienie powoduje **przechowywanie haseł w postaci jawnego tekstu w LSASS** (Local Security Authority Subsystem Service). Atakujący może użyć Mimikatz, aby **wyodrębnić te poświadczenia**, wykonując:<sup>[[8]](#references)</sup>
```bash
sekurlsa::wdigest
```
Aby **wyłączyć lub włączyć tę funkcję**, klucze rejestru _**UseLogonCredential**_ i _**Negotiate**_ w _**HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest**_ muszą mieć wartość „1”. Jeśli tych kluczy **brakuje lub mają wartość „0”**, WDigest jest **wyłączony**:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
```
## Ochrona LSA (procesy chronione przez PP i PPL)

**Protected Process (PP)** oraz **Protected Process Light (PPL)** to **ochrony na poziomie jądra Windows**, zaprojektowane w celu zapobiegania nieautoryzowanemu dostępowi do wrażliwych procesów, takich jak **LSASS**. Wprowadzone w **Windows Vista**, **model PP** został pierwotnie utworzony na potrzeby egzekwowania **DRM** i pozwalał na ochronę wyłącznie plików binarnych podpisanych **specjalnym certyfikatem medialnym**. Proces oznaczony jako **PP** może być otwierany wyłącznie przez inne procesy, które również są **PP** i mają **równy lub wyższy poziom ochrony**, a nawet wtedy, **tylko z ograniczonymi prawami dostępu**, chyba że wyraźnie na to zezwolono.

**PPL**, wprowadzone w **Windows 8.1**, jest bardziej elastyczną wersją PP. Umożliwia **szerszy zakres zastosowań** (np. LSASS, Defender), wprowadzając **„poziomy ochrony”** oparte na polu **EKU (Enhanced Key Usage)** **podpisu cyfrowego**. Poziom ochrony jest przechowywany w polu `EPROCESS.Protection`, które jest strukturą `PS_PROTECTION` zawierającą:
- **Type** (`Protected` lub `ProtectedLight`)
- **Signer** (np. `WinTcb`, `Lsa`, `Antimalware` itd.)

Ta struktura jest upakowana w pojedynczym bajcie i określa, **kto może uzyskać dostęp do kogo**:
- **Wyższe wartości Signer mogą uzyskiwać dostęp do niższych**
- **PPL nie mogą uzyskiwać dostępu do PP**
- **Niezabezpieczone procesy nie mogą uzyskiwać dostępu do żadnych procesów PPL/PP**

### Co musisz wiedzieć z perspektywy ofensywnej

- Gdy **LSASS działa jako PPL**, próby otwarcia go za pomocą `OpenProcess(PROCESS_VM_READ | QUERY_INFORMATION)` ze zwykłego kontekstu administratora **kończą się niepowodzeniem z kodem `0x5 (Access Denied)`**, nawet jeśli `SeDebugPrivilege` jest włączone.
- Możesz **sprawdzić poziom ochrony LSASS** za pomocą narzędzi takich jak Process Hacker lub programowo, odczytując wartość `EPROCESS.Protection`.
- LSASS zazwyczaj ma `PsProtectedSignerLsa-Light` (`0x41`), do którego dostęp mogą uzyskać **wyłącznie procesy podpisane przez signera wyższego poziomu**, takie jak `WinTcb` (`0x61` lub `0x62`).
- PPL jest ograniczeniem **wyłącznie userlandowym**; kod działający na poziomie jądra może je całkowicie ominąć.
- Fakt, że LSASS działa jako PPL, **nie uniemożliwia zrzucania poświadczeń, jeśli możesz wykonać shellcode jądra** lub **wykorzystać uprzywilejowany proces z odpowiednim dostępem**.
- **Ustawienie lub usunięcie PPL** wymaga ponownego uruchomienia systemu albo ustawień **Secure Boot/UEFI**, które mogą zachować ustawienie PPL nawet po cofnięciu zmian w rejestrze.

### Utworzenie procesu PPL podczas uruchamiania (udokumentowane API)

Windows udostępnia udokumentowany sposób żądania poziomu Protected Process Light dla procesu potomnego podczas jego tworzenia, z użyciem rozszerzonej listy atrybutów uruchamiania. Nie omija to wymagań dotyczących podpisu — obraz docelowy musi być podpisany dla żądanej klasy signera.

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
- Użyj `STARTUPINFOEX` wraz z `InitializeProcThreadAttributeList` i `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_PROTECTION_LEVEL, ...)`, a następnie przekaż `EXTENDED_STARTUPINFO_PRESENT` do `CreateProcess*`.<sup>[[2]](#references)[[3]](#references)[[4]](#references)</sup>
- `DWORD` ochrony można ustawić na stałe, takie jak `PROTECTION_LEVEL_WINTCB_LIGHT`, `PROTECTION_LEVEL_WINDOWS`, `PROTECTION_LEVEL_WINDOWS_LIGHT`, `PROTECTION_LEVEL_ANTIMALWARE_LIGHT` lub `PROTECTION_LEVEL_LSA_LIGHT`.
- Proces potomny uruchomi się jako PPL tylko wtedy, gdy jego obraz jest podpisany dla danej klasy signera; w przeciwnym razie tworzenie procesu zakończy się niepowodzeniem, zwykle z błędem `ERROR_INVALID_IMAGE_HASH (577)` / `STATUS_INVALID_IMAGE_HASH (0xC0000428)`.
- Nie jest to bypass — to obsługiwane API przeznaczone dla odpowiednio podpisanych obrazów. Przydatne do hardeningu narzędzi lub weryfikowania konfiguracji chronionych przez PPL.

Przykład CLI z użyciem minimalnego loadera:<sup>[[1]](#references)</sup>
- Antimalware signer: `CreateProcessAsPPL.exe 3 C:\Tools\agent.exe --svc`
- LSA-light signer: `CreateProcessAsPPL.exe 4 C:\Windows\System32\notepad.exe`

**Opcje bypassu ochrony PPL:**

Jeśli chcesz zrzucić LSASS mimo ochrony PPL, masz 3 główne opcje:
1. **Użyj podpisanego sterownika kernel (np. Mimikatz + mimidrv.sys)**, aby **usunąć flagę ochrony LSASS**:

![Wyjście sterownika mimidrv Mimikatz pokazujące interakcję z ochroną poświadczeń](../../images/mimidrv.png)

2. **Bring Your Own Vulnerable Driver (BYOVD)**, aby uruchomić własny kod kernel i wyłączyć ochronę. Narzędzia takie jak **PPLKiller**, **gdrv-loader** lub **kdmapper** ułatwiają wykonanie tego.
3. **Wykradnij istniejący uchwyt LSASS** z innego procesu, który ma go otwarty (np. procesu AV), a następnie **zduplikuj go** w swoim procesie. Na tym opiera się technika `pypykatz live lsa --method handledup`.
4. **Wykorzystaj uprzywilejowany proces**, który pozwala załadować dowolny kod do swojej przestrzeni adresowej lub do wnętrza innego uprzywilejowanego procesu, skutecznie omijając ograniczenia PPL. Przykład tego podejścia znajdziesz w [bypassing-lsa-protection-in-userland](https://blog.scrt.ch/2021/04/22/bypassing-lsa-protection-in-userland/) lub [https://github.com/itm4n/PPLdump](https://github.com/itm4n/PPLdump).

**Sprawdź bieżący stan ochrony LSA (PPL/PP) dla LSASS**:
```bash
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL
```
Gdy uruchomisz **`mimikatz privilege::debug sekurlsa::logonpasswords`**, prawdopodobnie zakończy się to niepowodzeniem z kodem błędu `0x00000005` z tego powodu.

- Więcej informacji na temat tego mechanizmu check znajdziesz tutaj: [https://itm4n.github.io/lsass-runasppl/](https://itm4n.github.io/lsass-runasppl/)<sup>[[5]](#references)</sup>


## Credential Guard

**Credential Guard**, funkcja dostępna wyłącznie w systemie **Windows 10 (edycje Enterprise i Education)**, zwiększa bezpieczeństwo poświadczeń maszyn przy użyciu **Virtual Secure Mode (VSM)** i **Virtualization Based Security (VBS)**. Wykorzystuje rozszerzenia wirtualizacji procesora do odizolowania kluczowych procesów w chronionej przestrzeni pamięci, poza zasięgiem głównego systemu operacyjnego. Ta izolacja gwarantuje, że nawet kernel nie może uzyskać dostępu do pamięci w VSM, skutecznie chroniąc poświadczenia przed atakami takimi jak **pass-the-hash**. **Local Security Authority (LSA)** działa w tym bezpiecznym środowisku jako trustlet, podczas gdy proces **LSASS** w głównym systemie operacyjnym pełni jedynie funkcję komunikatora z LSA w VSM.

Domyślnie **Credential Guard** nie jest aktywny i wymaga ręcznego włączenia w organizacji. Ma kluczowe znaczenie dla zwiększenia ochrony przed narzędziami takimi jak **Mimikatz**, które mają ograniczone możliwości wyodrębniania poświadczeń. Nadal można jednak wykorzystać luki poprzez dodanie niestandardowych **Security Support Providers (SSP)** w celu przechwytywania poświadczeń w jawnym tekście podczas prób logowania.

Aby sprawdzić stan aktywacji **Credential Guard**, można skontrolować klucz rejestru _**LsaCfgFlags**_ w _**HKLM\System\CurrentControlSet\Control\LSA**_. Wartość "**1**" oznacza aktywację z **UEFI lock**, "**2**" aktywację bez blokady, a "**0**" oznacza, że funkcja nie jest włączona. Ta kontrola rejestru, choć jest silnym wskaźnikiem, nie jest jedynym krokiem wymaganym do włączenia Credential Guard. Szczegółowe instrukcje oraz skrypt PowerShell umożliwiający włączenie tej funkcji są dostępne online.
```bash
reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags
```
Aby uzyskać pełne informacje i instrukcje dotyczące włączania funkcji **Credential Guard** w Windows 10 oraz jej automatycznej aktywacji w zgodnych systemach **Windows 11 Enterprise i Education (wersja 22H2)**, odwiedź [dokumentację Microsoft](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage).<sup>[[9]](#references)</sup>

Więcej informacji na temat implementowania niestandardowych SSP do przechwytywania credentials znajduje się w [tym przewodniku](../active-directory-methodology/custom-ssp.md).

## Tryb RDP RestrictedAdmin

**Windows 8.1 i Windows Server 2012 R2** wprowadziły kilka nowych funkcji zabezpieczeń, w tym _**tryb Restricted Admin dla RDP**_. Tryb ten został zaprojektowany w celu zwiększenia bezpieczeństwa poprzez ograniczenie ryzyka związanego z atakami [**pass the hash**](https://blog.ahasayen.com/pass-the-hash/).

Tradycyjnie podczas łączenia się ze zdalnym komputerem za pośrednictwem RDP poświadczenia są przechowywane na komputerze docelowym. Stanowi to poważne zagrożenie bezpieczeństwa, szczególnie w przypadku korzystania z kont z podwyższonymi uprawnieniami. Jednak wraz z wprowadzeniem _**trybu Restricted Admin**_ ryzyko to zostało znacznie ograniczone.

Po nawiązaniu połączenia RDP za pomocą polecenia **mstsc.exe /RestrictedAdmin** uwierzytelnianie na komputerze zdalnym odbywa się bez przechowywania na nim credentials. Takie podejście gwarantuje, że w przypadku infekcji malware lub uzyskania dostępu do serwera zdalnego przez złośliwego użytkownika credentials nie zostaną ujawnione, ponieważ nie są przechowywane na serwerze.

Należy pamiętać, że w **trybie Restricted Admin** próby uzyskania dostępu do zasobów sieciowych z sesji RDP nie będą korzystać z osobistych credentials użytkownika; zamiast tego używana jest **tożsamość komputera**.

Funkcja ta stanowi znaczący krok naprzód w zabezpieczaniu połączeń zdalnego pulpitu i ochronie poufnych informacji przed ujawnieniem w przypadku naruszenia bezpieczeństwa.

![Diagram pamięci RAM systemu Windows w kontekście ekstrakcji credentials](../../images/RAM.png)

Więcej szczegółowych informacji można znaleźć w [tym źródle](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/).<sup>[[6]](#references)</sup>

## Zbuforowane credentials

Windows zabezpiecza **credentials domenowe** za pośrednictwem **Local Security Authority (LSA)**, obsługując procesy logowania z użyciem protokołów bezpieczeństwa, takich jak **Kerberos** i **NTLM**. Jedną z kluczowych funkcji Windows jest możliwość buforowania **dziesięciu ostatnich logowań domenowych**, dzięki czemu użytkownicy nadal mogą uzyskać dostęp do swoich komputerów, nawet gdy **domain controller jest niedostępny** — jest to szczególnie przydatne dla użytkowników laptopów, którzy często przebywają poza siecią firmową.

Liczbę zbuforowanych logowań można dostosować za pomocą określonego **klucza rejestru lub group policy**. Aby wyświetlić lub zmienić to ustawienie, używa się następującego polecenia:
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
Dostęp do tych poświadczeń w pamięci podręcznej jest ściśle kontrolowany — tylko konto **SYSTEM** ma niezbędne uprawnienia do ich przeglądania. Administratorzy potrzebujący dostępu do tych informacji muszą korzystać z uprawnień użytkownika SYSTEM. Poświadczenia są przechowywane w: `HKEY_LOCAL_MACHINE\SECURITY\Cache`

**Mimikatz** może zostać użyty do wyodrębnienia tych poświadczeń w pamięci podręcznej za pomocą polecenia `lsadump::cache`.

Więcej informacji zawiera oryginalne [źródło](http://juggernaut.wikidot.com/cached-credentials).<sup>[[7]](#references)</sup>

## Protected Users

Członkostwo w **Protected Users group** wprowadza szereg ulepszeń zabezpieczeń dla użytkowników, zapewniając wyższy poziom ochrony przed kradzieżą i niewłaściwym użyciem poświadczeń:

- **Credential Delegation (CredSSP)**: Nawet jeśli ustawienie Group Policy **Allow delegating default credentials** jest włączone, poświadczenia użytkowników Protected Users w postaci tekstu jawnego nie będą buforowane.
- **Windows Digest**: Począwszy od **Windows 8.1 i Windows Server 2012 R2**, system nie będzie buforować poświadczeń użytkowników Protected Users w postaci tekstu jawnego, niezależnie od stanu Windows Digest.
- **NTLM**: System nie będzie buforować poświadczeń użytkowników Protected Users w postaci tekstu jawnego ani jednokierunkowych funkcji NT (NTOWF).
- **Kerberos**: W przypadku Protected Users uwierzytelnianie Kerberos nie wygeneruje kluczy **DES** ani **RC4**, a także nie będzie buforować poświadczeń w postaci tekstu jawnego ani kluczy długoterminowych poza początkowym uzyskaniem Ticket-Granting Ticket (TGT).
- **Logowanie offline**: Podczas logowania lub odblokowywania dla użytkowników Protected Users nie zostanie utworzony buforowany weryfikator, co oznacza, że logowanie offline nie jest obsługiwane dla tych kont.

Zabezpieczenia te zostają aktywowane w chwili, gdy użytkownik będący członkiem **Protected Users group** loguje się na urządzeniu. Gwarantuje to zastosowanie kluczowych środków bezpieczeństwa chroniących przed różnymi metodami przejęcia poświadczeń.

Więcej szczegółowych informacji można znaleźć w oficjalnej [dokumentacji](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group).<sup>[[10]](#references)</sup>

**Tabela z** [**dokumentacji**](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)**.**<sup>[[11]](#references)</sup>

| Windows Server 2003 RTM | Windows Server 2003 SP1+ | <p>Windows Server 2012,<br>Windows Server 2008 R2,<br>Windows Server 2008</p> | Windows Server 2016          |
| ----------------------- | ------------------------ | ----------------------------------------------------------------------------- | ---------------------------- |
| Account Operators       | Account Operators        | Account Operators                                                             | Account Operators            |
| Administrator           | Administrator            | Administrator                                                                 | Administrator                |
| Administrators          | Administrators            | Administrators                                                                | Administrators               |
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

- [1] [CreateProcessAsPPL – minimal PPL process launcher](https://github.com/2x7EQ13/CreateProcessAsPPL)
- [2] [STARTUPINFOEX structure (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-startupinfoexw)
- [3] [InitializeProcThreadAttributeList (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-initializeprocthreadattributelist)
- [4] [UpdateProcThreadAttribute (Win32 API)](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute)
- [5] [LSASS RunAsPPL – background and internals](https://itm4n.github.io/lsass-runasppl/)
- [6] [Restricted Admin Mode for RDP](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/)
- [7] [Cached Credentials - Juggernaut AppSec Wiki](http://juggernaut.wikidot.com/cached-credentials)
- [8] [WDigest Authentication (Microsoft TechNet)](<https://technet.microsoft.com/pt-pt/library/cc778868(v=ws.10).aspx?f=255&MSPPError=-2147217396>)
- [9] [Manage Windows Defender Credential Guard (Microsoft Learn)](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage)
- [10] [Protected Users Security Group (Microsoft Learn)](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group)
- [11] [Appendix C: Protected Accounts and Groups in Active Directory (Microsoft Learn)](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)

{{#include ../../banners/hacktricks-training.md}}
