# Ochrona poświadczeń w systemie Windows

## Ochrona poświadczeń

{{#include ../../banners/hacktricks-training.md}}

## WDigest

Protokół [WDigest](<https://technet.microsoft.com/pt-pt/library/cc778868(v=ws.10).aspx?f=255&MSPPError=-2147217396>), wprowadzony z systemem Windows XP, jest zaprojektowany do uwierzytelniania za pomocą protokołu HTTP i jest **włączony domyślnie w systemach Windows XP do Windows 8.0 oraz Windows Server 2003 do Windows Server 2012**. To ustawienie domyślne skutkuje **przechowywaniem haseł w postaci niezaszyfrowanej w LSASS** (Local Security Authority Subsystem Service). Atakujący może użyć Mimikatz do **wyodrębnienia tych poświadczeń** poprzez wykonanie:
```bash
sekurlsa::wdigest
```
Aby **wyłączyć lub włączyć tę funkcję**, klucze rejestru _**UseLogonCredential**_ i _**Negotiate**_ w _**HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\SecurityProviders\WDigest**_ muszą być ustawione na "1". Jeśli te klucze są **nieobecne lub ustawione na "0"**, WDigest jest **wyłączony**:
```bash
reg query HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential
```
## Ochrona LSA

Począwszy od **Windows 8.1**, Microsoft poprawił bezpieczeństwo LSA, aby **zablokować nieautoryzowane odczyty pamięci lub wstrzykiwanie kodu przez nieufne procesy**. To ulepszenie utrudnia typowe działanie poleceń takich jak `mimikatz.exe sekurlsa:logonpasswords`. Aby **włączyć tę ulepszoną ochronę**, wartość _**RunAsPPL**_ w _**HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA**_ powinna zostać ustawiona na 1:
```
reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\LSA /v RunAsPPL
```
### Bypass

Możliwe jest obejście tej ochrony za pomocą sterownika Mimikatz mimidrv.sys:

![](../../images/mimidrv.png)

## Credential Guard

**Credential Guard**, funkcja dostępna wyłącznie w **Windows 10 (edycje Enterprise i Education)**, zwiększa bezpieczeństwo poświadczeń maszyny za pomocą **Virtual Secure Mode (VSM)** i **Virtualization Based Security (VBS)**. Wykorzystuje rozszerzenia wirtualizacji CPU do izolacji kluczowych procesów w chronionej przestrzeni pamięci, z dala od zasięgu głównego systemu operacyjnego. Ta izolacja zapewnia, że nawet jądro nie ma dostępu do pamięci w VSM, skutecznie chroniąc poświadczenia przed atakami takimi jak **pass-the-hash**. **Local Security Authority (LSA)** działa w tym bezpiecznym środowisku jako trustlet, podczas gdy proces **LSASS** w głównym systemie operacyjnym działa jedynie jako komunikator z LSA VSM.

Domyślnie **Credential Guard** nie jest aktywowany i wymaga ręcznej aktywacji w organizacji. Jest to kluczowe dla zwiększenia bezpieczeństwa przed narzędziami takimi jak **Mimikatz**, które mają ograniczone możliwości wydobywania poświadczeń. Jednak luki mogą być nadal wykorzystywane poprzez dodanie niestandardowych **Security Support Providers (SSP)** do przechwytywania poświadczeń w postaci czystego tekstu podczas prób logowania.

Aby zweryfikować status aktywacji **Credential Guard**, można sprawdzić klucz rejestru _**LsaCfgFlags**_ w _**HKLM\System\CurrentControlSet\Control\LSA**_. Wartość "**1**" oznacza aktywację z **UEFI lock**, "**2**" bez blokady, a "**0**" oznacza, że nie jest włączona. To sprawdzenie rejestru, choć jest silnym wskaźnikiem, nie jest jedynym krokiem do włączenia Credential Guard. Szczegółowe wskazówki oraz skrypt PowerShell do włączenia tej funkcji są dostępne online.
```powershell
reg query HKLM\System\CurrentControlSet\Control\LSA /v LsaCfgFlags
```
Aby uzyskać kompleksowe zrozumienie i instrukcje dotyczące włączania **Credential Guard** w systemie Windows 10 oraz jego automatycznej aktywacji w kompatybilnych systemach **Windows 11 Enterprise i Education (wersja 22H2)**, odwiedź [dokumentację Microsoftu](https://docs.microsoft.com/en-us/windows/security/identity-protection/credential-guard/credential-guard-manage).

Dalsze szczegóły dotyczące wdrażania niestandardowych SSP do przechwytywania poświadczeń znajdują się w [tym przewodniku](../active-directory-methodology/custom-ssp.md).

## Tryb RestrictedAdmin RDP

**Windows 8.1 i Windows Server 2012 R2** wprowadziły kilka nowych funkcji zabezpieczeń, w tym _**tryb Restricted Admin dla RDP**_. Tryb ten został zaprojektowany w celu zwiększenia bezpieczeństwa poprzez ograniczenie ryzyka związanego z [**pass the hash**](https://blog.ahasayen.com/pass-the-hash/) atakami.

Tradycyjnie, podczas łączenia się z zdalnym komputerem za pomocą RDP, twoje poświadczenia są przechowywane na docelowej maszynie. Stanowi to znaczące ryzyko bezpieczeństwa, szczególnie przy użyciu kont z podwyższonymi uprawnieniami. Jednak dzięki wprowadzeniu _**trybu Restricted Admin**_, to ryzyko jest znacznie zredukowane.

Podczas inicjowania połączenia RDP za pomocą polecenia **mstsc.exe /RestrictedAdmin**, uwierzytelnienie do zdalnego komputera odbywa się bez przechowywania twoich poświadczeń na nim. Takie podejście zapewnia, że w przypadku infekcji złośliwym oprogramowaniem lub jeśli złośliwy użytkownik uzyska dostęp do zdalnego serwera, twoje poświadczenia nie zostaną skompromitowane, ponieważ nie są przechowywane na serwerze.

Ważne jest, aby zauważyć, że w **trybie Restricted Admin** próby dostępu do zasobów sieciowych z sesji RDP nie będą używać twoich osobistych poświadczeń; zamiast tego używana jest **tożsamość maszyny**.

Funkcja ta stanowi znaczący krok naprzód w zabezpieczaniu połączeń pulpitu zdalnego i ochronie wrażliwych informacji przed ujawnieniem w przypadku naruszenia bezpieczeństwa.

![](../../images/RAM.png)

Aby uzyskać bardziej szczegółowe informacje, odwiedź [ten zasób](https://blog.ahasayen.com/restricted-admin-mode-for-rdp/).

## Pamiętane Poświadczenia

Windows zabezpiecza **poświadczenia domeny** za pomocą **Local Security Authority (LSA)**, wspierając procesy logowania z protokołami zabezpieczeń takimi jak **Kerberos** i **NTLM**. Kluczową cechą systemu Windows jest jego zdolność do pamiętania **ostatnich dziesięciu logowań do domeny**, aby zapewnić użytkownikom dostęp do ich komputerów, nawet jeśli **kontroler domeny jest offline**—co jest korzystne dla użytkowników laptopów często poza siecią swojej firmy.

Liczba pamiętanych logowań jest regulowana za pomocą konkretnego **klucza rejestru lub polityki grupowej**. Aby wyświetlić lub zmienić to ustawienie, wykorzystuje się następujące polecenie:
```bash
reg query "HKEY_LOCAL_MACHINE\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINLOGON" /v CACHEDLOGONSCOUNT
```
Dostęp do tych pamiętanych poświadczeń jest ściśle kontrolowany, a jedynie konto **SYSTEM** ma niezbędne uprawnienia do ich przeglądania. Administratorzy, którzy muszą uzyskać dostęp do tych informacji, muszą to zrobić z uprawnieniami użytkownika SYSTEM. Poświadczenia są przechowywane w: `HKEY_LOCAL_MACHINE\SECURITY\Cache`

**Mimikatz** może być użyty do wyodrębnienia tych pamiętanych poświadczeń za pomocą polecenia `lsadump::cache`.

Aby uzyskać więcej szczegółów, oryginalne [źródło](http://juggernaut.wikidot.com/cached-credentials) dostarcza kompleksowych informacji.

## Chronieni Użytkownicy

Członkostwo w **grupie Chronionych Użytkowników** wprowadza kilka ulepszeń bezpieczeństwa dla użytkowników, zapewniając wyższy poziom ochrony przed kradzieżą i nadużywaniem poświadczeń:

- **Delegacja Poświadczeń (CredSSP)**: Nawet jeśli ustawienie zasad grupy dla **Zezwól na delegowanie domyślnych poświadczeń** jest włączone, poświadczenia w postaci tekstu jawnego Chronionych Użytkowników nie będą pamiętane.
- **Windows Digest**: Począwszy od **Windows 8.1 i Windows Server 2012 R2**, system nie będzie pamiętał poświadczeń w postaci tekstu jawnego Chronionych Użytkowników, niezależnie od statusu Windows Digest.
- **NTLM**: System nie będzie pamiętał poświadczeń w postaci tekstu jawnego Chronionych Użytkowników ani funkcji jednokierunkowych NT (NTOWF).
- **Kerberos**: Dla Chronionych Użytkowników, uwierzytelnianie Kerberos nie wygeneruje **kluczy DES** ani **RC4**, ani nie będzie pamiętać poświadczeń w postaci tekstu jawnego ani kluczy długoterminowych poza początkowym uzyskaniem biletu TGT (Ticket-Granting Ticket).
- **Logowanie Offline**: Chronieni Użytkownicy nie będą mieli utworzonego pamiętanego weryfikatora podczas logowania lub odblokowywania, co oznacza, że logowanie offline nie jest wspierane dla tych kont.

Te zabezpieczenia są aktywowane w momencie, gdy użytkownik, który jest członkiem **grupy Chronionych Użytkowników**, loguje się do urządzenia. Zapewnia to, że krytyczne środki bezpieczeństwa są wprowadzone, aby chronić przed różnymi metodami kompromitacji poświadczeń.

Aby uzyskać bardziej szczegółowe informacje, zapoznaj się z oficjalną [dokumentacją](https://docs.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group).

**Tabela z** [**dokumentów**](https://docs.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory)**.**

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

{{#include ../../banners/hacktricks-training.md}}
