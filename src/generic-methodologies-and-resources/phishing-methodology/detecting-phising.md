# Otkrivanje Phishing-a

{{#include ../../banners/hacktricks-training.md}}

## Uvod

Da biste otkrili pokušaj phishing-a, važno je **razumeti tehnike phishing-a koje se danas koriste**. Na roditeljskoj stranici ovog posta možete pronaći te informacije, pa ako niste upoznati sa tehnikama koje se danas koriste, preporučujem vam da odete na roditeljsku stranicu i pročitate barem taj deo.

Ovaj post se zasniva na ideji da će **napadači pokušati na neki način da imituju ili koriste ime domena žrtve**. Ako se vaš domen zove `example.com` i ako ste phishing-ovani koristeći potpuno drugačije ime domena, kao što je `youwonthelottery.com`, ove tehnike neće ga otkriti.

## Varijacije imena domena

Relativno je **lako** da se **otkriju** ti **phishing** pokušaji koji će koristiti **sličan naziv domena** unutar email-a.\
Dovoljno je da **generišete listu najverovatnijih phishing imena** koje napadač može koristiti i **proverite** da li je **registrovano** ili jednostavno proverite da li postoji neki **IP** koji ga koristi.

### Pronalaženje sumnjivih domena

Za ovu svrhu možete koristiti bilo koji od sledećih alata. Imajte na umu da će ovi alati takođe automatski izvršiti DNS zahteve da provere da li domen ima dodeljen neki IP:

- [**dnstwist**](https://github.com/elceef/dnstwist)
- [**urlcrazy**](https://github.com/urbanadventurer/urlcrazy)

### Bitflipping

**Možete pronaći kratko objašnjenje ove tehnike na roditeljskoj stranici. Ili pročitajte originalno istraživanje na** [**https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/**](https://www.bleepingcomputer.com/news/security/hijacking-traffic-to-microsoft-s-windowscom-with-bitflipping/)

Na primer, 1 bit modifikacija u domenu microsoft.com može ga transformisati u _windnws.com._\
**Napadači mogu registrovati što više domena sa bit-flipping-om koji su povezani sa žrtvom kako bi preusmerili legitimne korisnike na svoju infrastrukturu**.

**Svi mogući nazivi domena sa bit-flipping-om takođe bi trebali biti praćeni.**

### Osnovne provere

Kada imate listu potencijalno sumnjivih imena domena, trebali biste ih **proveriti** (pretežno portove HTTP i HTTPS) da **vidite da li koriste neki obrazac za prijavu sličan** nekom od domena žrtve.\
Takođe možete proveriti port 3333 da vidite da li je otvoren i da li pokreće instancu `gophish`.\
Takođe je zanimljivo znati **koliko je stara svaka otkrivena sumnjiva domena**, što je mlađa, to je rizičnija.\
Možete takođe dobiti **screenshot-ove** sumnjive web stranice HTTP i/ili HTTPS da vidite da li je sumnjiva i u tom slučaju **pristupiti joj da biste je detaljnije pregledali**.

### Napredne provere

Ako želite da idete korak dalje, preporučujem vam da **pratite te sumnjive domene i povremeno tražite više** (svakog dana? to traje samo nekoliko sekundi/minuta). Takođe biste trebali **proveriti** otvorene **portove** povezanih IP-ova i **tražiti instance `gophish` ili slične alate** (da, napadači takođe prave greške) i **pratiti HTTP i HTTPS web stranice sumnjivih domena i poddomena** da vidite da li su kopirali neki obrazac za prijavu sa web stranica žrtve.\
Da biste **automatizovali ovo**, preporučujem da imate listu obrazaca za prijavu domena žrtve, da pretražujete sumnjive web stranice i upoređujete svaki obrazac za prijavu pronađen unutar sumnjivih domena sa svakim obrascem za prijavu domena žrtve koristeći nešto poput `ssdeep`.\
Ako ste locirali obrasce za prijavu sumnjivih domena, možete pokušati da **pošaljete lažne kredencijale** i **proverite da li vas preusmerava na domen žrtve**.

## Imena domena koristeći ključne reči

Roditeljska stranica takođe pominje tehniku varijacije imena domena koja se sastoji od stavljanja **imena domena žrtve unutar većeg domena** (npr. paypal-financial.com za paypal.com).

### Transparentnost sertifikata

Nije moguće primeniti prethodni pristup "Brute-Force", ali je zapravo **moguće otkriti takve phishing pokušaje** takođe zahvaljujući transparentnosti sertifikata. Svaki put kada sertifikat izda CA, detalji se objavljuju. To znači da čitanjem transparentnosti sertifikata ili čak njenim praćenjem, **može se pronaći domene koje koriste ključnu reč unutar svog imena**. Na primer, ako napadač generiše sertifikat za [https://paypal-financial.com](https://paypal-financial.com), gledajući sertifikat moguće je pronaći ključnu reč "paypal" i znati da se koristi sumnjivi email.

Post [https://0xpatrik.com/phishing-domains/](https://0xpatrik.com/phishing-domains/) sugeriše da možete koristiti Censys da tražite sertifikate koji utiču na određenu ključnu reč i filtrirate po datumu (samo "novi" sertifikati) i po CA izdavaču "Let's Encrypt":

![https://0xpatrik.com/content/images/2018/07/cert_listing.png](<../../images/image (1115).png>)

Međutim, možete učiniti "isto" koristeći besplatni web [**crt.sh**](https://crt.sh). Možete **tražiti ključnu reč** i **filtrirati** rezultate **po datumu i CA** ako želite.

![](<../../images/image (519).png>)

Korišćenjem ove poslednje opcije možete čak koristiti polje Matching Identities da vidite da li se neka identitet iz pravog domena poklapa sa bilo kojim od sumnjivih domena (imajte na umu da sumnjivi domen može biti lažno pozitivan).

**Još jedna alternativa** je fantastičan projekat pod nazivom [**CertStream**](https://medium.com/cali-dog-security/introducing-certstream-3fc13bb98067). CertStream pruža real-time tok novoregistrovanih sertifikata koje možete koristiti za otkrivanje određenih ključnih reči u (neposrednom) realnom vremenu. U stvari, postoji projekat pod nazivom [**phishing_catcher**](https://github.com/x0rz/phishing_catcher) koji to upravo radi.

### **Novi domeni**

**Jedna poslednja alternativa** je da prikupite listu **novoregistrovanih domena** za neke TLD-ove ([Whoxy](https://www.whoxy.com/newly-registered-domains/) pruža takvu uslugu) i **proverite ključne reči u tim domenima**. Međutim, dugi domeni obično koriste jedan ili više poddomena, stoga ključna reč neće biti prisutna unutar FLD-a i nećete moći pronaći phishing poddomen.

{{#include ../../banners/hacktricks-training.md}}
