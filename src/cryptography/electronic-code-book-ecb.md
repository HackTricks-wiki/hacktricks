{{#include ../banners/hacktricks-training.md}}

# ECB

(ECB) Elektronska knjiga kodova - simetrična šema enkripcije koja **menja svaki blok otvorenog teksta** sa **blokom šifrovanog teksta**. To je **najjednostavnija** šema enkripcije. Glavna ideja je da se **podeli** otvoreni tekst na **blokove od N bita** (zavisi od veličine bloka ulaznih podataka, algoritma enkripcije) i zatim da se enkriptuje (dekriptuje) svaki blok otvorenog teksta koristeći jedini ključ.

![](https://upload.wikimedia.org/wikipedia/commons/thumb/e/e6/ECB_decryption.svg/601px-ECB_decryption.svg.png)

Korišćenje ECB ima više bezbednosnih implikacija:

- **Blokovi iz šifrovane poruke mogu biti uklonjeni**
- **Blokovi iz šifrovane poruke mogu biti pomerani**

# Otkrivanje ranjivosti

Zamislite da se prijavljujete u aplikaciju nekoliko puta i **uvek dobijate isti kolačić**. To je zato što je kolačić aplikacije **`<username>|<password>`**.\
Zatim, generišete nove korisnike, oboje sa **istim dugim lozinkama** i **gotovo** **istim** **korisničkim imenima**.\
Otkrivate da su **blokovi od 8B** gde su **informacije obojice korisnika** iste **jednaki**. Tada zamišljate da bi to moglo biti zato što se **koristi ECB**.

Kao u sledećem primeru. Posmatrajte kako ova **2 dekodirana kolačića** imaju nekoliko puta blok **`\x23U\xE45K\xCB\x21\xC8`**.
```
\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8\x04\xB6\xE1H\xD1\x1E \xB6\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8+=\xD4F\xF7\x99\xD9\xA9

\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8\x04\xB6\xE1H\xD1\x1E \xB6\x23U\xE45K\xCB\x21\xC8\x23U\xE45K\xCB\x21\xC8+=\xD4F\xF7\x99\xD9\xA9
```
Ovo je zato što **korisničko ime i lozinka tih kolačića sadrže nekoliko puta slovo "a"** (na primer). **Blokovi** koji su **različiti** su blokovi koji sadrže **barem 1 različit karakter** (možda delimiter "|" ili neka neophodna razlika u korisničkom imenu).

Sada, napadaču je potrebno samo da otkrije da li je format `<username><delimiter><password>` ili `<password><delimiter><username>`. Da bi to uradio, može jednostavno **generisati nekoliko korisničkih imena** sa **sličnim i dugim korisničkim imenima i lozinkama dok ne pronađe format i dužinu delimitera:**

| Dužina korisničkog imena: | Dužina lozinke: | Dužina korisničkog imena+lozinke: | Dužina kolačića (nakon dekodiranja): |
| -------------------------- | ---------------- | --------------------------------- | ------------------------------------- |
| 2                          | 2                | 4                                 | 8                                   |
| 3                          | 3                | 6                                 | 8                                   |
| 3                          | 4                | 7                                 | 8                                   |
| 4                          | 4                | 8                                 | 16                                  |
| 7                          | 7                | 14                                | 16                                  |

# Iskorišćavanje ranjivosti

## Uklanjanje celih blokova

Znajući format kolačića (`<username>|<password>`), kako bi se predstavio kao korisnik `admin`, kreirajte novog korisnika pod imenom `aaaaaaaaadmin` i dobijte kolačić i dekodirajte ga:
```
\x23U\xE45K\xCB\x21\xC8\xE0Vd8oE\x123\aO\x43T\x32\xD5U\xD4
```
Možemo videti obrazac `\x23U\xE45K\xCB\x21\xC8` koji je prethodno kreiran sa korisničkim imenom koje je sadržalo samo `a`.\
Zatim, možete ukloniti prvi blok od 8B i dobićete važeći kolačić za korisničko ime `admin`:
```
\xE0Vd8oE\x123\aO\x43T\x32\xD5U\xD4
```
## Premještanje blokova

U mnogim bazama podataka je isto pretraživati `WHERE username='admin';` ili `WHERE username='admin    ';` _(Obratite pažnju na dodatne razmake)_

Dakle, drugi način da se impersonira korisnik `admin` bio bi:

- Generisati korisničko ime koje: `len(<username>) + len(<delimiter) % len(block)`. Sa veličinom bloka od `8B` možete generisati korisničko ime pod nazivom: `username       `, sa delimiterom `|` deo `<username><delimiter>` će generisati 2 bloka od 8B.
- Zatim, generisati lozinku koja će popuniti tačan broj blokova koji sadrže korisničko ime koje želimo da impersoniramo i razmake, kao što je: `admin   `

Kolačić ovog korisnika će se sastojati od 3 bloka: prva 2 su blokovi korisničkog imena + delimiter, a treći je lozinka (koja lažira korisničko ime): `username       |admin   `

**Zatim, samo zamenite prvi blok sa poslednjim i bićete impersonirajući korisnika `admin`: `admin          |username`**

## Reference

- [http://cryptowiki.net/index.php?title=Electronic_Code_Book\_(ECB)](<http://cryptowiki.net/index.php?title=Electronic_Code_Book_(ECB)>)

{{#include ../banners/hacktricks-training.md}}
