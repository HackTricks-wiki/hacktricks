{{#include ../banners/hacktricks-training.md}}

# CBC

Ako je **kolačić** **samo** **korisničko ime** (ili je prvi deo kolačića korisničko ime) i želite da se lažno predstavljate kao korisničko ime "**admin**". Tada možete kreirati korisničko ime **"bdmin"** i **bruteforce**-ovati **prvi bajt** kolačića.

# CBC-MAC

**Cipher block chaining message authentication code** (**CBC-MAC**) je metoda koja se koristi u kriptografiji. Funkcioniše tako što uzima poruku i šifruje je blok po blok, pri čemu je šifrovanje svakog bloka povezano sa prethodnim. Ovaj proces stvara **lanac blokova**, osiguravajući da će promena čak i jednog bita originalne poruke dovesti do nepredvidive promene u poslednjem bloku šifrovanih podataka. Da bi se izvršila ili obrnula takva promena, potrebna je šifrovana ključeva, čime se osigurava bezbednost.

Da bi se izračunao CBC-MAC poruke m, šifruje se m u CBC režimu sa nultim inicijalizacionim vektorom i čuva se poslednji blok. Sledeća slika prikazuje izračunavanje CBC-MAC-a poruke koja se sastoji od blokova![https://wikimedia.org/api/rest_v1/media/math/render/svg/bbafe7330a5e40a04f01cc776c9d94fe914b17f5](https://wikimedia.org/api/rest_v1/media/math/render/svg/bbafe7330a5e40a04f01cc776c9d94fe914b17f5) koristeći tajni ključ k i blok šifru E:

![https://upload.wikimedia.org/wikipedia/commons/thumb/b/bf/CBC-MAC_structure_(en).svg/570px-CBC-MAC_structure_(en).svg.png](<https://upload.wikimedia.org/wikipedia/commons/thumb/b/bf/CBC-MAC_structure_(en).svg/570px-CBC-MAC_structure_(en).svg.png>)

# Ranljivost

Sa CBC-MAC obično je **IV koji se koristi 0**.\
To je problem jer 2 poznate poruke (`m1` i `m2`) nezavisno generišu 2 potpisa (`s1` i `s2`). Tako:

- `E(m1 XOR 0) = s1`
- `E(m2 XOR 0) = s2`

Tada poruka sastavljena od m1 i m2 konkateniranih (m3) generisaće 2 potpisa (s31 i s32):

- `E(m1 XOR 0) = s31 = s1`
- `E(m2 XOR s1) = s32`

**Što je moguće izračunati bez poznavanja ključa šifrovanja.**

Zamislite da šifrujete ime **Administrator** u **8 bajtnih** blokova:

- `Administ`
- `rator\00\00\00`

Možete kreirati korisničko ime pod nazivom **Administ** (m1) i dobiti potpis (s1).\
Zatim, možete kreirati korisničko ime koje je rezultat `rator\00\00\00 XOR s1`. Ovo će generisati `E(m2 XOR s1 XOR 0)` što je s32.\
sada, možete koristiti s32 kao potpis punog imena **Administrator**.

### Sažetak

1. Dobijte potpis korisničkog imena **Administ** (m1) koji je s1
2. Dobijte potpis korisničkog imena **rator\x00\x00\x00 XOR s1 XOR 0** je s32**.**
3. Postavite kolačić na s32 i biće to validan kolačić za korisnika **Administrator**.

# Napad Kontrolisanjem IV

Ako možete kontrolisati korišćeni IV, napad bi mogao biti vrlo lak.\
Ako je kolačić samo šifrovano korisničko ime, da biste se lažno predstavljali kao korisnik "**administrator**", možete kreirati korisnika "**Administrator**" i dobićete njegov kolačić.\
Sada, ako možete kontrolisati IV, možete promeniti prvi bajt IV-a tako da **IV\[0] XOR "A" == IV'\[0] XOR "a"** i regenerisati kolačić za korisnika **Administrator.** Ovaj kolačić će biti validan za **lažno predstavljanje** korisnika **administrator** sa inicijalnim **IV**.

## Reference

Više informacija na [https://en.wikipedia.org/wiki/CBC-MAC](https://en.wikipedia.org/wiki/CBC-MAC)

{{#include ../banners/hacktricks-training.md}}
