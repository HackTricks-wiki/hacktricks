# Adversarialni napadi vođeni mehanističkom interpretabilnošću

{{#include ../banners/hacktricks-training.md}}

## Superpozicija kao površina napada

Nedovoljno parametrizovan aktivacioni prostor može da kodira više semantičkih obeležja nego što ima dimenzija tako što obeležjima dodeljuje neortogonalne vektore. Zbog toga se aktivirano obeležje projektuje i na pravce drugih obeležja. Treniranje može da kompenzuje kombinacije viđene u distribuciji, ali neuobičajena kombinacija inače validnih obeležja može konstruktivno da se sabira u pravcu ciljnog obeležja koje nije prisutno u ulazu.<sup>[[1]](#references)[[2]](#references)</sup>

Za vektore obeležja `v_i ∈ R^D`, aktivacije `a_i` i cilj `t`, sledeća veličina je korisna za pronalaženje potencijalnih kombinacija:<sup>[[1]](#references)</sup>

```text
I_t = Σ_i≠t |a_i (v_i · v_t) / ||v_t|| |
candidate condition: I_t > max(a)
```

Ovo je samo heuristika za početnu procenu. Exploit mora da zadrži znakove i veličine vrednosti i da evaluira stvarni decoder, na primer `h_hat[t] = ReLU(b_t + Σ_i a_i(v_i · v_t))` kod linearnog decodera sa vezanim težinama. Negativni članovi mogu da ponište napad, dok bias decodera, norme vektora karakteristika, pragovi aktivacije i ReLU gating mogu sprečiti da veliki apsolutni cosine score proizvede ciljnu aktivaciju.<sup>[[1]](#references)</sup>

## Tok rada za white-box napad

Praktična procena može da koristi usko grlo modela, sparse autoencoder (SAE) ili drugi interpretabilni rečnik karakteristika. Cilj nije samo da se promeni konačna klasa, već da rekonstrukcija uvede odabranu internu karakteristiku koja nije bila aktivna pre kompresije. Predloženi tok rada je:<sup>[[1]](#references)</sup>

1. **Oporavite pravce karakteristika:** izdvojite relevantne vektore enkodera/dekodera, uklonite mrtve karakteristike i povežite aktivne pravce sa konceptima pomoću uzoraka koji ih maksimalno aktiviraju ili analizom kola karakteristika.
2. **Rangirajte interferenciju:** normalizujte kopiju vektora, izračunajte matricu kosinusne sličnosti, uklonite dijagonalu i pregledajte najjače van-dijagonalne susede cilja. Ponovo izračunajte kandidate koristeći stvarne veličine aktivacija i potpisane sirove skalarne proizvode.
3. **Obezbedite koaktivaciju:** zadržite mali skup karakteristika koje daju pozitivan doprinos i mogu istovremeno da se aktiviraju u istom sloju ili rezidualnom toku. Dajte prednost kombinacijama koje su retke ili odsutne u podacima za obuku; obične korelisane kombinacije verovatnije su već kompenzovane tokom obuke.
4. **Sintetišite ulaz:** kombinujte primere iz skupa podataka ili obrasce koji maksimalno aktiviraju izabrane doprinosioce. Za ograničeni linearni detektor piksela, postavite piksel na visoku vrednost ako je težina pozitivna, a na nisku ako je negativna, pa zatim preklopite dobijene obrasce. Ručnim očuvanjem strukture iz distribucije i inhibitornog **negativnog prostora** mogu se potisnuti nepovezane karakteristike.
5. **Proverite mehanizam:** u jednom prolazu unapred zabeležite aktivacije pre kompresije, kompresovane koordinate, rekonstruisane aktivacije i izlaz nizvodnog dela. Uspešan test pokazuje da cilj nije aktivan pre rekonstrukcije, ali jeste nakon nje, a da predviđena promena nestaje kada se doprinosioci abluju.

Sledeća minimalna trijaža rangira doprinosioce za decoder sa vezanim težinama čiji su **redovi** vektori karakteristika (ako su karakteristike predstavljene kolonama, prvo transponujte). Za potpisani skor koristite sirove težine, a za rangiranje po kosinusnoj sličnosti normalizovane težine.<sup>[[1]](#references)</sup>

```python
import numpy as np

norm = np.linalg.norm(W_dec, axis=1, keepdims=True)
unit = W_dec / np.clip(norm, 1e-12, None)
cosine = unit @ unit.T
np.fill_diagonal(cosine, 0.0)

target = 42
signed = activations * (W_dec @ W_dec[target])
signed[target] = -np.inf
order = np.argsort(signed)[::-1]
print([(int(i), float(signed[i]), float(cosine[i, target]))
       for i in order[:20] if signed[i] > 0])
```

Ne zaključujte da je nešto moguće iskoristiti samo na osnovu kosinusne sličnosti. Testirajte ceo decoder, uključujući njegov bias i nelinearnost, potvrdite da doprinosioci zaista mogu da se pojave istovremeno i uporedite ih sa odgovarajućim kombinacijama iz distribucije. Slični pravci mogu kodirati legitimnu semantičku vezu, a ne iskoristivu interferenciju usled pakovanja.<sup>[[1]](#references)</sup>

## Demonstrirani napad na toy model

Dokaz koncepta koristio je namerno lako protumačiv MNIST klasifikator sa dve grane. Retki 128-dimenzionalni vektor ReLU osobina klasifikovan je direktno u jednoj grani, a u drugoj komprimovan u dvodimenzionalni prostor superpozicije; isti klasifikator je obradio i izvorne i rekonstruisane osobine.<sup>[[1]](#references)</sup>

```text
h       = ReLU(MLP(x))
z       = W_enc h
h_hat   = ReLU(W_enc^T z + b)
y_plain = C(h)
y_super = C(h_hat)
```

Dva pravca osobina povezana sa oblicima nalik 3/0 bili su geometrijski okruženi pravcima klase 5. Dodavanje njihovih slika koje ih maksimalno aktiviraju učinilo je te osobine koje doprinose najjačima pre kompresije, ali je rekonstrukcija aktivirala nekoliko osobina klase 5, pa je grana superpozicije predvidela 5. Ručno nacrtan ulaz koji koristi samo minimalne i maksimalne vrednosti piksela reprodukovao je ovaj efekat, što pokazuje da u ovom igračkom okruženju nisu bile potrebne precizne perturbacije piksela optimizovane gradijentom.<sup>[[1]](#references)</sup>

## Geometrijska trijaža većeg modela

Rad je ispitao i Gemma Scope `layer 20 / width 65k / average L0 20` SAE. Pomnožili su dekodersku matricu normalizovanu na jediničnu normu njenom transponovanom matricom, postavili elemente dijagonale na nulu, sortirali susede svake osobine i izračunali prosek po rangu. Prosečna kosinusna sličnost sa najbližim susedom bila je `0.49`, dok je prosečna sličnost sa 27. susedom bila `0.25`; geometrijski, četiri takva pravca mogla bi da odgovaraju jediničnoj projekciji cilja. Ove vrednosti samo izdvajaju kandidate — ne pokazuju da se četiri odgovarajuće osobine mogu zajednički aktivirati niti da cilj prelazi prag dekodera.<sup>[[1]](#references)</sup>

## Opseg i ograničenja

Ovo je tehnika u fazi istraživanja **white-box**, a ne demonstrirani napad na CNN ili frontier LLM koji su pušteni u upotrebu. Zahteva superpoziciju, korisne neortogonalne pravce, pristup internim osobinama koje se mogu tumačiti, mogućnost kontrolisanja aktivacije osobina koje doprinose i njihovo okupljanje u istom sloju tokom jednog prolaza unapred.<sup>[[1]](#references)</sup>

MLP-ovi za slike omogućavaju neuobičajeno direktno kombinovanje osobina. Transformer je teži jer pažnja mora da prikupi izabrane aktivacije osobina u isti rezidualni tok; rad ne pokazuje kako to nametnuti za kombinaciju van distribucije. Tvrdnje o manipulisanju pravcima ponašanja ili odbijanja, fizičkim sistemima vida ili frontier modelima stoga ostaju hipoteze.<sup>[[1]](#references)</sup>

## References

- [1] [Wilkinson and Anley — Preliminarno istraživanje interpretabilnih adversarijalnih napada posredstvom interferencije osobina u superpoziciji (PDF)](https://www.nccgroup.com/media/kahclmxj/interpretable-adversarial-attacks-in-superpos_.pdf)
- [2] [NCC Group — Interpretabilni adversarijalni napadi u superpoziciji](https://www.nccgroup.com/research/interpretable-adversarial-attacks-in-superposition/)
{{#include ../banners/hacktricks-training.md}}
