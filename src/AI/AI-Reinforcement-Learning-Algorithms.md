# Versterking Leer Algoritmes

{{#include ../banners/hacktricks-training.md}}

## Versterking Leer

Versterking leer (RL) is 'n tipe masjienleer waar 'n agent leer om besluite te neem deur met 'n omgewing te kommunikeer. Die agent ontvang terugvoer in die vorm van belonings of strawwe gebaseer op sy aksies, wat dit toelaat om optimale gedrag oor tyd te leer. RL is veral nuttig vir probleme waar die oplossing sekwensiële besluitneming behels, soos robotika, speletjies speel, en outonome stelsels.

### Q-Learning

Q-Learning is 'n model-vrye versterking leer algoritme wat die waarde van aksies in 'n gegewe toestand leer. Dit gebruik 'n Q-tabel om die verwagte nut van die neem van 'n spesifieke aksie in 'n spesifieke toestand te stoor. Die algoritme werk die Q-waardes op gebaseer op die belonings wat ontvang is en die maksimum verwagte toekomstige belonings.
1. **Inisialiserings**: Inisialiseer die Q-tabel met arbitrêre waardes (dikwels nul).
2. **Aksie Keuse**: Kies 'n aksie met 'n verkenningsstrategie (bv. ε-greedy, waar met 'n waarskynlikheid van ε 'n ewekansige aksie gekies word, en met 'n waarskynlikheid van 1-ε die aksie met die hoogste Q-waarde gekies word).
- Let daarop dat die algoritme altyd die bekende beste aksie kan kies gegewe 'n toestand, maar dit sal nie die agent toelaat om nuwe aksies te verken wat beter belonings kan oplewer nie. Daarom word die ε-greedy veranderlike gebruik om verkenning en benutting te balanseer.
3. **Interaksie met die Omgewing**: Voer die gekose aksie in die omgewing uit, observeer die volgende toestand en beloning.
- Let daarop dat, afhangende van die ε-greedy waarskynlikheid, die volgende stap 'n ewekansige aksie kan wees (vir verkenning) of die beste bekende aksie (vir benutting).
4. **Q-Waarde Opdatering**: Werk die Q-waarde vir die toestand-aksie paar op met behulp van die Bellman vergelyking:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * max(Q(s', a')) - Q(s, a))
```
waar:
- `Q(s, a)` is die huidige Q-waarde vir toestand `s` en aksie `a`.
- `α` is die leer tempo (0 < α ≤ 1), wat bepaal hoeveel die nuwe inligting die ou inligting oorskry.
- `r` is die beloning wat ontvang is na die neem van aksie `a` in toestand `s`.
- `γ` is die afslag faktor (0 ≤ γ < 1), wat die belangrikheid van toekomstige belonings bepaal.
- `s'` is die volgende toestand na die neem van aksie `a`.
- `max(Q(s', a'))` is die maksimum Q-waarde vir die volgende toestand `s'` oor alle moontlike aksies `a'`.
5. **Herhaling**: Herhaal stappe 2-4 totdat die Q-waardes konvergeer of 'n stopkriterium bereik word.

Let daarop dat met elke nuwe gekose aksie die tabel opdateer word, wat die agent toelaat om oor tyd van sy ervarings te leer om te probeer om die optimale beleid te vind (die beste aksie om in elke toestand te neem). Die Q-tabel kan egter groot word vir omgewings met baie toestande en aksies, wat dit onprakties maak vir komplekse probleme. In sulke gevalle kan funksie benaderingsmetodes (bv. neurale netwerke) gebruik word om Q-waardes te skat.

> [!TIP]
> Die ε-greedy waarde word gewoonlik oor tyd opdateer om verkenning te verminder namate die agent meer oor die omgewing leer. Byvoorbeeld, dit kan begin met 'n hoë waarde (bv. ε = 1) en dit afneem na 'n laer waarde (bv. ε = 0.1) namate die leer vorder.

> [!TIP]
> Die leer tempo `α` en die afslag faktor `γ` is hiperparameters wat aangepas moet word op grond van die spesifieke probleem en omgewing. 'n Hoër leer tempo laat die agent toe om vinniger te leer, maar kan tot onstabiliteit lei, terwyl 'n laer leer tempo lei tot meer stabiele leer maar stadiger konvergensie. Die afslag faktor bepaal hoeveel die agent toekomstige belonings waardeer (`γ` nader aan 1) in vergelyking met onmiddellike belonings.

### SARSA (Staat-Aksie-Beloning-Staat-Aksie)

SARSA is 'n ander model-vrye versterking leer algoritme wat soortgelyk is aan Q-Learning, maar verskil in hoe dit die Q-waardes opdateer. SARSA staan vir Staat-Aksie-Beloning-Staat-Aksie, en dit werk die Q-waardes op gebaseer op die aksie wat in die volgende toestand geneem word, eerder as die maksimum Q-waarde.
1. **Inisialiserings**: Inisialiseer die Q-tabel met arbitrêre waardes (dikwels nul).
2. **Aksie Keuse**: Kies 'n aksie met 'n verkenningsstrategie (bv. ε-greedy).
3. **Interaksie met die Omgewing**: Voer die gekose aksie in die omgewing uit, observeer die volgende toestand en beloning.
- Let daarop dat, afhangende van die ε-greedy waarskynlikheid, die volgende stap 'n ewekansige aksie kan wees (vir verkenning) of die beste bekende aksie (vir benutting).
4. **Q-Waarde Opdatering**: Werk die Q-waarde vir die toestand-aksie paar op met behulp van die SARSA opdateringsreël. Let daarop dat die opdateringsreël soortgelyk is aan Q-Learning, maar dit gebruik die aksie wat in die volgende toestand `s'` geneem sal word eerder as die maksimum Q-waarde vir daardie toestand:
```plaintext
Q(s, a) = Q(s, a) + α * (r + γ * Q(s', a') - Q(s, a))
```
waar:
- `Q(s, a)` is die huidige Q-waarde vir toestand `s` en aksie `a`.
- `α` is die leer tempo.
- `r` is die beloning wat ontvang is na die neem van aksie `a` in toestand `s`.
- `γ` is die afslag faktor.
- `s'` is die volgende toestand na die neem van aksie `a`.
- `a'` is die aksie wat in die volgende toestand `s'` geneem word.
5. **Herhaling**: Herhaal stappe 2-4 totdat die Q-waardes konvergeer of 'n stopkriterium bereik word.

#### Softmax vs ε-Greedy Aksie Keuse

Benewens ε-greedy aksie keuse, kan SARSA ook 'n softmax aksie keuse strategie gebruik. In softmax aksie keuse is die waarskynlikheid om 'n aksie te kies **proportioneel aan sy Q-waarde**, wat 'n meer genuanseerde verkenning van die aksieruimte toelaat. Die waarskynlikheid om aksie `a` in toestand `s` te kies, word gegee deur:
```plaintext
P(a|s) = exp(Q(s, a) / τ) / Σ(exp(Q(s, a') / τ))
```
waar:
- `P(a|s)` is die waarskynlikheid om aksie `a` in toestand `s` te kies.
- `Q(s, a)` is die Q-waarde vir toestand `s` en aksie `a`.
- `τ` (tau) is die temperatuurparameter wat die vlak van verkenning beheer. 'n Hoër temperatuur lei tot meer verkenning (meer uniforme waarskynlikhede), terwyl 'n laer temperatuur lei tot meer benutting (hoër waarskynlikhede vir aksies met hoër Q-waardes).

> [!TIP]
> Dit help om verkenning en benutting in 'n meer deurlopende manier te balanseer in vergelyking met ε-greedy aksiekeuse.

### Op-Polis vs Af-Polis Leer

SARSA is 'n **op-polis** leeralgoritme, wat beteken dat dit die Q-waardes opdateer gebaseer op die aksies wat deur die huidige beleid geneem is (die ε-greedy of softmax beleid). In teenstelling hiermee is Q-Learning 'n **af-polis** leeralgoritme, aangesien dit die Q-waardes opdateer gebaseer op die maksimum Q-waarde vir die volgende toestand, ongeag die aksie wat deur die huidige beleid geneem is. Hierdie onderskeid beïnvloed hoe die algoritmes leer en aanpas by die omgewing.

Op-polis metodes soos SARSA kan meer stabiel wees in sekere omgewings, aangesien hulle leer uit die aksies wat werklik geneem is. Hulle kan egter stadiger konvergeer in vergelyking met af-polis metodes soos Q-Learning, wat uit 'n breër reeks ervarings kan leer.

{{#include ../banners/hacktricks-training.md}}
