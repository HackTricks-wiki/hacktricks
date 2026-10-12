# Adversariële aanvalle gelei deur meganistiese interpretasie

{{#include ../banners/hacktricks-training.md}}

## Superposisie as ’n aanvalsvlak

’n Ondergeparameteriseerde aktiveringsruimte kan meer semantiese kenmerke as wat dit dimensies het kodeer deur kenmerke aan nie-ortogonale vektore toe te wys. Gevolglik projekteer ’n geaktiveerde kenmerk ook op ander kenmerkrigtings. Opleiding kan kompenseer vir kombinasies wat in-distribution voorkom, maar ’n ongewone kombinasie van andersins geldige kenmerke kan konstruktief in die rigting van ’n teikenkenmerk optel wat nie in die inset voorkom nie.<sup>[[1]](#references)[[2]](#references)</sup>

Vir kenmerkvektore `v_i ∈ R^D`, aktiverings `a_i` en teiken `t`, is die volgende grootte nuttig om kandidaatkombinasies te vind:<sup>[[1]](#references)</sup>

```text
I_t = Σ_i≠t |a_i (v_i · v_t) / ||v_t|| |
candidate condition: I_t > max(a)
```

Dit is slegs ’n siftingsheuristiek. ’n Exploit moet die tekens en groottes behou en die werklike decoder evalueer, byvoorbeeld `h_hat[t] = ReLU(b_t + Σ_i a_i(v_i · v_t))` in ’n lineêre decoder met vasgebinde gewigte. Negatiewe terme kan die aanval kanselleer, terwyl decoder-vooroordeel, kenmerkvektornorme, aktiveringsdrempels en ReLU-hekbeheer kan keer dat ’n groot absolute cosinus-telling die teikenaktivering oplewer.<sup>[[1]](#references)</sup>

## Witboks-aanvalwerkvloei

’n Praktiese assessering kan ’n modelbottelnek, ’n sparse autoencoder (SAE) of ’n ander interpreteerbare kenmerkwoordeboek gebruik. Die doel is nie bloot om die finale klas te verander nie: dit is om te sorg dat rekonstruksie ’n gekose interne kenmerk invoer wat nie voor kompressie aktief was nie. Die voorgestelde werkvloei is:<sup>[[1]](#references)</sup>

1. **Herwin kenmerkrigtings:** onttrek die relevante encoder-/decodervektore, verwyder dooie kenmerke en koppel aktiewe rigtings aan konsepte deur monsters wat dit maksimaal aktiveer of kenmerkringanalise te gebruik.
2. **Rangskik interferensie:** normaliseer ’n kopie van die vektore, bereken hul cosinus-ooreenkomsmatriks, maak die diagonaal nul en ondersoek die sterkste nie-diagonale bure van die teiken. Bereken kandidate weer met werklike aktiveringsgroottes en getekende rou puntskaleerprodukte.
3. **Dwing mede-aktivering af:** behou ’n klein stel positief bydraende kenmerke wat in dieselfde laag of residuele stroom geaktiveer kan word. Verkies kombinasies wat skaars is of nie in die opleidingsdata voorkom nie; gewone gekorreleerde kombinasies is waarskynliker tydens opleiding daarvoor gekompenseer.
4. **Sintetiseer die invoer:** kombineer datastelvoorbeelde of patrone wat aktivering maksimeer vir die geselekteerde bydraers. Vir ’n begrensde lineêre pixelverklikker, stel ’n pixel hoog vir ’n positiewe gewig en laag vir ’n negatiewe gewig, en plaas dan die resulterende patrone bo-op mekaar. Deur die in-verspreiding-struktuur en inhiberende **negatiewe ruimte** met die hand te behou, kan onverwante kenmerke onderdruk word.
5. **Verifieer die meganisme:** teken die aktiverings voor kompressie, die saamgepersde koördinate, die gerekonstrueerde aktiverings en die stroomaf-uitset in een vorentoe-deurgang aan. ’n Suksesvolle toets toon dat die teiken voor rekonstruksie onaktief is, maar daarna aktief word, en dat die voorspelde verandering verdwyn wanneer bydraers geablateer word.

Die volgende minimale triage rangskik bydraers vir ’n decoder met vasgebinde gewigte waarvan die **rye** kenmerkvektore is (transponeer eers as die kenmerke kolomme is). Gebruik rou gewigte vir die getekende telling en genormaliseerde gewigte slegs vir cosinusrangskikking.<sup>[[1]](#references)</sup>

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

Moenie afleibaarheid van ’n exploit aflei slegs op grond van cosinus-ooreenkoms nie. Toets die volledige decoder met sy bias en nie-lineariteit, bevestig dat die bydraers werklik gelyktydig kan voorkom, en vergelyk dit met ooreenstemmende kombinasies uit die verspreiding. Soortgelyke rigtings kan ’n legitieme semantiese verwantskap kodeer eerder as uitbuitbare steuring deur packing.<sup>[[1]](#references)</sup>

## Gedemonstreerde toy-model-aanval

Die proof of concept het ’n doelbewus interpreteerbare MNIST-klassifiseerder met twee takke gebruik. ’n Sparser 128-dimensionele ReLU-kenmerkvektor is direk in een tak geklassifiseer en in die ander tak saamgepers tot ’n tweedimensionele superposisieruimte; dieselfde klassifiseerder het beide die oorspronklike en gerekonstrueerde kenmerke verwerk.<sup>[[1]](#references)</sup>

```text
h       = ReLU(MLP(x))
z       = W_enc h
h_hat   = ReLU(W_enc^T z + b)
y_plain = C(h)
y_super = C(h_hat)
```

Twee kenkrigtings wat met 3/0-agtige vorms geassosieer word, het klas-5-rigtings geometries omsluit. Deur hul maksimaal aktiverende beelde by te voeg, het daardie bydraende kenmerke die sterkste geword voor kompressie, maar die rekonstruksie het verskeie klas-5-kenmerke geaktiveer en die superposisietak het 5 voorspel. ’n Handgetekende inset wat slegs minimum-/maksimum-pikselwaardes gebruik het, het die effek gereproduseer. Dit wys dat presiese gradiëntgeoptimaliseerde pixelversteurings nie in hierdie speelgoedopstelling nodig was nie.<sup>[[1]](#references)</sup>

## Geometriese siftingsproses vir groter modelle

Die artikel het ook die Gemma Scope `layer 20 / width 65k / average L0 20` SAE ondersoek. Dit het die eenheidsgenormaliseerde dekodeerdermatriks met sy getransponeerde matriks vermenigvuldig, die diagonaal op nul gestel, elke kenmerk se bure gerangskik en die gemiddeldes per rang bereken. Die gemiddelde kosinusooreenkoms met die sterkste buur was `0.49`, terwyl die gemiddelde ooreenkoms met die 27ste buur `0.25` was; geometries kon vier sulke rigtings met een teikenprojeksie op ’n eenheidsvektor ooreenstem. Hierdie syfers dui slegs kandidate aan—hulle wys nie dat vier geskikte kenmerke gesamentlik geaktiveer kan word of dat die teiken sy dekodeerderdrempel oorskry nie.<sup>[[1]](#references)</sup>

## Omvang en beperkings

Dit is ’n **white-box**-tegniek in die navorsingstadium, nie ’n gedemonstreerde aanval teen ’n ontplooide CNN of ’n grens-LLM nie. Dit vereis superposisie, bruikbare nie-ortogonale rigtings, interpreteerbare toegang tot interne kenmerke, beheerbare aktivering van die bydraende kenmerke en dat hulle tydens een voorwaartse deurloop in dieselfde laag saamgebring word.<sup>[[1]](#references)</sup>

Beeld-MLP’s maak kenmerksamestelling buitengewoon direk. ’n Transformer is moeiliker omdat attention die gekose kenmerkaktiverings in dieselfde residuele stroom moet versamel; die artikel wys nie hoe om dit vir ’n kombinasie buite die verspreiding af te dwing nie. Bewerings oor die manipulering van gedrags- of weieringsrigtings, fisiese visiestelsels of grensmodelle bly dus hipoteses.<sup>[[1]](#references)</sup>

## References

- [1] [Wilkinson and Anley — ’n Voorlopige ondersoek na interpreteerbare adversariële aanvalle deur kenmerkinmenging in superposisie (PDF)](https://www.nccgroup.com/media/kahclmxj/interpretable-adversarial-attacks-in-superpos_.pdf)
- [2] [NCC Group — Interpreteerbare adversariële aanvalle in superposisie](https://www.nccgroup.com/research/interpretable-adversarial-attacks-in-superposition/)
{{#include ../banners/hacktricks-training.md}}
