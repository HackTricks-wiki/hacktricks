# LLM Training - Datavoorbereiding

{{#include ../../banners/hacktricks-training.md}}

**Hierdie is my notas uit die sterk aanbevole boek** [**https://www.manning.com/books/build-a-large-language-model-from-scratch**](https://www.manning.com/books/build-a-large-language-model-from-scratch) **met bykomende inligting.**<sup>[[1]](#references)</sup>

## Basiese Inligting

Jy behoort hierdie plasing te lees vir 'n paar basiese konsepte waarvan jy bewus moet wees:


{{#ref}}
0.-basic-llm-concepts.md
{{#endref}}

## 1. Tokenisering

> [!TIP]
> Die doel van hierdie fase is om **die invoer in tokens te verdeel en dit aan token-ID's te koppel**.


{{#ref}}
1.-tokenizing.md
{{#endref}}

## 2. Datasteekproefneming

> [!TIP]
> Die doel van hierdie fase is om opleidingreekse van 'n gekose kontekslengte, saam met hul verskuifde voorspellingsteikens, voor te berei.


{{#ref}}
2.-data-sampling.md
{{#endref}}

## 3. Token-embeddings

> [!TIP]
> Die doel van hierdie derde fase is baie eenvoudig: **Ken aan elkeen van die vorige tokens in die woordeskat 'n vektor van die verlangde dimensies toe om die model op te lei.** Elke woord in die woordeskat sal 'n punt in 'n ruimte van X dimensies wees.\
> Let daarop dat die posisie van elke woord in die ruimte aanvanklik bloot "ewekansig" geïnisialiseer word, en dat hierdie posisies opleibare parameters is (hulle sal tydens die opleiding verbeter word).
>
> Daarbenewens word daar tydens token-embedding **nog 'n embedding-laag geskep** wat (in hierdie geval) **die absolute posisie van die woord in die opleidingsin** verteenwoordig. Op hierdie manier het 'n woord op verskillende posisies in die sin 'n verskillende voorstelling.


{{#ref}}
3.-token-embeddings.md
{{#endref}}

## 4. Attention-meganismes

> [!TIP]
> Die doel van hierdie vierde fase is baie eenvoudig: **Pas sommige attention-meganismes toe**. Dit gaan baie **herhaalde lae** wees wat die **verband tussen 'n woord in die woordeskat en sy bure in die huidige sin wat gebruik word om die LLM op te lei, sal vasvang**.\
> Baie lae word hiervoor gebruik, dus sal baie opleibare parameters hierdie inligting vasvang.


{{#ref}}
4.-attention-mechanisms.md
{{#endref}}

## 5. LLM-argitektuur

> [!TIP]
> Die doel van hierdie vyfde fase is baie eenvoudig: **Ontwikkel die argitektuur van die volledige LLM**. Voeg alles saam, pas al die lae toe en skep al die funksies om teks te genereer of teks na ID's en terug te omskep.
>
> Hierdie argitektuur sal gebruik word vir beide opleiding en die voorspelling van teks nadat dit opgelei is.


{{#ref}}
5.-llm-architecture.md
{{#endref}}

## 6. Vooropleiding en die laai van modelle

> [!TIP]
> Die doel van hierdie sesde fase is baie eenvoudig: **Lei die model van nuuts af op**. Hiervoor sal die vorige LLM-argitektuur gebruik word, met lusse wat oor die datastelle gaan en die gedefinieerde verliesfunksies en optimizer gebruik om al die parameters van die model op te lei.


{{#ref}}
6.-pre-training-and-loading-models.md
{{#endref}}

## 7.0. LoRA-verbeterings in fine-tuning

> [!TIP]
> LoRA verminder die aantal opleibare parameters en optimizer-toestand wat nodig is om 'n voorafopgeleide model te fine-tune, aansienlik.


{{#ref}}
7.0.-lora-improvements-in-fine-tuning.md
{{#endref}}

## 7.1. Fine-Tuning vir klassifikasie

> [!TIP]
> Die doel van hierdie afdeling is om te wys hoe om 'n reeds voorafopgeleide model te fine-tune sodat die LLM, in plaas daarvan om nuwe teks te genereer, die **waarskynlikhede sal gee dat die gegewe teks in elk van die gegewe kategorieë geklassifiseer word** (byvoorbeeld of 'n teks spam is of nie).


{{#ref}}
7.1.-fine-tuning-for-classification.md
{{#endref}}

## 7.2. Fine-Tuning om instruksies te volg

> [!TIP]
> Die doel van hierdie afdeling is om te wys hoe om 'n reeds voorafopgeleide model te **fine-tune om instruksies te volg**, eerder as om bloot teks te genereer, byvoorbeeld om op take as 'n kletsbot te reageer.


{{#ref}}
7.2.-fine-tuning-to-follow-instructions.md
{{#endref}}

## References

- [1] [Bou 'n groot taalmodel (van nuuts af) - Manning](https://www.manning.com/books/build-a-large-language-model-from-scratch)
{{#include ../../banners/hacktricks-training.md}}
