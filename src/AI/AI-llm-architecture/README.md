# LLM Training - Datavoorbereiding

{{#include ../../banners/hacktricks-training.md}}

**Dit is my notas uit die sterk aanbevole boek** [**https://www.manning.com/books/build-a-large-language-model-from-scratch**](https://www.manning.com/books/build-a-large-language-model-from-scratch) **met bykomende inligting.**<sup>[[1]](#references)</sup>

## Basiese Inligting

Jy behoort hierdie plasing te lees vir ’n paar basiese konsepte wat jy behoort te ken:


{{#ref}}
0.-basic-llm-concepts.md
{{#endref}}

## 1. Tokenization

> [!TIP]
> Die doel van hierdie aanvanklike fase is baie eenvoudig: **Verdeel die invoer op ’n sinvolle manier in tokens (ids)**.


{{#ref}}
1.-tokenizing.md
{{#endref}}

## 2. Data Sampling

> [!TIP]
> Die doel van hierdie tweede fase is baie eenvoudig: **Sample die invoerdata en berei dit voor vir die training-fase, gewoonlik deur die dataset in sinne van ’n spesifieke lengte te verdeel en ook die verwagte respons te genereer.**


{{#ref}}
2.-data-sampling.md
{{#endref}}

## 3. Token Embeddings

> [!TIP]
> Die doel van hierdie derde fase is baie eenvoudig: **Ken aan elkeen van die vorige tokens in die woordeskat ’n vektor met die verlangde dimensies toe om die model te train.** Elke woord in die woordeskat sal ’n punt in ’n ruimte met X dimensies wees.\
> Let daarop dat die posisie van elke woord in die ruimte aanvanklik net “ewekansig” geïnisialiseer word, en dat hierdie posisies trainable parameters is (dit sal tydens die training verbeter word).
>
> Verder word daar tydens die token embedding **nog ’n laag embeddings geskep** wat (in hierdie geval) die **absolute posisie van die woord in die training-sin** voorstel. Op hierdie manier sal ’n woord op verskillende posisies in die sin ’n verskillende voorstelling (betekenis) hê.


{{#ref}}
3.-token-embeddings.md
{{#endref}}

## 4. Attention Mechanisms

> [!TIP]
> Die doel van hierdie vierde fase is baie eenvoudig: **Pas sommige attention mechanisms toe**. Dit gaan uit ’n groot aantal **herhaalde lae** bestaan wat die **verhouding tussen ’n woord in die woordeskat en sy bure in die huidige sin wat gebruik word om die LLM te train, sal vasvang**.\
> Baie lae word hiervoor gebruik, dus gaan baie trainable parameters hierdie inligting vasvang.


{{#ref}}
4.-attention-mechanisms.md
{{#endref}}

## 5. LLM Architecture

> [!TIP]
> Die doel van hierdie vyfde fase is baie eenvoudig: **Ontwikkel die architecture van die volledige LLM**. Voeg alles saam, pas al die lae toe en skep al die funksies om teks te genereer of teks na IDs en terug te transformeer.
>
> Hierdie architecture sal vir beide training en die voorspelling van teks ná training gebruik word.


{{#ref}}
5.-llm-architecture.md
{{#endref}}

## 6. Pre-training & Loading models

> [!TIP]
> Die doel van hierdie sesde fase is baie eenvoudig: **Train die model van nuuts af**. Hiervoor sal die vorige LLM architecture gebruik word, met sommige loops wat oor die datasets gaan en die gedefinieerde loss functions en optimizer gebruik om al die parameters van die model te train.


{{#ref}}
6.-pre-training-and-loading-models.md
{{#endref}}

## 7.0. LoRA Improvements in fine-tuning

> [!TIP]
> Die gebruik van **LoRA verminder die computation wat nodig is** om reeds getrainde modelle te **fine-tune** aansienlik.


{{#ref}}
7.0.-lora-improvements-in-fine-tuning.md
{{#endref}}

## 7.1. Fine-Tuning for Classification

> [!TIP]
> Die doel van hierdie afdeling is om te wys hoe om ’n reeds pre-trained model te fine-tune sodat die LLM, in plaas daarvan om nuwe teks te genereer, die **waarskynlikhede sal gee dat die gegewe teks in elk van die gegewe categories gekategoriseer word** (byvoorbeeld of ’n teks spam is of nie).


{{#ref}}
7.1.-fine-tuning-for-classification.md
{{#endref}}

## 7.2. Fine-Tuning to follow instructions

> [!TIP]
> Die doel van hierdie afdeling is om te wys hoe om ’n **reeds pre-trained model te fine-tune om instruksies te volg** eerder as om net teks te genereer, byvoorbeeld deur op take as ’n chat bot te reageer.


{{#ref}}
7.2.-fine-tuning-to-follow-instructions.md
{{#endref}}

## Verwysings

- [1] [Build a Large Language Model (From Scratch) - Manning](https://www.manning.com/books/build-a-large-language-model-from-scratch)

{{#include ../../banners/hacktricks-training.md}}
