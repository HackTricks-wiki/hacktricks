# LLM Opleiding - Data Voorbereiding

**Dit is my aantekeninge uit die baie aanbevole boek** [**https://www.manning.com/books/build-a-large-language-model-from-scratch**](https://www.manning.com/books/build-a-large-language-model-from-scratch) **met 'n paar ekstra inligting.**

## Basiese Inligting

Jy moet begin deur hierdie pos te lees vir 'n paar basiese konsepte wat jy moet weet:

{{#ref}}
0.-basic-llm-concepts.md
{{#endref}}

## 1. Tokenisering

> [!TIP]
> Die doel van hierdie aanvanklike fase is baie eenvoudig: **Verdeel die invoer in tokens (ids) op 'n manier wat sin maak**.

{{#ref}}
1.-tokenizing.md
{{#endref}}

## 2. Data Monsters

> [!TIP]
> Die doel van hierdie tweede fase is baie eenvoudig: **Monster die invoerdata en berei dit voor vir die opleidingsfase deur gewoonlik die datastel in sinne van 'n spesifieke lengte te skei en ook die verwagte reaksie te genereer.**

{{#ref}}
2.-data-sampling.md
{{#endref}}

## 3. Token Inbedings

> [!TIP]
> Die doel van hierdie derde fase is baie eenvoudig: **Ken elkeen van die vorige tokens in die woordeskat 'n vektor van die verlangde dimensies toe om die model te oefen.** Elke woord in die woordeskat sal 'n punt in 'n ruimte van X dimensies wees.\
> Let daarop dat die posisie van elke woord in die ruimte aanvanklik net "ewekansig" geinitialiseer word en hierdie posisies is opleibare parameters (sal verbeter word tydens die opleiding).
>
> Boonop, tydens die token inbedding **word 'n ander laag van inbeddings geskep** wat (in hierdie geval) die **absolute posisie van die woord in die opleidingssin** verteenwoordig. Op hierdie manier sal 'n woord in verskillende posisies in die sin 'n ander voorstelling (betekenis) hê.

{{#ref}}
3.-token-embeddings.md
{{#endref}}

## 4. Aandag Meganismes

> [!TIP]
> Die doel van hierdie vierde fase is baie eenvoudig: **Pas 'n paar aandag meganismes toe**. Hierdie gaan baie **herhaalde lae** wees wat gaan **die verhouding van 'n woord in die woordeskat met sy bure in die huidige sin wat gebruik word om die LLM op te lei, vasvang**.\
> 'n Baie lae word hiervoor gebruik, so 'n baie opleibare parameters gaan hierdie inligting vasvang.

{{#ref}}
4.-attention-mechanisms.md
{{#endref}}

## 5. LLM Argitektuur

> [!TIP]
> Die doel van hierdie vyfde fase is baie eenvoudig: **Ontwikkel die argitektuur van die volle LLM**. Sit alles saam, pas al die lae toe en skep al die funksies om teks te genereer of teks na IDs en terug te transformeer.
>
> Hierdie argitektuur sal vir beide, opleiding en voorspellings van teks gebruik word nadat dit opgelei is.

{{#ref}}
5.-llm-architecture.md
{{#endref}}

## 6. Voor-Opleiding & Laai Modelle

> [!TIP]
> Die doel van hierdie sesde fase is baie eenvoudig: **Oefen die model van nuuts af**. Hiervoor sal die vorige LLM argitektuur gebruik word met 'n paar lusse wat oor die datastelle gaan met die gedefinieerde verliesfunksies en optimizer om al die parameters van die model op te lei.

{{#ref}}
6.-pre-training-and-loading-models.md
{{#endref}}

## 7.0. LoRA Verbeterings in fyn-afstemming

> [!TIP]
> Die gebruik van **LoRA verminder baie die berekening** wat nodig is om **fyn af te stel** reeds opgelei modelle.

{{#ref}}
7.0.-lora-improvements-in-fine-tuning.md
{{#endref}}

## 7.1. Fyn-Afstemming vir Kategorisering

> [!TIP]
> Die doel van hierdie afdeling is om te wys hoe om 'n reeds voor-opgeleide model fyn af te stel sodat die LLM eerder as om nuwe teks te genereer, die **waarskynlikhede van die gegewe teks wat in elkeen van die gegewe kategorieë gekategoriseer word** (soos of 'n teks spam is of nie) sal gee.

{{#ref}}
7.1.-fine-tuning-for-classification.md
{{#endref}}

## 7.2. Fyn-Afstemming om Instruksies te Volg

> [!TIP]
> Die doel van hierdie afdeling is om te wys hoe om **'n reeds voor-opgeleide model fyn af te stel om instruksies te volg** eerder as net om teks te genereer, byvoorbeeld, om op take te reageer as 'n chat bot.

{{#ref}}
7.2.-fine-tuning-to-follow-instructions.md
{{#endref}}
