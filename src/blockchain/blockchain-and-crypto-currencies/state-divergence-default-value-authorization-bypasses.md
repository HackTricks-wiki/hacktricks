# Toestandafwyking en omseiling van magtiging met verstekwaardes

{{#include ../../banners/hacktricks-training.md}}

Magtiging hang soms af van afgeleide ekonomiese toestand eerder as ’n eksplisiete rol—byvoorbeeld: “die oproeper besit die hele voorraad.” As die waardes in daardie predikaat uit verskillende stores kom, kan ’n verouderde duplikaat ’n wettige eienaarskapkortpad in ’n magtigingsomseiling verander. Die Provenance marker-module het die gevaarlike kombinasie getoon: ’n lewendige oproeperbalans is vergelyk met marker-plaaslike voorraadmetadata wat nie vir bates met ’n nie-vaste voorraad opgedateer is nie.<sup>[[1]](#references)</sup>

## Oudit duplikaattoestand as ’n magtigingsgrens

Vir elke waarde wat in ’n toestemmingstoets gebruik word, lys **alle voorstellings**: kanonieke moduletoestand, objekvelde, gekasde aggregaatwaardes, indekse, momentopnames, brugrekords en buiteketting-spieëls. Volg dan elke skep-, mint-, burn-, oordrag-, terugstel-, migrasie- en sinchronisasiepad om te bepaal watter kopie in elke objekmodus opgedateer word. ’n Veld kan vir een modus gesaghebbend en vir ’n ander bloot ter inligting wees.<sup>[[1]](#references)</sup>

’n Praktiese hersieningswerkvloei is:<sup>[[1]](#references)</sup>

1. Vind beskermde aksies en herlei elke magtigingstak tot ’n Booleaanse predikaat.
2. Teken vir elke operand sy store, opdateringspaaie, lewensiklustoestande en bron van waarheid aan.
3. Genereer oorgange wat net een voorstelling opdateer, en vergelyk dan alle kopieë.
4. Probeer die beskermde aksie ná elke oorgang vanaf ’n nuwe rekening uitvoer.
5. Gaan verder as die omseiling: as die aksie ’n ACL wysig, ken aan jouself volgehoue rolle toe en roep gewone bevoorregte API’s aan.

Verdagte patrone sluit `cachedSupply == balance`, `metadataOwner == caller` of `snapshotShares == currentShares` in wanneer die twee kante verskillende sinchronisasiereëls het. Om ’n gesaghebbende waarde vir een operand te raadpleeg, maak die vergelyking nie veilig as die ander operand verouderd is nie.<sup>[[1]](#references)</sup>

## Omseiling met verstekwaardegelykheid

’n Gelykheidspredikaat is ook onveilig wanneer albei operande onafhanklik dieselfde verstekwaarde kan aanneem. Die kontrole hieronder gee aan enige leë rekening “beheer oor die volle voorraad” wanneer `supply` nul is, ongeag of nul die gevolg is van verouderde metadata of ’n voorwerp wat wettiglik nie befonds is nie.<sup>[[1]](#references)[[3]](#references)</sup>

```go
balance := bank.GetBalance(ctx, caller, denom)
supply := marker.GetSupply() // duplicate or stale representation
return balance.Amount.Equal(supply.Amount) // 0 == 0 -> true
```

Om na die kanonieke store oor te skakel, herstel divergensie, maar nie die leë-objekgeval nie. Die sekuriteitseienskap moet ’n onafhanklike geldigheidsvoorwaarde insluit; die Provenance-patch gebruik die bank se huidige voorraad en verwerp nil of nul voorraad voordat dit die caller se balans vergelyk.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

```go
supply := bank.GetSupply(ctx, denom)
if supply.Amount.IsNil() || supply.Amount.IsZero() {
    return false
}
balance := bank.GetBalance(ctx, caller, denom)
return supply.Equal(NewCoin(denom, balance.Amount))
```

Pas dieselfde redenasie toe op kworumtellings, eienaarskappersentasies, skuld, kollateraal, epogge, nonces, tydstempels en tellers: `callerValue == protectedValue` mag ’n oproeper nie magtig voordat die beskermde waarde onafhanklik geldig is en aan die verwagte domein behoort nie.<sup>[[1]](#references)</sup>

## ACL takeover na wettige bevoorregte bewerkings

’n Bypass in ’n ACL-redigeringsbewerking is ’n blywende primitief vir voorregte-eskalasie. In die Provenance-geval kon ’n onbevoorregte rekening met nul tokens die verouderde `0 == 0`-aanbodtoets slaag, homself administratiewe, mint- en onttrekkingstoestemmings verleen, en daarna gewone boodskapverwerkers gebruik om bates te mint of escrow te onttrek. Die exploit het dus geen tweede kwesbaarheid ná die ACL-verandering vereis nie.<sup>[[1]](#references)</sup>

Algemene exploit-volgorde:<sup>[[1]](#references)</sup>

1. Vind ’n objek waarvan ’n nie-gesaghebbende veld van die lewendige toestand verskil, of waarvan die beskermde waarde die verstekwaarde is.
2. Gebruik ’n nuwe/leë identiteit sodat sy plaaslike waarde met daardie verouderde/verstekwaarde ooreenstem.
3. Roep die rolbestuur-, eienaarskapsoordrag- of beleidopdaterings-endpoint aan en verleen jouself blywende vermoëns.
4. Bevestig dat dit voortduur deur die ACL uit die kanonieke toestand te lees.
5. Roep die wettige hoë-impakbewerking aan (mint, onttrek, opgradeer, eienaarskap oordra of beleid verander).

Wanneer jy die impak triage, ondersoek elke vermoë waartoe die nuwe rol toegang gee, eerder as om by die authorization bypass te stop. Escrow-agtige rekeninge kan bates bewaar wat nie verband hou met die objek waarvan die verouderde metadata die oorneming moontlik gemaak het nie.<sup>[[1]](#references)</sup>

## Invarianten en teikens vir stateful fuzzing

Spesifiseer magtiging onafhanklik van die implementering. Vir ’n vol-aanbod-kortpad is die minimum invariant:<sup>[[1]](#references)[[2]](#references)</sup>

```text
controlsAllSupply(caller, asset) == true
    => authoritativeSupply(asset) > 0
    && authoritativeBalance(caller, asset) == authoritativeSupply(asset)
```

Gebruik ’n model-/toestandmasjien-fuzzer om reekse—nie geïsoleerde oproepe nie—te genereer wat skepping, nulwaarde-inisialisering, aktivering/afhandeling, minting, burning, oordragte, terugstellings, migrasies, sync-oproepe en ACL-veranderinge dek. Vergelyk ná elke oorgang die duplikaatvoorstellings en bevestig dat ’n nuwe rekening geen beskermde handeling kan uitvoer nie. Voeg uitdruklike gevalle by vir nul, een eenheid, gedeeltelike eienaarskap, volle eienaarskap, ’n verouderde lae waarde en ’n verouderde hoë waarde.<sup>[[1]](#references)[[2]](#references)</sup>

Eienskappe vir hoë-sein-regressietoetse is:<sup>[[1]](#references)[[2]](#references)</sup>

- Nul gesaghebbende aanbod impliseer nooit eienaarskap of administrasie nie.
- Gedeeltelike houers kan nie administrateurs word wanneer ’n duplikaataanbod gelyk is aan hul saldo nie.
- ’n Werklike volle houer behou die bedoelde kortpad wanneer die lewendige aanbod positief is.
- Mislukte selftoekennings wysig nie die ACL of aktiveer daaropvolgende bevoorregte oproepe nie.
- Modusveranderinge kan nie stilweg verander watter voorstelling ’n magtigingskontrole as gesaghebbend beskou nie.

## References

- [1] [Toestandafwyking maak ongemagtigde toegang moontlik (Trail of Bits)](https://blog.trailofbits.com/2026/08/25/state-divergence-enables-unauthorized-access/)
- [2] [Provenance PR #2734 - Stel verouderde aanbodkontroles reg](https://github.com/provenance-io/provenance/pull/2734)
- [3] [Provenance commit c81fd65 - Verwerp nul-aanbod in die totale-aanbod-magtigingskortpad](https://github.com/provenance-io/provenance/commit/c81fd65f8ad48de42d5a6d68e761a0851c7e72c4)
{{#include ../../banners/hacktricks-training.md}}
