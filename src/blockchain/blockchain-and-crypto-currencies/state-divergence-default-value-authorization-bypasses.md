# Divergencija stanja i zaobilaženje autorizacije pomoću podrazumevanih vrednosti

{{#include ../../banners/hacktricks-training.md}}

Autorizacija ponekad zavisi od izvedenog ekonomskog stanja umesto od eksplicitne uloge — na primer, „pozivalac poseduje celokupnu ponudu“. Ako vrednosti u tom uslovu potiču iz različitih skladišta, zastareli duplikat može legitimnu prečicu za vlasništvo pretvoriti u zaobilaženje autorizacije. Modul Provenance marker pokazao je opasnu kombinaciju: saldo pozivaoca uživo upoređivao se sa metapodacima o ponudi u samom markeru, koji se nisu ažurirali za sredstva sa nepromenljivom ponudom.<sup>[[1]](#references)</sup>

## Proverite duplirano stanje kao granicu autorizacije

Za svaku vrednost koja se koristi u proveri dozvola popišite **sve reprezentacije**: kanonsko stanje modula, polja objekta, keširane agregate, indekse, snimke stanja, zapise mosta i off-chain preslike. Zatim pratite svaku putanju kreiranja, kovanja, spaljivanja, prenosa, resetovanja, migracije i sinhronizacije da biste utvrdili koja se kopija ažurira u svakom režimu objekta. Polje može biti merodavno u jednom režimu, a informativno u drugom.<sup>[[1]](#references)</sup>

Praktičan postupak pregleda:<sup>[[1]](#references)</sup>

1. Pronađite zaštićene radnje i svedite svaku granu autorizacije na Bulov predikat.
2. Za svaki operand zabeležite njegovo skladište, putanje ažuriranja, stanja životnog ciklusa i izvor istine.
3. Osmislite prelaze koji ažuriraju samo jednu reprezentaciju, pa uporedite sve kopije.
4. Posle svakog prelaza pokušajte da izvršite zaštićenu radnju sa novog naloga.
5. Istražite i posledice zaobilaženja: ako radnja menja ACL, dodelite sebi trajne uloge i pozovite uobičajene privilegovane API-je.

Sumnjivi obrasci obuhvataju `cachedSupply == balance`, `metadataOwner == caller` ili `snapshotShares == currentShares` kada dve strane imaju različita pravila sinhronizacije. Čitanje merodavne vrednosti za jedan operand ne čini poređenje bezbednim ako je drugi operand zastareo.<sup>[[1]](#references)</sup>

## Zaobilaženje pomoću jednakosti podrazumevanih vrednosti

Predikat jednakosti takođe nije bezbedan kada oba operanda mogu nezavisno poprimiti istu podrazumevanu vrednost. Provera ispod daje „potpunu kontrolu nad ponudom“ svakom praznom nalogu kada je `supply` nula, bez obzira na to da li je nula posledica zastarelih metapodataka ili objekta koji legitimno nema sredstva.<sup>[[1]](#references)[[3]](#references)</sup>

```go
balance := bank.GetBalance(ctx, caller, denom)
supply := marker.GetSupply() // duplicate or stale representation
return balance.Amount.Equal(supply.Amount) // 0 == 0 -> true
```

Prelazak na kanonsko skladište rešava divergenciju, ali **ne** i slučaj praznog objekta. Bezbednosno svojstvo mora da obuhvati nezavisan uslov validnosti; zakrpa za Provenance koristi aktuelnu ponudu banke i odbacuje nil ili nultu ponudu pre nego što uporedi saldo pozivaoca.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

```go
supply := bank.GetSupply(ctx, denom)
if supply.Amount.IsNil() || supply.Amount.IsZero() {
    return false
}
balance := bank.GetBalance(ctx, caller, denom)
return supply.Equal(NewCoin(denom, balance.Amount))
```

Primeni isto rezonovanje na broj članova kvoruma, procente vlasništva, dug, kolateral, epohe, nonce vrednosti, vremenske oznake i brojače: `callerValue == protectedValue` ne sme da ovlasti pozivaoca dok se nezavisno ne potvrdi da je zaštićena vrednost validna i da pripada očekivanom domenu.<sup>[[1]](#references)</sup>

## Preuzimanje ACL-a radi legitimnih privilegovanih operacija

Zaobilaženje u operaciji izmene ACL-a predstavlja trajni mehanizam za eskalaciju privilegija. U slučaju Provenance, neprivilegovani nalog sa nula tokena mogao je da prođe zastarelu proveru ponude `0 == 0`, dodeli sebi administrativne dozvole i dozvole za mintovanje i povlačenje, a zatim koristi obične message handlere za mintovanje sredstava ili povlačenje sredstava iz escrow-a. Zato nakon izmene ACL-a nije bila potrebna druga ranjivost da bi exploit uspeo.<sup>[[1]](#references)</sup>

Opšti sled eksploatacije:<sup>[[1]](#references)</sup>

1. Pronađi objekat čije se neautoritativno polje razlikuje od aktivnog stanja ili čija je zaštićena vrednost podrazumevana.
2. Upotrebi novi/prazan identitet tako da se njegova lokalna vrednost poklapa sa tom zastarelom/podrazumevanom vrednošću.
3. Pozovi endpoint za upravljanje ulogama, prenos vlasništva ili ažuriranje pravila i dodeli sebi trajne mogućnosti.
4. Proveri postojanost tako što ćeš pročitati ACL iz kanonskog stanja.
5. Pozovi legitimnu operaciju sa velikim uticajem (mintovanje, povlačenje, nadogradnju, prenos vlasništva ili izmenu pravila).

Pri proceni uticaja, pregledaj sve mogućnosti dostupne preko nove uloge umesto da se zaustaviš na zaobilaženju autorizacije. Nalozi nalik escrow-u mogu čuvati sredstva koja nisu povezana sa objektom čiji je zastareli metapodatak omogućio preuzimanje.<sup>[[1]](#references)</sup>

## Ciljevi za invarijante i stateful-fuzzing

Definiši autorizaciju nezavisno od implementacije. Za prečicu za punu ponudu, minimalna invarijanta glasi:<sup>[[1]](#references)[[2]](#references)</sup>

```text
controlsAllSupply(caller, asset) == true
    => authoritativeSupply(asset) > 0
    && authoritativeBalance(caller, asset) == authoritativeSupply(asset)
```

Koristite model/state-machine fuzzer za generisanje sekvenci, a ne izolovanih poziva, koje obuhvataju kreiranje, inicijalizaciju vrednošću nula, aktivaciju/finalizaciju, mintovanje, spaljivanje, transfere, resetovanja, migracije, sync pozive i promene ACL-a. Nakon svakog prelaza uporedite duplirane reprezentacije i proverite da novi nalog ne može da izvrši nijednu zaštićenu radnju. Dodajte eksplicitne slučajeve za nulu, jednu jedinicu, delimično vlasništvo, puno vlasništvo, zastarele preniske i zastarele previsoke vrednosti.<sup>[[1]](#references)[[2]](#references)</sup>

Regresiona svojstva koja otkrivaju najviše problema su:<sup>[[1]](#references)[[2]](#references)</sup>

- Nulta merodavna ponuda nikad ne podrazumeva vlasništvo ili administratorska ovlašćenja.
- Delimični vlasnici ne mogu postati administratori kada je duplirana ponuda jednaka njihovom saldu.
- Stvarni vlasnik celokupne ponude zadržava predviđenu prečicu kada je ponuda u sistemu veća od nule.
- Neuspešni pokušaji dodele ovlašćenja samom sebi ne menjaju ACL niti omogućavaju naknadne privilegovane pozive.
- Promene režima ne mogu neprimetno da promene koja se reprezentacija smatra merodavnom pri proveri ovlašćenja.

## References

- [1] [Odstupanje stanja omogućava neovlašćen pristup (Trail of Bits)](https://blog.trailofbits.com/2026/08/25/state-divergence-enables-unauthorized-access/)
- [2] [Provenance PR #2734 - Ispravka provera zastarele ponude](https://github.com/provenance-io/provenance/pull/2734)
- [3] [Provenance commit c81fd65 - Odbacivanje nulte ponude u prečici za autorizaciju ukupne ponude](https://github.com/provenance-io/provenance/commit/c81fd65f8ad48de42d5a6d68e761a0851c7e72c4)
{{#include ../../banners/hacktricks-training.md}}
