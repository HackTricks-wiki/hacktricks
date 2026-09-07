# Divergencija stanja i zaobilaženja autorizacije zasnovana na podrazumevanim vrednostima

{{#include ../../banners/hacktricks-training.md}}

Autorizacija ponekad zavisi od izvedenog ekonomskog stanja umesto od eksplicitne uloge — na primer, „caller poseduje celokupnu ponudu“. Ako vrednosti u tom predikatu potiču iz različitih skladišta, zastarela kopija može legitimnu prečicu za proveru vlasništva pretvoriti u authorization bypass. Modul Provenance marker pokazao je opasnu kombinaciju: živo stanje balansa caller-a poređeno je sa supply metapodacima lokalnim za marker, koji nisu ažurirani za asset-e sa promenljivom ponudom.<sup>[[1]](#references)</sup>

## Proverite duplicirano stanje kao granicu autorizacije

Za svaku vrednost koja se koristi u permission check-u navedite **sve reprezentacije**: kanonsko stanje modula, polja objekta, keširane agregate, indekse, snapshots, bridge zapise i off-chain mirrors. Zatim pratite svaku create, mint, burn, transfer, reset, migration i synchronization putanju da biste utvrdili koja se kopija ažurira u svakom režimu objekta. Polje može biti authoritative za jedan režim, a informativno za drugi.<sup>[[1]](#references)</sup>

Praktičan workflow za review je:<sup>[[1]](#references)</sup>

1. Pronađite protected actions i svedite svaku authorization granu na boolean predikat.
2. Za svaki operand zabeležite njegovo skladište, update putanje, lifecycle states i source of truth.
3. Generišite tranzicije koje ažuriraju samo jednu reprezentaciju, a zatim uporedite sve kopije.
4. Pokušajte da izvršite protected action sa fresh account-om nakon svake tranzicije.
5. Nastavite dalje od bypass-a: ako action menja ACL, dodelite sebi persistent roles i pozovite normalne privileged APIs.

Sumnjivi obrasci uključuju `cachedSupply == balance`, `metadataOwner == caller` ili `snapshotShares == currentShares` kada dve strane imaju različita pravila synchronizacije. Čitanje authoritative vrednosti za jedan operand ne čini poređenje bezbednim kada je drugi operand zastareo.<sup>[[1]](#references)</sup>

## Zaobilaženje autorizacije jednakošću podrazumevane vrednosti

Equality predicate je takođe nebezbedan kada oba operanda nezavisno mogu dobiti istu podrazumevanu vrednost. Provera ispod dodeljuje „potpunu kontrolu nad supply-em“ svakom praznom account-u kada je `supply` nula, bez obzira na to da li je nula posledica zastarelih metapodataka ili legitimno nefinansiranog objekta.<sup>[[1]](#references)[[3]](#references)</sup>
```go
balance := bank.GetBalance(ctx, caller, denom)
supply := marker.GetSupply() // duplicate or stale representation
return balance.Amount.Equal(supply.Amount) // 0 == 0 -> true
```
Prebacivanje na canonical store rešava divergenciju, ali **ne** i slučaj praznog objekta. Bezbednosno svojstvo mora da obuhvati nezavisni uslov validnosti; Provenance patch koristi trenutnu zalihu banke i odbacuje nil ili nultu zalihu pre poređenja stanja računa pozivaoca.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>
```go
supply := bank.GetSupply(ctx, denom)
if supply.Amount.IsNil() || supply.Amount.IsZero() {
return false
}
balance := bank.GetBalance(ctx, caller, denom)
return supply.Equal(NewCoin(denom, balance.Amount))
```
Primeni isto rezonovanje na quorum counts, procente vlasništva, dug, collateral, epohe, nonce-ove, timestamps i counters: `callerValue == protectedValue` ne sme autorizovati caller dok protected value nije nezavisno validna vrednost i dok ne pripada očekivanom domenu.<sup>[[1]](#references)</sup>

## Preuzimanje ACL-a do legitimnih privilegovanih operacija

Bypass u operaciji izmene ACL-a predstavlja trajni primitive za eskalaciju privilegija. U slučaju Provenance-a, neprivilegovani nalog sa nula tokena mogao je da prođe zastareli test ponude `0 == 0`, dodeli sebi administratorske dozvole, dozvole za mint i withdrawal, a zatim koristi obične message handlere za mintovanje asseta ili withdrawal iz escrow-a. Exploit stoga nije zahtevao drugu ranjivost nakon izmene ACL-a.<sup>[[1]](#references)</sup>

Opšti redosled exploitacije:<sup>[[1]](#references)</sup>

1. Pronađi objekat čije se neautoritativno polje razlikuje od live state-a ili čija je zaštićena vrednost podrazumevana.
2. Koristi novi/prazan identity tako da se njegova lokalna vrednost podudara sa tom zastarelom/podrazumevanom vrednošću.
3. Pozovi endpoint za upravljanje ulogama, prenos vlasništva ili ažuriranje policy-ja i dodeli sebi trajne capabilities.
4. Potvrdi persistence čitanjem ACL-a iz canonical state-a.
5. Pozovi legitimnu high-impact operaciju (mint, withdrawal, upgrade, prenos vlasništva ili izmenu policy-ja).

Prilikom procene uticaja, proveri svaku capability dostupnu iz nove uloge umesto da se zaustaviš na authorization bypass-u. Escrow-like nalozi mogu čuvati assete koji nisu povezani sa objektom čiji je zastareli metadata omogućio preuzimanje.<sup>[[1]](#references)</sup>

## Ciljevi za invariant i stateful-fuzzing

Definiši autorizaciju nezavisno od implementacije. Za prečicu za full-supply, minimalni invariant je:<sup>[[1]](#references)[[2]](#references)</sup>
```text
controlsAllSupply(caller, asset) == true
=> authoritativeSupply(asset) > 0
&& authoritativeBalance(caller, asset) == authoritativeSupply(asset)
```
Koristite model/state-machine fuzzer za generisanje sekvenci — ne izolovanih poziva — koje obuhvataju kreiranje, inicijalizaciju nultom vrednošću, aktivaciju/finalizaciju, minting, burning, transfere, resetovanja, migracije, sync pozive i promene ACL-a. Nakon svakog prelaza uporedite duplirane reprezentacije i proverite da nov nalog ne može da izvrši nijednu zaštićenu radnju. Eksplicitno uključite slučajeve za nulu, jednu jedinicu, delimično vlasništvo, potpuno vlasništvo, zastarele niske i zastarele visoke vrednosti.<sup>[[1]](#references)[[2]](#references)</sup>

Regresiona svojstva sa visokim signalom su:<sup>[[1]](#references)[[2]](#references)</sup>

- Nulta authoritative supply nikada ne podrazumeva vlasništvo ili administraciju.
- Delimični holders ne mogu postati administratori kada je duplicate supply jednak njihovom saldu.
- Pravi full holder zadržava predviđenu prečicu kada je live supply pozitivan.
- Neuspešni self-grants ne menjaju ACL niti omogućavaju naknadne privilegovane pozive.
- Promene režima ne mogu neprimetno promeniti koju reprezentaciju authorization check tretira kao authoritative.

## References

- [1] [State divergence enables unauthorized access (Trail of Bits)](https://blog.trailofbits.com/2026/08/25/state-divergence-enables-unauthorized-access/)
- [2] [Provenance PR #2734 - Fix stale supply checks](https://github.com/provenance-io/provenance/pull/2734)
- [3] [Provenance commit c81fd65 - Reject zero supply in the total-supply authorization shortcut](https://github.com/provenance-io/provenance/commit/c81fd65f8ad48de42d5a6d68e761a0851c7e72c4)
{{#include ../../banners/hacktricks-training.md}}
