# Granice poverenja LLM gateway-a

{{#include ../banners/hacktricks-training.md}}

LLM gateway upravlja rutiranjem modela i često čuva akreditive provajdera, pa njegovi uobičajeni API pozivaoci ne smeju da dobiju ovlašćenja za konfiguraciju ili na nivou provajdera. Procena LiteLLM gateway-a u verziji 1.77.7 pokazuje dve odvojene granice: autorizaciju UI sesije za administrativnu konfiguraciju i konfiguraciju rutiranja koju prosleđuje pozivalac za inferenciju. Prijavljeni problemi ispravljeni su u verziji 1.83.9.<sup>[[1]](#references)</sup>

## Klasifikacija UI rute nije autorizacija

U procenjenoj verziji LiteLLM-a, UI login ključevi pripadali su timu `litellm-dashboard`. Autorizacija je klasifikovala ključ kao UI token na osnovu identifikatora tog tima, bez obzira na ulogu korisnika. Provera UI rute zatim je prihvatala svaku rutu koja počinje prefiksom sa liste dozvoljenih. Zbog toga se unos `/config` poklapao i sa administrativnim handler-om `/config/update`. Taj handler je zahtevao generičku autentifikaciju, ali nije nezavisno zahtevao `PROXY_ADMIN`, pa je UI sesija sa nižim privilegijama dobila pristup za upis konfiguracije.<sup>[[1]](#references)</sup>

Ovo se razlikuje od nepoklapanja normalizacije putanje na proxy/backend strani: autorizacioni kod i handler se ne slažu oko ovlašćenja za *istu* rutu.<sup>[[1]](#references)</sup> Prilikom pregleda gateway-a uporedite klasifikaciju tokena, tačno poklapanje rute i metode i proveru uloge koju sprovodi sam handler.<sup>[[1]](#references)</sup> Pogledajte [autorizaciju web API-ja](../pentesting-web/web-api-pentesting.md), [zaobilaženja 401/403](../pentesting-web/403-and-401-bypasses.md) i [izuzetke za proxy prefikse](../pentesting-web/proxy-waf-protections-bypass.md#prefix-exemptions-become-routing-keys) za povezane, ali različite granice.

## Upisi konfiguracije dosežu dalje od skladišta konfiguracije

Isto ažuriranje LiteLLM konfiguracije prihvatalo je vrednosti promenljivih okruženja i primenjivalo ih na pokrenuti proces. Jedan potrošač je tretirao `UI_LOGO_PATH` kao lokalnu putanju za `FileResponse`, bez provere da li putanja vodi do logotipa; drugi je čitao `UI_USERNAME` i `UI_PASSWORD` tokom login-a koji nije koristio SSO i dodeljivao `PROXY_ADMIN` ako se vrednosti poklapaju. Tako je dozvola za upis konfiguracije mogla da omogući i otkrivanje lokalnih datoteka i promenu administrativnog identiteta, u zavisnosti od nizvodnog potrošača. Tip medija u odgovoru ne potvrđuje da je poslužena datoteka slika.<sup>[[1]](#references)</sup>

Konfiguracija pass-through endpoint-a bila je još jedno nizvodno odredište. Inicijalizacija je prihvatala udaljene S3/GCS adaptere, preuzimala Python module i uvozila ih pomoću `importlib`-ovog `exec_module`. Uvoz izvršava kod najvišeg nivoa pre upotrebe instance adaptera; samo ograničavanje pozivanja adaptera ne bi uklonilo tu granicu izvršavanja. Tretirajte ovo kao učitavanje koda kojim upravlja konfiguracija, a ne deserijalizaciju modelskih datoteka.<sup>[[1]](#references)</sup> Za odvojeni primitiv za čitanje datoteka pogledajte [uključivanje datoteka i traversal putanja](../pentesting-web/file-inclusion/).

## Rutiranje modela po zahtevu može da leak-uje akreditive gateway-a

LiteLLM-ova funkcija klijentskih akreditiva prihvatala je objekat `user_config` u LLM zahtevu. Procenjena ruta je kreirala privremeni `litellm.Router` na osnovu tog objekta, uključujući njegovu listu modela i `api_base` provajdera. Odredište provajdera koje kontroliše pozivalac moglo je da primi gateway-ov odlazni zahtev za completion i konfigurisana zaglavlja za autentifikaciju provajdera. Ograničenja na poljima `api_base` ili `api_key` najvišeg nivoa nisu obuhvatala ovu zasebnu putanju ugnježdene konfiguracije. Ovo je SSRF granica koja nosi akreditive, a ne problem prompt injection-a.<sup>[[1]](#references)</sup>

Tokom autorizovane procene gateway-a, uporedite svaku putanju koja može da konstruiše router ili klijent provajdera, uključujući konfiguraciju po zahtevu, sa pravilima za odredišta i akreditive koja koristi uobičajena konfigurisana ruta.<sup>[[1]](#references)</sup> [SSRF vodič](../pentesting-web/ssrf-server-side-request-forgery/) obrađuje opštu kontrolu odredišta na serverskoj strani; specifičan propust gateway-a je dozvola manje pouzdanom objektu zahteva da izabere odredište, uz ponovnu upotrebu privilegovanih odlaznih akreditiva.<sup>[[1]](#references)</sup>

## References

- [1] [Check Point Research — Kada LLM gateway-i zakažu: nalazi iz LiteLLM-a](https://research.checkpoint.com/2026/when-llm-gateways-go-wrong-findings-from-litellm/)
{{#include ../banners/hacktricks-training.md}}
