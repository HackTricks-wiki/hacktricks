# Granice poverenja LLM gateway-a

{{#include ../banners/hacktricks-training.md}}

LLM gateway upravlja rutiranjem modela i često čuva akreditive provajdera, zato njegovi uobičajeni API pozivaoci ne smeju da nasleđuju ovlašćenja za konfiguraciju ili na nivou provajdera. Procena LiteLLM-a verzije 1.77.7 pokazuje dve zasebne granice: autorizaciju UI sesije za administrativnu konfiguraciju i konfiguraciju rutiranja koju prosleđuje pozivalac za inference. Prijavljeni problemi ispravljeni su u verziji 1.83.9.<sup>[[1]](#references)</sup>

## Klasifikacija UI rute nije autorizacija

U procenjivanoj verziji LiteLLM-a, ključevi za UI prijavu pripadali su timu `litellm-dashboard`. Autorizacija je klasifikovala ključ kao UI token na osnovu identifikatora tog tima, bez obzira na korisničku ulogu. Provera UI rute zatim je prihvatala svaku rutu koja počinje prefiksom sa liste dozvoljenih prefiksa. Zbog toga se unos `/config` poklapao i sa administrativnim rukovaocem `/config/update`. Taj rukovalac je zahtevao generičku autentifikaciju, ali nije nezavisno zahtevao `PROXY_ADMIN`, pa je UI sesija sa nižim privilegijama dobila pristup upisu konfiguracije.<sup>[[1]](#references)</sup>

Ovo se razlikuje od nepoklapanja normalizacije putanje između proxy-ja i backend-a: autorizacioni kod i rukovalac se ne slažu oko ovlašćenja za *istu* rutu.<sup>[[1]](#references)</sup> Pri pregledu gateway-a, uporedite klasifikaciju tokena, tačno poklapanje rute i metode i proveru uloge koju obavlja sam rukovalac.<sup>[[1]](#references)</sup> Pogledajte [autorizaciju web API-ja](../pentesting-web/web-api-pentesting.md), [zaobilaženja 401/403](../pentesting-web/403-and-401-bypasses.md) i [izuzetke za prefikse proxy-ja](../pentesting-web/proxy-waf-protections-bypass.md#prefix-exemptions-become-routing-keys) za povezane, ali zasebne granice.

## Upisi konfiguracije dopiru dalje od skladišta konfiguracije

Isto ažuriranje konfiguracije u LiteLLM-u prihvatalo je vrednosti promenljivih okruženja i primenjivalo ih na pokrenuti proces. Jedna komponenta je tretirala `UI_LOGO_PATH` kao lokalnu putanju za `FileResponse`, ne proveravajući da li ona zaista pokazuje na logo; druga je tokom prijave bez SSO-a čitala `UI_USERNAME` i `UI_PASSWORD` i dodeljivala `PROXY_ADMIN` ako su se poklapali. Tako je dozvola za upis konfiguracije mogla da dovede do otkrivanja lokalnih datoteka, kao i do promene administratorskog identiteta, u zavisnosti od nizvodne komponente. Tip medija u odgovoru ne dokazuje da je poslužena datoteka slika.<sup>[[1]](#references)</sup>

Konfiguracija endpoint-a pass-through била је još jedno nizvodno odredište. Inicijalizacija je prihvatala udaljene ciljeve S3/GCS adaptera, preuzimala Python module i uvozila ih pomoću `exec_module` iz `importlib`-a. Uvoz izvršava kod na najvišem nivou pre korišćenja instance adaptera; samo ograničavanje poziva adaptera ne bi uklonilo tu granicu izvršavanja. Tretirajte ovo kao učitavanje koda kojim upravlja konfiguracija, a ne kao deserijalizaciju datoteke modela.<sup>[[1]](#references)</sup> Za zaseban primitiv za čitanje datoteka pogledajte [uključivanje datoteka i traversal putanja](../pentesting-web/file-inclusion/).

## Rutiranje modela po zahtevu može da leak gateway akreditive

LiteLLM-ova funkcija akreditiva na strani klijenta prihvatala je objekat `user_config` u LLM zahtevu. Procena je pokazala da ta ruta kreira privremeni `litellm.Router` na osnovu tog objekta, uključujući njegovu listu modela i `api_base` provajdera. Odredište provajdera koje kontroliše pozivalac moglo je da primi gateway-ov odlazni zahtev za completion, kao i podešena zaglavlja za autentifikaciju provajdera. Ograničenja za polja `api_base` ili `api_key` na najvišem nivou nisu obuhvatala ovu zasebnu putanju ugnježdene konfiguracije. Ovo je SSRF granica koja nosi akreditive, a ne problem prompt injection-a.<sup>[[1]](#references)</sup>

Pri ovlašćenoj proceni gateway-a, uporedite svaku putanju koja može da konstruiše ruter ili klijenta provajdera, uključujući konfiguraciju po zahtevu, sa pravilima za odredišta i akreditive koja koristi uobičajena konfigurisana ruta.<sup>[[1]](#references)</sup> [SSRF vodič](../pentesting-web/ssrf-server-side-request-forgery/) obrađuje opštu kontrolu odredišta na strani servera; specifičan propust gateway-a je dopuštanje da objekat zahteva sa nižim nivoom poverenja izabere odredište, uz ponovno korišćenje privilegovanih odlaznih akreditiva.<sup>[[1]](#references)</sup>

## Registracija guardrail-a može da zaobiđe sandbox koji štiti samo UI

Putanja za testiranje koda i putanja za registraciju koda u gateway-u mogu da primenjuju različite validacije. U LiteLLM-u pre verzije v1.82.0, UI test prilagođenog guardrail-a odbijao je opasnu sintaksu i izvršavao kod sa `__builtins__ = {}`, ali je `POST /guardrails` kompajlirao poslati `custom_code` pomoću `exec(compile(...), exec_globals)` bez ijedne od tih provera. Python umeće builtins u globalni rečnik kojem nedostaje `__builtins__`, pa su se uvozi i komande na nivou modula izvršavali **prilikom registracije guardrail-a**, pre bilo kog inference poziva. Kasniji callback `apply_guardrail` mogao je da izloži sačuvani rezultat kroz razlog blokiranja.<sup>[[2]](#references)[[3]](#references)</sup>

Pri ovlašćenom testiranju, uporedite rukovaoce za testiranje i registraciju umesto da pretpostavite da uspešan UI sandbox test dokazuje da je registracija bezbedna. Oblik prijavljenog zahteva pre ispravke bio je:<sup>[[2]](#references)</sup>

```http
POST /guardrails HTTP/1.1
Authorization: Bearer <master_key>
Content-Type: application/json

{
  "guardrail": {
    "guardrail_name": "probe",
    "litellm_params": {
      "guardrail": "custom_code", "mode": "pre_call", "default_on": true,
      "custom_code": "import os\nresult = os.popen('id').read()\ndef apply_guardrail(inputs, request_data, input_type):\n    return {'action': 'block', 'reason': result}"
    }
  }
}
```

Registraciona krajnja tačka prihvatala je i obične API ključeve jer nije proveravala `PROXY_ADMIN`. Kada nije bio konfigurisan master key niti JWT/OAuth2 autentifikacija, handler za autentifikaciju pre ispravke dodeljivao je `PROXY_ADMIN` čak i anonimnim zahtevima. Ispravkom je uloga bez autentifikacije promenjena u `INTERNAL_USER`, dodate su administratorske provere guardrail-a, a ugrađene funkcije su proveravane i ograničene tokom registracije. Ove granice uloga i izvršavanja koda odvojene su od [problema sa rezervnim korišćenjem MCP tokena](AI-MCP-Servers.md#mcp-token-passthrough-must-not-create-an-anonymous-session).<sup>[[2]](#references)[[3]](#references)</sup>

## Administratorske pass-through rute mogu da prosleđuju zahteve ka metapodacima clouda

LiteLLM-ova funkcija pass-through krajnjih tačaka omogućava administratoru da konfiguriše HTTP cilj i po želji dodaje podputanje. Za razliku od prethodno opisanog problema rutiranja po `user_config`-u za svaki zahtev, ovo zahteva **ovlašćenje za upis konfiguracije**; sama funkcija je namenjena tome da veruje administratorima. U prijavljenom deployment-u, cilj nije bio proveravan u odnosu na privatne ili link-local adrese.<sup>[[2]](#references)[[4]](#references)</sup> Pre v1.83.0, obični autentifikovani ključevi mogli su da pristupe i putanji `/config/update` jer nije proveravala administratorsku ulogu; za povezanu granicu upisa konfiguracije pogledajte [klasifikaciju UI ruta](#ui-route-classification-is-not-authorization).<sup>[[2]](#references)[[6]](#references)</sup>

Uz to ovlašćenje i mrežnu dostupnost EC2 metapodataka sa proxy-ja, ruta poput sledeće izlaže metapodatke preko gateway-a. Oznaka `include_subpath` usmerava `/meta/meta-data/iam/security-credentials/` unutar `/latest/`.<sup>[[2]](#references)[[4]](#references)</sup>

```http
POST /config/pass_through_endpoint HTTP/1.1
Authorization: Bearer <master_key>
Content-Type: application/json

{"path":"/meta","target":"http://169.254.169.254/latest/","headers":{},"include_subpath":true}
```

[Cloud SSRF vodič](../pentesting-web/ssrf-server-side-request-forgery/cloud-ssrf.md#aws) pokriva razmenu IMDSv2 tokena; ova ruta mora da dozvoli zahtev `PUT` i prosledi oba metapodatkovna zaglavlja.<sup>[[5]](#references)</sup> LiteLLM-ovo generičko rukovanje pass-through zaglavljima uklanja prefiks `x-pass-` pre prosleđivanja, pa `x-pass-X-aws-ec2-metadata-token-ttl-seconds: 21600` i `x-pass-X-aws-ec2-metadata-token: <token>` mogu da obezbede ta zaglavlja.<sup>[[2]](#references)[[7]](#references)</sup> Proxy mora da može da dosegne IMDS, odgovor sa tokenom mora da prođe kroz podešeno ograničenje broja skokova, a zahtev za token ne sme da sadrži `X-Forwarded-For`.<sup>[[5]](#references)</sup> Varijacija specifična za gateway jeste **trajna ruta pod kontrolom administratora uz prosleđivanje zaglavlja zahteva**.

## References

- [1] [Check Point Research — Kada LLM gateway-i pođu po zlu: nalazi iz LiteLLM](https://research.checkpoint.com/2026/when-llm-gateways-go-wrong-findings-from-litellm/)
- [2] [Wiz — Off Guard: Kako kompromitovati LiteLLM, od zaobilaženja autentifikacije do kompromitovanja cloud-a](https://wiz.io/blog/off-guard-breaking-litellm-from-authentication-bypass-to-cloud-compromise)
- [3] [LiteLLM PR #22095 — popravka neautentifikovanog RCE-a i bekstva iz sandbox-a u zaštitnom mehanizmu za prilagođeni kod](https://github.com/BerriAI/litellm/pull/22095)
- [4] [LiteLLM — Kreiranje pass-through endpointa](https://docs.litellm.ai/docs/proxy/pass_through)
- [5] [AWS — Kako funkcioniše Instance Metadata Service Version 2](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-metadata-v2-how-it-works.html)
- [6] [LiteLLM savetodavno obaveštenje — endpoint za neograničenu konfiguraciju proxy-ja](https://github.com/advisories/GHSA-53mr-6c8q-9789)
- [7] [Implementacija prosleđivanja pass-through zaglavlja u LiteLLM-u](https://github.com/BerriAI/litellm/blob/v1.84.0/litellm/passthrough/utils.py)
{{#include ../banners/hacktricks-training.md}}
