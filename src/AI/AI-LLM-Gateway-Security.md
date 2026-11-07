# Granice zaufania w LLM Gateway

{{#include ../banners/hacktricks-training.md}}

LLM gateway obsługuje routing modeli i często przechowuje poświadczenia dostawców, dlatego zwykli klienci jego API nie mogą dziedziczyć uprawnień do konfiguracji ani uprawnień na poziomie dostawcy. Ocena gateway LiteLLM w wersji 1.77.7 pokazuje dwie odrębne granice: autoryzację sesji UI przy konfiguracji administracyjnej oraz konfigurację routingu dostarczaną przez klienta przy inferencji. Zgłoszone problemy naprawiono w wersji 1.83.9.<sup>[[1]](#references)</sup>

## Klasyfikacja UI route to nie autoryzacja

W ocenianej wersji LiteLLM klucze logowania UI należały do zespołu `litellm-dashboard`. Autoryzacja klasyfikowała klucz jako token UI na podstawie identyfikatora tego zespołu, niezależnie od roli użytkownika. Kontrola UI route akceptowała następnie każdą route zaczynającą się od prefiksu z listy dozwolonych. W efekcie wpis `/config` pasował również do administracyjnego handlera `/config/update`. Ten handler wymagał ogólnego uwierzytelnienia, ale nie sprawdzał niezależnie uprawnienia `PROXY_ADMIN`, przez co sesja UI o niższych uprawnieniach uzyskiwała dostęp do zapisu konfiguracji.<sup>[[1]](#references)</sup>

Różni się to od niezgodności w normalizacji ścieżek proxy/backend: kod autoryzacji i handler różnie oceniają uprawnienia do *tej samej* route.<sup>[[1]](#references)</sup> Podczas oceny gateway porównaj klasyfikację tokenów, dokładne dopasowanie route i metody oraz kontrolę roli w samym handlerze.<sup>[[1]](#references)</sup> Zobacz [autoryzację web API](../pentesting-web/web-api-pentesting.md), [bypasses 401/403](../pentesting-web/403-and-401-bypasses.md) oraz [wyjątki prefiksów proxy](../pentesting-web/proxy-waf-protections-bypass.md#prefix-exemptions-become-routing-keys), które dotyczą powiązanych, ale odrębnych granic.

## Zapisy konfiguracji trafiają do więcej niż samego magazynu konfiguracji

Ten sam endpoint aktualizacji konfiguracji LiteLLM akceptował wartości zmiennych środowiskowych i stosował je do działającego procesu. Jeden z odbiorców traktował `UI_LOGO_PATH` jako lokalną ścieżkę dla `FileResponse`, nie sprawdzając, czy wskazuje ona logo; inny odczytywał `UI_USERNAME` i `UI_PASSWORD` podczas logowania bez SSO i przypisywał rolę `PROXY_ADMIN`, gdy dane się zgadzały. Uprawnienie do zapisu konfiguracji mogło więc prowadzić zarówno do ujawnienia lokalnych plików, jak i do zmiany tożsamości administracyjnej — zależnie od dalszego odbiorcy. Typ MIME odpowiedzi nie potwierdza, że serwowany plik jest obrazem.<sup>[[1]](#references)</sup>

Konfiguracja endpointu pass-through była kolejnym dalszym punktem wejścia. Inicjalizacja akceptowała zdalne cele adapterów S3/GCS, pobierała moduły Pythona i importowała je przy użyciu `exec_module` z `importlib`. Import wykonuje kod najwyższego poziomu, zanim zostanie użyta instancja adaptera; samo ograniczenie wywoływania adaptera nie usuwa tej granicy wykonania. Traktuj to jako ładowanie kodu kontrolowane przez konfigurację, a nie deserializację pliku modelu.<sup>[[1]](#references)</sup> Informacje o odrębnym prymitywie odczytu plików znajdziesz w sekcji [file inclusion i path traversal](../pentesting-web/file-inclusion/).

## Routing modelu dla każdego żądania może leakować poświadczenia gateway

Funkcja poświadczeń po stronie klienta w LiteLLM akceptowała obiekt `user_config` w żądaniu LLM. Oceniana route tworzyła tymczasowy `litellm.Router` na podstawie tego obiektu, w tym jego listy modeli i `api_base` dostawcy. Kontrolowany przez klienta cel dostawcy mógł otrzymać wychodzące żądanie completion gateway oraz skonfigurowane nagłówki uwierzytelniające dostawcy. Ograniczenia dotyczące pól `api_base` lub `api_key` na najwyższym poziomie nie obejmowały tej odrębnej, zagnieżdżonej ścieżki konfiguracji. Jest to granica SSRF z dostępem do poświadczeń, a nie problem prompt-injection.<sup>[[1]](#references)</sup>

Podczas autoryzowanej oceny gateway porównaj każdą ścieżkę, która może utworzyć router lub klienta dostawcy — w tym konfigurację dla pojedynczego żądania — z polityką dotyczącą celów i poświadczeń używaną przez standardową, skonfigurowaną route.<sup>[[1]](#references)</sup> [Przewodnik SSRF](../pentesting-web/ssrf-server-side-request-forgery/) omawia ogólną kontrolę nad celami po stronie serwera; charakterystyczny błąd gateway polega na umożliwieniu mniej zaufanemu obiektowi żądania wyboru celu przy jednoczesnym użyciu uprzywilejowanych poświadczeń wychodzących.<sup>[[1]](#references)</sup>

## Rejestracja guardrail może ominąć sandbox dostępny tylko w UI

Ścieżka testowania kodu i ścieżka rejestracji kodu w gateway mogą stosować różne walidacje. W LiteLLM przed wersją v1.82.0 test niestandardowego guardrail w UI odrzucał niebezpieczną składnię i uruchamiał kod z `__builtins__ = {}`, ale `POST /guardrails` kompilował przesłane `custom_code` za pomocą `exec(compile(...), exec_globals)` bez żadnej z tych kontroli. Python wstawia builtins do słownika globals, w którym brakuje `__builtins__`, więc importy i polecenia na poziomie modułu wykonywały się **podczas rejestracji guardrail**, jeszcze przed wywołaniem inferencji. Późniejsze wywołanie zwrotne `apply_guardrail` mogło ujawnić zapisany wynik w przyczynie blokady.<sup>[[2]](#references)[[3]](#references)</sup>

Podczas autoryzowanego testu porównaj handlery testowania i rejestracji, zamiast zakładać, że pomyślny test sandboxa w UI dowodzi bezpieczeństwa rejestracji. Zgłoszony kształt żądania sprzed poprawki wyglądał następująco:<sup>[[2]](#references)</sup>

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

Endpoint rejestracji akceptował również zwykłe klucze API, ponieważ nie sprawdzał roli `PROXY_ADMIN`. Jeśli nie skonfigurowano master key ani uwierzytelniania JWT/OAuth2, handler uwierzytelniania sprzed poprawki przypisywał rolę `PROXY_ADMIN` nawet anonimowym żądaniom. Poprawka zmieniła rolę przy braku uwierzytelniania na `INTERNAL_USER`, dodała kontrole uprawnień administratora w guardrailach oraz walidację i ograniczenia wbudowanych funkcji podczas rejestracji. Granice uprawnień i wykonywania kodu są odrębne od [problemu z awaryjnym użyciem tokenu MCP](AI-MCP-Servers.md#mcp-token-passthrough-must-not-create-an-anonymous-session).<sup>[[2]](#references)[[3]](#references)</sup>

## Trasy proxy administratora mogą pośredniczyć w dostępie do metadanych chmurowych

Funkcja endpointów pass-through w LiteLLM pozwala administratorowi skonfigurować cel HTTP i opcjonalnie dołączać ścieżki podrzędne. W przeciwieństwie do opisanego powyżej problemu z routingiem `user_config` dla poszczególnych żądań, wymaga to **uprawnień do zapisu konfiguracji**; sama funkcja została zaprojektowana tak, aby ufać administratorom. W opisanym wdrożeniu cel nie był sprawdzany pod kątem prywatnych ani lokalnych adresów IP.<sup>[[2]](#references)[[4]](#references)</sup> Przed wersją v1.83.0 zwykłe uwierzytelnione klucze również mogły uzyskać dostęp do `/config/update`, ponieważ trasa nie sprawdzała roli administratora; powiązaną granicę zapisu konfiguracji opisano w sekcji [Klasyfikacja tras UI nie jest autoryzacją](#ui-route-classification-is-not-authorization).<sup>[[2]](#references)[[6]](#references)</sup>

Przy takich uprawnieniach i dostępności sieciowej proxy do metadanych EC2 trasa taka jak poniższa ujawnia metadane za pośrednictwem gatewaya. Flaga `include_subpath` sprawia, że `/meta/meta-data/iam/security-credentials/` jest mapowane pod `/latest/`.<sup>[[2]](#references)[[4]](#references)</sup>

```http
POST /config/pass_through_endpoint HTTP/1.1
Authorization: Bearer <master_key>
Content-Type: application/json

{"path":"/meta","target":"http://169.254.169.254/latest/","headers":{},"include_subpath":true}
```

[Przewodnik Cloud SSRF](../pentesting-web/ssrf-server-side-request-forgery/cloud-ssrf.md#aws) omawia wymianę tokenu IMDSv2; ta ścieżka musi zezwalać na żądanie `PUT` i przekazywać oba nagłówki metadanych.<sup>[[5]](#references)</sup> Ogólna obsługa nagłówków pass-through w LiteLLM usuwa prefiks `x-pass-` przed przekazaniem żądania dalej, dlatego `x-pass-X-aws-ec2-metadata-token-ttl-seconds: 21600` i `x-pass-X-aws-ec2-metadata-token: <token>` mogą dostarczyć te nagłówki.<sup>[[2]](#references)[[7]](#references)</sup> Proxy musi mieć dostęp do IMDS, odpowiedź z tokenem musi przejść przez skonfigurowany limit przeskoków, a żądanie tokenu nie może zawierać `X-Forwarded-For`.<sup>[[5]](#references)</sup> Specyficzna dla gatewaya odmiana polega na **trwałej trasie kontrolowanej przez administratora oraz przekazywaniu nagłówków żądania**.

## References

- [1] [Check Point Research — Co może pójść nie tak z gatewayami LLM: ustalenia dotyczące LiteLLM](https://research.checkpoint.com/2026/when-llm-gateways-go-wrong-findings-from-litellm/)
- [2] [Wiz — Bez osłony: od obejścia uwierzytelniania do przejęcia chmury przez LiteLLM](https://wiz.io/blog/off-guard-breaking-litellm-from-authentication-bypass-to-cloud-compromise)
- [3] [LiteLLM PR #22095 — naprawa nieuwierzytelnionego RCE i ucieczki z sandboxa w zabezpieczeniach kodu niestandardowego](https://github.com/BerriAI/litellm/pull/22095)
- [4] [LiteLLM — tworzenie endpointów pass-through](https://docs.litellm.ai/docs/proxy/pass_through)
- [5] [AWS — Jak działa usługa metadanych instancji w wersji 2](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-metadata-v2-how-it-works.html)
- [6] [Doradztwo LiteLLM — nieograniczony endpoint konfiguracji proxy](https://github.com/advisories/GHSA-53mr-6c8q-9789)
- [7] [Implementacja przekazywania nagłówków pass-through w LiteLLM](https://github.com/BerriAI/litellm/blob/v1.84.0/litellm/passthrough/utils.py)
{{#include ../banners/hacktricks-training.md}}
