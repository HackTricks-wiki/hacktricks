# Granice zaufania bramy LLM

{{#include ../banners/hacktricks-training.md}}

Brama LLM obsługuje routing modeli i często przechowuje poświadczenia dostawców, dlatego zwykli wywołujący jej API nie mogą dziedziczyć uprawnień do konfiguracji ani uprawnień na poziomie dostawcy. Ocena bramy LiteLLM w wersji 1.77.7 pokazuje dwa odrębne obszary zaufania: autoryzację sesji UI do konfiguracji administracyjnej oraz konfigurację routingu podawaną przez wywołującego do inferencji. Zgłoszone problemy naprawiono w wersji 1.83.9.<sup>[[1]](#references)</sup>

## Klasyfikacja tras UI nie jest autoryzacją

W ocenianej wersji LiteLLM klucze logowania do UI należały do zespołu `litellm-dashboard`. Autoryzacja klasyfikowała klucz jako token UI na podstawie identyfikatora tego zespołu, niezależnie od roli użytkownika. Kontrola tras UI akceptowała następnie każdą trasę zaczynającą się od prefiksu z listy dozwolonych. W rezultacie wpis `/config` pasował również do administracyjnego handlera `/config/update`. Ten handler wymagał ogólnego uwierzytelnienia, ale samodzielnie nie wymagał roli `PROXY_ADMIN`, przez co sesja UI o niższych uprawnieniach uzyskiwała dostęp do zapisu konfiguracji.<sup>[[1]](#references)</sup>

To różni się od rozbieżności w normalizacji ścieżek między proxy a backendem: kod autoryzacji i handler nie zgadzają się co do uprawnień dla *tej samej* trasy.<sup>[[1]](#references)</sup> Podczas przeglądu bramy porównaj klasyfikację tokenów, dokładne dopasowanie trasy i metody oraz własną kontrolę roli w handlerze.<sup>[[1]](#references)</sup> Zobacz [autoryzację web API](../pentesting-web/web-api-pentesting.md), [obejścia 401/403](../pentesting-web/403-and-401-bypasses.md) oraz [wyjątki dla prefiksów proxy](../pentesting-web/proxy-waf-protections-bypass.md#prefix-exemptions-become-routing-keys), które dotyczą powiązanych, lecz odrębnych granic.

## Zapis konfiguracji oddziałuje na więcej niż sam magazyn konfiguracji

Ta sama aktualizacja konfiguracji LiteLLM przyjmowała wartości zmiennych środowiskowych i stosowała je w działającym procesie. Jeden z komponentów używał `UI_LOGO_PATH` jako lokalnej ścieżki dla `FileResponse`, nie sprawdzając, czy wskazuje ona logo; inny odczytywał `UI_USERNAME` i `UI_PASSWORD` podczas logowania bez SSO i przypisywał rolę `PROXY_ADMIN`, jeśli wartości się zgadzały. W efekcie uprawnienie do zapisu konfiguracji mogło prowadzić zarówno do ujawnienia lokalnych plików, jak i do zmiany tożsamości administracyjnej — zależnie od komponentu, który z niej korzystał. Typ MIME odpowiedzi nie potwierdza, że udostępniany plik jest obrazem.<sup>[[1]](#references)</sup>

Konfiguracja endpointu pass-through była kolejnym miejscem, do którego trafiały dane. Podczas inicjalizacji akceptowano zdalne cele adapterów S3/GCS, pobierano moduły Pythona i importowano je za pomocą `exec_module` z `importlib`. Import wykonuje kod najwyższego poziomu przed użyciem instancji adaptera; samo ograniczenie wywoływania adaptera nie usuwa tej granicy wykonania. Traktuj to jako ładowanie kodu kontrolowane przez konfigurację, a nie deserializację pliku modelu.<sup>[[1]](#references)</sup> Informacje o odrębnym prymitywie odczytu plików znajdziesz w sekcji [file inclusion i path traversal](../pentesting-web/file-inclusion/).

## Routing modeli dla poszczególnych żądań może powodować leak poświadczeń bramy

Funkcja poświadczeń po stronie klienta w LiteLLM przyjmowała obiekt `user_config` w żądaniu LLM. Oceniana trasa tworzyła tymczasowy `litellm.Router` na podstawie tego obiektu, w tym listy modeli i `api_base` dostawcy. Cel dostawcy kontrolowany przez wywołującego mógł otrzymać wychodzące żądanie completion bramy oraz skonfigurowane nagłówki uwierzytelniające dostawcy. Ograniczenia dotyczące pól najwyższego poziomu `api_base` lub `api_key` nie obejmowały tej odrębnej ścieżki konfiguracji zagnieżdżonej. To granica SSRF z dostępem do poświadczeń, a nie problem prompt-injection.<sup>[[1]](#references)</sup>

Podczas autoryzowanej oceny bramy porównaj każdą ścieżkę, która może tworzyć router lub klienta dostawcy — w tym konfigurację dla poszczególnych żądań — z polityką dotyczącą celów i poświadczeń używaną przez standardową, skonfigurowaną trasę.<sup>[[1]](#references)</sup> [Przewodnik SSRF](../pentesting-web/ssrf-server-side-request-forgery/) omawia ogólną kontrolę celów po stronie serwera; specyficzny dla bramy problem polega na zezwoleniu żądaniu o niższym poziomie zaufania na wybór celu przy jednoczesnym ponownym użyciu uprzywilejowanych poświadczeń wychodzących.<sup>[[1]](#references)</sup>

## References

- [1] [Check Point Research — Kiedy bramy LLM zawodzą: wnioski z LiteLLM](https://research.checkpoint.com/2026/when-llm-gateways-go-wrong-findings-from-litellm/)
{{#include ../banners/hacktricks-training.md}}
