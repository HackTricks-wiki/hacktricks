# Vertrauensgrenzen von LLM-Gateways

{{#include ../banners/hacktricks-training.md}}

Ein LLM-Gateway übernimmt das Routing von Modellen und hält häufig Zugangsdaten von Providern. Daher dürfen gewöhnliche API-Aufrufer keine Konfigurations- oder Provider-Berechtigungen erben. Die Untersuchung des LiteLLM-Gateways in Version 1.77.7 veranschaulicht zwei separate Grenzen: die Autorisierung von UI-Sitzungen für administrative Konfigurationen und die vom Aufrufer bereitgestellte Routing-Konfiguration für Inferenz. Die gemeldeten Probleme wurden in Version 1.83.9 behoben.<sup>[[1]](#references)</sup>

## UI-Routenklassifizierung ist keine Autorisierung

In der untersuchten LiteLLM-Version gehörten UI-Login-Keys zum Team `litellm-dashboard`. Die Autorisierung klassifizierte einen Key anhand dieser Team-ID als UI-Token, unabhängig von der Rolle des Benutzers. Die UI-Routenprüfung akzeptierte dann jede Route, die mit einem freigegebenen Präfix begann. Dadurch stimmte auch der Eintrag `/config` mit dem administrativen Handler `/config/update` überein. Dieser Handler verlangte eine allgemeine Authentifizierung, aber keine separate Rolle `PROXY_ADMIN`. So erhielt eine UI-Sitzung mit geringeren Berechtigungen Zugriff auf die Konfiguration.<sup>[[1]](#references)</sup>

Das unterscheidet sich von einer Abweichung bei der Pfadnormalisierung zwischen Proxy und Backend: Der Autorisierungscode und der Handler beurteilen die Berechtigung für *dieselbe* Route unterschiedlich.<sup>[[1]](#references)</sup> Prüfen Sie bei der Untersuchung eines Gateways die Tokenklassifizierung, den exakten Abgleich von Route und Methode sowie die rollenbasierte Prüfung im Handler selbst.<sup>[[1]](#references)</sup> Siehe [Autorisierung von Web-APIs](../pentesting-web/web-api-pentesting.md), [401/403-Umgehungen](../pentesting-web/403-and-401-bypasses.md) und [Ausnahmen für Proxy-Präfixe](../pentesting-web/proxy-waf-protections-bypass.md#prefix-exemptions-become-routing-keys) zu verwandten, aber unterschiedlichen Grenzen.

## Konfigurationsänderungen erreichen mehr als nur den Konfigurationsspeicher

Dieselbe LiteLLM-Konfigurationsaktualisierung akzeptierte Umgebungsvariablenwerte und übernahm sie in den laufenden Prozess. Ein Verbraucher behandelte `UI_LOGO_PATH` als lokalen Pfad für eine `FileResponse`, ohne zu prüfen, ob es sich dabei um ein Logo handelte; ein anderer las `UI_USERNAME` und `UI_PASSWORD` bei der Nicht-SSO-Anmeldung aus und wies bei Übereinstimmung die Rolle `PROXY_ADMIN` zu. Eine Berechtigung zum Ändern der Konfiguration konnte somit je nach nachgelagertem Verbraucher sowohl zur Offenlegung lokaler Dateien als auch zur Änderung einer administrativen Identität führen. Der Response-Medientyp belegt nicht, dass die ausgelieferte Datei ein Bild ist.<sup>[[1]](#references)</sup>

Die Konfiguration des Pass-through-Endpoints war ein weiterer nachgelagerter Angriffspunkt. Bei der Initialisierung wurden entfernte S3/GCS-Adapterziele akzeptiert, Python-Module heruntergeladen und mit `exec_module` von `importlib` importiert. Beim Import wird der Code auf oberster Ebene ausgeführt, bevor eine Adapterinstanz verwendet wird. Die Ausführung durch bloße Beschränkung der Adapteraufrufe zu verhindern, beseitigt diese Ausführungsgrenze also nicht. Behandeln Sie dies als konfigurationsgesteuertes Laden von Code, nicht als Deserialisierung von Modelldateien.<sup>[[1]](#references)</sup> Informationen zum separaten Primitive für das Lesen von Dateien finden Sie unter [File Inclusion und Path Traversal](../pentesting-web/file-inclusion/).

## Modell-Routing pro Anfrage kann Gateway-Zugangsdaten leaken

Die clientseitige Funktion für Zugangsdaten von LiteLLM akzeptierte in einer LLM-Anfrage ein `user_config`-Objekt. Die untersuchte Route erstellte daraus einen temporären `litellm.Router` mit seiner Modellliste und dem Provider-`api_base`. Ein vom Aufrufer kontrolliertes Provider-Ziel konnte die ausgehende Completion-Anfrage des Gateways und konfigurierte Provider-Authentifizierungsheader empfangen. Einschränkungen für die Felder `api_base` oder `api_key` auf oberster Ebene deckten diesen separaten, verschachtelten Konfigurationspfad nicht ab. Dies ist eine SSRF-Grenze mit Zugangsdaten, kein Prompt-Injection-Problem.<sup>[[1]](#references)</sup>

Vergleichen Sie bei einer autorisierten Gateway-Untersuchung alle Pfade, über die ein Router oder Provider-Client erstellt werden kann – einschließlich der Konfiguration pro Anfrage – mit den Ziel- und Zugangsdatenrichtlinien der regulär konfigurierten Route.<sup>[[1]](#references)</sup> Der [SSRF-Leitfaden](../pentesting-web/ssrf-server-side-request-forgery/) behandelt die allgemeine Kontrolle serverseitiger Ziele. Das gatewayspezifische Problem besteht darin, einem weniger vertrauenswürdigen Anfrageobjekt die Auswahl eines Ziels zu erlauben und dabei privilegierte ausgehende Zugangsdaten wiederzuverwenden.<sup>[[1]](#references)</sup>

## References

- [1] [Check Point Research — Wenn LLM-Gateways schieflaufen: Erkenntnisse aus LiteLLM](https://research.checkpoint.com/2026/when-llm-gateways-go-wrong-findings-from-litellm/)
{{#include ../banners/hacktricks-training.md}}
