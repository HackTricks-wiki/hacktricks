# LLM Gateway Trust Boundaries

{{#include ../banners/hacktricks-training.md}}

Ein LLM-Gateway übernimmt das Model-Routing und verwahrt oft Provider-Zugangsdaten. Daher dürfen gewöhnliche API-Aufrufer nicht die Konfigurations- oder Provider-Berechtigungen des Gateways erben. Die LiteLLM-Gateway-Analyse für Version 1.77.7 veranschaulicht zwei separate Grenzen: die Autorisierung von UI-Sitzungen für administrative Konfigurationen und die vom Aufrufer bereitgestellte Routing-Konfiguration für Inference. Die gemeldeten Probleme wurden in Version 1.83.9 behoben.<sup>[[1]](#references)</sup>

## UI route classification is not authorization

In der untersuchten LiteLLM-Version gehörten UI-Login-Schlüssel zum Team `litellm-dashboard`. Die Autorisierung stufte einen Schlüssel anhand dieser Team-ID als UI-Token ein, unabhängig von der Rolle des Benutzers. Die UI-Routenprüfung akzeptierte anschließend jede Route, die mit einem freigegebenen Präfix begann. Dadurch stimmte auch der Eintrag `/config` mit dem administrativen Handler `/config/update` überein. Dieser Handler verlangte eine generische Authentifizierung, aber keine eigenständige Prüfung auf `PROXY_ADMIN`. So erhielt eine UI-Sitzung mit geringeren Berechtigungen Zugriff auf Konfigurationsänderungen.<sup>[[1]](#references)</sup>

Dies unterscheidet sich von einer Abweichung bei der Pfadnormalisierung zwischen Proxy und Backend: Der Autorisierungscode und der Handler stufen die Berechtigung für *dieselbe* Route unterschiedlich ein.<sup>[[1]](#references)</sup> Überprüfen Sie bei der Analyse eines Gateways die Token-Einstufung, den exakten Abgleich von Route und Methode sowie die eigene Rollenprüfung des Handlers.<sup>[[1]](#references)</sup> Weitere Informationen zu verwandten, aber unterschiedlichen Grenzen finden Sie unter [web API authorization](../pentesting-web/web-api-pentesting.md), [401/403 bypasses](../pentesting-web/403-and-401-bypasses.md) und [proxy prefix exemptions](../pentesting-web/proxy-waf-protections-bypass.md#prefix-exemptions-become-routing-keys).

## Configuration writes reach more than the configuration store

Dieselbe LiteLLM-Konfigurationsaktualisierung akzeptierte Werte für Umgebungsvariablen und wandte sie auf den laufenden Prozess an. Ein Verbraucher verwendete `UI_LOGO_PATH` als lokalen Pfad für eine `FileResponse`, ohne zu prüfen, ob es sich dabei um ein Logo handelte. Ein anderer las bei der Anmeldung ohne SSO `UI_USERNAME` und `UI_PASSWORD` aus und wies `PROXY_ADMIN` zu, wenn die Werte übereinstimmten. Eine Berechtigung zum Ändern der Konfiguration konnte somit – je nach nachgelagertem Verbraucher – sowohl zur Offenlegung lokaler Dateien als auch zur Änderung einer administrativen Identität führen. Der Media-Type der Antwort belegt nicht, dass es sich bei der ausgelieferten Datei um ein Bild handelt.<sup>[[1]](#references)</sup>

Die Konfiguration des Pass-through-Endpoints war ein weiterer nachgelagerter Sink. Bei der Initialisierung akzeptierte das System Remote-Ziele für S3/GCS-Adapter, lud Python-Module herunter und importierte sie mit `exec_module` aus `importlib`. Beim Import wird Code der obersten Ebene ausgeführt, bevor eine Adapterinstanz verwendet wird. Selbst eine Einschränkung der Adapteraufrufe würde diese Ausführungsgrenze nicht beseitigen. Behandeln Sie dies als konfigurationsgesteuertes Laden von Code, nicht als Deserialisierung von Model-Dateien.<sup>[[1]](#references)</sup> Für die separate Primitive zum Lesen von Dateien siehe [file inclusion and path traversal](../pentesting-web/file-inclusion/).

## Per-request model routing can leak gateway credentials

Die clientseitige Credential-Funktion von LiteLLM akzeptierte ein `user_config`-Objekt in einer LLM-Anfrage. Die untersuchte Route erstellte anhand dieses Objekts einen temporären `litellm.Router`, einschließlich seiner Modellliste und des `api_base` des Providers. Ein vom Aufrufer kontrolliertes Provider-Ziel konnte die ausgehende Completion-Anfrage des Gateways und konfigurierte Provider-Authentifizierungsheader empfangen. Einschränkungen für die Felder `api_base` oder `api_key` der obersten Ebene erfassten diesen separaten Pfad über eine verschachtelte Konfiguration nicht. Dies ist eine SSRF-Grenze mit Zugangsdaten und kein Prompt-Injection-Problem.<sup>[[1]](#references)</sup>

Vergleichen Sie bei einer autorisierten Gateway-Analyse jeden Pfad, der einen Router oder Provider-Client erstellen kann – einschließlich der Konfiguration pro Anfrage – mit der Richtlinie für Ziele und Zugangsdaten, die für die regulär konfigurierte Route gilt.<sup>[[1]](#references)</sup> Der [SSRF guide](../pentesting-web/ssrf-server-side-request-forgery/) behandelt die allgemeine Kontrolle serverseitiger Ziele. Der gatewayspezifische Fehler besteht darin, dass ein weniger vertrauenswürdiges Anfrageobjekt ein Ziel auswählen kann, während privilegierte Zugangsdaten für ausgehende Verbindungen wiederverwendet werden.<sup>[[1]](#references)</sup>

## Guardrail registration can bypass a UI-only sandbox

Der Code-Testpfad eines Gateways und sein Code-Registrierungspfad können unterschiedlich validieren. In LiteLLM vor v1.82.0 lehnte der UI-Test für benutzerdefinierte Guardrails gefährliche Syntax ab und führte den Code mit `__builtins__ = {}` aus. `POST /guardrails` kompilierte den übermittelten `custom_code` hingegen mit `exec(compile(...), exec_globals)`, ohne eine der beiden Prüfungen durchzuführen. Wenn `__builtins__` fehlt, fügt Python die Built-ins in das globale Dictionary ein. Dadurch wurden Importe und Befehle auf Modulebene **bei der Registrierung der Guardrail** ausgeführt, noch vor einem Inference-Aufruf. Der spätere `apply_guardrail`-Callback konnte ein gespeichertes Ergebnis über den Blockierungsgrund offenlegen.<sup>[[2]](#references)[[3]](#references)</sup>

Vergleichen Sie bei einem autorisierten Test den Test-Handler mit dem Registrierungs-Handler, statt anzunehmen, dass ein erfolgreicher UI-Sandbox-Test eine sichere Registrierung belegt. Die gemeldete Request-Form vor der Behebung war:<sup>[[2]](#references)</sup>

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

Der Registrierungsendpunkt akzeptierte auch gewöhnliche API keys, da ihm eine `PROXY_ADMIN`-Prüfung fehlte. Wenn weder ein Master Key noch eine JWT-/OAuth2-Authentifizierung konfiguriert war, wies der Auth-Handler vor dem Fix selbst anonymen Anfragen die Rolle `PROXY_ADMIN` zu. Der Fix änderte die Rolle ohne Authentifizierung zu `INTERNAL_USER`, ergänzte Guardrail-Adminprüfungen und validierte und beschränkte Builtins während der Registrierung. Diese Rollen- und Codeausführungsgrenzen sind unabhängig vom [MCP token-fallback issue](AI-MCP-Servers.md#mcp-token-passthrough-must-not-create-an-anonymous-session).<sup>[[2]](#references)[[3]](#references)</sup>

## Admin-pass-through-Routen können Cloud-Metadaten weiterleiten

Die Pass-through-Endpunktfunktion von LiteLLM ermöglicht es einem Administrator, ein HTTP-Ziel zu konfigurieren und optional Unterpfade anzuhängen. Anders als beim obigen Routing-Problem mit `user_config` pro Anfrage erfordert dies **Berechtigung zum Schreiben der Konfiguration**; die Funktion ist ausdrücklich darauf ausgelegt, Administratoren zu vertrauen. In der gemeldeten Bereitstellung wurde das Ziel nicht auf private oder Link-Local-Adressen geprüft.<sup>[[2]](#references)[[4]](#references)</sup> Vor v1.83.0 konnten gewöhnliche authentifizierte Schlüssel außerdem `/config/update` aufrufen, da dort eine Prüfung der Administratorrolle fehlte. Siehe [UI route classification](#ui-route-classification-is-not-authorization) zur verwandten Grenze beim Schreiben der Konfiguration.<sup>[[2]](#references)[[6]](#references)</sup>

Mit dieser Berechtigung und Netzwerkzugriff vom Proxy auf die EC2-Metadaten kann eine Route wie die folgende Metadaten über das Gateway offenlegen. Das Flag `include_subpath` sorgt dafür, dass `/meta/meta-data/iam/security-credentials/` unter `/latest/` abgebildet wird.<sup>[[2]](#references)[[4]](#references)</sup>

```http
POST /config/pass_through_endpoint HTTP/1.1
Authorization: Bearer <master_key>
Content-Type: application/json

{"path":"/meta","target":"http://169.254.169.254/latest/","headers":{},"include_subpath":true}
```

Der [Cloud-SSRF-Leitfaden](../pentesting-web/ssrf-server-side-request-forgery/cloud-ssrf.md#aws) behandelt den IMDSv2-Tokenaustausch; diese Route muss die `PUT`-Anfrage zulassen und beide Metadaten-Header weiterleiten.<sup>[[5]](#references)</sup> LiteLLMs generische Pass-through-Header-Verarbeitung entfernt vor der Weiterleitung das Präfix `x-pass-`. Daher können `x-pass-X-aws-ec2-metadata-token-ttl-seconds: 21600` und `x-pass-X-aws-ec2-metadata-token: <token>` diese Header bereitstellen.<sup>[[2]](#references)[[7]](#references)</sup> Der Proxy muss IMDS erreichen können, die Token-Antwort muss das konfigurierte Hop-Limit durchlaufen und die Token-Anfrage darf keinen `X-Forwarded-For`-Header enthalten.<sup>[[5]](#references)</sup> Die gatewayspezifische Variante besteht aus der **dauerhaften, vom Admin kontrollierten Route plus Weiterleitung von Request-Headern**.

## References

- [1] [Check Point Research — Wenn LLM-Gateways schiefgehen: Erkenntnisse aus LiteLLM](https://research.checkpoint.com/2026/when-llm-gateways-go-wrong-findings-from-litellm/)
- [2] [Wiz — Ungeschützt: LiteLLM vom Authentifizierungs-Bypass bis zur Cloud-Kompromittierung aufbrechen](https://wiz.io/blog/off-guard-breaking-litellm-from-authentication-bypass-to-cloud-compromise)
- [3] [LiteLLM PR #22095 — Unauthentifizierte RCE und Sandbox-Ausbruch in der Custom-Code-Guardrail beheben](https://github.com/BerriAI/litellm/pull/22095)
- [4] [LiteLLM — Pass-Through-Endpunkte erstellen](https://docs.litellm.ai/docs/proxy/pass_through)
- [5] [AWS — Funktionsweise von Instance Metadata Service Version 2](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-metadata-v2-how-it-works.html)
- [6] [LiteLLM-Advisory — uneingeschränkter Proxy-Konfigurationsendpunkt](https://github.com/advisories/GHSA-53mr-6c8q-9789)
- [7] [Implementierung der LiteLLM-Pass-Through-Header-Weiterleitung](https://github.com/BerriAI/litellm/blob/v1.84.0/litellm/passthrough/utils.py)
{{#include ../banners/hacktricks-training.md}}
