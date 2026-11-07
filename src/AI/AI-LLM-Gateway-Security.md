# Límites de confianza de LLM Gateway

{{#include ../banners/hacktricks-training.md}}

Un LLM gateway gestiona el enrutamiento de modelos y suele almacenar credenciales de proveedores, por lo que quienes llaman a su API ordinaria no deben heredar autoridad sobre la configuración ni sobre los proveedores. La evaluación del gateway LiteLLM en la versión 1.77.7 ilustra dos límites distintos: la autorización de sesiones de UI para la configuración administrativa y la configuración de enrutamiento proporcionada por el caller para la inferencia. Los problemas reportados se corrigieron en la versión 1.83.9.<sup>[[1]](#references)</sup>

## La clasificación de rutas de UI no es autorización

En la versión de LiteLLM evaluada, las claves de inicio de sesión de UI pertenecían al equipo `litellm-dashboard`. La autorización clasificaba una clave como token de UI según el identificador de ese equipo, independientemente del rol del usuario. Luego, la comprobación de rutas de UI aceptaba cualquier ruta que comenzara con un prefijo de una allowlist. Como resultado, la entrada `/config` también coincidía con el handler administrativo `/config/update`. Ese handler requería autenticación genérica, pero no exigía por separado `PROXY_ADMIN`, por lo que una sesión de UI con menos privilegios podía acceder a la escritura de configuración.<sup>[[1]](#references)</sup>

Esto difiere de un desajuste de normalización de rutas entre proxy y backend: el código de autorización y el handler discrepan sobre la autoridad de la *misma* ruta.<sup>[[1]](#references)</sup> Al revisar un gateway, compara la clasificación de tokens, la coincidencia exacta de ruta y método, y la comprobación de rol propia del handler.<sup>[[1]](#references)</sup> Consulta [autorización de web API](../pentesting-web/web-api-pentesting.md), [bypasses de 401/403](../pentesting-web/403-and-401-bypasses.md) y [exenciones de prefijos de proxy](../pentesting-web/proxy-waf-protections-bypass.md#prefix-exemptions-become-routing-keys) para ver límites relacionados, pero distintos.

## Las escrituras de configuración afectan más que al almacén de configuración

La misma actualización de configuración de LiteLLM aceptaba valores de variables de entorno y los aplicaba al proceso en ejecución. Un consumidor trataba `UI_LOGO_PATH` como una ruta local para un `FileResponse`, sin validar que apuntara a un logo; otro leía `UI_USERNAME` y `UI_PASSWORD` durante el inicio de sesión sin SSO y asignaba `PROXY_ADMIN` si coincidían. Así, un permiso de escritura de configuración podía permitir tanto la divulgación de archivos locales como un cambio de identidad administrativa, según el consumidor posterior. El tipo de medio de la respuesta no demuestra que el archivo servido sea una imagen.<sup>[[1]](#references)</sup>

La configuración del endpoint pass-through era otro sink posterior. La inicialización aceptaba destinos de adaptadores remotos de S3/GCS, descargaba módulos de Python y los importaba mediante `exec_module` de `importlib`. La importación ejecuta el código de nivel superior antes de usar una instancia del adaptador; limitar únicamente la invocación del adaptador no eliminaría ese límite de ejecución. Trátalo como carga de código controlada por configuración, no como deserialización de archivos de modelo.<sup>[[1]](#references)</sup> Para la primitiva independiente de lectura de archivos, consulta [inclusión de archivos y path traversal](../pentesting-web/file-inclusion/).

## El enrutamiento de modelos por solicitud puede provocar el leak de credenciales del gateway

La función de credenciales del lado del cliente de LiteLLM aceptaba un objeto `user_config` en una solicitud LLM. La ruta evaluada creaba un `litellm.Router` temporal a partir de ese objeto, incluida su lista de modelos y el `api_base` del proveedor. Un destino de proveedor controlado por el caller podía recibir la solicitud de completion saliente del gateway y las cabeceras de autenticación configuradas del proveedor. Las restricciones sobre los campos `api_base` o `api_key` de nivel superior no cubrían esta ruta de configuración anidada independiente. Este es un límite de SSRF con credenciales, no un problema de prompt injection.<sup>[[1]](#references)</sup>

Al evaluar un gateway con autorización, compara todas las rutas que pueden crear un router o un cliente de proveedor, incluida la configuración por solicitud, con la política de destinos y credenciales aplicada a la ruta configurada normal.<sup>[[1]](#references)</sup> La [guía de SSRF](../pentesting-web/ssrf-server-side-request-forgery/) cubre el control general de destinos del lado del servidor; el fallo específico del gateway consiste en permitir que un objeto de solicitud menos confiable seleccione un destino y, a la vez, reutilice credenciales salientes privilegiadas.<sup>[[1]](#references)</sup>

## El registro de guardrails puede eludir un sandbox exclusivo de UI

La ruta de prueba de código de un gateway y la ruta de registro de código pueden aplicar validaciones distintas. En LiteLLM anterior a v1.82.0, la prueba de guardrails personalizados de UI rechazaba sintaxis peligrosa y ejecutaba el código con `__builtins__ = {}`, pero `POST /guardrails` compilaba el `custom_code` enviado con `exec(compile(...), exec_globals)` sin ninguna de esas comprobaciones. Python inserta builtins en un diccionario global que no contiene `__builtins__`, por lo que las importaciones y los comandos de nivel de módulo se ejecutaban **al registrar el guardrail**, antes de cualquier llamada de inferencia. La callback posterior `apply_guardrail` podía revelar un resultado almacenado mediante su motivo de bloqueo.<sup>[[2]](#references)[[3]](#references)</sup>

Para una prueba autorizada, compara los handlers de prueba y registro en lugar de asumir que superar una prueba de sandbox de UI demuestra que el registro es seguro. La estructura de la solicitud reportada antes de la corrección era:<sup>[[2]](#references)</sup>

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

El endpoint de registro también aceptaba claves API normales porque no tenía una comprobación de `PROXY_ADMIN`. Cuando no se había configurado una master key ni la autenticación JWT/OAuth2, el controlador de autenticación anterior a la corrección asignaba `PROXY_ADMIN` incluso a las solicitudes anónimas. La corrección cambió el rol sin autenticación a `INTERNAL_USER`, añadió comprobaciones administrativas de guardrails y validó y restringió los builtins durante el registro. Estos límites de roles y ejecución de código son independientes del [problema de fallback de tokens de MCP](AI-MCP-Servers.md#mcp-token-passthrough-must-not-create-an-anonymous-session).<sup>[[2]](#references)[[3]](#references)</sup>

## Las rutas de pass-through de administración pueden usar el proxy para acceder a metadatos de cloud

La función de endpoints pass-through de LiteLLM permite que un administrador configure un destino HTTP y, opcionalmente, añada subrutas. A diferencia del problema de enrutamiento `user_config` por solicitud mencionado arriba, esto requiere **autoridad para modificar la configuración**; la función está diseñada para confiar en los administradores. En el despliegue reportado, el destino no se comprobaba para descartar direcciones privadas o de enlace local.<sup>[[2]](#references)[[4]](#references)</sup> Antes de la v1.83.0, las claves autenticadas normales también podían acceder a `/config/update` porque no tenía una comprobación de rol de administrador; consulta [clasificación de rutas de UI](#ui-route-classification-is-not-authorization) para ver el límite relacionado con la modificación de la configuración.<sup>[[2]](#references)[[6]](#references)</sup>

Con esa autoridad y conectividad de red entre el proxy y los metadatos de EC2, una ruta como la siguiente expone los metadatos a través del gateway. La opción `include_subpath` hace que `/meta/meta-data/iam/security-credentials/` se enrute bajo `/latest/`.<sup>[[2]](#references)[[4]](#references)</sup>

```http
POST /config/pass_through_endpoint HTTP/1.1
Authorization: Bearer <master_key>
Content-Type: application/json

{"path":"/meta","target":"http://169.254.169.254/latest/","headers":{},"include_subpath":true}
```

La [guía de Cloud SSRF](../pentesting-web/ssrf-server-side-request-forgery/cloud-ssrf.md#aws) cubre el intercambio de tokens de IMDSv2; esta ruta debe permitir su solicitud `PUT` y retransmitir ambos encabezados de metadatos.<sup>[[5]](#references)</sup> El manejo genérico de encabezados pass-through de LiteLLM elimina el prefijo `x-pass-` antes de reenviarlos, por lo que `x-pass-X-aws-ec2-metadata-token-ttl-seconds: 21600` y `x-pass-X-aws-ec2-metadata-token: <token>` pueden proporcionar esos encabezados.<sup>[[2]](#references)[[7]](#references)</sup> El proxy debe poder alcanzar IMDS, la respuesta del token debe atravesar el límite de saltos configurado y la solicitud del token no debe incluir `X-Forwarded-For`.<sup>[[5]](#references)</sup> La variante específica de la gateway es la **ruta persistente controlada por el administrador más la retransmisión de encabezados de solicitud**.

## References

- [1] [Check Point Research — Cuando las gateways de LLM fallan: hallazgos de LiteLLM](https://research.checkpoint.com/2026/when-llm-gateways-go-wrong-findings-from-litellm/)
- [2] [Wiz — Sin protección: vulnerar LiteLLM, desde la omisión de autenticación hasta el compromiso de la nube](https://wiz.io/blog/off-guard-breaking-litellm-from-authentication-bypass-to-cloud-compromise)
- [3] [LiteLLM PR #22095 — corregir la ejecución remota de código sin autenticación y la evasión del sandbox en la protección de código personalizado](https://github.com/BerriAI/litellm/pull/22095)
- [4] [LiteLLM — Crear endpoints Pass Through](https://docs.litellm.ai/docs/proxy/pass_through)
- [5] [AWS — Cómo funciona la versión 2 del servicio de metadatos de instancias](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-metadata-v2-how-it-works.html)
- [6] [Aviso de LiteLLM — endpoint de configuración de proxy sin restricciones](https://github.com/advisories/GHSA-53mr-6c8q-9789)
- [7] [Implementación del reenvío de encabezados pass-through de LiteLLM](https://github.com/BerriAI/litellm/blob/v1.84.0/litellm/passthrough/utils.py)
{{#include ../banners/hacktricks-training.md}}
