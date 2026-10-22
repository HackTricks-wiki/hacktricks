# Límites de confianza del gateway LLM

{{#include ../banners/hacktricks-training.md}}

Un gateway LLM gestiona el enrutamiento de modelos y suele almacenar credenciales de proveedores, por lo que sus clientes habituales de API no deben heredar autoridad de configuración ni de nivel de proveedor. La evaluación del gateway LiteLLM en la versión 1.77.7 ilustra dos límites independientes: la autorización de sesiones de UI para la configuración administrativa y la configuración de enrutamiento proporcionada por el cliente para la inferencia. Los problemas reportados se corrigieron en la versión 1.83.9.<sup>[[1]](#references)</sup>

## La clasificación de rutas de UI no es autorización

En la versión evaluada de LiteLLM, las claves de inicio de sesión de UI pertenecían al equipo `litellm-dashboard`. La autorización clasificaba una clave como token de UI según el identificador de ese equipo, independientemente del rol del usuario. Luego, la comprobación de rutas de UI aceptaba cualquier ruta que comenzara con un prefijo permitido. Como resultado, la entrada `/config` también coincidía con el handler administrativo `/config/update`. Ese handler requería autenticación genérica, pero no exigía de forma independiente `PROXY_ADMIN`, por lo que una sesión de UI con menos privilegios obtenía acceso de escritura a la configuración.<sup>[[1]](#references)</sup>

Esto difiere de una discrepancia en la normalización de rutas entre el proxy y el backend: el código de autorización y el handler discrepan sobre la autoridad de la *misma* ruta.<sup>[[1]](#references)</sup> Al revisar un gateway, compara la clasificación de tokens, la coincidencia exacta de rutas y métodos, y la comprobación de roles propia del handler.<sup>[[1]](#references)</sup> Consulta [autorización de API web](../pentesting-web/web-api-pentesting.md), [bypasses de 401/403](../pentesting-web/403-and-401-bypasses.md) y [exenciones de prefijos del proxy](../pentesting-web/proxy-waf-protections-bypass.md#prefix-exemptions-become-routing-keys) para conocer límites relacionados, pero distintos.

## Las escrituras de configuración llegan más allá del almacén de configuración

La misma actualización de configuración de LiteLLM aceptaba valores de variables de entorno y los aplicaba al proceso en ejecución. Un consumidor trataba `UI_LOGO_PATH` como una ruta local para `FileResponse`, sin validar que apuntara a un logotipo; otro leía `UI_USERNAME` y `UI_PASSWORD` durante el inicio de sesión sin SSO y asignaba `PROXY_ADMIN` si coincidían. Así, el permiso de escritura de configuración podía convertirse tanto en divulgación de archivos locales como en un cambio de identidad administrativa, según el consumidor posterior. El tipo de medio de la respuesta no demuestra que el archivo servido sea una imagen.<sup>[[1]](#references)</sup>

La configuración del endpoint pass-through era otro sumidero posterior. La inicialización aceptaba destinos de adaptadores remotos S3/GCS, descargaba módulos de Python y los importaba mediante `exec_module` de `importlib`. La importación ejecuta el código de nivel superior antes de usar una instancia del adaptador; restringir únicamente la invocación del adaptador no eliminaría ese límite de ejecución. Trátalo como carga de código controlada por la configuración, no como deserialización de archivos de modelo.<sup>[[1]](#references)</sup> Para la primitiva independiente de lectura de archivos, consulta [inclusión de archivos y traversal de rutas](../pentesting-web/file-inclusion/).

## El enrutamiento de modelos por solicitud puede filtrar credenciales del gateway

La función de credenciales del lado del cliente de LiteLLM aceptaba un objeto `user_config` en una solicitud LLM. La ruta evaluada creaba un `litellm.Router` temporal a partir de ese objeto, incluida su lista de modelos y el `api_base` del proveedor. Un destino de proveedor controlado por el cliente podía recibir la solicitud de completado saliente del gateway y los encabezados de autenticación del proveedor configurado. Las restricciones sobre los campos `api_base` o `api_key` de nivel superior no cubrían esta ruta de configuración anidada independiente. Este es un límite de SSRF con credenciales, no un problema de prompt-injection.<sup>[[1]](#references)</sup>

En una evaluación autorizada de un gateway, compara todas las rutas que pueden construir un router o un cliente de proveedor, incluida la configuración por solicitud, con la política de destinos y credenciales usada por la ruta configurada normal.<sup>[[1]](#references)</sup> La [guía de SSRF](../pentesting-web/ssrf-server-side-request-forgery/) cubre el control general de destinos del lado del servidor; el fallo específico del gateway consiste en permitir que un objeto de solicitud menos confiable seleccione un destino mientras reutiliza credenciales salientes privilegiadas.<sup>[[1]](#references)</sup>

## References

- [1] [Check Point Research — Cuando los gateways LLM fallan: hallazgos de LiteLLM](https://research.checkpoint.com/2026/when-llm-gateways-go-wrong-findings-from-litellm/)
{{#include ../banners/hacktricks-training.md}}
