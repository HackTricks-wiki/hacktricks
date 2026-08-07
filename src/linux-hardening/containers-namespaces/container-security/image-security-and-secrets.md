# Seguridad de imágenes, firma y secrets

{{#include ../../../banners/hacktricks-training.md}}

## Registros de imágenes y trust

La seguridad de los containers comienza antes de lanzar el workload. La imagen determina qué binarios, intérpretes, librerías, scripts de inicio y configuración integrada llegan a producción. Si la imagen contiene una backdoor, está desactualizada o se ha creado con secrets incorporados, el hardening del runtime que se aplique después ya estará operando sobre un artefacto comprometido.

Por eso, la procedencia de la imagen, el vulnerability scanning, la verificación de firmas y la gestión de secrets forman parte de la misma conversación que los namespaces y seccomp. Protegen una fase diferente del ciclo de vida, pero los fallos aquí suelen definir la superficie de ataque que el runtime tendrá que contener posteriormente.

## Registros de imágenes y trust

Las imágenes pueden proceder de registros públicos como Docker Hub o de registros privados gestionados por una organización. La cuestión de seguridad no es simplemente dónde reside la imagen, sino si el equipo puede establecer su procedencia e integridad. Hacer pull de imágenes sin firmar o con un seguimiento deficiente desde fuentes públicas aumenta el riesgo de que contenido malicioso o manipulado entre en producción. Incluso los registros alojados internamente necesitan una propiedad, una revisión y una política de trust claras.

Docker Content Trust utilizaba históricamente conceptos de Notary y TUF para exigir imágenes firmadas. El ecosistema exacto ha evolucionado, pero la lección duradera sigue siendo útil: la identidad y la integridad de la imagen deben poder verificarse, en lugar de darse por supuestas.

Ejemplo de workflow histórico de Docker Content Trust:
```bash
export DOCKER_CONTENT_TRUST=1
docker pull nginx:latest
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
El objetivo del ejemplo no es que todos los equipos deban seguir usando las mismas herramientas, sino que el signing y la gestión de claves son tareas operativas, no teoría abstracta.

## Scanning de vulnerabilidades

El scanning de imágenes ayuda a responder dos preguntas diferentes. Primero, ¿la imagen contiene paquetes o librerías vulnerables conocidos? Segundo, ¿la imagen incluye software innecesario que amplía la superficie de ataque? Una imagen llena de herramientas de debugging, shells, intérpretes y paquetes obsoletos es más fácil de explotar y más difícil de analizar.

Algunos ejemplos de scanners utilizados habitualmente son:
```bash
docker scan hello-world
trivy -q -f json alpine:3.19
snyk container test nginx:latest --severity-threshold=high
clair-scanner -w example-alpine.yaml --ip YOUR_LOCAL_IP alpine:3.5
```
Los resultados de estas herramientas deben interpretarse con cuidado. Una vulnerabilidad en un paquete no utilizado no tiene el mismo riesgo que una ruta RCE expuesta, pero ambas siguen siendo relevantes para las decisiones de hardening.

## Secretos en tiempo de compilación

Uno de los errores más antiguos en los pipelines de compilación de contenedores es incorporar secretos directamente en la imagen o pasarlos mediante variables de entorno que posteriormente quedan visibles a través de `docker inspect`, los logs de compilación o las capas recuperadas. Los secretos en tiempo de compilación deben montarse de forma efímera durante la compilación en lugar de copiarse al sistema de archivos de la imagen.

BuildKit mejoró este modelo al permitir una gestión específica de secretos en tiempo de compilación. En lugar de escribir un secreto en una capa, la etapa de compilación puede consumirlo de forma transitoria:
```bash
export DOCKER_BUILDKIT=1
docker build --secret id=my_key,src=path/to/my_secret_file .
```
Esto es importante porque las capas de image son artefactos duraderos. Una vez que un secreto entra en una capa confirmada, eliminar posteriormente el archivo en otra capa no elimina realmente la divulgación original del historial de la image.

## Secretos en tiempo de ejecución

Los secretos necesarios para una carga de trabajo en ejecución también deberían evitar patrones ad hoc, como las variables de entorno en texto plano, siempre que sea posible. Los volúmenes, las integraciones específicas de gestión de secretos, Docker secrets y Kubernetes Secrets son mecanismos habituales. Ninguno de ellos elimina todos los riesgos, especialmente si el atacante ya tiene ejecución de código en la carga de trabajo, pero siguen siendo preferibles a almacenar credenciales permanentemente en la image o exponerlas de forma casual mediante herramientas de inspección.

Una declaración sencilla de secretos con el estilo de Docker Compose tiene este aspecto:
```yaml
version: "3.7"
services:
my_service:
image: centos:7
entrypoint: "cat /run/secrets/my_secret"
secrets:
- my_secret
secrets:
my_secret:
file: ./my_secret_file.txt
```
En Kubernetes, los objetos Secret, los volúmenes projected, los tokens de service account y las identidades de workload en la nube crean un modelo más amplio y potente, pero también generan más oportunidades de exposición accidental mediante montajes del host, RBAC demasiado permisivo o un diseño débil del Pod.

## Abuso

Al revisar un objetivo, el propósito es descubrir si los secretos se incorporaron en la imagen, se filtraron en las capas o se montaron en ubicaciones de runtime predecibles:
```bash
env | grep -iE 'secret|token|key|passwd|password'
find / -maxdepth 4 \( -iname '*.env' -o -iname '*secret*' -o -iname '*token*' \) 2>/dev/null | head -n 100
grep -RniE 'secret|token|apikey|password' /app /srv /usr/src 2>/dev/null | head -n 100
```
Estos comandos ayudan a distinguir entre tres problemas diferentes: leaks de configuración de la aplicación, leaks de la capa de la imagen y archivos de secretos inyectados en runtime. Si aparece un secreto en `/run/secrets`, un volumen proyectado o una ruta de token de identidad de cloud, el siguiente paso es comprender si concede acceso únicamente al workload actual o a un control plane mucho más amplio.

### Ejemplo completo: secreto incrustado en el filesystem de la imagen

Si un build pipeline copió archivos `.env` o credenciales en la imagen final, el post-exploitation se vuelve sencillo:
```bash
find / -type f -iname '*.env*' 2>/dev/null
cat /usr/src/app/.env 2>/dev/null
grep -iE 'secret|token|jwt|password' /usr/src/app/.env 2>/dev/null
```
El impacto depende de la aplicación, pero las claves de firma incrustadas, los secretos JWT o las credenciales cloud pueden convertir fácilmente el compromiso del contenedor en un compromiso de la API, movimiento lateral o falsificación de tokens de aplicación confiables.

### Ejemplo completo: Comprobación de Secret Leak durante la compilación

Si la preocupación es que el historial de la imagen haya capturado una capa que contiene secretos:
```bash
docker history --no-trunc <image>
docker save <image> -o /tmp/image.tar
tar -tf /tmp/image.tar | head
```
Este tipo de revisión es útil porque un secret puede haberse eliminado de la vista final del filesystem y seguir permaneciendo en una capa anterior o en los metadatos de build.

## Comprobaciones

Estas comprobaciones tienen como objetivo determinar si la imagen y el pipeline de gestión de secrets probablemente han aumentado la superficie de ataque antes del runtime.
```bash
docker history --no-trunc <image> 2>/dev/null
env | grep -iE 'secret|token|key|passwd|password'
find /run /var/run /var/lib/kubelet -type f -iname '*token*' 2>/dev/null | head -n 50
grep -RniE 'secret|token|apikey|password' /etc /app /srv /usr/src 2>/dev/null | head -n 100
```
Qué es interesante aquí:

- Un historial de build sospechoso puede revelar credenciales copiadas, material SSH o build steps inseguros.
- Los Secrets ubicados bajo rutas de projected volumes pueden permitir acceso al cluster o a la cloud, no solo acceso a la aplicación local.
- Un gran número de archivos de configuración con credenciales en texto plano suele indicar que la image o el modelo de deployment transporta más material de confianza del necesario.

## Valores predeterminados de Runtime

| Runtime / plataforma | Estado predeterminado | Comportamiento predeterminado | Debilitamiento manual común |
| --- | --- | --- | --- |
| Docker / BuildKit | Admite montajes seguros de secrets durante el build, pero no automáticamente | Los Secrets pueden montarse de forma efímera durante `build`; la firma y el scanning de images requieren decisiones explícitas sobre el workflow | copiar Secrets en la image, pasar Secrets mediante `ARG` o `ENV`, desactivar las comprobaciones de provenance |
| Podman / Buildah | Admite builds nativos de OCI y workflows conscientes de los Secrets | Hay workflows de build sólidos disponibles, pero los operadores deben elegirlos de forma intencionada | incrustar Secrets en Containerfiles, usar build contexts demasiado amplios, permitir bind mounts excesivos durante los builds |
| Kubernetes | Objetos Secret nativos y projected volumes | La entrega de Secrets en Runtime es una funcionalidad de primer nivel, pero la exposición depende de RBAC, el diseño del pod y los host mounts | montajes de Secret demasiado amplios, uso indebido de tokens de service accounts, acceso mediante `hostPath` a volúmenes gestionados por kubelet |
| Registries | La integridad es opcional salvo que se imponga | Tanto los registries públicos como los privados dependen de las políticas, la firma y las decisiones de admission | extraer images sin firmar libremente, admission control débil, mala gestión de claves |

{{#include ../../../banners/hacktricks-training.md}}
