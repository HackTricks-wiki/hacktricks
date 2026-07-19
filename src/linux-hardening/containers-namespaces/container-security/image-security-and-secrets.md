# Seguridad de Imágenes, Signing y Secrets

{{#include ../../../banners/hacktricks-training.md}}

## Descripción general

La seguridad de los containers comienza antes de lanzar el workload. La image determina qué binaries, interpreters, libraries, startup scripts y configuración embebida llegan a production. Si la image tiene un backdoor, está desactualizada o se ha construido con secrets incorporados, el hardening del runtime que se aplique después ya estará operando sobre un artifact comprometido.

Por eso, la procedencia de la image, el vulnerability scanning, la verificación de signatures y el manejo de secrets forman parte de la misma conversación que los namespaces y seccomp. Protegen una fase diferente del lifecycle, pero los fallos en esta fase suelen definir la attack surface que el runtime tendrá que contener posteriormente.

## Image Registries y Trust

Las images pueden proceder de public registries como Docker Hub o de private registries gestionados por una organización. La cuestión de seguridad no es simplemente dónde reside la image, sino si el equipo puede establecer su procedencia e integridad. Hacer pull de images unsigned o con un seguimiento deficiente desde fuentes públicas aumenta el riesgo de que contenido malicioso o manipulado entre en production. Incluso los registries alojados internamente necesitan ownership, revisión y una trust policy claros.

Docker Content Trust utilizaba históricamente conceptos de Notary y TUF para exigir images firmadas. El ecosistema exacto ha evolucionado, pero la lección sigue siendo útil: la identidad y la integridad de la image deben poder verificarse, no darse por supuestas.

Ejemplo de un workflow histórico de Docker Content Trust:
```bash
export DOCKER_CONTENT_TRUST=1
docker pull nginx:latest
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
El objetivo del ejemplo no es que todos los equipos tengan que seguir utilizando las mismas herramientas, sino que la firma y la gestión de claves son tareas operativas, no teoría abstracta.

## Escaneo de vulnerabilidades

El escaneo de imágenes ayuda a responder a dos preguntas diferentes. Primero, ¿la imagen contiene paquetes o librerías con vulnerabilidades conocidas? Segundo, ¿la imagen incluye software innecesario que amplía la superficie de ataque? Una imagen llena de herramientas de debugging, shells, intérpretes y paquetes obsoletos es más fácil de explotar y más difícil de analizar.

Algunos ejemplos de scanners utilizados habitualmente son:
```bash
docker scan hello-world
trivy -q -f json alpine:3.19
snyk container test nginx:latest --severity-threshold=high
clair-scanner -w example-alpine.yaml --ip YOUR_LOCAL_IP alpine:3.5
```
Los resultados de estas herramientas deben interpretarse cuidadosamente. Una vulnerability en un package sin usar no tiene el mismo riesgo que un path de RCE expuesto, pero ambas siguen siendo relevantes para las decisiones de hardening.

## Secrets durante el build

Uno de los errores más antiguos en los pipelines de build de containers consiste en incrustar secrets directamente en la image o pasarlos mediante environment variables que posteriormente quedan visibles a través de `docker inspect`, los build logs o las layers recuperadas. Los secrets durante el build deben montarse de forma efímera durante el build en lugar de copiarse al filesystem de la image.

BuildKit mejoró este modelo al permitir un manejo específico de los secrets durante el build. En lugar de escribir un secret en una layer, el build step puede consumirlo de forma transitoria:
```bash
export DOCKER_BUILDKIT=1
docker build --secret id=my_key,src=path/to/my_secret_file .
```
Esto es importante porque las capas de imagen son artefactos duraderos. Una vez que un secreto entra en una capa confirmada, eliminar posteriormente el archivo en otra capa no elimina realmente la divulgación original del historial de la imagen.

## Secretos en tiempo de ejecución

Los secretos necesarios para una workload en ejecución también deberían evitar patrones improvisados, como las variables de entorno sin protección, siempre que sea posible. Los volúmenes, las integraciones específicas de gestión de secretos, Docker secrets y Kubernetes Secrets son mecanismos comunes. Ninguno elimina todos los riesgos, especialmente si el atacante ya tiene ejecución de código en la workload, pero siguen siendo preferibles a almacenar credenciales permanentemente en la imagen o exponerlas de manera imprudente mediante herramientas de inspección.

Una declaración sencilla de secretos al estilo Docker Compose tiene este aspecto:
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
En Kubernetes, los objetos Secret, los volúmenes proyectados, los tokens de service-account y las identidades de workload en la nube crean un modelo más amplio y potente, pero también generan más oportunidades de exposición accidental mediante montajes del host, RBAC demasiado permisivo o un diseño débil del Pod.

## Abuso

Al revisar un objetivo, el propósito es descubrir si los secrets se incorporaron en la image, se filtraron en las capas o se montaron en ubicaciones predecibles de runtime:
```bash
env | grep -iE 'secret|token|key|passwd|password'
find / -maxdepth 4 \( -iname '*.env' -o -iname '*secret*' -o -iname '*token*' \) 2>/dev/null | head -n 100
grep -RniE 'secret|token|apikey|password' /app /srv /usr/src 2>/dev/null | head -n 100
```
Estos comandos ayudan a distinguir entre tres problemas diferentes: filtraciones de configuración de la aplicación, filtraciones en las capas de la image y archivos de secretos inyectados en runtime. Si aparece un secreto en `/run/secrets`, en un volumen proyectado o en una ruta de token de identidad cloud, el siguiente paso es comprender si solo concede acceso al workload actual o a un control plane mucho más amplio.

### Ejemplo completo: secreto incrustado en el filesystem de la image

Si un build pipeline copió archivos `.env` o credenciales en la image final, el post-exploitation se vuelve sencillo:
```bash
find / -type f -iname '*.env*' 2>/dev/null
cat /usr/src/app/.env 2>/dev/null
grep -iE 'secret|token|jwt|password' /usr/src/app/.env 2>/dev/null
```
El impacto depende de la aplicación, pero las claves de firma incrustadas, los secretos JWT o las credenciales cloud pueden convertir fácilmente el compromiso del contenedor en un compromiso de la API, movimiento lateral o falsificación de tokens de aplicación confiables.

### Ejemplo completo: Comprobación de leak de secretos durante el build

Si la preocupación es que el historial de la imagen capturó una capa que contenía un secreto:
```bash
docker history --no-trunc <image>
docker save <image> -o /tmp/image.tar
tar -tf /tmp/image.tar | head
```
Este tipo de revisión es útil porque un secreto puede haberse eliminado de la vista final del filesystem y, aun así, permanecer en una capa anterior o en los metadatos de build.

## Comprobaciones

Estas comprobaciones tienen como objetivo determinar si la imagen y el pipeline de gestión de secretos probablemente han aumentado la superficie de ataque antes del runtime.
```bash
docker history --no-trunc <image> 2>/dev/null
env | grep -iE 'secret|token|key|passwd|password'
find /run /var/run /var/lib/kubelet -type f -iname '*token*' 2>/dev/null | head -n 50
grep -RniE 'secret|token|apikey|password' /etc /app /srv /usr/src 2>/dev/null | head -n 100
```
Qué resulta interesante aquí:

- Un historial de build sospechoso puede revelar credenciales copiadas, material SSH o pasos de build inseguros.
- Los secretos ubicados en rutas de volúmenes proyectados pueden permitir el acceso al cluster o a la cloud, no solo a la aplicación local.
- Una gran cantidad de archivos de configuración con credenciales en texto plano normalmente indica que la image o el modelo de deployment transporta más material de confianza del necesario.

## Valores predeterminados de Runtime

| Runtime / plataforma | Estado predeterminado | Comportamiento predeterminado | Debilitamiento manual habitual |
| --- | --- | --- | --- |
| Docker / BuildKit | Admite montajes seguros de secretos durante el build, pero no de forma automática | Los secretos pueden montarse de forma efímera durante `build`; la firma y el scanning de la image requieren decisiones explícitas sobre el workflow | copiar secretos en la image, pasar secretos mediante `ARG` o `ENV`, deshabilitar las comprobaciones de provenance |
| Podman / Buildah | Admite builds nativos de OCI y workflows con soporte para secretos | Hay workflows de build sólidos disponibles, pero los operadores deben elegirlos de forma intencionada | incrustar secretos en los Containerfiles, usar contextos de build demasiado amplios, montajes bind permisivos durante los builds |
| Kubernetes | Objetos Secret nativos y volúmenes proyectados | La entrega de secretos en Runtime es una función de primera clase, pero la exposición depende de RBAC, del diseño del pod y de los montajes del host | montajes de Secret demasiado amplios, uso indebido de tokens de service account, acceso mediante `hostPath` a volúmenes gestionados por kubelet |
| Registries | La integridad es opcional salvo que se fuerce | Tanto los registries públicos como los privados dependen de las políticas, la firma y las decisiones de admisión | extraer libremente images sin firmar, controles de admisión débiles, mala gestión de claves |
{{#include ../../../banners/hacktricks-training.md}}
