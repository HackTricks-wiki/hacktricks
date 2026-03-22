# Seguridad de imágenes, firmado y secretos

{{#include ../../../banners/hacktricks-training.md}}

## Overview

La seguridad de contenedores comienza antes de que se lance la carga de trabajo. La imagen determina qué binarios, intérpretes, librerías, scripts de inicio y configuración embebida llegan a producción. Si la imagen está comprometida con una puerta trasera, obsoleta o fue construida con secretos incluidos en ella, el endurecimiento en tiempo de ejecución que sigue ya estará operando sobre un artefacto comprometido.

Por eso la procedencia de las imágenes, el escaneo de vulnerabilidades, la verificación de firmas y el manejo de secretos pertenecen a la misma conversación que namespaces y seccomp. Protegen una fase distinta del ciclo de vida, pero las fallas aquí a menudo definen la superficie de ataque que el runtime tendrá que contener más adelante.

## Image Registries And Trust

Las imágenes pueden venir de registros públicos como Docker Hub o de registros privados operados por una organización. La pregunta de seguridad no es simplemente dónde reside la imagen, sino si el equipo puede establecer su procedencia e integridad. Descargar imágenes sin firmar o con un seguimiento deficiente desde fuentes públicas aumenta el riesgo de que contenido malicioso o manipulado llegue a producción. Incluso los registros alojados internamente necesitan propiedad clara, revisión y una política de confianza.

Docker Content Trust históricamente usó los conceptos de Notary y TUF para exigir imágenes firmadas. El ecosistema exacto ha evolucionado, pero la lección perdurable sigue siendo útil: la identidad e integridad de la imagen deben ser verificables en lugar de asumidas.

Example historical Docker Content Trust workflow:
```bash
export DOCKER_CONTENT_TRUST=1
docker pull nginx:latest
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
El punto del ejemplo no es que cada equipo deba seguir usando las mismas herramientas, sino que signing and key management son tareas operativas, no teoría abstracta.

## Escaneo de Vulnerabilidades

El escaneo de imágenes ayuda a responder dos preguntas diferentes. Primero: ¿la imagen contiene paquetes o bibliotecas conocidas con vulnerabilidades? Segundo: ¿la imagen incluye software innecesario que amplía la superficie de ataque? Una imagen llena de herramientas de depuración, shells, intérpretes y paquetes obsoletos es, a la vez, más fácil de explotar y más difícil de analizar.

Ejemplos de escáneres comúnmente usados incluyen:
```bash
docker scan hello-world
trivy -q -f json alpine:3.19
snyk container test nginx:latest --severity-threshold=high
clair-scanner -w example-alpine.yaml --ip YOUR_LOCAL_IP alpine:3.5
```
Los resultados de estas herramientas deben interpretarse con cuidado. Una vulnerabilidad en un paquete no utilizado no equivale en riesgo a una ruta RCE expuesta, pero ambos siguen siendo relevantes para las decisiones de hardening.

## Build-Time Secrets

Uno de los errores más antiguos en los pipelines de build de contenedores es incrustar secrets directamente en la imagen o pasarlos mediante variables de entorno que después quedan visibles a través de `docker inspect`, los logs de build o capas recuperadas. Los build-time secrets deben montarse de forma efímera durante la build en lugar de copiarse en el sistema de archivos de la imagen.

BuildKit mejoró este modelo permitiendo el manejo dedicado de build-time secrets. En lugar de escribir un secret en una layer, el paso de build puede consumirlo de forma transitoria:
```bash
export DOCKER_BUILDKIT=1
docker build --secret id=my_key,src=path/to/my_secret_file .
```
Esto importa porque las capas de la imagen son artefactos duraderos. Una vez que un secreto entra en una capa confirmada, eliminar después el archivo en otra capa no elimina realmente la divulgación original del historial de la imagen.

## Secretos en tiempo de ejecución

Los secretos necesarios para una carga de trabajo en ejecución también deben evitar patrones ad hoc como las simples variables de entorno siempre que sea posible. Los volúmenes, las integraciones dedicadas de gestión de secretos, Docker secrets y Kubernetes Secrets son mecanismos comunes. Ninguno de estos elimina todos los riesgos, especialmente si el atacante ya tiene ejecución de código en la carga de trabajo, pero siguen siendo preferibles a almacenar credenciales de forma permanente en la imagen o exponerlas de forma casual mediante herramientas de inspección.

Una declaración simple de secret al estilo Docker Compose se ve así:
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
En Kubernetes, los objetos Secret, los projected volumes, los service-account tokens y las cloud workload identities crean un modelo más amplio y potente, pero también crean más oportunidades de exposición accidental a través de host mounts, RBAC demasiado amplio o un diseño de Pod débil.

## Abuso

Al revisar un objetivo, la meta es descubrir si los secretos fueron incorporados en la imagen, leaked en las capas, o montados en ubicaciones de runtime previsibles:
```bash
env | grep -iE 'secret|token|key|passwd|password'
find / -maxdepth 4 \( -iname '*.env' -o -iname '*secret*' -o -iname '*token*' \) 2>/dev/null | head -n 100
grep -RniE 'secret|token|apikey|password' /app /srv /usr/src 2>/dev/null | head -n 100
```
Estos comandos ayudan a distinguir entre tres problemas diferentes: application configuration leaks, image-layer leaks y runtime-injected secret files. Si un secreto aparece bajo `/run/secrets`, un volumen proyectado, o una ruta de token de identidad en la nube, el siguiente paso es entender si otorga acceso solo a la carga de trabajo actual o a un plano de control mucho más amplio.

### Ejemplo completo: secreto embebido en el sistema de archivos de la imagen

Si una pipeline de build copió archivos `.env` o credenciales en la imagen final, post-exploitation se vuelve simple:
```bash
find / -type f -iname '*.env*' 2>/dev/null
cat /usr/src/app/.env 2>/dev/null
grep -iE 'secret|token|jwt|password' /usr/src/app/.env 2>/dev/null
```
El impacto depende de la aplicación, pero claves de firma embebidas, secretos JWT o credenciales en la nube pueden convertir fácilmente el compromiso del contenedor en compromiso de la API, lateral movement o falsificación de tokens de aplicación confiables.

### Ejemplo completo: Build-Time Secret Leakage Check

Si la preocupación es que el historial de la imagen capturó una capa que contiene secretos:
```bash
docker history --no-trunc <image>
docker save <image> -o /tmp/image.tar
tar -tf /tmp/image.tar | head
```
Este tipo de revisión es útil porque un secreto puede haber sido eliminado de la vista final del sistema de archivos mientras aún permanece en una capa anterior o en los metadatos de compilación.

## Comprobaciones

Estas comprobaciones están destinadas a determinar si es probable que la imagen y la pipeline de manejo de secretos hayan aumentado la superficie de ataque antes del tiempo de ejecución.
```bash
docker history --no-trunc <image> 2>/dev/null
env | grep -iE 'secret|token|key|passwd|password'
find /run /var/run /var/lib/kubelet -type f -iname '*token*' 2>/dev/null | head -n 50
grep -RniE 'secret|token|apikey|password' /etc /app /srv /usr/src 2>/dev/null | head -n 100
```
Lo interesante aquí:

- Un historial de build sospechoso puede revelar credenciales copiadas, material SSH o pasos de build inseguros.
- Secrets bajo rutas de volúmenes proyectados pueden dar acceso al cluster o a la cloud, no solo acceso local de la aplicación.
- Un gran número de archivos de configuración con credenciales en texto plano suele indicar que la imagen o el modelo de despliegue transporta más material de confianza del necesario.

## Valores predeterminados en tiempo de ejecución

| Runtime / plataforma | Estado predeterminado | Comportamiento predeterminado | Debilitamiento manual común |
| --- | --- | --- | --- |
| Docker / BuildKit | Soporta montajes seguros de Secrets en tiempo de build, pero no automáticamente | Los Secrets pueden montarse de forma efímera durante `build`; el firmado y escaneado de la imagen requieren elecciones explícitas en el workflow | copiar Secrets dentro de la imagen, pasar Secrets por `ARG` o `ENV`, desactivar las comprobaciones de provenance |
| Podman / Buildah | Soporta builds nativos OCI y workflows conscientes de Secrets | Están disponibles workflows de build fuertes, pero los operadores aún deben elegirlos intencionalmente | incrustar Secrets en Containerfiles, contextos de build amplios, bind mounts permisivos durante builds |
| Kubernetes | Objetos Secret nativos y volúmenes proyectados | La entrega de Secrets en tiempo de ejecución es de primera clase, pero la exposición depende de RBAC, diseño del pod y montajes del host | montajes de Secret demasiado amplios, mal uso de service-account tokens, acceso `hostPath` a volúmenes gestionados por kubelet |
| Registries | La integridad es opcional a menos que se haga cumplir | Los registries públicos y privados dependen de políticas, firmado y decisiones de admission | descargar imágenes sin firmar libremente, control de admisión débil, mala gestión de claves |
{{#include ../../../banners/hacktricks-training.md}}
