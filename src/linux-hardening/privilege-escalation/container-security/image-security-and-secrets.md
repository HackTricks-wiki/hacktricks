# Seguridad de imágenes, firmado y secretos

{{#include ../../../banners/hacktricks-training.md}}

## Resumen

La seguridad de contenedores comienza antes de que se lance la carga de trabajo. La imagen determina qué binarios, intérpretes, bibliotecas, scripts de arranque y configuración embebida llegan a producción. Si la imagen tiene una puerta trasera, está obsoleta o fue construida con secretos integrados, el endurecimiento en tiempo de ejecución que sigue ya está operando sobre un artefacto comprometido.

Por eso la procedencia de la imagen, el escaneo de vulnerabilidades, la verificación de firmas y el manejo de secretos deben formar parte de la misma conversación que namespaces y seccomp. Protegen una fase diferente del ciclo de vida, pero las fallas aquí suelen definir la superficie de ataque que el runtime tendrá que contener más adelante.

## Registros de imágenes y confianza

Las imágenes pueden provenir de registros públicos como Docker Hub o de registros privados operados por una organización. La cuestión de seguridad no es simplemente dónde reside la imagen, sino si el equipo puede establecer su procedencia e integridad. Descargar imágenes sin firmar o con poco control desde fuentes públicas aumenta el riesgo de que contenido malicioso o manipulado llegue a producción. Incluso los registros alojados internamente necesitan una propiedad clara, revisión y políticas de confianza.

Docker Content Trust históricamente usó los conceptos de Notary y TUF para requerir imágenes firmadas. El ecosistema exacto ha evolucionado, pero la lección perdurable sigue siendo útil: la identidad e integridad de la imagen deben ser verificables y no asumidas.

Ejemplo de flujo de trabajo histórico de Docker Content Trust:
```bash
export DOCKER_CONTENT_TRUST=1
docker pull nginx:latest
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
El objetivo del ejemplo no es que todos los equipos deban seguir usando las mismas herramientas, sino que el firmado y la gestión de claves son tareas operativas, no teoría abstracta.

## Escaneo de Vulnerabilidades

El escaneo de imágenes ayuda a responder dos preguntas diferentes. Primero, ¿la imagen contiene paquetes o bibliotecas con vulnerabilidades conocidas? Segundo, ¿la imagen incluye software innecesario que amplía la superficie de ataque? Una imagen llena de herramientas de depuración, shells, intérpretes y paquetes obsoletos es tanto más fácil de explotar como más difícil de analizar.

Ejemplos de escáneres comúnmente usados incluyen:
```bash
docker scan hello-world
trivy -q -f json alpine:3.19
snyk container test nginx:latest --severity-threshold=high
clair-scanner -w example-alpine.yaml --ip YOUR_LOCAL_IP alpine:3.5
```
Los resultados de estas herramientas deben interpretarse con cuidado. Una vulnerabilidad en un paquete sin usar no equivale en riesgo a una ruta RCE expuesta, pero ambos siguen siendo relevantes para las decisiones de hardening.

## Secretos en tiempo de compilación

Uno de los errores más antiguos en las pipelines de construcción de contenedores es incrustar secretos directamente en la imagen o pasarlos mediante variables de entorno que luego quedan visibles a través de `docker inspect`, registros de construcción o capas recuperadas. Los secretos en tiempo de compilación deben montarse de forma efímera durante la construcción en lugar de copiarse al sistema de archivos de la imagen.

BuildKit mejoró este modelo permitiendo un manejo dedicado de secretos en tiempo de construcción. En lugar de escribir un secreto en una capa, el paso de construcción puede consumirlo de forma transitoria:
```bash
export DOCKER_BUILDKIT=1
docker build --secret id=my_key,src=path/to/my_secret_file .
```
Esto importa porque las capas de la imagen son artefactos duraderos. Una vez que un secreto entra en una capa comprometida, eliminar el archivo más tarde en otra capa no elimina realmente la divulgación original del historial de la imagen.

## Secretos en tiempo de ejecución

Los secretos necesarios por una carga de trabajo en ejecución también deben evitar patrones ad hoc, como el uso directo de variables de entorno, siempre que sea posible. Volúmenes, integraciones dedicadas de gestión de secretos, Docker secrets y Kubernetes Secrets son mecanismos comunes. Ninguno de estos elimina todo el riesgo, especialmente si el atacante ya tiene ejecución de código en la carga de trabajo, pero siguen siendo preferibles a almacenar credenciales de forma permanente en la imagen o exponerlas de forma casual mediante herramientas de inspección.

Una simple declaración de secret al estilo Docker Compose se ve así:
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
En Kubernetes, Secret objects, projected volumes, service-account tokens y cloud workload identities crean un modelo más amplio y potente, pero también generan más oportunidades de exposición accidental a través de host mounts, un RBAC excesivamente amplio o un diseño de Pod débil.

## Abuso

Al revisar un objetivo, la meta es descubrir si los secrets fueron incorporados en la image, leaked en las layers o montados en ubicaciones de runtime predecibles:
```bash
env | grep -iE 'secret|token|key|passwd|password'
find / -maxdepth 4 \( -iname '*.env' -o -iname '*secret*' -o -iname '*token*' \) 2>/dev/null | head -n 100
grep -RniE 'secret|token|apikey|password' /app /srv /usr/src 2>/dev/null | head -n 100
```
Estos comandos ayudan a distinguir entre tres problemas diferentes: application configuration leaks, image-layer leaks y runtime-injected secret files. Si un secreto aparece bajo `/run/secrets`, en un volumen proyectado o en una ruta de token de identidad en la nube, el siguiente paso es entender si concede acceso solo al workload actual o a un plano de control mucho más amplio.

### Ejemplo completo: Secreto incrustado en el sistema de archivos de la imagen

Si un pipeline de build copió archivos `.env` o credenciales en la imagen final, post-exploitation se vuelve simple:
```bash
find / -type f -iname '*.env*' 2>/dev/null
cat /usr/src/app/.env 2>/dev/null
grep -iE 'secret|token|jwt|password' /usr/src/app/.env 2>/dev/null
```
El impacto depende de la aplicación, pero claves de firma incrustadas, secretos JWT o credenciales en la nube pueden convertir fácilmente la compromisión de un contenedor en una compromisión de la API, movimiento lateral o la falsificación de tokens de aplicación confiables.

### Full Example: Build-Time Secret Leakage Check

Si la preocupación es que el historial de la imagen capturó una capa que contiene secretos:
```bash
docker history --no-trunc <image>
docker save <image> -o /tmp/image.tar
tar -tf /tmp/image.tar | head
```
Este tipo de revisión es útil porque un secreto puede haberse eliminado de la vista final del sistema de archivos mientras todavía permanece en una capa anterior o en los metadatos de compilación.

## Comprobaciones

Estas comprobaciones están destinadas a determinar si la imagen y la pipeline de gestión de secretos probablemente han aumentado la superficie de ataque antes del tiempo de ejecución.
```bash
docker history --no-trunc <image> 2>/dev/null
env | grep -iE 'secret|token|key|passwd|password'
find /run /var/run /var/lib/kubelet -type f -iname '*token*' 2>/dev/null | head -n 50
grep -RniE 'secret|token|apikey|password' /etc /app /srv /usr/src 2>/dev/null | head -n 100
```
Qué es interesante aquí:

- Un historial de build sospechoso puede revelar credenciales copiadas, material SSH o pasos de build inseguros.
- Los secretos en rutas de volúmenes proyectados pueden permitir acceso al cluster o a la nube, no solo acceso a la aplicación local.
- Un gran número de archivos de configuración con credenciales en texto plano suele indicar que la imagen o el modelo de despliegue porta más material de confianza del necesario.

## Runtime Defaults

| Runtime / platform | Default state | Default behavior | Common manual weakening |
| --- | --- | --- | --- |
| Docker / BuildKit | Admite montajes seguros de secretos en tiempo de build, pero no automáticamente | Los secretos pueden montarse efímeramente durante `build`; el firmado y escaneo de imágenes requieren decisiones explícitas de flujo de trabajo | copiar secretos dentro de la imagen, pasar secretos por `ARG` o `ENV`, deshabilitar las comprobaciones de procedencia |
| Podman / Buildah | Admite builds nativos OCI y flujos de trabajo con soporte para secretos | Hay flujos de build robustos disponibles, pero los operadores deben elegirlos intencionalmente | incrustar secretos en Containerfiles, contextos de build amplios, montajes bind permisivos durante las builds |
| Kubernetes | Objetos Secret nativos y volúmenes proyectados | La entrega de secretos en tiempo de ejecución es de primera clase, pero la exposición depende de RBAC, el diseño de pods y los montajes del host | montajes de Secret demasiado amplios, uso indebido de tokens de la cuenta de servicio, acceso por `hostPath` a volúmenes gestionados por kubelet |
| Registries | La integridad es opcional a menos que se haga cumplir | Los registries públicos y privados dependen de políticas, firmado y decisiones de admisión | descargar imágenes sin firmar libremente, control de admisión débil, mala gestión de claves |
{{#include ../../../banners/hacktricks-training.md}}
