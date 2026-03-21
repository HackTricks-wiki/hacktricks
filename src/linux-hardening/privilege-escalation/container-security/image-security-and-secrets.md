# Seguridad de imágenes, firmado y secretos

{{#include ../../../banners/hacktricks-training.md}}

## Resumen

La seguridad de contenedores empieza antes de lanzar la carga de trabajo. La imagen determina qué binarios, intérpretes, librerías, scripts de arranque y configuración embebida llegan a producción. Si la imagen tiene una puerta trasera, está desactualizada o fue construida con secretos incrustados, el hardening en tiempo de ejecución que siga ya estará operando sobre un artefacto comprometido.

Por eso la procedencia de las imágenes, el escaneo de vulnerabilidades, la verificación de firmas y el manejo de secretos deben entrar en la misma conversación que namespaces y seccomp. Protegen una fase distinta del ciclo de vida, pero las fallas aquí a menudo definen la superficie de ataque que el runtime luego tendrá que contener.

## Registros de imágenes y confianza

Las imágenes pueden venir de registries públicos como Docker Hub o de registries privados operados por una organización. La pregunta de seguridad no es simplemente dónde vive la imagen, sino si el equipo puede establecer procedencia e integridad. Descargar imágenes sin firmar o con poco seguimiento desde fuentes públicas aumenta el riesgo de que contenido malicioso o manipulado llegue a producción. Incluso los registries alojados internamente necesitan propiedad clara, revisión y políticas de confianza.

Docker Content Trust históricamente usó conceptos de Notary y TUF para requerir imágenes firmadas. El ecosistema exacto ha evolucionado, pero la lección perdurable sigue siendo útil: la identidad e integridad de la imagen deben ser verificables en lugar de asumidas.

Ejemplo histórico del flujo de trabajo de Docker Content Trust:
```bash
export DOCKER_CONTENT_TRUST=1
docker pull nginx:latest
tar -zcvf private_keys_backup.tar.gz ~/.docker/trust/private
```
El punto del ejemplo no es que todos los equipos deban seguir usando las mismas herramientas, sino que signing y key management son tareas operativas, no teoría abstracta.

## Escaneo de vulnerabilidades

El escaneo de imágenes ayuda a responder dos preguntas diferentes. Primero, ¿contiene la imagen paquetes o bibliotecas con vulnerabilidades conocidas? Segundo, ¿incluye la imagen software innecesario que amplía la superficie de ataque? Una imagen llena de herramientas de depuración, shells, intérpretes y paquetes desactualizados es tanto más fácil de explotar como más difícil de comprender.

Ejemplos de escáneres comúnmente usados incluyen:
```bash
docker scan hello-world
trivy -q -f json alpine:3.19
snyk container test nginx:latest --severity-threshold=high
clair-scanner -w example-alpine.yaml --ip YOUR_LOCAL_IP alpine:3.5
```
Los resultados de estas herramientas deben interpretarse con cuidado. Una vulnerabilidad en un paquete sin usar no tiene el mismo riesgo que una ruta de RCE expuesta, pero ambas siguen siendo relevantes para las decisiones de hardening.

## Secretos en tiempo de compilación

Uno de los errores más antiguos en las pipelines de compilación de contenedores es incrustar secretos directamente en la imagen o pasarlos mediante variables de entorno que más tarde se hacen visibles mediante `docker inspect`, registros de compilación o capas recuperadas. Los secretos en tiempo de compilación deberían montarse de forma efímera durante la compilación en lugar de copiarse en el sistema de archivos de la imagen.

BuildKit mejoró este modelo al permitir un manejo dedicado de secretos en tiempo de compilación. En lugar de escribir un secreto en una capa, el paso de compilación puede consumirlo de forma transitoria:
```bash
export DOCKER_BUILDKIT=1
docker build --secret id=my_key,src=path/to/my_secret_file .
```
Esto importa porque las capas de imagen son artefactos duraderos. Una vez que un secreto entra en una capa comprometida, borrar después el archivo en otra capa no elimina realmente la divulgación original del historial de la imagen.

## Secretos en tiempo de ejecución

Los secretos necesarios para una carga de trabajo en ejecución también deberían evitar patrones ad hoc como las variables de entorno en texto plano siempre que sea posible. Los volúmenes, las integraciones dedicadas de gestión de secretos, Docker secrets y Kubernetes Secrets son mecanismos comunes. Ninguno de estos elimina todo el riesgo, especialmente si el atacante ya tiene ejecución de código en la carga de trabajo, pero siguen siendo preferibles a almacenar credenciales de forma permanente en la imagen o exponerlas de forma casual mediante herramientas de inspección.

Una declaración simple de secretos al estilo Docker Compose se ve así:
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
En Kubernetes, los Secret objects, los projected volumes, los service-account tokens y las cloud workload identities crean un modelo más amplio y potente, pero también generan más oportunidades de exposición accidental a través de host mounts, RBAC amplio o un diseño débil del Pod.

## Abuso

Al revisar un objetivo, la intención es descubrir si los secrets fueron baked into the image, leaked into layers o montados en ubicaciones de runtime previsibles:
```bash
env | grep -iE 'secret|token|key|passwd|password'
find / -maxdepth 4 \( -iname '*.env' -o -iname '*secret*' -o -iname '*token*' \) 2>/dev/null | head -n 100
grep -RniE 'secret|token|apikey|password' /app /srv /usr/src 2>/dev/null | head -n 100
```
Estos comandos ayudan a distinguir entre tres problemas diferentes: application configuration leaks, image-layer leaks y runtime-injected secret files. Si un secreto aparece bajo `/run/secrets`, un projected volume, o una ruta de token de identidad en la nube, el siguiente paso es entender si otorga acceso solo al workload actual o a un plano de control mucho más amplio.

### Ejemplo completo: Secreto incrustado en el sistema de archivos de la imagen

Si un pipeline de build copió archivos `.env` o credenciales en la imagen final, post-exploitation se vuelve simple:
```bash
find / -type f -iname '*.env*' 2>/dev/null
cat /usr/src/app/.env 2>/dev/null
grep -iE 'secret|token|jwt|password' /usr/src/app/.env 2>/dev/null
```
El impacto depende de la aplicación, pero embedded signing keys, JWT secrets o cloud credentials pueden convertir fácilmente una container compromise en API compromise, lateral movement o la falsificación de tokens de aplicación confiables.

### Ejemplo completo: Build-Time Secret Leakage Check

Si la preocupación es que el historial de la imagen capturó una capa que contiene secretos:
```bash
docker history --no-trunc <image>
docker save <image> -o /tmp/image.tar
tar -tf /tmp/image.tar | head
```
Este tipo de revisión es útil porque un secreto puede haber sido eliminado de la vista final del sistema de archivos mientras todavía permanecía en una capa anterior o en los metadatos de compilación.

## Comprobaciones

Estas comprobaciones tienen como objetivo determinar si la imagen y el flujo de gestión de secretos probablemente hayan aumentado la superficie de ataque antes del tiempo de ejecución.
```bash
docker history --no-trunc <image> 2>/dev/null
env | grep -iE 'secret|token|key|passwd|password'
find /run /var/run /var/lib/kubelet -type f -iname '*token*' 2>/dev/null | head -n 50
grep -RniE 'secret|token|apikey|password' /etc /app /srv /usr/src 2>/dev/null | head -n 100
```
Lo interesante aquí:

- Un historial de build sospechoso puede revelar credenciales copiadas, material SSH o pasos de build inseguros.
- Secrets bajo rutas de volúmenes proyectados pueden dar acceso al clúster o a la nube, no solo a la aplicación local.
- Un gran número de archivos de configuración con credenciales en texto plano suele indicar que la imagen o el modelo de despliegue transporta más material de confianza del necesario.

## Valores predeterminados en tiempo de ejecución

| Runtime / plataforma | Estado predeterminado | Comportamiento predeterminado | Prácticas manuales comunes que lo debilitan |
| --- | --- | --- | --- |
| Docker / BuildKit | Admite montajes seguros de secretos en tiempo de build, pero no de forma automática | Los Secrets pueden montarse de forma efímera durante `build`; el firmado y escaneo de imágenes requieren elecciones explícitas en el flujo de trabajo | copiar secrets dentro de la imagen, pasar secrets por ARG o ENV, desactivar las comprobaciones de procedencia |
| Podman / Buildah | Admite builds nativos OCI y flujos de trabajo conscientes de secretos | Están disponibles workflows de build robustos, pero los operadores deben elegirlos intencionalmente | incrustar secretos en Containerfiles, contextos de build demasiado amplios, montajes bind permisivos durante las builds |
| Kubernetes | Objetos Secret nativos y volúmenes proyectados | La entrega de secrets en tiempo de ejecución es de primera clase, pero la exposición depende de RBAC, del diseño del pod y de los montajes en el host | montajes de Secret demasiado amplios, uso indebido de tokens de service-account, `hostPath` acceso a volúmenes gestionados por kubelet |
| Registries | La integridad es opcional salvo que se haga cumplir | Tanto los registries públicos como privados dependen de políticas, firmado y decisiones de admisión | permitir la descarga de imágenes sin firmar libremente, control de admisión débil, mala gestión de claves |
