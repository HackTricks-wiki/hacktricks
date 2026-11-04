# Ejecución mediante un recurso compartido de escritura de extensiones de VS Code

{{#include ../banners/hacktricks-training.md}}

Las extensiones de VS Code y las extensiones de Visual Studio VSSDK usan paquetes `.vsix`, pero tienen manifiestos y runtimes distintos. Un recurso compartido SMB con permisos de escritura se convierte en una ruta de ejecución **solo si** otro usuario o un job de despliegue instala sus paquetes en VS Code. Entonces, la función `activate()` de la extensión se ejecuta en el host de extensiones con los privilegios de ese usuario. Escribir un `.vsix` en un recurso compartido no lo ejecuta por sí solo.<sup>[[1]](#references)[[2]](#references)</sup>

## Flujo de empaquetado y activación

Primero, confirma la versión de VS Code del usuario que consume la extensión y que el recurso compartido realmente se sincronice o se instale. Genera una extensión TypeScript y coloca la acción de Node.js prevista en `activate()`. Usa un evento de activación que se ejecute sin que el usuario seleccione un comando, como `onStartupFinished`; luego, compila y empaqueta la extensión. `engines.vscode` es la **barrera de compatibilidad del runtime**; hacer coincidir `@types/vscode` con la versión de la API de destino es una medida de compatibilidad en tiempo de compilación, no un requisito en tiempo de instalación.<sup>[[1]](#references)[[2]](#references)[[3]](#references)</sup>

```bash
npx --package yo --package generator-code -- yo code
npm install --save-dev @types/vscode@^1.118.0
npm install -g @vscode/vsce
vsce package
code --install-extension ./example-0.0.1.vsix   # Test locally before delivery
```

Para un editor que ejecuta VS Code 1.118, los campos relevantes de `package.json` son:<sup>[[1]](#references)[[2]](#references)</sup>

```json
{
  "activationEvents": ["onStartupFinished"],
  "engines": { "vscode": "^1.118.0" },
  "devDependencies": { "@types/vscode": "^1.118.0" }
}
```

Una comprobación mínima de `activate()` puede ejecutar un comando y registrar su salida desde el host de extensiones. Sustituye la acción de prueba solo después de verificar que el paquete se activa en la cuenta/sesión esperada. El evento `onStartupFinished` se ejecuta después del inicio, por lo que no demuestra que se haya ejecutado hasta que el editor se inicia realmente y la extensión está instalada y habilitada.<sup>[[1]](#references)[[2]](#references)</sup>

```typescript
import { execFile } from 'node:child_process';
export function activate() {
  execFile('cmd.exe', ['/c', 'whoami'], (_err, stdout) => {
    console.log(stdout);
  });
}
export function deactivate() {}
```

Un atacante con acceso de escritura al recurso compartido de entrega puede cargar el paquete probado y esperar al job que lo consuma. En el ejemplo de Checkpoint, el acceso al recurso compartido de la cuenta restaurada proporcionó ese permiso de escritura; la cuenta inicial con pocos privilegios solo podía leer el recurso compartido. Mantén estos dos requisitos previos diferenciados. Para las extensiones de **Visual Studio**, consulta el capítulo independiente [Abuso de extensiones VSIX de Visual Studio](visual-studio-vsix-extension-abuse.md) en lugar de este flujo de trabajo de VS Code.<sup>[[1]](#references)</sup>

## References

- [1] [0xdf - HTB: Checkpoint](https://0xdf.gitlab.io/2026/10/24/htb-checkpoint.html)
- [2] [VS Code - Eventos de activación](https://code.visualstudio.com/api/references/activation-events)
- [3] [VS Code - Publicación de extensiones](https://code.visualstudio.com/api/working-with-extensions/publishing-extension)
