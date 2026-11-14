# Límites de confianza de la actualización automática de Electron

{{#include ../../banners/hacktricks-training.md}}

## Superficie de ataque de la actualización automática de Electron

Trata un actualizador como un límite de ejecución remota de código: recupera contenido ejecutable, decide si ese contenido es más reciente y confiable, lo prepara localmente y se lo entrega a un instalador. Revisa todo el grafo de confianza —índice de versiones, metadatos por versión, artefacto, firmas separadas, clave de verificación integrada, caché, ruta temporal e instalador—, no solo si el `.app` final está firmado.<sup>[[1]](#references)[[2]](#references)</sup>

### Pruebas de alto valor

- **Rollback/replay:** vuelve a reproducir un manifiesto que antes era válido y su artefacto aún firmado. Una firma autentica su entrada, pero no garantiza que esta sea reciente; el cliente debe rechazar las versiones inferiores a un límite monotónico persistente, salvo que una política de recuperación autenticada autorice explícitamente el rollback.<sup>[[2]](#references)</sup>
- **Sustitución de metadatos/artefactos:** modifica por separado la versión, la URL, el hash esperado, el artefacto y la firma separada. También intenta mezclar un par válido de artefacto y firma de una versión con los metadatos de otra. Si los metadatos de la versión no están firmados, TLS o un ejecutable final firmado no impiden que un origen/CDN comprometido cambie la lógica de selección.<sup>[[1]](#references)[[2]](#references)</sup>
- **Confusión de canal con firma válida:** sirve una compilación alpha, beta, de desarrollo o depuración firmada legítimamente a través del feed de producción. Reutilizar la misma clave y política en distintos entornos permite que el artefacto pase una comprobación que solo verifica al firmante; la identidad/canal de producción debe formar parte de la política autenticada o debe usarse una raíz de confianza separada.<sup>[[2]](#references)</sup>
- **TOCTOU en archivos temporales:** determina si la verificación abre una ruta y luego la instalación vuelve a abrirla. Si un atacante local puede renombrar, reemplazar o redirigir el objeto preparado entre esas operaciones, el instalador podría consumir bytes que nunca se verificaron. Un directorio de preparación con modo `0700` limita el acceso, pero no hace atómicas las dos operaciones.<sup>[[2]](#references)</sup>

El análisis estático y el triaje en tiempo de ejecución pueden localizar rápidamente estos límites.<sup>[[1]](#references)[[2]](#references)</sup>

```bash
npx asar extract /path/to/app.asar /tmp/app-src
rg -n 'autoUpdater|electron-updater|setFeedURL|latest\.yml|allowInsecureTLS|downgrade' /tmp/app-src
rg -n 'sha(256|512)|ed25519|verify|signature|version|mkdtemp|chmod|rename' /tmp/app-src
sudo fs_usage -w -f filesystem "$PID" | rg -i 'update|latest|\.ya?ml|\.zip|\.dmg|tmp'
```

Durante una prueba autorizada, intercepta la comprobación de actualizaciones, archiva cada respuesta y modifica un campo a la vez. Luego inspecciona la propiedad y los permisos del directorio de staging, y rastrea las aperturas de archivos desde la descarga hasta la instalación. En macOS, continúa con las [pruebas de límites de confianza del instalador](../../macos-hardening/macos-security-and-privilege-escalation/macos-files-folders-and-binaries/macos-installers-abuse.md) si el flujo llega a un helper con privilegios, y revisa las [debilidades de code signing](../../macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-code-signing-weaknesses-and-sandbox-escapes.md) en lugar de tratar «firmado» como una comprobación de identidad completa.<sup>[[2]](#references)</sup>

### Vinculación y política esperadas

Un diseño defendible autentica tanto los metadatos de selección como los bytes del artefacto. El diseño de referencia SafeUpdater demuestra el uso de una clave pública Ed25519 integrada, manifiestos y artefactos firmados, un mensaje firmado derivado de `SHA-256(file)` más la versión, y un hash SHA-512 del artefacto almacenado en metadatos firmados; se presenta explícitamente como una referencia de investigación, no como un paquete listo para producción.<sup>[[1]](#references)[[2]](#references)</sup>

Verifica que el objetivo también proporcione estas propiedades.<sup>[[1]](#references)[[2]](#references)</sup>

- usa una representación firmada inequívoca que vincula el hash del artefacto con su versión canónica y el entorno de publicación;
- desactiva las versiones anteriores de forma predeterminada y aplica una versión mínima aceptada para las reversiones autorizadas;
- separa producción de los entornos no productivos mediante claves/canales distintos o datos autenticados de la política de publicación; y
- instala el archivo abierto ya verificado (o un identificador/objeto inmutable equivalente) en vez de resolver de nuevo la misma ruta.

## References

- [1] [Implementación de referencia Doyensec ElectronSafeUpdater](https://github.com/doyensec/ElectronSafeUpdater)
- [2] [Electron SafeUpdater: Diseño de un mecanismo seguro de actualización automática para Electron](https://blog.doyensec.com/2026/02/16/electron-safe-updater.html)
{{#include ../../banners/hacktricks-training.md}}
