# Sistemas operativos para la privacidad

{{#include ../banners/hacktricks-training.md}}

Los sistemas operativos centrados en la privacidad reducen los errores de routing y persistencia, pero ninguno puede compensar un comportamiento identificable o un hardware comprometido.

## Elige el modelo de aislamiento

| Sistema | Uso ideal | Persistencia | Aplicación de red | Principal desventaja |
|---|---|---|---|---|
| **Tor Browser en un OS mantenido** | Navegación web anónima ocasional | El estado del navegador normalmente se limita a la sesión | Solo el tráfico del navegador | Las demás aplicaciones y el host permanecen fuera de Tor |
| **Tails** | Sesiones portátiles, amnésicas y de propósito único | Persistent Storage cifrado opcional | El tráfico de Internet se fuerza a través de Tor | Fricción al reiniciar y en el workflow; confianza en el firmware y el hardware |
| **Whonix** | Aplicaciones persistentes que necesitan routing forzado mediante Tor | VMs persistentes | División entre Gateway y Workstation | El host/hypervisor y la mezcla de identidades siguen siendo factores |
| **Qubes-Whonix** | Separación estricta por compartimentos para usuarios avanzados | Por qube | Qubes de red dedicadas y Whonix | Requisitos de hardware y complejidad operativa |

## Tails

Tails se inicia de forma independiente desde un medio extraíble, enruta el tráfico de Internet mediante Tor y está diseñado para dejar un estado local mínimo. Sus propias advertencias enfatizan que no puede proteger contra un BIOS/firmware/hardware comprometido, divulgaciones identificables, metadatos de archivos o un observador potente que correlacione ambos extremos.<sup>[[1]](#references)</sup>

### Workflow de Tails de propósito único

1. Descarga Tails desde el sitio oficial en un equipo de confianza y actualizado, y sigue el proceso oficial de verificación e instalación.
2. Usa una unidad USB compatible únicamente para iniciar Tails; no la uses también como unidad general de transferencia de archivos.
3. Inicia el sistema en hardware bajo tu control físico. Un live OS no puede neutralizar un keylogger de hardware ni un firmware malicioso.
4. Mantén Persistent Storage desactivado, salvo que el workflow realmente lo necesite. Si lo activas, conserva únicamente las categorías necesarias y utiliza una passphrase robusta.
5. Conéctate a una red legal. Si un captive portal es inevitable, utiliza Unsafe Browser de Tails únicamente para el portal, no reveles ninguna identidad innecesaria, ciérralo inmediatamente y conéctate a Tor antes de realizar cualquier actividad sensible.<sup>[[2]](#references)</sup>
6. Configura un bridge de Tor si la visibilidad o el bloqueo directo de Tor son relevantes.
7. Realiza **una identidad/finalidad contextual por sesión**. Tails recomienda reiniciar entre actividades que no deban vincularse.<sup>[[1]](#references)</sup>
8. Inspecciona y sanitiza los archivos antes de publicarlos. No abras documentos activos descargados en una aplicación que pueda eludir el contexto previsto.
9. Apaga completamente el sistema al terminar y mantén el USB protegido físicamente.

## Whonix

Whonix separa un **Gateway** que enruta mediante Tor de una **Workstation** cuyas aplicaciones no pueden conocer directamente la IP externa. Esto reduce de forma significativa los errores de proxy/DNS, pero el host, el hypervisor, el comportamiento y los documentos aún pueden revelar la identidad. Whonix advierte explícitamente contra el uso de una misma workstation para varias identidades o la combinación de actividad anónima y no anónima.<sup>[[3]](#references)</sup>

### Workflow de compartimentación

1. Verifica la imagen de Whonix y la plataforma de virtualización desde fuentes oficiales.
2. Aplica parches al host, hypervisor, Gateway y Workstation antes de usarlos.
3. Clona una Workstation nueva para cada identidad o actividad; no clones nunca una VM después de haber introducido estado asociado a una identidad.
4. Mantén fuera de la Workstation las cuentas personales, las carpetas compartidas del host, la sincronización del portapapeles, los dispositivos USB y los datos de tiempo/ubicación.
5. Usa snapshots para la recuperación, no como sustituto de las copias de seguridad o la separación de identidades.
6. Confirma que la Workstation no puede acceder a Internet cuando el Gateway está detenido.
7. Para archivos especialmente peligrosos, utiliza una VM/qube desechable y exporta únicamente un resultado sanitizado.

## Qubes OS y Qubes-Whonix

Qubes implementa la seguridad mediante la compartimentación con qubes respaldadas por Xen. Su diseño limita que un compromiso en un dominio alcance automáticamente a otros, pero las aplicaciones dentro del **mismo** qube no están aisladas entre sí.<sup>[[4]](#references)</sup> Las qubes desechables proporcionan un estado nuevo para sitios, archivos y dispositivos no confiables.<sup>[[5]](#references)</sup>

Una distribución práctica:
```text
vault-offline        keys, recovery codes; no network
personal             real-identity daily accounts
client-red-2026      engagement administration only
client-red-net       approved VPN/bastion routing
anon-research        Qubes-Whonix Workstation
anon-research-net    Whonix Gateway
disp-untrusted       links and document rendering
```
Reglas:

- Asigna a cada qube un nivel de confianza y un propósito de identidad.
- Mantén los secretos en un qube de vault offline y usa operaciones explícitas de copia de archivos entre qubes.
- Abre archivos y enlaces no solicitados en disposables.
- Enruta únicamente los qubes previstos a través de Whonix o de un qube VPN dedicado.
- Etiqueta las ventanas de forma distintiva y detén los qubes no relacionados durante el trabajo sensible.
- No asumas que dos qubes impiden la correlación si comparten cuentas, contenido, horarios o pagos.

## Verification and maintenance

- Verifica las firmas y sumas de comprobación del instalador mediante las instrucciones oficiales.
- Aplica parches primero a las plantillas y, después, reinicia los qubes/VM dependientes.
- Confirma el comportamiento de denegación de red, DNS, IPv6, reloj, portapapeles, directorios compartidos y asignación de USB.
- Revisa Persistent Storage y las snapshots de las VM en busca de datos antiguos asociados a identidades.
- Mantén backups offline cifrados de seeds/keys y prueba la restauración en un entorno aislado.
- Reconstruye un compartimento tras sospechar una intrusión; cambiar su IP de egress es insuficiente.

## References

- [1] [Tails — Advertencias: Tails es seguro, pero no es magia](https://tails.net/doc/about/warnings/index.en.html)
- [2] [Tails — Iniciar sesión en una red mediante un portal cautivo](https://tails.net/doc/anonymous_internet/unsafe_browser/index.en.html)
- [3] [Whonix — Limitaciones de Whonix y Tor](https://www.whonix.org/wiki/Warning)
- [4] [Qubes OS — Objetivos de diseño de seguridad](https://doc.qubes-os.org/en/latest/developer/system/security-design-goals.html)
- [5] [Qubes OS — Cómo usar disposables](https://doc.qubes-os.org/en/latest/user/how-to-guides/how-to-use-disposables.html)
{{#include ../banners/hacktricks-training.md}}
