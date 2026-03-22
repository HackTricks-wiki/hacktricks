# Evaluación y endurecimiento

{{#include ../../../banners/hacktricks-training.md}}

## Visión general

Una buena evaluación de contenedores debe responder a dos preguntas en paralelo. Primero, ¿qué puede hacer un atacante desde la carga de trabajo actual? Segundo, ¿qué decisiones del operador hicieron eso posible? Las herramientas de enumeración ayudan con la primera pregunta, y la guía de hardening ayuda con la segunda. Mantener ambas en una sola página hace que la sección sea más útil como referencia de campo en lugar de solo un catálogo de trucos de escape.

## Herramientas de enumeración

Varias herramientas siguen siendo útiles para caracterizar rápidamente un entorno de contenedores:

- `linpeas` puede identificar muchos indicadores de contenedor, sockets montados, capability sets, sistemas de archivos peligrosos y pistas de breakout.
- `CDK` se centra específicamente en entornos de contenedores e incluye enumeración además de algunas comprobaciones automatizadas de escape.
- `amicontained` es ligero y útil para identificar restricciones de contenedor, capabilities, exposición de namespaces y clases probables de breakout.
- `deepce` es otro enumerador enfocado en contenedores con comprobaciones orientadas a breakout.
- `grype` es útil cuando la evaluación incluye revisión de vulnerabilidades de paquetes en la imagen en lugar de solo análisis de escape en tiempo de ejecución.

El valor de estas herramientas es velocidad y cobertura, no certeza. Ayudan a revelar la postura aproximada rápidamente, pero los hallazgos interesantes aún necesitan interpretación manual contra el modelo real de runtime, namespaces, capabilities y mounts.

## Prioridades de hardening

Los principios de hardening más importantes son conceptualmente simples aunque su implementación varíe según la plataforma. Evitar contenedores privilegiados. Evitar sockets de runtime montados. No dar a los contenedores rutas del host escribibles a menos que haya una razón muy específica. Usar user namespaces o rootless execution cuando sea factible. Drop all capabilities y añadir solo las que la carga de trabajo realmente necesita. Mantener seccomp, AppArmor y SELinux habilitados en lugar de desactivarlos para arreglar problemas de compatibilidad de la aplicación. Limitar recursos para que un contenedor comprometido no pueda, de forma trivial, negar servicio al host.

La higiene de las imágenes y del build importa tanto como la postura en tiempo de ejecución. Usar imágenes mínimas, reconstruir con frecuencia, escanearlas, exigir procedencia cuando sea práctico y mantener secretos fuera de las capas. Un contenedor que se ejecuta como non-root con una imagen pequeña y una superficie de syscalls y capabilities reducida es mucho más fácil de defender que una imagen grande de conveniencia que se ejecuta con root equivalente al host y con herramientas de depuración preinstaladas.

## Ejemplos de agotamiento de recursos

Los controles de recursos no son glamorosos, pero forman parte de la seguridad de contenedores porque limitan el radio de impacto de un compromiso. Sin límites de memoria, CPU o PID, un simple shell puede ser suficiente para degradar el host o las cargas de trabajo vecinas.

Ejemplos de pruebas que afectan al host:
```bash
stress-ng --vm 1 --vm-bytes 1G --verify -t 5m
docker run -d --name malicious-container -c 512 busybox sh -c 'while true; do :; done'
nc -lvp 4444 >/dev/null & while true; do cat /dev/urandom | nc <target_ip> 4444; done
```
Estos ejemplos son útiles porque muestran que no todos los resultados peligrosos en contenedores son un "escape" limpio. Los límites débiles de cgroup aún pueden convertir la ejecución de código en un impacto operativo real.

## Herramientas de endurecimiento

Para entornos centrados en Docker, `docker-bench-security` sigue siendo una base útil de auditoría en el host, porque comprueba problemas comunes de configuración frente a pautas de referencia ampliamente reconocidas:
```bash
git clone https://github.com/docker/docker-bench-security.git
cd docker-bench-security
sudo sh docker-bench-security.sh
```
La herramienta no sustituye al threat modeling, pero sigue siendo valiosa para encontrar defaults descuidados de daemon, mount, network y runtime que se acumulan con el tiempo.

## Comprobaciones

Usa estos como comandos rápidos de primera pasada durante la evaluación:
```bash
id
capsh --print 2>/dev/null
grep -E 'Seccomp|NoNewPrivs' /proc/self/status
mount
find / -maxdepth 3 \( -name docker.sock -o -name containerd.sock -o -name crio.sock -o -name podman.sock \) 2>/dev/null
```
- Un proceso root con amplias capacidades y `Seccomp: 0` merece atención inmediata.
- Los puntos de montaje sospechosos y los sockets en tiempo de ejecución a menudo proporcionan una vía más rápida hacia el impacto que cualquier kernel exploit.
- La combinación de una postura en tiempo de ejecución débil y límites de recursos laxos suele indicar un entorno de contenedores generalmente permisivo en lugar de un único error aislado.
{{#include ../../../banners/hacktricks-training.md}}
