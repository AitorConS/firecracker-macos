# Dependencia de red HVF

libslirp 4.9.4 procede del archivo upstream identificado en `libslirp.json`.
Se conserva su árbol y sus avisos de licencia (`libslirp/COPYRIGHT`). El parche
`libslirp-hvf.patch` selecciona únicamente el resolver IPv4 declarado en modo
endurecido; el modo de desarrollo explícito conserva la resolución upstream. También corrige
la traducción de respuestas desde resolvers IPv4 en puertos distintos de 53: se
compara el destino original antes de sustituirlo por la IP virtual del DNS.
También evita container_of(NULL) al crear una cola de reensamblado IPv4,
hallazgo UBSan reproducido por el corpus de fragmentos de la campaña final.
Valida la longitud declarada y disponible de los paquetes NC-SI antes de leer
payloads OEM, incluidos los campos específicos de Mellanox. El corpus permanente
`ncsi-oem-truncated-payload` reproduce la lectura fuera de límites original.
`libslirp-version.h` se genera desde la plantilla upstream.

Ambos builds locales compilan **todas** las unidades C con la inclusión forzada
`native/slirp_policy.h`: socket, connect, bind, listen, sendto, recvfrom,
getsockname y close pasan por los adaptadores. No se enlaza libslirp de Homebrew.
El build de desarrollo acepta `GLIB_PREFIX` (por defecto Homebrew). El flujo
`experiments/hvf/distribution/` compila GLib 2.88.3 y dependencias verificadas
en un prefijo privado y empaqueta dylibs relativas; su ejecución reubicada ya
se probó sin acceso a Homebrew. La distribución pública sigue pendiente.

En modo endurecido, Seatbelt deniega acceso a archivos, ejecución y red directa
en el broker que analiza las tramas. Una autoridad separada, sin libslirp,
recibe solicitudes de tamaño fijo por IPC y autoriza el destino **traducido**
IPv4/puerto/protocolo antes de abrir TCP o emitir UDP. No hay excepciones para
loopback, gateway ni LAN. DNS exige resolver explícito. Los listeners necesitan
su autorización; UDP solo responde a un peer observado en un listener declarado
(durante 60 segundos, máximo 32 peers por socket).

La autoridad es parte de la base de confianza: su perfil Seatbelt permite red,
pero deniega archivos y ejecución. Esto es deliberado porque Seatbelt macOS 26
no admite filtros para literales IPv4 arbitrarios. La autorización exacta la
implementa `socket_gate.c`; el broker recibe sockets TCP conectados/listeners
ya abiertos y proxies Unix para UDP, nunca sockets UDP de Internet. La autoridad
no conserva la RAM del huésped ni descriptores de disco. Tiene como máximo 256
proxies UDP y procesa como máximo 128 datagramas por iteración, con rotación.
No equivale a una auditoría. Las regresiones de DNS, proxies UDP, TCP y
transferencia de descriptores se describen en
[NETWORK_REGRESSIONS.md](../../../experiments/hvf/NETWORK_REGRESSIONS.md).
