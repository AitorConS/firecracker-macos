# Transporte Ethernet Unix para HVF

`unix-stream` es un cliente Ethernet genérico compatible con el framing del
[netdev stream de QEMU](https://www.qemu.org/docs/master/system/qemu-manpage.html).
No necesita ejecutar QEMU. El VMM no gestiona IPAM ni DNS de servicios.
El switch externo configura y autoriza la red. `slirp` conserva su
configuración y su autoridad de sockets independiente.

```json
{
  "network-interfaces": [{
    "iface_id": "eth0",
    "backend": "unix-stream",
    "guest_mac": "02:00:00:00:00:01",
    "socket_path": "/private/tmp/my-private-network/link.sock"
  }],
  "security": {
    "version": 1,
    "unix_stream": "/private/tmp/my-private-network/link.sock"
  }
}
```

Esas secciones se añaden a una configuración normal de boot/machine/drives.
La autorización `security.unix_stream` debe coincidir exactamente con el socket
del backend. Se rechazan `forwards`, `security.egress`, `security.listeners` y
`security.dns` con este transporte: el switch externo es la autoridad IP y debe
aplicar esos permisos. Conceder el socket concede conectividad al switch que lo
atiende; el VMM no promete filtrar sus destinos IP.

El directorio padre debe pertenecer al usuario y ser privado (0700); el socket
debe pertenecer al mismo usuario y ser 0600. Se resuelve el padre antes de
instalar Seatbelt. El broker recibe solamente permiso de conexión y metadata
para esa ruta canónica, comprueba `getpeereid`, y no obtiene permiso de conexión
Internet, apertura de archivos del host ni acceso a otros sockets Unix. El VMM
mantiene su sandbox habitual. La protección no pretende aislar procesos
maliciosos del mismo UID capaces de modificar el directorio autorizado.
El cliente nunca crea, elimina ni sustituye el socket del servidor.

## Contrato de transporte

- Una longitud **u32 big endian**, seguida de la trama Ethernet sin prefijos
  VirtIO ni cabeceras de offload. Tamaño admitido: 14–65536 bytes.
- RX y TX usan cada uno un buffer fijo de 65540 bytes. Se conservan offsets
  entre operaciones parciales; se valida la longitud antes de leer el payload.
- El broker mantiene una sola trama TX pendiente. Si se satura, descarta la
  siguiente trama completa; nunca intercala bytes ni trunca la trama pendiente.
  Los descartes se suman a los contadores TX de la API. El IPC broker/VMM y el
  procesamiento por poll también están acotados.
- El arranque exige poder iniciar la conexión. Una vez arrancado, EOF, errores,
  framing inválido o cinco segundos sin progreso de una trama/conexión pendiente
  cierran el enlace, descartan su estado parcial y reintentan cada segundo.
  No se retransmiten tramas pendientes al nuevo peer. Las aplicaciones deben
  tolerar pérdida y reconectar; no se preservan sesiones TCP del switch reiniciado.
- Se aplican las cuotas agregadas de bytes/paquetes de VirtIO existentes.
  Pause/Resume mantiene la barrera del broker; no procesa tramas mientras está
  pausado. Los deadlines de transporte usan tiempo monotónico del host.
- Los snapshots conservan el dispositivo, pero no el estado del switch externo.
  Antes de restaurar, configurar una interfaz `unix-stream` con el mismo
  `iface_id` y MAC, un socket actual y su autorización `security.unix_stream`.
  La restauración valida esa compatibilidad y reconecta al socket autorizado;
  nunca reutiliza implícitamente la autoridad guardada en el snapshot.
  Slirp también reinicializa la red al restaurar.

`GET /capabilities` anuncia ambos backends, el framing, tamaño máximo, intervalo
de reconexión, contrato de restauración de snapshots y
`network_policy: external-switch-unix-capability` cuando corresponde. La API
macOS sigue siendo 1.0; son campos aditivos. Linux/KVM usa su backend separado.

## Build y validación sin sustituir otro trabajo

```sh
export CARGO_TARGET_DIR="$PWD/experiments/hvf/build/my-network-cargo"
export HVF_OUTPUT_DIR="$PWD/experiments/hvf/build/my-network-bin"
export GLIB_PREFIX="$PWD/experiments/hvf/build/distribution/native"
sh experiments/hvf/build-native.sh
export HVF_BINARY="$HVF_OUTPUT_DIR/firecracker"
sh experiments/hvf/test-network-stream.sh
python3 -m unittest discover -s experiments/hvf -p test_network_stream.py -v
```

El helper C usa ASan/UBSan y prueba framing fragmentado/coalescido, longitudes
adversariales, escrituras parciales, saturación, timeout, EOF, permisos y
reconexión. El helper Seatbelt verifica conexiones permitidas y denegadas.
La prueba API arranca una VM HVF real y comprueba reconexión, capacidades,
Pause/Resume y captura de snapshot. Los tests Rust comprueban la compatibilidad
de interfaz y la sustitución explícita de la autorización al restaurar.

`distribution/verify-reproducible.py --reuse-native --output NUEVO_DIRECTORIO`
reconstruye el VMM en dos targets y empaqueta las dependencias ya instaladas,
sin sustituir dylibs usadas por otra campaña. Su informe distingue ese alcance
de una reconstrucción completa de dependencias. Los paquetes conservan firma
ad-hoc, entitlement Hypervisor, dependencias relativas, licencias y checksums.
