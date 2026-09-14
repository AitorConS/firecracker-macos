# VMM genérico macOS ARM64 / Hypervisor.framework

Este fork local de Firecracker ejecuta huéspedes ARM64 mediante HVF. El primer
hito independiente está implementado: Linux ARM64 con initramfs, disco VirtIO y red,
usando exclusivamente el fork, herramientas genéricas y artefactos públicos de
Alpine. No se necesitan otros repositorios para compilar, configurar ni probar
el VMM. La red admite slirp y un transporte Ethernet Unix genérico descrito en
[UNIX_STREAM.md](UNIX_STREAM.md). La campaña completa de 24 horas, otros Macs y
la certificación mediante cortes eléctricos siguen fuera de la validación local.

El target Darwin usa `src/hvf-vmm`: configuración, cargadores y API en Rust;
HVF, PCI/VirtIO y transporte slirp en C. Sigue siendo un backend experimental
nuevo, no una abstracción completa del VMM Linux upstream. Las garantías de
seguridad, snapshots y API de Firecracker Linux no se trasladan automáticamente.

## Compilar y demostrar el hito

Host probado: macOS 26.6.2 ARM64. El producto requiere macOS 26 y Apple Silicon
con Hypervisor disponible. No se ha certificado una matriz de chips/versiones.

Herramientas: Xcode Command Line Tools, Rust 1.97.0 y Python 3. Las dependencias
nativas se compilan en un prefijo privado desde fuentes con SHA-256 fijado.
El paquete incluye sus bibliotecas y no necesita Homebrew para ejecutarse.
Para generar Alpine se requiere el extractor `unsquashfs` fijado en
`guests/linux/tools.json`; Debian usa el `bsdtar` de macOS registrado allí.
Go 1.26.0 se descarga con checksum y se instala en el directorio privado de build.
LLVM con libFuzzer solo se necesita para fuzzing. QEMU no es dependencia.

```sh
python3 experiments/hvf/distribution/build-native-deps.py
GLIB_PREFIX="$PWD/experiments/hvf/build/distribution/native" experiments/hvf/build-native.sh
python3 experiments/hvf/guests/linux/prepare.py
python3 experiments/hvf/guests/debian/prepare.py
build/macos-arm64/firecracker --no-api --config-file build/linux-guest/config.json
```

En otra terminal:

```sh
curl http://127.0.0.1:19000/
curl http://127.0.0.1:19000/shutdown
```

La respuesta identifica Linux, ARM64, cuatro CPU, la MAC configurada y un contador
persistente. El guest verifica una marca del disco, lee/incrementa un contador
mediante `/dev/vda`, hace fsync y sirve TCP 9000 y UDP 9001. Los puertos del host
son 19000 y 19001. El VMM no interpreta el contenido del disco ni conoce un
sistema de archivos. El ejemplo conserva `disk.raw` al repetir la preparación.

`prepare.py` descarga kernel/initramfs de Alpine 3.23.5 desde URLs versionadas y
comprueba los SHA-256 de `guests/linux/assets.json`. Extrae el Image del contenedor
EFI zboot **en la herramienta del huésped**, añade un pequeño programa Go y genera
un initramfs newc con ownership, timestamps e inodos normalizados. No parchea el
kernel Linux. Usa `--go /ruta/go` o `GO` para seleccionar un Go externo.

El build usa Cargo del PATH o el toolchain aislado de `experiments/hvf/build`.
`GLIB_PREFIX` selecciona las dependencias privadas; libslirp está vendorizado
con su parche de autorización. El binario se firma ad-hoc con entitlement
Hypervisor. Véase [distribución y notarización opcional](distribution/README.md).
Cada preparación registra hashes de herramientas e Image/initrd en
`provenance.json`. Cambiar extractores requiere revisar su procedencia y actualizar
explícitamente el lock; no se acepta silenciosamente otro binario del PATH.

## Protocolos de arranque

- `boot_protocol: "linux-image"`: Linux AArch64 Image sin comprimir, little endian,
  cabecera v3.17+ con tamaño no nulo. Acepta `boot_args` (máximo 4096 bytes) e
  `initrd_path`. Coloca Image según `text_offset`, reserva su tamaño declarado y
  valida que initrd no lo solape. Publica ambos en el DTB. No ejecuta EFI.
- `boot_protocol: "elf"` (valor por defecto): ELF64 AArch64 EXEC, PT_LOAD dentro de
  RAM y entrada alineada en segmento ejecutable con dirección virtual=física.
  Los primeros 2 MiB quedan reservados para DTB. Este protocolo no define
  initrd ni argumentos Linux y rechaza esos campos.

Ambos arrancan en EL1 con MMU apagada, interrupciones enmascaradas, x0=DTB,
x1=x2=x3=0. RAM en `0x40000000`; 1–4 CPU y 64–2048 MiB de RAM configurables.
La capacidad del VMM no implica que cualquier huésped quepa en 64 MiB.
El ejemplo Linux se valida con 256 MiB. Consola PL011 de salida, GICv3, PSCI,
VirtIO PCI legacy y fw_cfg MMIO. No se ofrece consola de entrada interactiva.

## Configuración genérica

```json
{
  "boot-source": {
    "boot_protocol": "linux-image",
    "kernel_image_path": "/ruta/Image",
    "initrd_path": "/ruta/initrd.gz",
    "boot_args": "console=ttyAMA0 rdinit=/init"
  },
  "machine-config": {"vcpu_count": 4, "mem_size_mib": 256, "power_button": true},
  "drives": [
    {"drive_id": "disk0", "path_on_host": "/ruta/disk.raw", "copy_on_start": false}
  ],
  "firmware": {"opt/example/data": "/ruta/payload.bin"},
  "network-interfaces": [{
    "iface_id": "net0", "backend": "slirp", "guest_mac": "02:12:34:56:78:90",
    "forwards": [{
      "protocol": "tcp", "host_addr": "127.0.0.1", "host_port": 19000,
      "guest_addr": "10.0.2.15", "guest_port": 9000
    }]
  }],
  "security": {"version": 1, "listeners": [{"protocol": "tcp", "address": "127.0.0.1", "port": 19000}]},
  "hvf": {"max_runtime_ms": 0, "trace": false}
}
```

Discos: cero a cuatro archivos regulares alineados a 512 bytes, `is_read_only`
opcional. `is_root_device` es una designación opcional que ordena ese dispositivo
primero; no selecciona un filesystem ni construye parámetros de montaje.
`copy_on_start` copia cualquier disco a un temporal privado; por defecto es
**false**, por lo que las escrituras persisten. Los escritores toman LOCK_EX y
los lectores LOCK_SH. La copia mantiene LOCK_SH del origen durante toda la copia
y lee del mismo descriptor bloqueado, no de una reapertura de su ruta. Son
bloqueos cooperativos, no protección contra escritores que ignoran flock.

Firmware: mapa de nombres a archivos binarios, máximo 64 archivos de 64 KiB y
nombres de hasta 55 bytes. Se entregan sin interpretación mediante fw_cfg.
Los nombres y el contenido pertenecen al contrato del huésped. No hay entorno,
montajes ni etiquetas de filesystem interpretados por el VMM.

Red: interfaz opcional e independiente de `forwards`, MAC unicast configurable,
hasta 64 reglas TCP/UDP IPv4 con direcciones/puertos explícitos. Una interfaz sin
reglas de forwarding solo puede salir a los destinos autorizados en `security`;
la salida y DNS están denegados por defecto. slirp ofrece NAT/DHCP/DNS en
`10.0.2.0/24` (gateway `.2`, DNS `.3`, DHCP desde `.15`). El transporte está detrás
de `net_backend.h`, separado de VirtIO; admite slirp y el transporte genérico
`unix-stream` descrito en [UNIX_STREAM.md](UNIX_STREAM.md).
El huésped configura su propia dirección y rutas. No hay dependencia de gVisor.

## API macOS 1.0

```sh
build/macos-arm64/firecracker --api-sock /ruta/privada/vmm.sock
```

Socket Unix 0600; usar directorio privado. HTTP/1.1 con cierre de conexión, sin
chunked encoding. Cabeceras hasta 8 KiB, cuerpo hasta 1 MiB. No hay API TCP.

| Operación | Contrato |
| --- | --- |
| GET `/` | Versión, estado, `operation_id`, `exit_code`, `last_error`, `shutdown_delivered` |
| GET `/capabilities` | Protocolos y límites implementados; capacidades ausentes explícitas |
| GET `/vm/config` | Configuración actual |
| GET `/operations`, `/operations/{id}` | Hasta 64 operaciones recientes, estado, diagnóstico y resultado |
| GET `/metrics` | JSON; `Accept: text/plain` selecciona Prometheus |
| PUT `/security`, `/limits` | Secciones versionadas de configuración, con la VM parada |
| PUT `/actions`, `Pause` / `Resume` | 202; barrera completa y reloj virtual congelado |
| PUT `/snapshot/create`, `/snapshot/load` | 202; `snapshot_path` absoluto, captura desde Paused y restauración a Paused |
| PUT `/boot-source`, `/machine-config`, `/drives/{id}` | Subconjunto de nombres/estructura upstream; campos no soportados se rechazan |
| PUT `/firmware`, `/network-interfaces`, `/hvf` | Extensiones macOS; mapa, lista y opciones respectivamente |
| PUT `/actions`, `InstanceStart` | 202 con `Starting` y `operation_id`; inicialización en worker |
| PUT `/actions`, `ForceStop` | 202 con `Stopping`; cancela arranque o mata VM, conserva supervisor/API; `Stop` es alias |
| PUT `/actions`, `Shutdown` | 202 con `Stopping`; requiere `machine-config.power_button: true` |

Estados: `Not started`, `Starting`, `Running`, `Pausing`, `Paused`, `Resuming`,
`Snapshotting`, `Restoring`, `Stopping`, `Failed`, `Exited`.
`InstanceStart` acepta una operación, no confirma su éxito. Consultar GET `/`:
`Failed` incluye `last_error.fault_code=BOOT_FAILED` y el diagnóstico real del
hijo (ELF inválido, locks, puertos ocupados). La inicialización tiene un máximo de
30 s y se puede cancelar con ForceStop o señal al supervisor. `Running` significa
HVF/dispositivos listos, no que el SO o la aplicación hayan terminado de arrancar.
Configurar o volver a arrancar mientras hay operación/VM activa devuelve 409.
Tras salida, `Exited` conserva el código y permite configurar y arrancar de nuevo.
`--api-sock --config-file` inicia también de forma asíncrona.

Apagado solicitado por VMM:

```json
{"action_type":"Shutdown","timeout_ms":5000,"force_on_timeout":false}
```

El dispositivo opcional VirtIO MMIO input publica EV_KEY/KEY_POWER estándar.
Linux necesita virtio_mmio, virtio_input y una política de espacio de usuario que
atienda el botón (la prueba usa evdev). El huésped decide si sincroniza y apaga.
`shutdown_delivered` solo confirma
que los eventos se escribieron en la cola, no que el SO los haya procesado.
El plazo admite 1–300000 ms (defecto 5000). Al vencer queda `SHUTDOWN_TIMEOUT`;
sin escalada se vuelve a Running, con `force_on_timeout:true` se mata la VM.
Cancelar el evento pendiente no retira eventos ya entregados: el huésped todavía
podría apagar después del plazo. Sin `power_button`, Shutdown devuelve 409.
La función HTTP `/shutdown` pertenece únicamente al huésped de prueba.
SIGTERM/Ctrl-C al supervisor da al proceso hijo 2 s antes de SIGKILL; no garantiza
fsync del guest. Las señales y ForceStop son paradas forzadas.
PSCI SYSTEM_OFF devuelve 0; pvpanic 1; salida no implementada 2; reset solicitado
3; watchdog 124; señal directa 128+señal. El reset aún no reinicia la VM.
El hijo monitoriza una conexión privada con el supervisor y se detiene si este
muere, incluso por SIGKILL. SIGKILL o crash del host no ejecutan los destructores
del padre: pueden quedar socket/configuración temporales, aunque la VM no siga
corriendo.

La API 1.0 conserva los nombres upstream indicados en la tabla y añade extensiones
macOS. No admite metadata/MMDS ni snapshots KVM. Para importar configuración 0.3,
use la migración explícita descrita abajo: los permisos de red no se conceden
implícitamente. El contrato Linux upstream permanece separado por target.

## Pruebas

```sh
experiments/hvf/test-native.sh              # incluye Linux; necesita Go y descarga assets fijados
experiments/hvf/test-native.sh --unit-only  # Rust, synthetic HVF, API y dispositivos
python3 experiments/hvf/test-linux.py       # usa build/linux-guest/config.json ya preparado
experiments/hvf/fuzz/run.sh                  # 60 s, ASan/UBSan y corpus incremental
```

La batería genérica prueba cargadores ELF/Linux y límites, copia/locks,
parser HTTP, errores reales de arranque con reintento, salida y limpieza del
supervisor, guest sintético HVF, bloque/firmware y Linux con 1/4 CPU. Linux realiza
dos arranques por configuración, fsync y persistencia, comprueba MAC, transfiere
16 MiB de HTTP por arranque, usa UDP y recibe Shutdown desde la API del VMM;
comprueba el marcador escrito/fsync por el manejador del botón antes de apagar. Otro arranque prueba
red saliente sin publicar puertos. Logs locales en `experiments/hvf/build`.
La [CI](ci/README.md) distingue tests sin virtualización de las pruebas que
arrancan huéspedes reales en hardware dedicado.

VirtIO valida índices, rangos DMA, direcciones y ciclos; no admite indirect/event_idx
ni offloads. Bloque limita peticiones a 4 MiB y trabajo por turno a 32 peticiones
con presupuesto de 8 MiB (puede terminar la petición en curso); lo pendiente se
retoma en el poll. TX limita cada turno a 256 paquetes. Errores de E/S se comunican
por estado VirtIO; descriptores inválidos terminan la VM. Esto no equivale a una
auditoría ni a fuzzing exhaustivo.

El código original de entrada/build y dependencias Linux se preserva por target.
Linux/KVM x86_64 se ha probado en un host Ubuntu 26.04 con kernel 7.0.0-28,
KVM API 12 y acceso mediante sudo. El host es virtualizado: la prueba usa KVM
anidado. Compilación GNU release y cuatro arranques reales de Linux 6.1.102
(1/2 vCPU) pasan con persistencia, 16 MiB HTTP total, UDP y salida por i8042.
El poweroff de ese kernel deja la VM en halt; no se afirma soporte ACPI poweroff.
La [batería KVM](guests/kvm/README.md) usa un namespace de red privado y conserva
los resultados en `experiments/hvf/build/kvm-validation`.

La base upstream independiente 16f9023f8 reprodujo 993 aprobados y tres fallos.
La comparación identificó una expectativa TSC incompatible con software catchup
admitido por KVM y dos polls que observaban eventos no terminales. Se corrigieron
las pruebas conservando las aserciones y el plazo total de 500 ms. El fork pasa
996 tests, cero ignorados; los tres casos afectados pasan tres repeticiones.
Evidencia en `build/kvm-validation/comparison/comparison.json` dentro de este
laboratorio. KVM ARM64, bare metal, jailer/musl y otros hosts siguen sin validar.
El build GNU usa el filtro seccomp vacío anunciado por upstream.

Fuentes de protocolo: [arranque Linux ARM64](https://docs.kernel.org/arch/arm64/booting.html),
[Alpine netboot 3.23.5](https://dl-cdn.alpinelinux.org/alpine/v3.23/releases/aarch64/netboot-3.23.5/),
[Hypervisor.framework](https://developer.apple.com/documentation/hypervisor),
[VirtIO](https://docs.oasis-open.org/virtio/virtio/v1.2/virtio-v1.2.html).

## Seguridad y migración de configuración

Los tests reproducibles de red se describen en
[NETWORK_REGRESSIONS.md](NETWORK_REGRESSIONS.md).

Las configuraciones antiguas requieren migración explícita:

```sh
build/macos-arm64/firecracker --migrate-config --config-file old.json > migration-report.json
```

El informe muestra `configuration` y `required_listener_permissions`. Revise y
extraiga la configuración, añadiendo solo los permisos necesarios: no es un
archivo ejecutable concedido automáticamente. Un arranque sin acceso de red usa
`"security": {"version": 1}`. Ejemplo con listener y salida TCP concretos:

```json
{
  "security": {
    "version": 1,
    "listeners": [{"protocol": "tcp", "address": "127.0.0.1", "port": 19000}],
    "egress": [{"protocol": "tcp", "address": "192.0.2.10", "port": 443}]
  },
  "limits": {
    "version": 1,
    "open_files": 1024,
    "file_size_bytes": 17179869184,
    "rss_mib": 3072,
    "cpu_seconds": 86400,
    "nice": 5,
    "disk_bytes_per_second": 268435456,
    "disk_operations_per_second": 20000,
    "network_bytes_per_second": 67108864,
    "network_packets_per_second": 100000
  }
}
```

En `security.listeners`, `0.0.0.0` autoriza un bind INADDR_ANY en todas las
interfaces IPv4 del host, solo para ese protocolo y puerto no nulo. Debe coincidir
exactamente con `forwards[].host_addr`: no sustituye un permiso de bind concreto
como `127.0.0.1`. No concede salida ni DNS; `egress` y `dns` siguen rechazando
direcciones wildcard. Socket gate conserva la comparación exacta y Seatbelt.
En Darwin, SO_REUSEADDR permite coexistencia TCP entre wildcard y dirección
concreta del mismo puerto; el bind concreto tiene precedencia. Los endpoints
idénticos colisionan.

Estas secciones se añaden a la configuración de arranque, discos e interfaz.
La IP de ejemplo debe sustituirse por el destino real. Los permisos se aplican
a las direcciones del host después de la traducción slirp: por ejemplo, acceder
al host mediante `10.0.2.2` requiere autorizar el destino efectivo de loopback.
DNS necesita `"dns": {"address": "IP_DEL_RESOLVER", "port": 53}`; no se usa
el resolver del host implícitamente. El desarrollo sin Seatbelt/política requiere
`"security": {"version": 1, "mode": "development"}` explícito.

`PUT /security` y `PUT /limits` cambian configuración solo con la VM parada.
`GET /capabilities` distingue aislamiento efectivo y límites disponibles.
RSS y CPU agregada del grupo son reactivos, muestreados cada 100 ms. RLIMIT_CPU
no es compatible con HVF en el host validado; solo se aplica a los procesos de red.
Los limitadores de E/S actúan en los dispositivos, con ráfagas de disco 4 MiB/32
operaciones y red 256 KiB/256 paquetes. No equivalen a cgroups ni a cuotas de red
del kernel. `--no-api` también mantiene un supervisor privado.

Los archivos de entrada deben ser regulares; se rechazan symlinks finales.
El supervisor bloquea y prepara los archivos, y transmite los discos abiertos.
La autoridad de sockets y su frontera de confianza se describen en
[README.hvf.md](../../src/hvf-vmm/vendor/README.hvf.md). El paquete autónomo
incluye GLib y libintl con rutas relativas al ejecutable.

## Pausa y reanudación

`PUT /actions` acepta `{"action_type":"Pause"}` desde Running y
`{"action_type":"Resume"}` desde Paused. Devuelve 202 con identificador de
operación; consultar `/operations/{id}` o el estado de `/`. Los estados
intermedios son Pausing y Resuming. Las acciones incompatibles devuelven 409;
ForceStop sigue disponible durante ambas transiciones y mientras está pausada.
Shutdown requiere Running: reanudar antes de entregar el botón al huésped.

Paused confirma que todas las vCPU, incluidas las secundarias que todavía no
han arrancado, están en la barrera. Se completan las solicitudes de disco/TX ya
publicadas, respetando las cuotas, y se detiene el procesamiento del broker.
Los paquetes RX ya entregados por el broker se consumen antes de confirmar.
Las interrupciones quedan pendientes en el GIC; no se limpia su estado. Al
reanudar, todas las vCPU ajustan su offset de CNTVCT antes de liberar la barrera.
Se descuenta también la pausa del reloj PL031 y del reloj de libslirp.

La consulta de métricas, la vigilancia de recursos y la detección de muerte del
broker siguen activas. La pausa puede tardar si hay E/S aplazada por cuotas.
Un fallo o un plazo interno excedido termina la VM con diagnóstico: 300 s para
pausar y 5 s para reanudar. El watchdog explícito de la VM sigue usando tiempo
del host. Los sockets externos pueden vencer durante una pausa prolongada;
no se garantiza conservar conexiones frente a timeouts del otro extremo.


## Snapshots locales, formato 1

Desde Paused, `PUT /snapshot/create` con `{"snapshot_path":"/ruta/privada/snapshot"}`
inicia la captura. Desde una VM parada, `/snapshot/load` con el mismo cuerpo
restaura en **Paused**; `Resume` permite ejecutar. Ambas devuelven 202 e
`operation_id`: el resultado definitivo está en `/operations/{id}`. La captura
conserva Paused incluso si falla; ForceStop cancela operaciones en curso.

El directorio contiene manifiesto versionado, RAM completa, estado de cada CPU
(registros generales/SIMD/sistema y SME cuando está activo), timers, blob GIC,
dispositivos, firmware, kernel/initrd y copias de todos los discos, incluidos RO.
No contiene punteros ni descriptores del host. Se escribe en un temporal privado,
se sincronizan archivos y directorio y se publica mediante renombrado atómico.
Un fallo conserva el snapshot anterior. La cuota de tamaño por archivo también
limita RAM y discos capturados; configure espacio suficiente antes de arrancar.

La restauración valida primero esquema, nombres, límites y compatibilidad;
después copia componentes verificando tamaño/SHA-256, propiedad y tipo regular.
Rechaza symlinks, componentes ausentes, rutas externas y corrupción. La
compatibilidad exige el mismo UUID de Mac, build de macOS, identificador de build
del VMM y modelo de dispositivos. El identificador deriva de fuentes y toolchain;
reubicar o volver a firmar el mismo build no lo cambia. Los hashes comprueban
integridad, no autentican al creador: mantenga los snapshots privados.

Los discos restaurados son copias independientes. El backend de red se reinicia;
las aplicaciones deben reconectar. Para `unix-stream`, la configuración actual
debe declarar una interfaz compatible y el socket autorizado del switch;
véase [el contrato de restauración](UNIX_STREAM.md).
Los manifiestos con formato, rutas o tamaños inválidos se rechazan con HTTP 400
antes de aceptar la operación; la integridad de los componentes se comprueba
durante la restauración asíncrona. No se ofrece consistencia transaccional de
aplicaciones, migración entre Macs, compatibilidad después de actualizaciones
del sistema ni snapshots KVM. La captura de una VM pausada conserva su estado
de bloque y RAM, pero no convierte buffers de una aplicación en transacciones.

## Métricas y estabilidad

El supervisor publica JSON/Prometheus por su socket Unix. Incluye CPU/RSS de
procesos, exits por vCPU, bytes/operaciones/errores de disco, paquetes/bytes de red,
colas VirtIO e IPC, descartes IPC y pérdidas de muestras de telemetría. CPU se
expresa en ticks del host. Los contadores de resultados y duración de operaciones
se conservan aunque se expulse una operación del historial de 64 entradas.
También se publican duración del estado actual y tiempo acumulado por estado.
El canal privado de métricas usa versión 2 con 26 campos acotados; tramas
truncadas o de versión desconocida se rechazan.

```sh
python3 experiments/hvf/test-snapshot-linux.py --config build/linux-guest/config.json
python3 experiments/hvf/test-snapshot-linux.py --config build/debian-guest/config.json --output-prefix experiments/hvf/build/debian-snapshot
FUZZ_SECONDS=600 sh experiments/hvf/fuzz/run.sh
python3 experiments/hvf/soak.py --config build/linux-guest/config.json --output experiments/hvf/build/soak-24h
```

La campaña de estabilidad realiza disco con fsync, TCP/UDP y snapshots periódicos
sin reiniciar la VM. Registra RSS, errores, latencia API y limpieza. Solo declara
`acceptance_24h_passed` si el objetivo es de al menos 86400 segundos y se completan
86400 segundos efectivos; una prueba corta no cumple ese criterio. El campo
`sample_label` identifica la duración objetivo: `--seconds 28800 --interval 5`
produce una muestra `8h`, que nunca acredita la aceptación de 24h.
Impide el reposo por inactividad únicamente mientras se ejecuta.
