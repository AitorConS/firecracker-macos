# VMM genérico macOS ARM64 / Hypervisor.framework

Este fork local de Firecracker ejecuta huéspedes ARM64 mediante HVF. El primer
hito independiente está implementado: Linux ARM64 con initramfs, disco VirtIO y red,
usando exclusivamente el fork, herramientas genéricas y artefactos públicos de
Alpine. Jerboa es un huésped opcional; no se necesita su repositorio para compilar,
configurar ni probar el VMM.

El target Darwin usa `src/hvf-vmm`: configuración, cargadores y API en Rust;
HVF, PCI/VirtIO y transporte slirp en C. Sigue siendo un backend experimental
nuevo, no una abstracción completa del VMM Linux upstream. Las garantías de
seguridad, snapshots y API de Firecracker Linux no se trasladan automáticamente.

## Compilar y demostrar el hito

Host probado: macOS 26.6.2 ARM64. La distribución local actual declara macOS 26.0
como mínimo por la biblioteca Homebrew libslirp utilizada. Las APIs HVF/GIC requieren
al menos macOS 15, pero bajar el mínimo exige reconstruir dependencias y validar
ese host. No se ha certificado una matriz de chips/versiones.

Herramientas: Xcode Command Line Tools, Rust 1.97.0, Homebrew libslirp y Python3.
La preparación del huésped de prueba requiere Go (probado 1.26.5), `unsquashfs` (`brew install squashfs`) y `bsdtar`,
que incluye macOS. El fuzzing requiere LLVM con libFuzzer (`brew install llvm`). `dtc` se usa solamente en el cargador ELF auxiliar del laboratorio.
QEMU no participa en estas pruebas ni es dependencia del VMM.

```sh
experiments/hvf/build-native.sh
python3 experiments/hvf/guests/linux/prepare.py
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
`SLIRP_PREFIX` permite otra instalación de libslirp; por defecto `/opt/homebrew`.
El binario se firma ad-hoc con entitlement Hypervisor. No es una distribución
notarizada ni contiene todas sus dependencias. Versiones mínimas diferentes y
firma Developer ID requieren validación adicional.

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
Las claves `opt/uni/*` existen únicamente en el adaptador opcional del huésped
Jerboa. No hay entorno, montajes, TFS ni etiquetas de filesystem en el VMM.

Red: interfaz opcional e independiente de `forwards`, MAC unicast configurable,
hasta 64 reglas TCP/UDP IPv4 con direcciones/puertos explícitos. Una interfaz sin
reglas sigue teniendo conectividad saliente. slirp ofrece NAT/DHCP/DNS en
`10.0.2.0/24` (gateway `.2`, DNS `.3`, DHCP desde `.15`). El transporte está detrás
de `net_backend.h`, separado de VirtIO; actualmente solo está implementado slirp.
El huésped configura su propia dirección y rutas. No hay dependencia de gVisor.

## API macOS 0.3

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
| PUT `/boot-source`, `/machine-config`, `/drives/{id}` | Subconjunto de nombres/estructura upstream; campos no soportados se rechazan |
| PUT `/firmware`, `/network-interfaces`, `/hvf` | Extensiones macOS; mapa, lista y opciones respectivamente |
| PUT `/actions`, `InstanceStart` | 202 con `Starting` y `operation_id`; inicialización en worker |
| PUT `/actions`, `ForceStop` | 202 con `Stopping`; cancela arranque o mata VM, conserva supervisor/API; `Stop` es alias |
| PUT `/actions`, `Shutdown` | 202 con `Stopping`; requiere `machine-config.power_button: true` |

Estados: `Not started`, `Starting`, `Running`, `Stopping`, `Failed`, `Exited`.
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
atienda el botón (la prueba usa evdev). No hay agente ni claves de Jerboa en el
VMM. El huésped decide si sincroniza y apaga. `shutdown_delivered` solo confirma
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

La versión 0.3 cambia InstanceStart/ForceStop a operaciones 202 y añade Shutdown.
La versión 0.2 ya retiró las opciones específicas del prototipo anterior:
`hvf.environment/network/mounts/http_port/persistent_root` se eliminan. La nueva
configuración anterior es el contrato vigente. No se afirma compatibilidad total
con los clientes upstream; snapshots, pause/resume, metadata y rate limiters están
pendientes. Véase [alcance y siguientes hitos](ROADMAP.md).

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
red saliente sin publicar puertos. Logs locales en `experiments/hvf/build`. La misma batería Linux pasa bajo una
política de prueba que deniega lectura de los repositorios Jerboa, Desktop y Docs
(`linux-independent.log`). Esto demuestra independencia de esos archivos, no una
auditoría de aislamiento. También pasa el adaptador opcional Jerboa con ELF/disco
preparados externamente (`jerboa-optional.log`).

VirtIO valida índices, rangos DMA, direcciones y ciclos; no admite indirect/event_idx
ni offloads. Bloque limita peticiones a 4 MiB y trabajo por turno a 32 peticiones
con presupuesto de 8 MiB (puede terminar la petición en curso); lo pendiente se
retoma en el poll. TX limita cada turno a 256 paquetes. Errores de E/S se comunican
por estado VirtIO; descriptores inválidos terminan la VM. Esto no equivale a una
auditoría ni a fuzzing exhaustivo.

La compatibilidad Jerboa es opcional y recibe archivos externos:
[adaptador de huésped](guests/jerboa/README.md). Sus parches SMP, generadores de
imágenes e integración con daemon/Desktop/Compose/health quedan fuera del fork.

El código original de entrada/build y dependencias Linux se preserva por target.
Linux/KVM queda pendiente por falta de host con `/dev/kvm`, por decisión del
usuario (2026-09-11). El guest Linux de esta prueba **no** verifica KVM.
El verificador `test-linux-kvm.py` requiere ese host y assets genéricos upstream;
no se ha ejecutado su compilación ni su prueba de arranque en Linux. Ejemplo para
ese futuro host, usando configuración upstream y un marcador serial del huésped:

```sh
python3 experiments/hvf/test-linux-kvm.py --config /assets/linux-kvm.json --boot-marker WORKLOAD_READY
```

El script verifica la API KVM, compila, ejecuta tests y busca el marcador en una
VM real. Usa copias privadas de los discos. La red requiere la configuración TAP
upstream del host; no traduce la configuración slirp/macOS. No compara rendimiento
ni certifica paridad con upstream. No hay certificación de aislamiento,
snapshots o distribución de producción.

Fuentes de protocolo: [arranque Linux ARM64](https://docs.kernel.org/arch/arm64/booting.html),
[Alpine netboot 3.23.5](https://dl-cdn.alpinelinux.org/alpine/v3.23/releases/aarch64/netboot-3.23.5/),
[Hypervisor.framework](https://developer.apple.com/documentation/hypervisor),
[VirtIO](https://docs.oasis-open.org/virtio/virtio/v1.2/virtio-v1.2.html).
