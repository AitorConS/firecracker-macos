# Fuzzing de dispositivos

`experiments/hvf/fuzz/run.sh` compila los dispositivos C reales con LLVM/libFuzzer,
ASan y UBSan. Requiere `brew install llvm`; `FUZZ_CC` admite otro clang con los
runtimes. `FUZZ_SECONDS` cambia los 60 s por defecto. El corpus creciente, logs y
crashes quedan bajo `experiments/hvf/build/fuzz`; los casos de regresión se
conservan en `fuzz/corpus` y se incorporan siempre.

El harness configura colas válidas de bloque, TX/RX e input, modifica descriptores,
rings y buffers, y ejecuta accesos ECAM, BAR y fw_cfg con tamaños arquitectónicos.
Usa el código de producción para DMA, validaciones y finalización. Solo sustituye
HVF/GIC y el transporte host de red; no prueba libslirp ni concurrencia con vCPU.
Los rechazos que en producción terminan la VM con código 2 vuelven al harness con
longjmp. No se interceptan abortos ni los informes de los sanitizadores.
Cada caso tiene RAM/estado de dispositivos limpios, disco temporal privado y un
máximo de 1024 mutaciones y 64 accesos MMIO. Las cuotas reales limitan las colas.

La primera campaña detectó cálculo intermedio de puntero fuera del objeto en la
lectura de configuración input (`config + off - 0x100`). Se corrigió a
`config + (off - 0x100)` y se corrigió la expresión equivalente en la MAC de red.
El archivo `corpus/input-config-pointer` reproduce el hallazgo original.
Una campaña finita sin nuevos hallazgos no constituye auditoría de seguridad ni
prueba de ausencia de fallos.

LLVM 23/macOS notificó 56 bytes al cerrar el hilo detached de monitorización RSS
de libFuzzer, con stack en `fuzzer::StartRssThread`, sin frames del VMM. Se usa
`-rss_limit_mb=0` para no crear ese hilo, manteniendo LeakSanitizer activo y el
límite por asignación en 256 MiB. No hay límite global RSS en esta campaña.
Fuente: [implementación LLVM de StartRssThread](https://github.com/llvm/llvm-project/blob/main/compiler-rt/lib/fuzzer/FuzzerDriver.cpp).

Campaña final local (2026-09-11): 4,912,942 casos en 61 s, código de salida 0,
sin nuevos informes de ASan/UBSan/LeakSanitizer. Log: `build/fuzz-final.log`
relativo a `experiments/hvf`.

## Protocolo de control

`sh experiments/hvf/fuzz/run-control.sh` prueba el parser y el emisor reales de
`native/control.h` mediante pares de sockets: fragmentación, concatenación,
versión/magic inválidos, EOF parcial e identificadores de 64 bits. El corpus y
los artefactos quedan en `build/fuzz-control`. Usa la misma configuración de
sanitizadores y evita el hilo RSS descrito arriba; no suprime LeakSanitizer.
El parser HTTP Rust tiene además una campaña determinista de mutaciones:
`HVF_FUZZ_CASES=1000000 cargo test --locked -p hvf-vmm mutation_campaign_bounded_requests`.
Esta campaña valida los límites del parser; los sanitizadores C se aplican a los
otros targets, no se atribuyen al test Rust.

## libslirp vendorizado

`sh experiments/hvf/fuzz/run-slirp.sh` compila libslirp 4.9.4 y los adaptadores
con ASan/UBSan/libFuzzer. Usa las mismas inclusiones obligatorias de política de
sockets que el producto, sin egress/DNS/listeners autorizados. Cada entrada crea,
procesa y destruye una pila; GLib local todavía no está instrumentado. Este target
no sustituye el fuzzing de IPC de la autoridad ni las pruebas con permisos activos.

Primera campaña: 2.502.154 entradas en 61 segundos sin informes de sanitizadores;
evidencia `build/slirp-fuzz.log`. La campaña de dispositivos posterior a copiar y
validar cadenas completas ejecutó 4.798.923 entradas/61 s (`build/resources-fuzz.log`).

## Cierre de implementación y snapshots

El target de dispositivos también deserializa el estado de bloques, red e input
mediante el lector de snapshots de producción, usando entradas de memoria
acotadas. El manifiesto, sus hashes y los registros/GIC se prueban por separado
con restauraciones HVF y corrupción deliberada en `test_snapshot.py`.

Campañas de 600 segundos completadas el 2026-09-12:
- Dispositivos: 34.717.374 entradas/601 s (`build/final-device-fuzz.log`).
- Control: 25.897.533 entradas/601 s (`build/final-control-fuzz.log`).
- HTTP: un millón de mutaciones (`build/final-http-mutation.log`).

La primera campaña prolongada de libslirp encontró aritmética sobre NULL en
`ip_reass` al llegar el primer fragmento IPv4. El parche calcula container_of
solo cuando ya existe una cola; conserva el flujo de creación de la cola nueva.
`slirp-corpus/ipv4-first-fragment-null-queue` conserva la entrada y se incorpora
en cada ejecución. El archivo original y el informe UBSan permanecen en
`build/final-slirp-fuzz.log`; la repetición está en
`build/final-slirp-fuzz-fixed.log`. Esa repetición encontró un heap-buffer-overflow
ASan distinto en `ncsi_rsp_handler_oem` (`vendor/libslirp/src/ncsi.c:136`): un
paquete de 31 bytes declaraba un payload OEM truncado y la función leía cuatro
bytes de fabricante donde solo quedaba uno. La validación comprueba ahora el
payload declarado, los bytes realmente disponibles y los mínimos OEM/Mellanox.
`slirp-corpus/ncsi-oem-truncated-payload` conserva el caso como regresión.
