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
