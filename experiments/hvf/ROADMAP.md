# Alcance del fork y siguientes hitos

Objetivo: VMM genérico para macOS ARM64, preservando Linux/KVM. Jerboa es uno de
los huéspedes de compatibilidad. El alcance no incluye modificar kernels de
huéspedes ni integrar daemon, Desktop, Compose o health checks de Jerboa.

## Hito 1: independencia del huésped — implementado

Linux ARM64 arranca con Image/initrd/argumentos, disco VirtIO y red usando solo el
fork y herramientas genéricas. Pruebas reproducibles con Alpine y guest sintético;
adaptador opcional Jerboa con archivos suministrados externamente.

| Punto acordado | Estado verificable |
| --- | --- |
| 1. Errores API y lock durante copia | Corregidos; pruebas de ELF inválido, error nativo de red, fuente bloqueada y reintento |
| 2. Dependencias Jerboa | Retiradas del VMM y pruebas por defecto; archivos históricos específicos conservados fuera del fork |
| 3. Protocolos de arranque | ELF y Linux Image; kernel/initrd/argumentos; no UEFI ni arranque desde firmware/disco |
| 4. Firmware genérico | Archivos binarios con nombre; ninguna clave del huésped dentro del VMM |
| 5. Discos de bloques | Archivos opacos, RO/RW/copia por dispositivo; sin TFS ni montajes |
| 6. Red genérica | Interfaz sin forwards, MAC, mappings TCP/UDP IPv4; transporte separado; un backend slirp y una interfaz |
| 7. API | Contrato 0.3, capacidades, estados, errores y subconjunto upstream documentados; no API upstream completa |
| 8. Parada | Starting/Stopping asíncronos; Shutdown mediante botón VirtIO input; plazo y escalada explícitos; pruebas Linux y synthetic |
| 9. Dispositivos | Validaciones, cuotas, errores de E/S y negativos; harness libFuzzer/ASan/UBSan; falta auditoría sistemática |
| 10. Aislamiento macOS | Pendiente de implementación y evaluación; no garantías multi-tenant actuales |
| 11. Métricas | Contadores diagnósticos locales; falta API de métricas y muestreo host |
| 12. Pausa/snapshots | No implementados, anunciados como no soportados |
| 13. Linux/KVM y automatización | Script macOS reproducible; falta ejecutar y verificar backend KVM en Linux |
| 14. Distribución | Rust/Cargo y assets guest fijados, firma ad-hoc, mínimo real documentado; falta empaquetado completo y notarización |
| 15. Huéspedes/workloads | Linux y synthetic en batería; Jerboa opcional; falta diversidad y pruebas prolongadas |

## Hito 2: ciclo de vida, robustez y evidencia multiplataforma

- Estado `Starting` observable sin bloquear la API y estados terminales tipados.
- Canal de petición de apagado guest con capacidad explícita y plazo definido;
  timeout retorna error o escala solo si la configuración lo autoriza. No llamar
  “ordenado” a matar el proceso del VMM.
- Fuzzing de cadenas/colas/ECAM/fw_cfg separado de HVF, sanitizers y corpus de
  descriptores negativos; garantizar progreso y cuotas globales de E/S.
- Tests Linux/KVM en host con /dev/kvm, comparando contra upstream; CI macOS en
  hardware con HVF habilitado, sin presentar un runner emulado como equivalente.
- Más distribuciones Linux, lectura/escritura con filesystem, presión de RAM,
  red prolongada, señales y fallos del host.

La ejecución Linux/KVM queda **pendiente por falta de host con `/dev/kvm`**,
por decisión del usuario (2026-09-11). Las pruebas macOS/HVF y las comprobaciones
de código o compilación no sustituyen esa validación. No se requiere provisionar
un host ni arrancar Docker para este hito.

El arranque asíncrono y el botón genérico están implementados y pasan las pruebas
macOS/HVF con Linux 1/4 vCPU. Fuzzing: 4.912.942 casos en 61 s con ASan/UBSan/LeakSanitizer sobre
bloque, red, input, ECAM y firmware; véase [harness y límites](fuzz/README.md). Esta evidencia no completa
la validación multiplataforma ni las pruebas prolongadas del hito.

## Diseño pendiente: aislamiento y límites

Supervisor y proceso VM separados. Abrir/validar/bloquear descriptores antes de
restringir el proceso; política explícita de archivos permitidos, red saliente y
bindings host. Elegir sandbox/macOS API soportada y evaluar sus vías de escape,
no equiparar sandbox-exec con una frontera auditada. Limitar archivos, hilos,
memoria/CPU y trabajo de dispositivos con mecanismos medidos de macOS; documentar
límites blandos y duros. Revisar slirp y superficie PCI/MMIO como código expuesto al
guest. Firma/notarización no sustituyen el modelo de aislamiento.

## Diseño pendiente: métricas y snapshots

Métricas del VMM: CPU/RSS host, exits por vCPU, colas/latencia/bytes de bloque,
paquetes/bytes/drop de red y estados del supervisor; API propia versionada, sin
dependencia de un daemon de producto.

Pausa: detener vCPU, drenar o cancelar E/S y congelar timers de manera coordinada.
Snapshot: cabecera con versión de formato/máquina, capacidades CPU/HVF/host,
registros, GIC, RAM, dispositivos, reloj y referencias consistentes a discos.
Validar compatibilidad antes de restaurar y rechazar combinaciones incompatibles.
No prometer compatibilidad binaria con snapshots KVM. Restauración de conexiones
slirp y atomicidad entre discos/RAM requieren decisiones explícitas, no una copia
de RAM aislada.

## Diseño pendiente: build y distribución

Fijar libslirp y dependencias transitivas, compilar con deployment target probado,
generar manifiesto/SBOM y comprobar un host limpio sin Homebrew. Firma Developer ID,
entitlements mínimos, notarización y entrega se hacen después de tener el paquete
concreto y credenciales del propietario. No hay publicación automática autorizada.
