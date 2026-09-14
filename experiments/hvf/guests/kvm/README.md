# Huésped Linux x86_64 para validar KVM

Este smoke usa el backend Linux original y herramientas genéricas. No usa HVF,
Jerboa ni QEMU. Necesita Linux x86_64 con `/dev/kvm`, GCC, un BusyBox estático,
Python 3, `ip`, `unshare` y un kernel vmlinux compatible con Firecracker que tenga
VirtIO MMIO, bloque y red integrados. `prepare.py` rechaza BusyBox dinámico.

```sh
python3 experiments/hvf/guests/kvm/prepare.py --output /ruta/validacion/guest
# Colocar el kernel proporcionado en /ruta/validacion/vmlinux.
sudo unshare --net python3 experiments/hvf/guests/kvm/smoke.py \
  --work /ruta/validacion \
  --binary /ruta/firecracker/build/cargo_target/release/firecracker
```

El namespace de red es obligatorio: el script rechaza el namespace del host.
Crea un TAP temporal y usa 192.0.2.0/30 solo dentro del namespace; no configura
NAT, rutas del host ni puertos públicos. El TAP y los procesos VM se eliminan en
`finally`. Los discos, configuraciones y logs se conservan en el directorio de
validación para revisar la prueba. Usar un directorio dedicado: el script crea
sus propios `kvm-disk-1.raw` y `kvm-disk-2.raw` desde cero.

La prueba arranca Linux con 1 y 2 vCPU, dos veces por disco, comprueba el contador
persistido con fsync, 4 MiB de HTTP por arranque, eco UDP y salida solicitada al huésped por HTTP (`/exit`). Tras sincronizar,
el huésped llama a reboot con `reboot=k`: el i8042 de Firecracker transforma el
reset en salida de la VM. No se presenta como soporte ACPI poweroff. Guarda `logs/smoke-result.json`. El servidor C del huésped es una
fixture mínima de prueba, no un servicio de producción.

Compilar Firecracker y ejecutar sus unit tests son comprobaciones separadas. Un
build GNU puede usar el filtro seccomp vacío anunciado por upstream: esta prueba
no valida el jailer, aislamiento de producción ni distribución musl. Tampoco
valida KVM ARM64, snapshots o paridad completa entre KVM y HVF.

Con el kernel CI 6.1.102 usado en esta validación, RB_POWER_OFF deja el guest en
“System halted” y no termina el proceso VMM. Se conserva esa limitación; no se
ha cambiado el backend upstream para ocultarla.

Para los tests upstream, compilar primero los ejecutables y ejecutarlos luego en
namespaces privados (el build se hace como usuario, los tests requieren sudo):

```sh
cargo test --release --locked -p vmm -p firecracker --no-run > /ruta/test-build.log 2>&1
python3 experiments/hvf/guests/kvm/run-units.py --source "$PWD" \
  --build-log /ruta/test-build.log --output /ruta/unit-results
```

El runner conserva cada resultado, incluidos fallos; limita cada binario a diez
minutos y recoge su grupo de procesos al vencer el plazo. La compilación requiere
el enlace de desarrollo de libseccomp además de Rust y GCC. En el host probado se
usó la biblioteca ya instalada mediante un enlace dentro del directorio privado
y `LIBRARY_PATH`, sin instalar paquetes ni modificar los grupos del usuario.

## Resultado local del 2026-09-11

Host Ubuntu 26.04, kernel 7.0.0-28, x86_64 virtualizado sobre KVM. API KVM 12.
El fork del commit 9dbd17b05 compila y pasa cuatro arranques, persistencia de disco,
16 MiB de HTTP total y UDP. Se corrigió `cc = "1.2"` a `cc = "1.2.0"` en hvf-vmm
para cumplir la política de dependencias; el rango permitido no cambia.

Resultados de los siete ejecutables de tests, incorporando el reintento de la
política de dependencias: **993 aprobados, 3 fallos, ninguno ignorado**. Los tres
fallos se reprodujeron por separado y siguen pendientes:

- `arch::x86_64::vcpu::tests::test_set_tsc`: el test espera error cuando TscControl
  no está anunciado, pero el SET de la frecuencia solicitada retorna éxito.
- `test_build_and_boot_microvm` y `test_build_microvm`: después de una llamada a
  `run_with_timeout(500)`, el estado de salida sigue en None, no Some(Ok).

Los dos archivos upstream que contienen estos tests son idénticos a los de la
base 16f9023f8; no se han cambiado sus aserciones ni marcado tests como ignorados.
Eso no demuestra por sí solo la causa ni sustituye ejecutar un build upstream
independiente. No se declara verde toda la batería ni validado KVM ARM64.

Logs, kernel URL/SHA256, hash del ejecutable y resultados completos:
`experiments/hvf/build/kvm-validation/verification.json`. El primer fallo del
runner por ausencia de CARGO_MANIFEST_DIR se corrigió replicando el directorio
de trabajo y esa variable de Cargo al ejecutar cada test bajo sudo.

## Comparación independiente y cierre de los tres fallos

Durante la implementación se compiló upstream 16f9023f8 en su propio directorio
con Rust 1.97.0, GNU release y su lockfile original. Su batería reprodujo
**993 aprobados/3 fallos/0 ignorados**. La batería del fork corregido obtiene
**996 aprobados/0 fallos/0 ignorados**, sin eliminar tests ni aserciones de salida.
Cada caso corregido pasó además tres repeticiones aisladas.

`strace` identifica EPOLLHUP de stdin como primer evento en ambos árboles.
Los tests esperan ahora el estado terminal durante el plazo total original de
500 ms. `tsc-probe.c` muestra que el ioctl permite subir TSC sin TscControl
(software catchup); el test exige éxito y lectura correcta para el aumento y
error para reducirlo a la mitad sin escalado. Ver el registro de implementación
para valores exactos y la referencia al código de Linux.

Los logs comparados, resultados y hashes están en
`experiments/hvf/build/kvm-validation/comparison/comparison.json`. La validación
sigue limitada a KVM x86_64 anidado y no prueba jailer/musl ni KVM ARM64.
