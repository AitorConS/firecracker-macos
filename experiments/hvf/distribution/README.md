# Paquete local macOS ARM64 experimental

El paquete incluye la API macOS 1.0 y las regresiones de red y almacenamiento.
La prueba final de 24 horas, otros Macs y la distribución firmada públicamente
no están certificados. Véanse los [tests disponibles](../ci/README.md).


Requiere macOS 26 y Apple Silicon con Hypervisor disponible. El ejecutable
`bin/firecracker` utiliza las bibliotecas de `lib/` relativas a su ubicación.
Conservar ambas carpetas juntas. No requiere Homebrew para ejecutarse.

`bin/firecracker --api-sock /ruta/privada/vmm.sock` inicia el supervisor.
Los huéspedes y discos los proporciona el usuario. La configuración requiere
`security: {"version": 1}` y deniega la red por defecto; las autorizaciones
IPv4/puerto/protocolo deben declararse expresamente. La API macOS 1.0 incluye
Pause/Resume y snapshots locales de formato 1. Capture desde Paused con
`PUT /snapshot/create {"snapshot_path":"/ruta/privada/snapshot"}` y restaure
con `/snapshot/load` usando el mismo cuerpo. Consulte `/operations/{id}`; la
restauración termina en Paused. Requiere el mismo Mac, build de macOS y del VMM.
Los discos se copian y las conexiones de red deben restablecerse.

Para reconstruir desde el repositorio:

```sh
/usr/bin/python3 experiments/hvf/distribution/build-native-deps.py
GLIB_PREFIX="$PWD/experiments/hvf/build/distribution/native" experiments/hvf/build-native.sh
/usr/bin/python3 experiments/hvf/distribution/package.py /ruta/nueva/paquete
```

Rust está fijado a 1.97.0; las dependencias Rust se registran en Cargo.lock.
Las fuentes nativas y herramientas Meson/Ninja están fijadas por SHA-256 en
sources.json. El SDK/compilador de Apple se registra en el manifiesto: no se
descarga ni se considera intercambiable con otra versión. Las fuentes nativas
se incluyen en sources/, con el parche de libslirp. Las licencias GLib se
incluyen en licenses/ y sus avisos originales permanecen en el archivo fuente.

El paquete tiene firma ad-hoc, sin notarización. El manifiesto distingue hashes
Mach-O antes de firmar y checksums finales. La comparación de dos builds con objetos nativos limpios y targets Cargo
separados confirmó igualdad de los tres Mach-O sin firma en este host/SDK.
`verify-reproducible.py` repite la comprobación; no cubre metadatos de procedencia
ni firmas/notarización. Los avisos de las dependencias Rust y de su biblioteca estándar se incluyen
en licenses/rust/. No es una release comercial terminada.

La prueba `test-relocated.py PAQUETE --linux-config CONFIG` ejecuta las regresiones
con el paquete copiado a un temporal. Además arranca un huésped sintético real
bajo un perfil externo que deniega el repositorio, /opt/homebrew y /usr/local.
Esta comprobación adicional usa modo de desarrollo explícito: macOS rechaza la
instalación del perfil Seatbelt interno dentro de otro sandbox heredado. La
batería principal sí conserva el modo endurecido y sus perfiles internos.

`sign-notarize.sh PAQUETE NUEVO.pkg` prepara opcionalmente un instalador firmado,
lo envía a Apple y solicita stapling. Requiere APPLICATION_IDENTITY,
INSTALLER_IDENTITY y NOTARY_PROFILE ya configurados. No se ejecuta como parte
del build local, requiere credenciales y realiza una transmisión externa.
Todavía no se ha validado con identidades comerciales. El paquete se instalaría
en /usr/local/libexec/firecracker-hvf; el build local no instala nada allí.

Para una revisión funcional limitada al empaquetado, ejecutar
`test-relocated.py PAQUETE --packaging-only`. Esta opción selecciona pruebas
explícitas de control y snapshots sintéticos, además del arranque reubicado
con acceso al repositorio/Homebrew denegado. Excluye las pruebas de red,
seguridad, estrés y estabilidad, y no admite configuración Linux. Ejecutar
sin esta opción sí incluye casos de red/seguridad de las suites completas.

Se conservan los avisos originales de Firecracker (`NOTICE` y `THIRD-PARTY`)
y se exponen los de proxy-libintl, PCRE2 y libffi en `licenses/`, además de
sus fuentes originales. El NOTICE original contiene referencias al bundle
Linux/libseccomp; el inventario de este paquete macOS figura en el manifiesto
y en sus dependencias Mach-O.
