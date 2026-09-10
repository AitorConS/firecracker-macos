# Huésped opcional: Jerboa

Proporciona un ELF ARM64 y una imagen de bloques ya preparados por herramientas
externas. Este adaptador traduce variables a `opt/uni/env`; es el único lugar
que conoce esa convención. El VMM entrega bytes de firmware y bloques opacos.

```sh
python3 experiments/hvf/guests/jerboa/run.py --kernel /ruta/kernel.img \
  --disk /ruta/root.img --cpus 4 --port 18080 --env MARKER=hvf-smoke
```

La raíz se copia por defecto; `--persistent` permite escribir el original. No
se generan imágenes ni se modifica o compila el kernel aquí. Los parches SMP
son responsabilidad del proyecto del huésped. Esta prueba no se ejecuta en la
batería genérica ni requiere que exista un checkout de Jerboa junto al fork.
