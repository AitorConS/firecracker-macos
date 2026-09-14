# Regresiones de red HVF

Los controles cambian un solo mecanismo en copias temporales: nunca se revierte
producción ni se usa HEAD como baseline de este checkout compartido.

- `python3 experiments/hvf/test-network-transfer.py --repeat 3`: autoridad real,
  transferencia SCM_RIGHTS, TCP y dos ecos por proxy UDP. El control cierra la
  referencia emisora antes del ACK. El estímulo crea/libera sockets Unix y puede
  activar GC en todo el host; ejecutar sin otras campañas de red concurrentes.
  El script exige reproducción en cada protocolo y entrega completa en corregido.
  `--churn 0` comprueba tráfico natural, sin garantizar discriminación.
- `python3 experiments/hvf/test-network-recovery.py --repeat 2`: gate, autoridad,
  política y libslirp reales; control desactiva solo recuperación del listener.
  Cubre fallo aislado, persistente, presupuesto, recuperación con tráfico entre
  fallos, DNS bajo presión, mapeos efímeros y autoridad caída.
- `python3 experiments/hvf/test-network-rpc.py`: inyecta timeout, respuesta con ID
  incorrecto, fallo de ACK y EINTR; comprueba estado fatal, cierre de descriptor y
  rechazo de solicitudes antes del ACK. `--control RUTA` permite comparar con la
  versión anterior de ese mecanismo.
- `test-network-{gate,fd,port}.py` conservan los discriminantes previos de ICMP,
  liberación TCP y colisiones de puertos.

Usar `--output` nuevo para preservar evidencia. `--sanitize --fixed-only` está
admitido en transferencia y recuperación. Los casos provocados se distinguen de
los fallos espontáneos. La inyección del listener equivale a cerrar su lectura:
no altera permisos ni finge que los datagramas ya perdidos se recuperan.

La validación VMM usa `test-network-closure.py` (contenido y estado HTTP exactos,
DNS y UDP), más `test-linux.py` (forwarding, tráfico bidireccional, disco y
ciclos de pausa). Ejecutar las campañas con presión de sockets de forma
secuencial para evitar interferencias entre pruebas. Los resultados corresponden
al binario y al host registrados por cada ejecución, no a builds posteriores.
