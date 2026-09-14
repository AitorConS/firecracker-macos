# Optional guest: Jerboa

Provides an ARM64 ELF and a block image already prepared by external
tools. This adapter translates variables to `opt/uni/env`; it is the only place
that knows that convention. The VMM delivers firmware bytes and opaque blocks.

```sh
python3 experiments/hvf/guests/jerboa/run.py --kernel /path/kernel.img \
  --disk /path/root.img --cpus 4 --port 18080 --env MARKER=hvf-smoke
```

The root is copied by default; `--persistent` allows writing the original. No
images are generated nor is the kernel modified or compiled here. SMP patches
are the responsibility of the guest project. This test does not run in the
generic suite nor does it require a Jerboa checkout next to the fork.
