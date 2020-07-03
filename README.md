swh-model
=========

Implementation of the Data model of the Software Heritage project, used to
archive source code artifacts.

This module defines the notion of SoftWare Heritage persistent IDentifiers
(SWHIDs) and provides tools to compute them:

```sh
   $ swh-identify fork.c kmod.c sched/deadline.c
   swh:1:cnt:2e391c754ae730bd2d8520c2ab497c403220c6e3    fork.c
   swh:1:cnt:0277d1216f80ae1adeed84a686ed34c9b2931fc2    kmod.c
   swh:1:cnt:57b939c81bce5d06fa587df8915f05affbe22b82    sched/deadline.c

   $ swh-identify --no-filename /usr/src/linux/kernel/
   swh:1:dir:f9f858a48d663b3809c9e2f336412717496202ab
```
