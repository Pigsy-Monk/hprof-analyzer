## Cross-Dump Growth

_How the reachable heap grew across a time series of dumps of the same application (first = baseline, last = current)._

### Reports

- `r1` = dump_1_mnemonics.hprof
- `r2` = dump_4_philosophers.hprof

**Verdict:** Heap grew 3.3% (+377.4 KiB shallow); largest driver `scala.concurrent.stm.ccstm.InTxnImpl` (+3.7 MiB retained). Gross retained churn: +13.2 MiB grown / −33.9 MiB reclaimed across steps. 2 new suspects.

### Headline Totals

- **Δ Objects (r1→rN):** −98,418
- **Δ Shallow heap (r1→rN):** +377.4 KiB
- **Gross growth (classes that grew, r1→rN):** +13.2 MiB
- **Gross reclaimed (classes that shrank, r1→rN):** −33.9 MiB
- **Gross Retained churn (growth + reclaimed, r1→rN):** +47.2 MiB
- **Net Δ Retained (all classes, r1→rN):** −20.7 MiB

### Growth Leaders (by peak−baseline retained)

| Class                                                                 |        r1 |        r2 |   Δ(r1→rN) |
| --------------------------------------------------------------------- | --------: | --------: | ---------: |
| `scala.concurrent.stm.ccstm.InTxnImpl`                                |       0 B |   3.7 MiB |   +3.7 MiB |
| `long[]`                                                              |  14.2 KiB |   1.1 MiB |   +1.1 MiB |
| `org.renaissance.scala.stm.RealityShowPhilosophers$PhilosopherThread` |       0 B |   1.0 MiB |   +1.0 MiB |
| `scala.concurrent.stm.ccstm.Handle[]`                                 |       0 B |   1.0 MiB |   +1.0 MiB |
| `java.util.zip.ZipFile$Source`                                        | 446.6 KiB |   1.3 MiB | +876.2 KiB |
| `java.lang.Object[]`                                                  |   2.9 MiB |   3.7 MiB | +825.1 KiB |
| `int[]`                                                               | 106.7 KiB | 875.9 KiB | +769.2 KiB |
| `java.lang.ref.SoftReference`                                         | 605.2 KiB |   1.1 MiB | +525.8 KiB |
| `java.util.jar.JarFile`                                               | 593.3 KiB |   1.1 MiB | +525.0 KiB |
| `java.util.jar.Manifest`                                              | 590.3 KiB |   1.1 MiB | +521.9 KiB |
| `scala.concurrent.stm.skel.CallbackList`                              |       0 B | 417.2 KiB | +417.2 KiB |
| `scala.Function1[]`                                                   |       0 B | 399.1 KiB | +399.1 KiB |
| `java.util.jar.Attributes`                                            | 238.4 KiB | 448.0 KiB | +209.7 KiB |
| `java.util.LinkedHashMap`                                             | 338.1 KiB | 507.4 KiB | +169.3 KiB |
| `java.net.URLClassLoader`                                             |  81.0 KiB | 243.7 KiB | +162.7 KiB |
| `org.renaissance.scala.stm.RealityShowPhilosophers$CameraThread`      |       0 B | 157.5 KiB | +157.5 KiB |
| `java.lang.Class`                                                     |   3.5 MiB |   3.6 MiB |  +98.6 KiB |
| `java.util.concurrent.ConcurrentHashMap`                              | 526.3 KiB | 611.6 KiB |  +85.3 KiB |
| `java.util.concurrent.ConcurrentHashMap$Node[]`                       | 519.6 KiB | 604.7 KiB |  +85.1 KiB |
| `java.util.ArrayList`                                                 |  76.0 KiB | 150.9 KiB |  +74.9 KiB |
| `java.util.concurrent.ConcurrentHashMap$Node`                         | 390.1 KiB | 463.1 KiB |  +73.0 KiB |
| `scala.concurrent.stm.skel.SimpleRandom$`                             |       0 B |  64.5 KiB |  +64.5 KiB |
| `java.lang.ThreadLocal$ThreadLocalMap`                                |   4.4 KiB |  54.6 KiB |  +50.2 KiB |
| `java.lang.ThreadLocal$ThreadLocalMap$Entry[]`                        |   4.4 KiB |  51.5 KiB |  +47.1 KiB |
| `java.lang.ThreadLocal$ThreadLocalMap$Entry`                          |   4.3 KiB |  41.4 KiB |  +37.1 KiB |

### New Classes

| Class                                                                 |  r1 |        r2 |   Δ(r1→rN) |
| --------------------------------------------------------------------- | --: | --------: | ---------: |
| `scala.concurrent.stm.ccstm.InTxnImpl`                                | 0 B |   3.7 MiB |   +3.7 MiB |
| `org.renaissance.scala.stm.RealityShowPhilosophers$PhilosopherThread` | 0 B |   1.0 MiB |   +1.0 MiB |
| `scala.concurrent.stm.ccstm.Handle[]`                                 | 0 B |   1.0 MiB |   +1.0 MiB |
| `scala.concurrent.stm.skel.CallbackList`                              | 0 B | 417.2 KiB | +417.2 KiB |
| `scala.Function1[]`                                                   | 0 B | 399.1 KiB | +399.1 KiB |
| `org.renaissance.scala.stm.RealityShowPhilosophers$CameraThread`      | 0 B | 157.5 KiB | +157.5 KiB |
| `scala.concurrent.stm.skel.SimpleRandom$`                             | 0 B |  64.5 KiB |  +64.5 KiB |
| `scala.Console$`                                                      | 0 B |  24.6 KiB |  +24.6 KiB |
| `scala.util.DynamicVariable`                                          | 0 B |  24.5 KiB |  +24.5 KiB |
| `java.io.BufferedReader`                                              | 0 B |  24.4 KiB |  +24.4 KiB |
| `java.util.concurrent.atomic.AtomicReferenceArray`                    | 0 B |  13.2 KiB |  +13.2 KiB |
| `scala.concurrent.stm.ccstm.TxnLevelImpl`                             | 0 B |  13.1 KiB |  +13.1 KiB |
| `scala.collection.GenIterable`                                        | 0 B |  11.2 KiB |  +11.2 KiB |
| `scala.collection.GenTraversable`                                     | 0 B |  10.5 KiB |  +10.5 KiB |
| `scala.concurrent.stm.ccstm.WakeupManager`                            | 0 B |   8.7 KiB |   +8.7 KiB |
| `java.io.InputStreamReader`                                           | 0 B |   8.3 KiB |   +8.3 KiB |
| `scala.concurrent.stm.ccstm.TxnSlotManager`                           | 0 B |   8.3 KiB |   +8.3 KiB |
| `sun.nio.cs.StreamDecoder`                                            | 0 B |   8.3 KiB |   +8.3 KiB |
| `scala.concurrent.stm.ccstm.RetrySet`                                 | 0 B |   5.4 KiB |   +5.4 KiB |
| `scala.collection.immutable.StringLike`                               | 0 B |   4.3 KiB |   +4.3 KiB |
| `java.util.concurrent.atomic.AtomicLongArray`                         | 0 B |   4.3 KiB |   +4.3 KiB |
| `scala.concurrent.stm.ccstm.CCSTMRefs$GenericRef`                     | 0 B |   4.0 KiB |   +4.0 KiB |
| `scala.collection.mutable.ResizableArray`                             | 0 B |   3.3 KiB |   +3.3 KiB |
| `scala.concurrent.stm.ccstm.CCSTMRefs$IntRef`                         | 0 B |   3.0 KiB |   +3.0 KiB |
| `scala.collection.MapLike`                                            | 0 B |   2.5 KiB |   +2.5 KiB |

### Removed Classes

| Class                                                                             |      r1 |  r2 | Δ(r1→rN) |
| --------------------------------------------------------------------------------- | ------: | --: | -------: |
| `org.renaissance.jdk.streams.MnemonicsCoderWithStream`                            | 6.7 KiB | 0 B | −6.7 KiB |
| `scopt.OptionDef$$Lambda+0x00007ff1d40dcd20`                                      | 2.4 KiB | 0 B | −2.4 KiB |
| `org.renaissance.jdk.streams.MnemonicsCoderWithStream$$Lambda+0x00007ff1d4127800` | 1.4 KiB | 0 B | −1.4 KiB |
| `org.renaissance.jdk.streams.MnemonicsCoderWithStream$1`                          |   456 B | 0 B |   −456 B |
| `org.renaissance.jdk.streams.Mnemonics`                                           |   312 B | 0 B |   −312 B |
| `scala.runtime.LazyVals$$$Lambda+0x00007ff1d40c7878`                              |   288 B | 0 B |   −288 B |
| `java.lang.invoke.BoundMethodHandle$Species_LLLLL`                                |   280 B | 0 B |   −280 B |
| `org.renaissance.jdk.streams.MnemonicsCoderWithStream$$Lambda+0x00007ff1d4126b18` |   256 B | 0 B |   −256 B |
| `java.util.stream.LongPipeline`                                                   |   224 B | 0 B |   −224 B |
| `java.util.stream.IntPipeline$1$1`                                                |   152 B | 0 B |   −152 B |
| `java.util.Comparators$NaturalOrderComparator`                                    |   136 B | 0 B |   −136 B |
| `java.util.stream.Sink$ChainedInt`                                                |   136 B | 0 B |   −136 B |
| `java.util.stream.IntPipeline$1`                                                  |   128 B | 0 B |   −128 B |
| `org.renaissance.harness.Config$$Lambda+0x00007ff1d40fc678`                       |   112 B | 0 B |   −112 B |
| `org.renaissance.harness.Config$$Lambda+0x00007ff1d4116280`                       |   112 B | 0 B |   −112 B |
| `org.renaissance.harness.ConfigParser$$anon$1$$Lambda+0x00007ff1d40dc778`         |   112 B | 0 B |   −112 B |
| `org.renaissance.harness.ConfigParser$$anon$1$$Lambda+0x00007ff1d40dd6a0`         |   112 B | 0 B |   −112 B |
| `org.renaissance.harness.ConfigParser$$anon$1$$Lambda+0x00007ff1d40de018`         |   112 B | 0 B |   −112 B |
| `org.renaissance.harness.ConfigParser$$anon$1$$Lambda+0x00007ff1d40de990`         |   112 B | 0 B |   −112 B |
| `org.renaissance.harness.ConfigParser$$anon$1$$Lambda+0x00007ff1d40def38`         |   112 B | 0 B |   −112 B |
| `org.renaissance.harness.ConfigParser$$anon$1$$Lambda+0x00007ff1d40df4e0`         |   112 B | 0 B |   −112 B |
| `org.renaissance.harness.ConfigParser$$anon$1$$Lambda+0x00007ff1d40e0000`         |   112 B | 0 B |   −112 B |
| `org.renaissance.harness.ConfigParser$$anon$1$$Lambda+0x00007ff1d40e05a8`         |   112 B | 0 B |   −112 B |
| `org.renaissance.harness.ConfigParser$$anon$1$$Lambda+0x00007ff1d40e0b50`         |   112 B | 0 B |   −112 B |
| `org.renaissance.harness.ConfigParser$$anon$1$$Lambda+0x00007ff1d40e10f8`         |   112 B | 0 B |   −112 B |

### New / Grown Leak Suspects

| Suspect                                |  r1 |      r2 | Δ(r1→rN) | New? |
| -------------------------------------- | --: | ------: | -------: | ---- |
| `scala.concurrent.stm.ccstm.InTxnImpl` | 0 B | 2.7 MiB | +2.7 MiB | yes  |
| `java.util.zip.ZipFile$Source`         | 0 B | 1.3 MiB | +1.3 MiB | yes  |

### Shrunk Leak Suspects

| Suspect                   |      r1 |      r2 | Δ(r1→rN) |
| ------------------------- | ------: | ------: | -------: |
| `scala.runtime.LazyVals$` | 2.5 MiB | 2.5 MiB |   −104 B |

### Disappeared Leak Suspects

| Suspect            |      r1 |  r2 | Δ(r1→rN) |
| ------------------ | ------: | --: | -------: |
| `java.lang.Thread` | 5.5 MiB | 0 B | −5.5 MiB |

