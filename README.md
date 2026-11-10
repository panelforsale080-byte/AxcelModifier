# AxcelModifier

Pick a process. The app calls `il2cpp_domain_get`, then you search a class by name or by hex address.

- Class name: `ShowEntity` or `UnityEngine.Camera`
- Address: `0x208020` is added to the IL2CPP base automatically (`base + 0x208020`). A full klass pointer still works as-is.

The result is the class address and its field offsets. Root is required to read another app.
