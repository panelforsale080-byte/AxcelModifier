# AxcelModifier

Pick a process. The app calls `il2cpp_domain_get`, then you search a class by name or by hex address.

- Class name: `ShowEntity` or `UnityEngine.Camera`
- Address: `0x7a1234abcd` (klass pointer) or a small lib offset added to the IL2CPP base

The result is the class address and its field offsets. Root is required to read another app.
