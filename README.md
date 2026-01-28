# DodgeML

> **Proof of Concept** for evading ML-based malware classifiers.

---

## Evasion Techniques

- **Benign code patterns** - Junk functions using common Windows APIs (file enumeration, registry, system info)
- **Resource metadata** - Fictional company identity in version info and manifest
- **Payload obfuscation** - XOR + Base64 encoding with multi-byte key (char array format)
- **API pattern breaking** - Separates `GetModuleHandle`/`GetProcAddress`, interleaves with benign calls
- **Memory noise** - Multiple allocations with actual usage to mask payload allocation
- **Compiler flags** - `-fno-ident` removes GCC strings, `-static` for larger binary

**Execution:** Uses callback functions (`EnumPwrSchemes`, `EnumWindows`, `EnumDisplayMonitors`). Newer techniques (syscalls, indirect calls, etc.) may perform better but were not tested.

---

## Limitations & Notes

- **Compiler**: GCC MinGW is used here. Visual Studio (MSVC) would likely produce better results due to more common PE characteristics.
- **Payload storage**: Currently stored in `.text` section. For larger payloads, consider using the resources section or staging.
- **Resources/Manifest**: These files should be regenerated for each deployment to avoid similarity-based detection. You can use your favorite LLM to generate them.
- **Dynamic detection**: This PoC focuses on static ML evasion. Runtime behavior analysis by EDRs may still detect the payload.

---

## Development Process

1. Test locally with **EMBER2024** model to get ML score
2. Iterate until score is below detection threshold
3. Validate on **VirusTotal** / **Hybrid Analysis** for real-world coverage

---

## Build

```bash
make        # Build both
make exe    # Build EXE
make dll    # Build DLL
```

## Encoder

```bash
# Edit xor_encoder.py with your payload and key
python xor_encoder.py
```

---

## Results

```powershell
PS C:\Dev\EMBER2024\examples> uv run .\classifier.py sysmon.exe # EXE FORMAT

            Scan Result: sysmon.exe
╭─────────────┬───────────────────────────────╮
│ Property    │ Value                         │
├─────────────┼───────────────────────────────┤
│ File        │ ..\..\DodgeML\dist\sysmon.exe │
│ Prediction  │ BENIGN                        │
│ Probability │ 0.4452                        │
│ Status      │ OK                            │
╰─────────────┴───────────────────────────────╯

PS C:\Dev\EMBER2024\examples> uv run .\classifier.py rthelper.dll # DLL FORMAT

            Scan Result: rthelper.dll
╭─────────────┬─────────────────────────────────╮
│ Property    │ Value                           │
├─────────────┼─────────────────────────────────┤
│ File        │ ..\..\DodgeML\dist\rthelper.dll │
│ Prediction  │ BENIGN                          │
│ Probability │ 0.0524                          │
│ Status      │ OK                              │
╰─────────────┴─────────────────────────────────╯
```
Random VT scan on both files:
- [EXE](https://www.virustotal.com/gui/file/d034d691ab377a782432499c1a8804eab3c935a40e7876ca1140df7cb92b5e9b)
- [DLL](https://www.virustotal.com/gui/file/d034d691ab377a782432499c1a8804eab3c935a40e7876ca1140df7cb92b5e9b)

Random Hybrid Analysis scan on both files:
- [EXE](https://hybrid-analysis.com/sample/b920581d9e5d98a786d60c00f50f8a8da6680a9c2fcc7406473b1b011654661a)
- [DLL](https://hybrid-analysis.com/sample/d034d691ab377a782432499c1a8804eab3c935a40e7876ca1140df7cb92b5e9b)
---

## References

- [Evaluating Implants with EMBER](https://mez0.cc/posts/evaluating-implants-with-ember/) - mez0
- [Evading the Machine](https://steve-s.gitbook.io/0xtriboulet/artificial-intelligence/evading-the-machine) - 0xTriboulet

## Disclaimer

This is a **Proof of Concept** for educational purposes. Use only in authorized engagements.
