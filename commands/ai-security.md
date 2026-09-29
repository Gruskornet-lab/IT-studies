## AI/ML Supply Chain

### Pickle vs SafeTensors

Pickle kan köra godtycklig kod vid inläsning via `__reduce__`, och det var därför en skadlig modellfil kunde ge en intrång. SafeTensors (Hugging Face) har bara en JSON-header och rå tensordata, så det går inte att bädda in körbar kod.

- Pickle: godtyckligt Python-bytecode, ingen validering
- SafeTensors: bara tensordata, headern valideras innan data läses, snabbt tack vare zero-copy memory mapping
- Innehåller inte optimizer-state eller träningskonfiguration, vilket räcker för inferens

Källa: [TryHackMe: Securing the AI Supply Chain](https://tryhackme.com/room/securing-the-ai-supplychain)

### Konvertera pickle-modell till SafeTensors

Ger en ren modellfil utan kodexekvering. Själva konverteringen måste läsa in pickle-filen, så en skadlig payload kan köras just där. Använd alltid `weights_only=True` vid inläsningen.

```python
import torch
from safetensors.torch import save_file, load_file

weights = torch.load("model.pkl", weights_only=True)
save_file(weights, "model.safetensors")
safe = load_file("model.safetensors")
```

### PyTorch: `weights_only=True`

Begränsar unpickler så att bara tensorobjekt kan återskapas. Försök att importera `os` eller anropa `system()` blockeras med ett fel. Från PyTorch 2.6 är detta standard, i äldre versioner måste det anges explicit.

```python
model = torch.load("model.pt", weights_only=True)   # säkert
model = torch.load("model.pt")                      # osäkert i PyTorch < 2.6
```

### Begränsningar med SafeTensors

Säker serialisering är nödvändig men inte tillräcklig. Verifiera alltid det faktiska formatet och inspektera arkitekturen.

- Filändelsen går inte att lita på: en `.safetensors`-fil kan innehålla pickle-bytecode (CVE-2023-6730, Hugging Face SFConvertBot)
- Skyddar bara vid inläsning, inte mot skadlig logik i modellens arkitektur vid inferens
- Exempel: ett Keras `Lambda`-lager kan köra godtycklig Python vid varje prediktion
