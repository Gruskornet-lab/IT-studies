# Sensitive Information Disclosure

Källa: [TryHackMe: Sensitive Information Disclosure](https://tryhackme.com/room/sensitiveinformationdisclosure)

## Vektorsökning och RAG

### Cosine similarity

Mäter hur nära två vektorer ligger varandra, vilket är det RAG-system rankar dokument efter. Högst poäng hämtas, oavsett om dokumentet är behörigt eller inte.

```python
import numpy as np

def cosine(a, b):
    return np.dot(a, b) / (np.linalg.norm(a) * np.linalg.norm(b))

query = np.array([0.8, 0.1])
doc_safe = np.array([0.7, 0.2])
doc_confidential = np.array([0.79, 0.11])

cosine(query, doc_safe)            # 0.98
cosine(query, doc_confidential)    # 0.999, det konfidentiella dokumentet rankas högst
```

### Retrieval med metadatafilter

Filtrerar bort obehöriga och raderade dokument innan likhetssökningen. Utan filter hamnar konfidentiella och inaktuella dokument i top-k, och högre `top_k` ökar exponeringen.

```python
def retrieve(top_k=2, apply_filter=False):
    scored = []
    for doc in documents:
        if apply_filter:
            if doc["metadata"].get("access") != "public":   # filtrera på behörighet
                continue
            if doc["metadata"].get("deleted"):              # filtrera bort raderade
                continue
        score = cosine(query_embedding, doc["embedding"])
        scored.append((score, doc))
    scored.sort(reverse=True, key=lambda x: x[0])
    return scored[:top_k]

# apply_filter=False, top_k=2: public_policy + confidential_payroll
# apply_filter=False, top_k=3: dessutom deleted_old_policy
# apply_filter=True:           bara public_policy
```
