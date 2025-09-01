import lief
import numpy as np

def extract_features(path):
    feats = np.zeros(2381, dtype=np.float32)  
    try:
        binary = lief.parse(path)
        if binary is None:
            return feats

        # Example simple features
        feats[0] = binary.header.machine if binary.header else 0
        feats[1] = binary.header.numberof_sections if binary.header else 0

        # FIX: convert to list before slicing
        sections = list(binary.sections)
        for i, sec in enumerate(sections[:10]):
            feats[2 + i] = sec.size

    except Exception as e:
        print(f"Feature extraction failed for {path}: {e}")
    return feats

