import hashlib

def derive_r(root_bytes, paths, curve_order):
    h = hashlib.sha256()
    h.update(root_bytes)
    # deterministic ordering:
    for path in sorted(paths):
        for idx in path:
            # choose an encoding length that can represent WIDTH (e.g. 1 byte if WIDTH<256)
            h.update(idx.to_bytes(2, 'big'))   # adjust length if needed
        h.update(b'\xFF')  # separator
    return int.from_bytes(h.digest(), 'big') % curve_order

def derive_r_factor_hash(root_bytes, path, level, curve_order):
    h = hashlib.sha256()
    h.update(root_bytes)
    for idx in path:
        h.update(idx.to_bytes(2, 'big'))
    h.update(level.to_bytes(2, 'big'))
    return int.from_bytes(h.digest(), 'big') % curve_order