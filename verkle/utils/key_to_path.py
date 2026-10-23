import math

def _key_to_path(width, key: bytes):
        step_bits = int(math.log2(width))

        bitstring = ''.join(f"{byte:08b}" for byte in key)

        if len(bitstring) % step_bits != 0:
            pad_len = step_bits - (len(bitstring) % step_bits)
            bitstring = ("0" * pad_len) + bitstring

        chunks = [
            bitstring[i:i + step_bits]
            for i in range(0, len(bitstring), step_bits)
        ]

        path = [int(chunk, 2) for chunk in chunks]

        return path