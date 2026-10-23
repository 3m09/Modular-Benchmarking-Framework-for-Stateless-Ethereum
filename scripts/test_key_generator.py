import random

rng = 5  # how many random numbers to generate

with open('input.txt', 'w') as f:
    f.write('[')
    for i in range(rng):
        num = random.randint(0, 1023)
        hex_str = num.to_bytes(2, "big").hex()
        f.write(f'"0x{hex_str}"')

        if i != rng - 1:
            f.write(', ')
        else:
            f.write(']')
