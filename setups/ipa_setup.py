from py_ecc import optimized_bls12_381 as b
from registry.setup import register_setup, BaseSetup


@register_setup("verkle_ipa")
class IPASetup(BaseSetup):
    """
    Minimal IPA setup for vector commitments in G1.

    Note:
    - For IPA, scalars should live in the curve order field.
      So MODULUS is set to b.curve_order by default.
    - Generator derivation here is deterministic but not cryptographically strong.
      Replace with hash-to-curve if you need stronger guarantees.
    """
    def __init__(self, security_parameter, width: int):
        super().__init__(security_parameter)
        self.WIDTH = width
        self.MODULUS = b.curve_order
        # Deterministic (non-CRS) generator list
        self.G = [b.multiply(b.G1, i + 1) for i in range(width)]
        self.H = b.multiply(b.G1, width + 1)