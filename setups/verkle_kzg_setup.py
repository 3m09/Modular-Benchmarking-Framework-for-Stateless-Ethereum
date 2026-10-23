from py_ecc import optimized_bls12_381 as b
from verkle.utils.fft import fft
from verkle.utils.poly_utils import PrimeField
from registry.setup import register_setup, BaseSetup

@register_setup("verkle_kzg")
class VerkleKZGSetup(BaseSetup):

    def __init__(self, security_parameter, width):
        super().__init__(security_parameter)
        self.WIDTH = width

        self.MODULUS = b.curve_order

        self.field = PrimeField(self.MODULUS)

        # Root of unity for a given evaluation domain size
        self.root_of_unity_candidates = {
            512: 12531186154666751577774347439625638674013361494693625348921624593362229945844,
            256: 21071158244812412064791010377580296085971058123779034548857891862303448703672,
            128: 3535074550574477753284711575859241084625659976293648650204577841347885064712,
            64: 6460039226971164073848821215333189185736442942708452192605981749202491651199,
            32: 32311457133713125762627935188100354218453688428796477340173861531654182464166,
            16: 35811073542294463015946892559272836998938171743018714161809767624935956676211
        }
        
        self.ROOT_OF_UNITY = self.root_of_unity_candidates[self.WIDTH]

        assert pow(self.ROOT_OF_UNITY, self.WIDTH // 2, self.MODULUS) != 1
        assert pow(self.ROOT_OF_UNITY, self.WIDTH, self.MODULUS) == 1

        # Powers of the root of unity
        self.POWERS = [pow(self.ROOT_OF_UNITY, i, self.MODULUS) for i in range(self.WIDTH)]

        # 1/(x-r) evaluated at every r, for every x in the set of powers
        self.INVERSES = [self.field.multi_inv([self.field.sub(p, x) for p in self.POWERS]) for x in self.POWERS]

        # Polynomials that evaluate to [000....010....000] across the evaluation domain,
        # one for every possible position of the 1
        self.LAGRANGE_POLYS = [
            fft([0]*i + [1] + [0]*(self.WIDTH-1-i), self.MODULUS, self.ROOT_OF_UNITY, inv=True)
            for i in range(self.WIDTH)
        ]

        self.setup = (
            [b.multiply(b.G1, pow(self.security_parameter, i, self.MODULUS)) for i in range(self.WIDTH+1)],
            [b.multiply(b.G2, pow(self.security_parameter, i, self.MODULUS)) for i in range(self.WIDTH+1)],
            [b.multiply(b.G1, self.field.eval_poly_at(l, self.security_parameter)) for l in self.LAGRANGE_POLYS],
            [b.multiply(b.G2, self.field.eval_poly_at(l, self.security_parameter)) for l in self.LAGRANGE_POLYS],
        )
