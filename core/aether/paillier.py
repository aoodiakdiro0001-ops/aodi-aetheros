"""Paillier additive homomorphic encryption (pure Python 3.8, stdlib only).

REAL cryptography: a remote node computes on ENCRYPTED numbers and learns
nothing about them. Supported homomorphic operations (additive scheme):

    E(a) * E(b) mod n^2      == E(a + b)          (ciphertext multiply)
    E(a) ** k mod n^2        == E(a * k)          (scalar multiply)

HONEST SCOPE: this is additively homomorphic — enough for secure
aggregation, private analytics and encrypted arithmetic kernels. It is
NOT fully homomorphic (no encrypted × encrypted with result reuse at
NN-training scale). For that, the roadmap points to TFHE/Rust libraries;
this module never pretends otherwise.

Security notes:
- Key sizes here default to 1024-bit n for demo speed; use bits=2048+
  for anything real. Randomness comes from `random.SystemRandom`.
- This is a compact, dependency-free implementation intended for
  research/demo use on trusted personal hardware — not a certified
  cryptographic library.
"""
import math
import random

_SECURE = random.SystemRandom()


def _is_prime(n, k=40):
    """Miller-Rabin primality test."""
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31):
        if n % p == 0:
            return n == p
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(k):
        a = _SECURE.randrange(2, n - 1)
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _rand_prime(bits):
    while True:
        p = _SECURE.getrandbits(bits) | (1 << (bits - 1)) | 1
        if _is_prime(p):
            return p


class PublicKey(object):
    def __init__(self, n, g):
        self.n = n
        self.g = g
        self.n_sq = n * n

    @property
    def bits(self):
        return self.n.bit_length()

    def to_dict(self):
        return {"n": str(self.n), "g": str(self.g)}

    @classmethod
    def from_dict(cls, d):
        return cls(int(d["n"]), int(d["g"]))


class SecretKey(object):
    def __init__(self, lam, mu, n, g):
        self.lam = lam      # lambda = lcm(p-1, q-1)
        self.mu = mu
        self.n = n
        self.g = g
        self.n_sq = n * n

    def to_dict(self):
        return {"lam": str(self.lam), "mu": str(self.mu),
                "n": str(self.n), "g": str(self.g)}

    @classmethod
    def from_dict(cls, d):
        return cls(int(d["lam"]), int(d["mu"]), int(d["n"]), int(d["g"]))


def generate_keypair(bits=1024):
    """Paillier keypair. `bits` = modulus size (p and q are bits/2 each)."""
    if bits < 256:
        raise ValueError("bits must be >= 256 (demo floor)")
    half = bits // 2
    while True:
        p, q = _rand_prime(half), _rand_prime(half)
        if p == q:
            continue
        n = p * q
        if n.bit_length() != bits:
            continue
        lam = (p - 1) * (q - 1) // math.gcd(p - 1, q - 1)
        g = n + 1                      # standard fast choice: g = n+1
        n_sq = n * n
        # mu = L(g^lam mod n^2)^-1 mod n ; with g=n+1, L((n+1)^lam) = lam
        u = pow(g, lam, n_sq)
        l_val = (u - 1) // n
        try:
            mu = pow(l_val, -1, n)     # Python 3.8: pow(a,-1,n) OK
        except ValueError:
            continue
        return PublicKey(n, g), SecretKey(lam, mu, n, g)


def encrypt(pk, m, r=None):
    """Encrypt integer message m (any int, negatives handled mod n)."""
    if not isinstance(m, int) or isinstance(m, bool):
        raise TypeError("Paillier encrypts integers; scale floats first")
    m %= pk.n
    if r is None:
        while True:
            r = _SECURE.randrange(1, pk.n)
            if math.gcd(r, pk.n) == 1:
                break
    # c = g^m * r^n mod n^2   (g = n+1 => g^m = 1 + m*n mod n^2)
    return ((1 + m * pk.n) * pow(r, pk.n, pk.n_sq)) % pk.n_sq


def decrypt(sk, c):
    """Decrypt ciphertext back to a signed integer in (-n/2, n/2]."""
    u = pow(c % sk.n_sq, sk.lam, sk.n_sq)
    l_val = (u - 1) // sk.n
    return (l_val * sk.mu) % sk.n


def _signed(x, n):
    """Map raw residue to a signed representative."""
    return x - n if x > n // 2 else x


def decrypt_signed(sk, c):
    """Decrypt and map into (-n/2, n/2) so negatives come back correctly."""
    return _signed(decrypt(sk, c), sk.n)


def add(pk, c1, c2):
    """Homomorphic ADD:  D(E(a) * E(b)) = a + b."""
    return (c1 * c2) % pk.n_sq


def add_many(pk, cs):
    out = 1
    for c in cs:
        out = (out * c) % pk.n_sq
    return out


def scalar_mul(pk, c, k):
    """Homomorphic MULTIPLY-BY-CONSTANT: D(E(a)^k) = a * k."""
    if not isinstance(k, int) or isinstance(k, bool):
        raise TypeError("scalar must be int (scale floats first)")
    return pow(c, k, pk.n_sq)


def sub(pk, c1, c2):
    """Homomorphic SUBTRACT: D(E(a) * E(b)^-1) = a - b."""
    return (c1 * pow(c2, -1, pk.n_sq)) % pk.n_sq


# ---- fixed-point helpers so floats work on an integer scheme -----------
SCALE_BITS = int(__import__("os").environ.get("AETHER_HE_SCALE_BITS", "6"))
SCALE = 10 ** SCALE_BITS


def enc_float(pk, x):
    """Encrypt a float as a scaled integer (default 10^6)."""
    return encrypt(pk, int(round(float(x) * SCALE)))


def dec_float(sk, c):
    """Decrypt back to float (accepts raw residue, maps signed)."""
    return _signed(decrypt(sk, c), sk.n) / float(SCALE)
