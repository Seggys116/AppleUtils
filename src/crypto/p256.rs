use super::hash::sha256;

pub const P256_ELEMENT_BYTES: usize = 32;
pub const P256_UNCOMPRESSED_BYTES: usize = 1 + 2 * P256_ELEMENT_BYTES;
pub const P256_SIGNATURE_BYTES: usize = 2 * P256_ELEMENT_BYTES;

const SEC1_UNCOMPRESSED_TAG: u8 = 0x04;
const SHA256_BLOCK_BYTES: usize = 64;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct U256([u64; 4]);

impl U256 {
    const ZERO: Self = Self([0; 4]);

    const fn one() -> Self {
        Self([1, 0, 0, 0])
    }

    fn from_be_bytes(bytes: &[u8; P256_ELEMENT_BYTES]) -> Self {
        let mut limbs = [0u64; 4];
        for (index, limb) in limbs.iter_mut().enumerate() {
            let start = P256_ELEMENT_BYTES - 8 * (index + 1);
            let mut word = [0u8; 8];
            word.copy_from_slice(&bytes[start..start + 8]);
            *limb = u64::from_be_bytes(word);
        }
        Self(limbs)
    }

    fn to_be_bytes(self) -> [u8; P256_ELEMENT_BYTES] {
        let mut bytes = [0u8; P256_ELEMENT_BYTES];
        for (index, limb) in self.0.iter().enumerate() {
            let start = P256_ELEMENT_BYTES - 8 * (index + 1);
            bytes[start..start + 8].copy_from_slice(&limb.to_be_bytes());
        }
        bytes
    }

    fn is_zero(self) -> bool {
        self.0.iter().all(|limb| *limb == 0)
    }

    fn bit(self, index: usize) -> u64 {
        (self.0[index / 64] >> (index % 64)) & 1
    }

    fn adc(self, other: Self) -> (Self, u64) {
        let mut out = [0u64; 4];
        let mut carry = 0u128;
        for ((out_limb, a), b) in out.iter_mut().zip(self.0.iter()).zip(other.0.iter()) {
            let sum = u128::from(*a) + u128::from(*b) + carry;
            *out_limb = sum as u64;
            carry = sum >> 64;
        }
        (Self(out), carry as u64)
    }

    fn sbb(self, other: Self) -> (Self, u64) {
        let mut out = [0u64; 4];
        let mut borrow = 0i128;
        for ((out_limb, a), b) in out.iter_mut().zip(self.0.iter()).zip(other.0.iter()) {
            let diff = i128::from(*a) - i128::from(*b) - borrow;
            *out_limb = diff as u64;
            borrow = i128::from(diff < 0);
        }
        (Self(out), borrow as u64)
    }

    fn ge(self, other: Self) -> bool {
        for index in (0..4).rev() {
            if self.0[index] != other.0[index] {
                return self.0[index] > other.0[index];
            }
        }
        true
    }

    fn select(a: Self, b: Self, choose_a: u64) -> Self {
        let mask = 0u64.wrapping_sub(choose_a);
        let mut out = [0u64; 4];
        for ((out_limb, a_limb), b_limb) in out.iter_mut().zip(a.0.iter()).zip(b.0.iter()) {
            *out_limb = (a_limb & mask) | (b_limb & !mask);
        }
        Self(out)
    }
}

fn mac(a: u64, b: u64, c: u64, carry: u64) -> (u64, u64) {
    let wide = u128::from(a) + u128::from(b) * u128::from(c) + u128::from(carry);
    (wide as u64, (wide >> 64) as u64)
}

#[derive(Clone, Copy)]
struct Modulus {
    m: U256,
    n0: u64,
    r2: U256,
    one: U256,
}

impl Modulus {
    fn new(m: U256) -> Self {
        let mut inverse = 1u64;
        for _ in 0..6 {
            inverse = inverse.wrapping_mul(2u64.wrapping_sub(m.0[0].wrapping_mul(inverse)));
        }
        let n0 = inverse.wrapping_neg();

        let (mut one, _) = U256::ZERO.sbb(m);
        while one.ge(m) {
            let (reduced, _) = one.sbb(m);
            one = reduced;
        }

        let mut r2 = one;
        for _ in 0..256 {
            let (doubled, carry) = r2.adc(r2);
            let (reduced, borrow) = doubled.sbb(m);
            r2 = if carry == 1 || borrow == 0 {
                reduced
            } else {
                doubled
            };
        }

        Self { m, n0, r2, one }
    }

    // CIOS Montgomery multiplication reads and writes `t` at both `j` and `j - 1` in one pass.
    #[allow(clippy::needless_range_loop)]
    fn mont_mul(&self, a: U256, b: U256) -> U256 {
        let mut t = [0u64; 6];
        for i in 0..4 {
            let mut carry = 0u64;
            for j in 0..4 {
                let (lo, hi) = mac(t[j], a.0[i], b.0[j], carry);
                t[j] = lo;
                carry = hi;
            }
            let (sum, overflow) = t[4].overflowing_add(carry);
            t[4] = sum;
            t[5] = t[5].wrapping_add(u64::from(overflow));

            let factor = t[0].wrapping_mul(self.n0);
            let (_, mut carry) = mac(t[0], factor, self.m.0[0], 0);
            for j in 1..4 {
                let (lo, hi) = mac(t[j], factor, self.m.0[j], carry);
                t[j - 1] = lo;
                carry = hi;
            }
            let (sum, overflow) = t[4].overflowing_add(carry);
            t[3] = sum;
            t[4] = t[5].wrapping_add(u64::from(overflow));
            t[5] = 0;
        }

        let value = U256([t[0], t[1], t[2], t[3]]);
        let (reduced, borrow) = value.sbb(self.m);
        if t[4] == 0 && borrow == 1 {
            value
        } else {
            reduced
        }
    }

    // `self` is the modulus context, not the value being converted.
    #[allow(clippy::wrong_self_convention)]
    fn to_mont(&self, value: U256) -> U256 {
        self.mont_mul(value, self.r2)
    }

    #[allow(clippy::wrong_self_convention)]
    fn from_mont(&self, value: U256) -> U256 {
        self.mont_mul(value, U256::one())
    }

    fn add(&self, a: U256, b: U256) -> U256 {
        let (sum, carry) = a.adc(b);
        let (reduced, borrow) = sum.sbb(self.m);
        if carry == 1 || borrow == 0 {
            reduced
        } else {
            sum
        }
    }

    fn sub(&self, a: U256, b: U256) -> U256 {
        let (diff, borrow) = a.sbb(b);
        if borrow == 1 {
            let (wrapped, _) = diff.adc(self.m);
            wrapped
        } else {
            diff
        }
    }

    fn neg(&self, a: U256) -> U256 {
        if a.is_zero() {
            a
        } else {
            let (diff, _) = self.m.sbb(a);
            diff
        }
    }

    fn sqr(&self, a: U256) -> U256 {
        self.mont_mul(a, a)
    }

    fn mont_pow(&self, base: U256, exponent: U256) -> U256 {
        let mut result = self.one;
        for bit in (0..256).rev() {
            result = self.sqr(result);
            let multiplied = self.mont_mul(result, base);
            result = U256::select(multiplied, result, exponent.bit(bit));
        }
        result
    }

    fn mont_inv(&self, a: U256) -> U256 {
        let (exponent, _) = self.m.sbb(U256([2, 0, 0, 0]));
        self.mont_pow(a, exponent)
    }

    fn reduce_once(&self, value: U256) -> U256 {
        let (reduced, borrow) = value.sbb(self.m);
        if borrow == 1 { value } else { reduced }
    }
}

const fn hex32(text: &str) -> U256 {
    let bytes = text.as_bytes();
    assert!(bytes.len() == 64, "curve parameter must be 64 hex digits");
    let mut limbs = [0u64; 4];
    let mut index = 0;
    while index < 64 {
        let digit = match bytes[index] {
            b'0'..=b'9' => bytes[index] - b'0',
            b'a'..=b'f' => bytes[index] - b'a' + 10,
            b'A'..=b'F' => bytes[index] - b'A' + 10,
            _ => panic!("curve parameter must be hexadecimal"),
        } as u64;
        let limb = 3 - index / 16;
        limbs[limb] = (limbs[limb] << 4) | digit;
        index += 1;
    }
    U256(limbs)
}

fn p256_p() -> U256 {
    hex32("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff")
}

fn p256_n() -> U256 {
    hex32("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551")
}

fn p256_b() -> U256 {
    hex32("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b")
}

fn p256_gx() -> U256 {
    hex32("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296")
}

fn p256_gy() -> U256 {
    hex32("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")
}

struct Curve {
    field: Modulus,
    scalar: Modulus,
    b: U256,
    generator: JacobianPoint,
    sqrt_exponent: U256,
    half_p: U256,
}

fn curve() -> &'static Curve {
    use std::sync::OnceLock;
    static CURVE: OnceLock<Curve> = OnceLock::new();
    CURVE.get_or_init(|| {
        let field = Modulus::new(p256_p());
        let scalar = Modulus::new(p256_n());
        let b = field.to_mont(p256_b());
        let generator = JacobianPoint {
            x: field.to_mont(p256_gx()),
            y: field.to_mont(p256_gy()),
            z: field.one,
        };
        let (plus_one, _) = p256_p().adc(U256::one());
        let sqrt_exponent = shift_right(plus_one, 2);
        let (minus_one, _) = p256_p().sbb(U256::one());
        let half_p = shift_right(minus_one, 1);
        Curve {
            field,
            scalar,
            b,
            generator,
            sqrt_exponent,
            half_p,
        }
    })
}

// The limb shift reads `value.0[index]` and `value.0[index + 1]` in one pass.
#[allow(clippy::needless_range_loop)]
fn shift_right(value: U256, bits: u32) -> U256 {
    let mut out = [0u64; 4];
    for index in 0..4 {
        let low = value.0[index] >> bits;
        let high = if index == 3 {
            0
        } else {
            value.0[index + 1] << (64 - bits)
        };
        out[index] = low | high;
    }
    U256(out)
}

#[derive(Clone, Copy)]
struct JacobianPoint {
    x: U256,
    y: U256,
    z: U256,
}

impl JacobianPoint {
    fn infinity() -> Self {
        Self {
            x: U256::one(),
            y: U256::one(),
            z: U256::ZERO,
        }
    }

    fn is_infinity(&self) -> bool {
        self.z.is_zero()
    }

    fn double(&self) -> Self {
        let f = &curve().field;
        if self.is_infinity() {
            return *self;
        }
        let delta = f.sqr(self.z);
        let gamma = f.sqr(self.y);
        let beta = f.mont_mul(self.x, gamma);
        let x_minus = f.sub(self.x, delta);
        let x_plus = f.add(self.x, delta);
        let product = f.mont_mul(x_minus, x_plus);
        let alpha = f.add(f.add(product, product), product);
        let alpha_squared = f.sqr(alpha);
        let beta2 = f.add(beta, beta);
        let beta4 = f.add(beta2, beta2);
        let beta8 = f.add(beta4, beta4);
        let x3 = f.sub(alpha_squared, beta8);
        let y_plus_z = f.add(self.y, self.z);
        let z3 = f.sub(f.sub(f.sqr(y_plus_z), gamma), delta);
        let gamma_squared = f.sqr(gamma);
        let gamma8 = {
            let two = f.add(gamma_squared, gamma_squared);
            let four = f.add(two, two);
            f.add(four, four)
        };
        let y3 = f.sub(f.mont_mul(alpha, f.sub(beta4, x3)), gamma8);
        Self {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    fn add(&self, other: &Self) -> Self {
        let f = &curve().field;
        if self.is_infinity() {
            return *other;
        }
        if other.is_infinity() {
            return *self;
        }
        let z1z1 = f.sqr(self.z);
        let z2z2 = f.sqr(other.z);
        let u1 = f.mont_mul(self.x, z2z2);
        let u2 = f.mont_mul(other.x, z1z1);
        let s1 = f.mont_mul(self.y, f.mont_mul(other.z, z2z2));
        let s2 = f.mont_mul(other.y, f.mont_mul(self.z, z1z1));
        let h = f.sub(u2, u1);
        let r = f.sub(s2, s1);
        if h.is_zero() {
            if r.is_zero() {
                return self.double();
            }
            return Self::infinity();
        }
        let r2 = f.add(r, r);
        let h2 = f.add(h, h);
        let i = f.sqr(h2);
        let j = f.mont_mul(h, i);
        let v = f.mont_mul(u1, i);
        let x3 = f.sub(f.sub(f.sqr(r2), j), f.add(v, v));
        let s1j = f.mont_mul(s1, j);
        let y3 = f.sub(f.mont_mul(r2, f.sub(v, x3)), f.add(s1j, s1j));
        let z_sum = f.add(self.z, other.z);
        let z3 = f.mont_mul(f.sub(f.sub(f.sqr(z_sum), z1z1), z2z2), h);
        Self {
            x: x3,
            y: y3,
            z: z3,
        }
    }

    fn to_affine(self) -> Option<(U256, U256)> {
        if self.is_infinity() {
            return None;
        }
        let f = &curve().field;
        let z_inv = f.mont_inv(self.z);
        let z_inv2 = f.sqr(z_inv);
        let z_inv3 = f.mont_mul(z_inv2, z_inv);
        Some((f.mont_mul(self.x, z_inv2), f.mont_mul(self.y, z_inv3)))
    }
}

fn scalar_mul(point: &JacobianPoint, scalar: U256) -> JacobianPoint {
    let mut accumulator = JacobianPoint::infinity();
    for bit in (0..256).rev() {
        accumulator = accumulator.double();
        let advanced = accumulator.add(point);
        let take = scalar.bit(bit);
        accumulator = JacobianPoint {
            x: U256::select(advanced.x, accumulator.x, take),
            y: U256::select(advanced.y, accumulator.y, take),
            z: U256::select(advanced.z, accumulator.z, take),
        };
    }
    accumulator
}

fn scalar_mul_sum(a: U256, point: &JacobianPoint, b: U256) -> JacobianPoint {
    let generator = curve().generator;
    let mut accumulator = JacobianPoint::infinity();
    for bit in (0..256).rev() {
        accumulator = accumulator.double();
        if a.bit(bit) == 1 {
            accumulator = accumulator.add(&generator);
        }
        if b.bit(bit) == 1 {
            accumulator = accumulator.add(point);
        }
    }
    accumulator
}

fn is_on_curve(x: U256, y: U256) -> bool {
    let c = curve();
    let f = &c.field;
    let three_x = {
        let two = f.add(x, x);
        f.add(two, x)
    };
    let rhs = f.add(f.sub(f.mont_mul(f.sqr(x), x), three_x), c.b);
    f.sqr(y) == rhs
}

pub fn hmac_sha256_parts(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut block = [0u8; SHA256_BLOCK_BYTES];
    if key.len() > SHA256_BLOCK_BYTES {
        block[..32].copy_from_slice(&sha256(key));
    } else {
        block[..key.len()].copy_from_slice(key);
    }

    let mut inner = Vec::with_capacity(SHA256_BLOCK_BYTES);
    let mut outer = Vec::with_capacity(SHA256_BLOCK_BYTES + 32);
    inner.extend(block.iter().map(|byte| byte ^ 0x36));
    outer.extend(block.iter().map(|byte| byte ^ 0x5c));
    for part in parts {
        inner.extend_from_slice(part);
    }
    outer.extend_from_slice(&sha256(&inner));
    sha256(&outer)
}

pub fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    hmac_sha256_parts(key, &[message])
}

#[derive(Clone, Copy)]
pub struct P256PrivateKey {
    scalar: U256,
    public_x: U256,
    public_y: U256,
}

impl core::fmt::Debug for P256PrivateKey {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("P256PrivateKey")
            .field("public_x", &hex(&self.public_x_bytes()))
            .finish_non_exhaustive()
    }
}

impl P256PrivateKey {
    pub fn derive(seed: &[u8], domain: &[u8]) -> Self {
        let c = curve();
        let mut counter: u32 = 0;
        let scalar = loop {
            let candidate =
                U256::from_be_bytes(&hmac_sha256_parts(seed, &[domain, &counter.to_be_bytes()]));
            counter = counter.wrapping_add(1);
            if !candidate.is_zero() && !candidate.ge(c.scalar.m) {
                break candidate;
            }
        };

        let point = scalar_mul(&c.generator, scalar);
        let (x, y) = point
            .to_affine()
            .expect("a non-zero scalar below the group order never yields infinity");

        if c.field.from_mont(y).ge(c.half_p) && c.field.from_mont(y) != c.half_p {
            let negated = c.scalar.sub(c.scalar.m, scalar);
            return Self {
                scalar: negated,
                public_x: x,
                public_y: c.field.neg(y),
            };
        }

        Self {
            scalar,
            public_x: x,
            public_y: y,
        }
    }

    pub fn public_x_bytes(&self) -> [u8; P256_ELEMENT_BYTES] {
        curve().field.from_mont(self.public_x).to_be_bytes()
    }

    pub fn public_uncompressed(&self) -> [u8; P256_UNCOMPRESSED_BYTES] {
        let field = &curve().field;
        let mut out = [0u8; P256_UNCOMPRESSED_BYTES];
        out[0] = SEC1_UNCOMPRESSED_TAG;
        out[1..1 + P256_ELEMENT_BYTES]
            .copy_from_slice(&field.from_mont(self.public_x).to_be_bytes());
        out[1 + P256_ELEMENT_BYTES..]
            .copy_from_slice(&field.from_mont(self.public_y).to_be_bytes());
        out
    }

    pub fn sign_digest(&self, digest: &[u8; 32]) -> [u8; P256_SIGNATURE_BYTES] {
        let c = curve();
        let e = c.scalar.reduce_once(U256::from_be_bytes(digest));
        let mut nonces = Rfc6979Nonces::new(&self.scalar.to_be_bytes(), digest);
        loop {
            let k = nonces.next_candidate();
            if k.is_zero() {
                continue;
            }
            let point = scalar_mul(&c.generator, k);
            let Some((x, _)) = point.to_affine() else {
                continue;
            };
            let r = c.scalar.reduce_once(c.field.from_mont(x));
            if r.is_zero() {
                continue;
            }
            let k_mont = c.scalar.to_mont(k);
            let k_inv = c.scalar.mont_inv(k_mont);
            let rd = c
                .scalar
                .mont_mul(c.scalar.to_mont(r), c.scalar.to_mont(self.scalar));
            let sum = c.scalar.add(c.scalar.to_mont(e), rd);
            let s = c.scalar.from_mont(c.scalar.mont_mul(k_inv, sum));
            if s.is_zero() {
                continue;
            }
            let mut out = [0u8; P256_SIGNATURE_BYTES];
            out[..P256_ELEMENT_BYTES].copy_from_slice(&r.to_be_bytes());
            out[P256_ELEMENT_BYTES..].copy_from_slice(&s.to_be_bytes());
            return out;
        }
    }

    // Unused under the `#[path]` re-inclusion in `tests/crypto_portable.rs`.
    #[allow(dead_code)]
    pub fn public(&self) -> P256PublicKey {
        P256PublicKey {
            point: JacobianPoint {
                x: self.public_x,
                y: self.public_y,
                z: curve().field.one,
            },
        }
    }
}

#[derive(Clone, Copy)]
pub struct P256PublicKey {
    point: JacobianPoint,
}

impl core::fmt::Debug for P256PublicKey {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("P256PublicKey")
            .field("x", &hex(&self.x_bytes()))
            .finish_non_exhaustive()
    }
}

impl P256PublicKey {
    pub fn x_bytes(&self) -> [u8; P256_ELEMENT_BYTES] {
        let (x, _) = self
            .point
            .to_affine()
            .expect("an imported public point is never infinity");
        curve().field.from_mont(x).to_be_bytes()
    }

    pub fn uncompressed(&self) -> [u8; P256_UNCOMPRESSED_BYTES] {
        let field = &curve().field;
        let (x, y) = self
            .point
            .to_affine()
            .expect("an imported public point is never infinity");
        let mut out = [0u8; P256_UNCOMPRESSED_BYTES];
        out[0] = SEC1_UNCOMPRESSED_TAG;
        out[1..1 + P256_ELEMENT_BYTES].copy_from_slice(&field.from_mont(x).to_be_bytes());
        out[1 + P256_ELEMENT_BYTES..].copy_from_slice(&field.from_mont(y).to_be_bytes());
        out
    }
}

pub fn import_public(bytes: &[u8]) -> Option<P256PublicKey> {
    let point = match bytes.len() {
        P256_ELEMENT_BYTES => {
            let mut x = [0u8; P256_ELEMENT_BYTES];
            x.copy_from_slice(bytes);
            import_compact(&x)?
        }
        P256_UNCOMPRESSED_BYTES => {
            let mut encoded = [0u8; P256_UNCOMPRESSED_BYTES];
            encoded.copy_from_slice(bytes);
            import_uncompressed(&encoded)?
        }
        _ => return None,
    };
    Some(P256PublicKey { point })
}

pub fn hkdf_sha256(salt: &[u8], ikm: &[u8], info: &[u8], out: &mut [u8]) {
    let prk = hmac_sha256(salt, ikm);
    let mut previous: [u8; 32] = [0u8; 32];
    let mut produced = 0usize;
    let mut counter: u8 = 1;
    while produced < out.len() {
        let block = if counter == 1 {
            hmac_sha256_parts(&prk, &[info, &[counter]])
        } else {
            hmac_sha256_parts(&prk, &[&previous, info, &[counter]])
        };
        let take = core::cmp::min(block.len(), out.len() - produced);
        out[produced..produced + take].copy_from_slice(&block[..take]);
        previous = block;
        produced += take;
        counter = counter.wrapping_add(1);
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
        out.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap_or('0'));
    }
    out
}

struct Rfc6979Nonces {
    k: [u8; 32],
    v: [u8; 32],
    started: bool,
}

impl Rfc6979Nonces {
    fn new(private_key: &[u8; 32], digest: &[u8; 32]) -> Self {
        let scalar = &curve().scalar;
        let reduced = scalar
            .reduce_once(U256::from_be_bytes(digest))
            .to_be_bytes();

        let mut v = [0x01u8; 32];
        let mut k = [0x00u8; 32];
        k = hmac_sha256_parts(&k, &[&v, &[0x00], private_key, &reduced]);
        v = hmac_sha256(&k, &v);
        k = hmac_sha256_parts(&k, &[&v, &[0x01], private_key, &reduced]);
        v = hmac_sha256(&k, &v);
        Self {
            k,
            v,
            started: false,
        }
    }

    fn next_candidate(&mut self) -> U256 {
        let scalar = &curve().scalar;
        loop {
            if self.started {
                self.k = hmac_sha256_parts(&self.k, &[&self.v, &[0x00]]);
                self.v = hmac_sha256(&self.k, &self.v);
            }
            self.started = true;
            self.v = hmac_sha256(&self.k, &self.v);
            let candidate = U256::from_be_bytes(&self.v);
            if !candidate.is_zero() && !candidate.ge(scalar.m) {
                return candidate;
            }
        }
    }
}

fn import_compact(x_bytes: &[u8; P256_ELEMENT_BYTES]) -> Option<JacobianPoint> {
    let c = curve();
    let f = &c.field;
    let x_raw = U256::from_be_bytes(x_bytes);
    if x_raw.ge(f.m) {
        return None;
    }
    let x = f.to_mont(x_raw);
    let three_x = {
        let two = f.add(x, x);
        f.add(two, x)
    };
    let rhs = f.add(f.sub(f.mont_mul(f.sqr(x), x), three_x), c.b);
    let root = f.mont_pow(rhs, c.sqrt_exponent);
    if f.sqr(root) != rhs {
        return None;
    }
    let ordinary = f.from_mont(root);
    let y = if ordinary.ge(c.half_p) && ordinary != c.half_p {
        f.neg(root)
    } else {
        root
    };
    Some(JacobianPoint { x, y, z: f.one })
}

fn import_uncompressed(bytes: &[u8; P256_UNCOMPRESSED_BYTES]) -> Option<JacobianPoint> {
    if bytes[0] != SEC1_UNCOMPRESSED_TAG {
        return None;
    }
    let f = &curve().field;
    let mut coordinate = [0u8; P256_ELEMENT_BYTES];
    coordinate.copy_from_slice(&bytes[1..1 + P256_ELEMENT_BYTES]);
    let x_raw = U256::from_be_bytes(&coordinate);
    coordinate.copy_from_slice(&bytes[1 + P256_ELEMENT_BYTES..]);
    let y_raw = U256::from_be_bytes(&coordinate);
    if x_raw.ge(f.m) || y_raw.ge(f.m) {
        return None;
    }
    let x = f.to_mont(x_raw);
    let y = f.to_mont(y_raw);
    if !is_on_curve(x, y) {
        return None;
    }
    Some(JacobianPoint { x, y, z: f.one })
}

pub fn verify_compact(
    public_x: &[u8; P256_ELEMENT_BYTES],
    digest: &[u8; 32],
    signature: &[u8; P256_SIGNATURE_BYTES],
) -> bool {
    match import_compact(public_x) {
        Some(point) => verify_point(&point, digest, signature),
        None => false,
    }
}

pub fn verify_uncompressed(
    public_key: &[u8; P256_UNCOMPRESSED_BYTES],
    digest: &[u8; 32],
    signature: &[u8; P256_SIGNATURE_BYTES],
) -> bool {
    match import_uncompressed(public_key) {
        Some(point) => verify_point(&point, digest, signature),
        None => false,
    }
}

fn verify_point(
    point: &JacobianPoint,
    digest: &[u8; 32],
    signature: &[u8; P256_SIGNATURE_BYTES],
) -> bool {
    let c = curve();
    let mut half = [0u8; P256_ELEMENT_BYTES];
    half.copy_from_slice(&signature[..P256_ELEMENT_BYTES]);
    let r = U256::from_be_bytes(&half);
    half.copy_from_slice(&signature[P256_ELEMENT_BYTES..]);
    let s = U256::from_be_bytes(&half);
    if r.is_zero() || s.is_zero() || r.ge(c.scalar.m) || s.ge(c.scalar.m) {
        return false;
    }

    let e = c.scalar.reduce_once(U256::from_be_bytes(digest));
    let s_inv = c.scalar.mont_inv(c.scalar.to_mont(s));
    let u1 = c
        .scalar
        .from_mont(c.scalar.mont_mul(c.scalar.to_mont(e), s_inv));
    let u2 = c
        .scalar
        .from_mont(c.scalar.mont_mul(c.scalar.to_mont(r), s_inv));

    let combined = scalar_mul_sum(u1, point, u2);
    let Some((x, _)) = combined.to_affine() else {
        return false;
    };
    c.scalar.reduce_once(c.field.from_mont(x)) == r
}

pub fn signature_to_der(signature: &[u8; P256_SIGNATURE_BYTES]) -> Vec<u8> {
    let mut body = Vec::with_capacity(2 * (P256_ELEMENT_BYTES + 3));
    for half in signature.chunks(P256_ELEMENT_BYTES) {
        let trimmed = half
            .iter()
            .position(|byte| *byte != 0)
            .map_or(&half[half.len() - 1..], |start| &half[start..]);
        body.push(0x02);
        if trimmed[0] & 0x80 != 0 {
            body.push((trimmed.len() + 1) as u8);
            body.push(0x00);
        } else {
            body.push(trimmed.len() as u8);
        }
        body.extend_from_slice(trimmed);
    }
    let mut out = Vec::with_capacity(body.len() + 2);
    out.push(0x30);
    out.push(body.len() as u8);
    out.extend_from_slice(&body);
    out
}
