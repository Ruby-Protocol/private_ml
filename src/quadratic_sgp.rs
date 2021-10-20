use miracl_core::bls12381::pair;
use num_bigint::{BigInt};

use crate::define::{BigNum, G1, G2, Gt, G1Vector, G2Vector, CURVE_ORDER, MODULUS};
use crate::math::matrix::{BigNumMatrix, BigIntMatrix, BigNumMatrix2x2, convert};
use crate::utils::{reduce, baby_step_giant_step};
use crate::utils::rand_utils::{RandUtilsRand, Sample};
use crate::traits::FunctionalEncryption;


/// Functional encryption scheme for quadratic polynomials. Implements the following work:
///
/// Reading in the Dark: Classifying Encrypted Digits with Functional Encryption.
///
/// Link: https://eprint.iacr.org/2018/206.pdf
///
/// # Examples
/// 
/// ```
/// use ruby::quadratic_sgp::Sgp; 
/// use ruby::traits::FunctionalEncryption;
/// const L: usize = 2;
/// let sgp = Sgp::<L>::new();
/// ```
#[derive(Debug)]
pub struct Sgp<const L: usize> {
    msk: SgpSecKey,
    pk: SgpPubKey
}

/// Master secret key
#[derive(Debug)]
pub struct SgpSecKey {
    s: Vec<BigNum>, 
    t: Vec<BigNum>,
}

/// Master public key
#[derive(Debug)]
pub struct SgpPubKey {
    g1s: G1Vector,
    g2t: G2Vector,
}

pub struct SgpPlain<const L: usize> {
    pub x: [BigInt; L],
    pub y: [BigInt; L]
}

/// Ciphertext
#[derive(Debug)]
pub struct SgpCipher<const L: usize> {
    g1_mul_gamma: G1,
    a: G1Vector,
    b: G2Vector,
}

/// Functional evaluation key
#[derive(Debug)]
pub struct SgpDecKey {
    key: G2,
    f: BigNumMatrix,
}

impl<const L: usize> FunctionalEncryption for Sgp<L> {
    type CipherText = SgpCipher<L>;
    type PlainData = SgpPlain<L>;
    type FEKeyData = BigIntMatrix;
    type EvaluationKey = SgpDecKey;

    /// Constructs a new `Sgp`. 
    ///
    /// # Examples
    /// 
    /// ```
    /// use ruby::quadratic_sgp::Sgp; 
    /// use ruby::traits::FunctionalEncryption;
    /// const L: usize = 2;
    /// let sgp = Sgp::<L>::new();
    /// ```
    fn new() -> Sgp<L> {
        let (msk, pk) = Sgp::<L>::generate_sec_key();
        Sgp {
            msk,
            pk
        }
    }

    /// Encrypt two vectors of numbers, resulting in a single ciphertext.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// let mut x: Vec<BigInt> = Vec::with_capacity(2);
    /// let mut y: Vec<BigInt> = Vec::with_capacity(2);
    /// for i in 0..2 {
    ///     x.push(BigInt::from(i));
    ///     y.push(BigInt::from(i+1));
    /// }
    /// let cipher = sgp.encrypt(&x, &y);
    /// ```
    fn encrypt(&self, plain: &Self::PlainData) -> Self::CipherText {
        let (x, y) = (&plain.x, &plain.y);
        if x.len() != L ||  y.len() != L {
            panic!("Malformed input: x.len ({}), y.len ({}), expected len ({})", x.len(), y.len(), L);
        }

        let mut rng = RandUtilsRand::new();

        let w = BigNumMatrix2x2::new_random(&(CURVE_ORDER));
        let mut w_inv = w.invmod(&(CURVE_ORDER));
        w_inv.transpose();

        let gamma = rng.sample(&(CURVE_ORDER));
        let mut g1_mul_gamma = G1::generator();
        g1_mul_gamma = g1_mul_gamma.mul(&gamma);

        let mut a: G1Vector = vec![G1::generator(); L * 2];
        let mut b: G2Vector = vec![G2::generator(); L * 2];

        for i in 0..L {

            let xi = reduce(&x[i], &MODULUS);
            let xi = BigNum::fromstring(xi.to_str_radix(16));

            let yi = reduce(&y[i], &MODULUS);
            let yi = BigNum::fromstring(yi.to_str_radix(16));

            let w00_mul_xi = BigNum::modmul(w_inv.get_element(0, 0), &xi, &CURVE_ORDER);
            let w01_mul_gamma = BigNum::modmul(w_inv.get_element(0, 1), &gamma, &CURVE_ORDER);
            let w10_mul_xi = BigNum::modmul(w_inv.get_element(1, 0), &xi, &CURVE_ORDER);
            let w11_mul_gamma = BigNum::modmul(w_inv.get_element(1, 1), &gamma, &CURVE_ORDER);

            a[i*2] = a[i*2].mul(&w00_mul_xi);
            a[i*2].add(&(self.pk.g1s[i].mul(&w01_mul_gamma)));

            a[i*2+1] = a[i*2+1].mul(&w10_mul_xi);
            a[i*2+1].add(&(self.pk.g1s[i].mul(&w11_mul_gamma)));


            let w00_mul_yi = BigNum::modmul(w.get_element(0, 0), &yi, &CURVE_ORDER);
            let w01_neg = BigNum::modneg(w.get_element(0, 1), &CURVE_ORDER);
            let w10_mul_yi = BigNum::modmul(w.get_element(1, 0), &yi, &CURVE_ORDER);
            let w11_neg = BigNum::modneg(w.get_element(1, 1), &CURVE_ORDER);

            b[i*2] = b[i*2].mul(&w00_mul_yi);
            b[i*2].add(&(self.pk.g2t[i].mul(&w01_neg)));

            b[i*2+1] = b[i*2+1].mul(&w10_mul_yi);
            b[i*2+1].add(&(self.pk.g2t[i].mul(&w11_neg)));
        }
        SgpCipher {
            g1_mul_gamma,
            a,
            b,
        }
    }

    /// Derive functional evaluation key for a matrix of numbers.
    ///
    /// # Examples
    /// ```ignore
    /// // Following the example of `encrypt`
    /// let a: [i64; 4] = [1; 4];
    /// let f = BigIntMatrix::new_ints(&a[..], 2, 2);
    /// let dk = sgp.derive_fe_key(&f);
    /// ```
    fn derive_fe_key(&self, f: &Self::FEKeyData) -> Self::EvaluationKey {
        let new_f = convert(f, &MODULUS);
        let new_s = BigNumMatrix::new_bigints(&self.msk.s, 1, self.msk.s.len(), &CURVE_ORDER);
        let new_t = BigNumMatrix::new_bigints(&self.msk.t, self.msk.t.len(), 1, &CURVE_ORDER);
        let exp = new_s.matmul(&new_f);
        let exp = exp.matmul(&new_t);
        let exp = exp.get_element(0, 0);
        SgpDecKey {
            key: (G2::generator()).mul(exp),
            f: new_f 
        }
    }


    /// Decrypt a ciphertext with the functional evaluation key. The parameter `bound` is the absolute value bound for
    /// numbers used in the inner product.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// // Following the example of `derive_fe_key`
    /// let result = sgp.decrypt(&cipher, &dk, &BigInt::from(100)); 
    /// ```
    fn decrypt(&self, ct: &Self::CipherText, dk: &Self::EvaluationKey, bound: &BigInt) -> Option<BigInt> {
        if ct.a.len() != dk.f.n_rows * 2 || ct.b.len() != dk.f.n_cols * 2 {
            panic!("Malformed input: a.len ({}), b.len ({}), f dimension ({} x {}).", ct.a.len() / 2, ct.b.len() / 2, dk.f.n_rows, dk.f.n_cols);
        }

        let mut out: Gt = pair::ate(&dk.key, &ct.g1_mul_gamma);
        out = pair::fexp(&out);
        let (mut proj0, mut proj1): (Gt, Gt);
        for i in 0..dk.f.n_rows {
            for j in 0..dk.f.n_cols {
                proj0 = pair::ate(&ct.b[j*2], &ct.a[i*2]);
                proj0 = pair::fexp(&proj0);
                proj1 = pair::ate(&ct.b[j*2 + 1], &ct.a[i*2 + 1]);
                proj1 = pair::fexp(&proj1);
                
                proj0.mul(&proj1);
                proj0 = proj0.pow(dk.f.get_element(i, j));
                out.mul(&proj0);
            }
        }

        let g1 = G1::generator();
        let g2 = G2::generator();
        let pair = pair::ate(&g2, &g1);
        let pair = pair::fexp(&pair);

        //dlog
        let mut result_bound = BigNum::fromstring(bound.to_str_radix(16));
        result_bound = result_bound.powmod(&BigNum::new_int(3), &CURVE_ORDER);
        result_bound = BigNum::modmul(&result_bound, &BigNum::new_int((dk.f.n_rows * dk.f.n_cols) as isize), &CURVE_ORDER);

        baby_step_giant_step(&out, &pair, &result_bound)
    }
}


impl<const L: usize> Sgp<L> {

    /// Generate a pair of master secret key and master public key.
    pub fn generate_sec_key() -> (SgpSecKey, SgpPubKey) {
        let mut rng = RandUtilsRand::new();
        let msk = SgpSecKey {
            s: rng.sample_vec(L, &(CURVE_ORDER)),
            t: rng.sample_vec(L, &(CURVE_ORDER)),
        };
        let mut pk = SgpPubKey {
            g1s: vec![G1::generator(); L],
            g2t: vec![G2::generator(); L],
        };
        for i in 0..L {
            pk.g1s[i] = pk.g1s[i].mul(&(msk.s[i]));
            pk.g2t[i] = pk.g2t[i].mul(&(msk.t[i]));
        }
        (msk, pk)
    }

    /// Project a ciphertext into another ciphertext with a projection matrix.
    /// 
    /// Read the paper for details.
    pub fn project(&self, cipher: &SgpCipher<L>, p: &BigIntMatrix) -> SgpCipher<L> {
        if L != p.n_rows {
            panic!("Malformed input: self.n ({}), cipher.n ({}), P.dim ({} x {})", L, L, p.n_rows, p.n_cols);
        }
        let new_p = convert(p, &MODULUS);
        let d = p.n_cols;
        let mut new_a: G1Vector = vec![G1::generator(); d * 2];
        let mut new_b: G2Vector = vec![G2::generator(); d * 2];
        for i in 0..d {
            new_a[i * 2].inf(); 
            new_a[i * 2 + 1].inf();
            new_b[i * 2].inf();
            new_b[i * 2 + 1].inf();
            for j in 0..L {
                let tmp1 = cipher.a[j * 2].mul(new_p.get_element(j, i));
                let tmp2 = cipher.a[j * 2 + 1].mul(new_p.get_element(j, i));
                new_a[i * 2].add(&tmp1);
                new_a[i * 2 + 1].add(&tmp2);

                let tmp1 = cipher.b[j * 2].mul(new_p.get_element(j, i));
                let tmp2 = cipher.b[j * 2 + 1].mul(new_p.get_element(j, i));
                new_b[i * 2].add(&tmp1);
                new_b[i * 2 + 1].add(&tmp2);
            }
        }

        SgpCipher {
            g1_mul_gamma: cipher.g1_mul_gamma.clone(),
            a: new_a,
            b: new_b,
        }
    }

    /// Derive functional evaluation key for a matrix of numbers, with a projection matrix.
    ///
    /// Read the paper for details.
    pub fn derive_fe_key_projected(&self, f: &BigIntMatrix, p: &BigIntMatrix) -> SgpDecKey {
        if L != p.n_rows || f.n_rows != f.n_cols || f.n_rows != p.n_cols {
            panic!("Malformed input: f.dim ({} x {}), P.dim ({} x {})", f.n_rows, f.n_cols, p.n_rows, p.n_cols);
        }
        let new_f = convert(f, &MODULUS);
        let new_p = convert(p, &MODULUS);
        let new_s = BigNumMatrix::new_bigints(&self.msk.s, 1, self.msk.s.len(), &CURVE_ORDER);
        let new_t = BigNumMatrix::new_bigints(&self.msk.t, 1, self.msk.t.len(), &CURVE_ORDER);
        let proj_s = new_s.matmul(&new_p);
        let proj_t = new_t.matmul(&new_p).transpose();

        let exp = proj_s.matmul(&new_f);
        let exp = exp.matmul(&proj_t);
        let exp = exp.get_element(0, 0);
        SgpDecKey {
            key: (G2::generator()).mul(exp),
            f: new_f 
        }
    }

}

