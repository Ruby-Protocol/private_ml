use miracl_core::bls12381::pair;
/* use  miracl_core::bn254::big;
use miracl_core::bn254::big::BIG;
use miracl_core::bn254::ecp;
use miracl_core::bn254::ecp::ECP;
use miracl_core::bn254::ecp2::ECP2;
use miracl_core::bn254::fp12::FP12;
use miracl_core::bn254::pair;
use miracl_core::bn254::rom; */
use num_bigint::{BigInt};

use crate::define::{BigNum, G1, G2, GT, G1Vector, G2Vector, CURVE_ORDER, MODULUS};

use crate::math::matrix::{BigNumMatrix, BigIntMatrix, BigNumMatrix2x2, convert};
use crate::utils::{reduce, baby_step_giant_step};
use crate::utils::rand_utils::{RandUtilsRAND, Sample};


#[derive(Debug)]
pub struct Sgp {
    n: usize,
    msk: SgpSecKey,
    pk: SgpPubKey
}

#[derive(Debug)]
pub struct SgpSecKey {
    s: Vec<BigNum>, 
    t: Vec<BigNum>,
}

#[derive(Debug)]
pub struct SgpPubKey {
    g1s: G1Vector,
    g2t: G2Vector,
}

#[derive(Debug)]
pub struct SgpCipher {
    g1_mul_gamma: G1,
    a: G1Vector,
    b: G2Vector,
    n: usize,
}

#[derive(Debug)]
pub struct SgpDecKey {
    key: G2,
    f: BigNumMatrix,
}



impl Sgp {
    pub fn new(n: usize) -> Sgp {
        let (msk, pk) = Sgp::generate_sec_key(n);
        Sgp {
            n,
            msk,
            pk
        }
    }

    pub fn generate_sec_key(n: usize) -> (SgpSecKey, SgpPubKey) {
        let mut rng = RandUtilsRAND::new();
        let msk = SgpSecKey {
            s: rng.sample_vec(n, &(CURVE_ORDER)),
            t: rng.sample_vec(n, &(CURVE_ORDER)),
        };
        let mut pk = SgpPubKey {
            g1s: vec![G1::generator(); n],
            g2t: vec![G2::generator(); n],
        };
        for i in 0..n {
            pk.g1s[i] = pk.g1s[i].mul(&(msk.s[i]));
            pk.g2t[i] = pk.g2t[i].mul(&(msk.t[i]));
        }
        (msk, pk)
    }

    pub fn encrypt(&self, x: &[BigInt], y: &[BigInt]) -> SgpCipher {
        if x.len() != self.n ||  y.len() != self.n {
            panic!("Malformed input: x.len ({}), y.len ({}), expected len ({})", x.len(), y.len(), self.n);
        }

        let mut rng = RandUtilsRAND::new();

        let w = BigNumMatrix2x2::new_random(&(CURVE_ORDER));
        let mut w_inv = w.invmod(&(CURVE_ORDER));
        w_inv.transpose();

        let gamma = rng.sample(&(CURVE_ORDER));
        let mut g1_mul_gamma = G1::generator();
        g1_mul_gamma = g1_mul_gamma.mul(&gamma);

        let mut a: G1Vector = vec![G1::generator(); self.n * 2];
        let mut b: G2Vector = vec![G2::generator(); self.n * 2];

        for i in 0..self.n {

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
            n: self.n
        }
    }

    pub fn project(&self, cipher: &SgpCipher, p: &BigIntMatrix) -> SgpCipher {
        if self.n != p.n_rows || self.n != cipher.n {
            panic!("Malformed input: self.n ({}), cipher.n ({}), P.dim ({} x {})", self.n, cipher.n, p.n_rows, p.n_cols);
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
            for j in 0..self.n {
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
            n: d
        }
    }

    pub fn derive_fe_key(&self, f: &BigIntMatrix) -> SgpDecKey {
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

    pub fn derive_fe_key_projected(&self, f: &BigIntMatrix, p: &BigIntMatrix) -> SgpDecKey {
        if self.n != p.n_rows || f.n_rows != f.n_cols || f.n_rows != p.n_cols {
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


    pub fn decrypt(&self, ct: &SgpCipher, dk: &SgpDecKey, bound: &BigInt) -> Option<BigInt> {
        if ct.a.len() != dk.f.n_rows * 2 || ct.b.len() != dk.f.n_cols * 2 {
            panic!("Malformed input: a.len ({}), b.len ({}), f dimension ({} x {}).", ct.a.len() / 2, ct.b.len() / 2, dk.f.n_rows, dk.f.n_cols);
        }

        let mut out: GT = pair::ate(&dk.key, &ct.g1_mul_gamma);
        out = pair::fexp(&out);
        let (mut proj0, mut proj1): (GT, GT);
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

