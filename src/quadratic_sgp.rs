use miracl_core::bls12381::pair;
/* use  miracl_core::bn254::big;
use miracl_core::bn254::big::BIG;
use miracl_core::bn254::ecp;
use miracl_core::bn254::ecp::ECP;
use miracl_core::bn254::ecp2::ECP2;
use miracl_core::bn254::fp12::FP12;
use miracl_core::bn254::pair;
use miracl_core::bn254::rom; */
use std::ops::Rem;
use num_traits::Zero;
use num_bigint::{BigInt, ToBigInt, RandBigInt, Sign};
use crate::rand::Rng;

use crate::define::{BigNum, G1, G2, GT, G1Vector, G2Vector, CURVE_ORDER, MODULUS};

use crate::math::matrix::{BigNumMatrix, BigIntMatrix, BigNumMatrix2x2, convert};
use crate::utils::{reduce, baby_step_giant_step};
use crate::utils::rand_utils::{RandUtilsRAND, RandUtilsRng, Sample};


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

    pub fn project(&self, cipher: &SgpCipher, P: &BigIntMatrix) -> SgpCipher {
        if self.n != P.n_rows || self.n != cipher.n {
            panic!("Malformed input: self.n ({}), cipher.n ({}), P.dim ({} x {})", self.n, cipher.n, P.n_rows, P.n_cols);
        }
        let new_P = convert(P, &MODULUS);
        let d = P.n_cols;
        let mut new_a: G1Vector = vec![G1::generator(); d * 2];
        let mut new_b: G2Vector = vec![G2::generator(); d * 2];
        for i in 0..d {
            new_a[i * 2].inf(); 
            new_a[i * 2 + 1].inf();
            new_b[i * 2].inf();
            new_b[i * 2 + 1].inf();
            for j in 0..self.n {
                let tmp1 = cipher.a[j * 2].mul(new_P.get_element(j, i));
                let tmp2 = cipher.a[j * 2 + 1].mul(new_P.get_element(j, i));
                new_a[i * 2].add(&tmp1);
                new_a[i * 2 + 1].add(&tmp2);

                let tmp1 = cipher.b[j * 2].mul(new_P.get_element(j, i));
                let tmp2 = cipher.b[j * 2 + 1].mul(new_P.get_element(j, i));
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

    pub fn derive_fe_key_projected(&self, f: &BigIntMatrix, P: &BigIntMatrix) -> SgpDecKey {
        if self.n != P.n_rows || f.n_rows != f.n_cols || f.n_rows != P.n_cols {
            panic!("Malformed input: f.dim ({} x {}), P.dim ({} x {})", f.n_rows, f.n_cols, P.n_rows, P.n_cols);
        }
        let new_f = convert(f, &MODULUS);
        let new_P = convert(P, &MODULUS);
        let new_s = BigNumMatrix::new_bigints(&self.msk.s, 1, self.msk.s.len(), &CURVE_ORDER);
        let new_t = BigNumMatrix::new_bigints(&self.msk.t, 1, self.msk.t.len(), &CURVE_ORDER);
        let proj_s = new_s.matmul(&new_P);
        let proj_t = new_t.matmul(&new_P).transpose();

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

#[cfg(test)]
mod tests {
    use super::*;

    fn quadratic_result(x: &[BigInt], y: &[BigInt], f: &BigIntMatrix) -> BigInt {
        if x.len() != f.n_rows ||  y.len() != f.n_cols {
            panic!("Malformed input: x.len ({}), y.len ({}), f dim ({} x {})", x.len(), y.len(), f.n_rows, f.n_cols);
        }
        let mut res = BigInt::zero();
        for i in 0..x.len() {
            for j in 0..y.len() {
                let mut tmp = f.get_element(i, j).clone();
                tmp = tmp * &(x[i]) * &(y[j]);
                res = res + tmp;
            }
        }
        res
    }

    #[test]
    fn test_sgp_1() {
        let sgp = Sgp::new(2);

        let mut x: Vec<BigInt> = Vec::with_capacity(2);
        let mut y: Vec<BigInt> = Vec::with_capacity(2);
        for i in 0..2 {
            x.push(BigInt::from(i));
            y.push(BigInt::from(i+1));
        }

        let a: [i64; 4] = [1; 4];
        let f = BigIntMatrix::new_ints(&a[..], 2, 2);
        let plain_result = quadratic_result(&x, &y, &f);
        println!("Groud truth: {:?}", plain_result);

        let cipher = sgp.encrypt(&x, &y);
        let dk = sgp.derive_fe_key(&f);
        let result = sgp.decrypt(&cipher, &dk, &BigInt::from(100)); 

        assert!(result.is_some());
        assert_eq!(result.unwrap(), plain_result);
    }

    #[test]
    fn test_sgp_2() {
        let mut rng = RandUtilsRng::new(); 
        const n: usize = 10;
        let bound = 64;
        let low = (-bound).to_bigint().unwrap();
        let high = bound.to_bigint().unwrap();

        let sgp = Sgp::new(n);

        let mut x: Vec<BigInt> = rng.sample_range_vec(n, &low, &high); 
        let mut y: Vec<BigInt> = rng.sample_range_vec(n, &low, &high);
        let f = BigIntMatrix::new_random(n, n, &low, &high);
        let plain_result = quadratic_result(&x, &y, &f);
        println!("Groud truth: {:?}", plain_result);

        let cipher = sgp.encrypt(&x, &y);
        let dk = sgp.derive_fe_key(&f);
        let result = sgp.decrypt(&cipher, &dk, &BigInt::from(bound)); 

        assert!(result.is_some());
        assert_eq!(result.unwrap(), plain_result);
    }
}

