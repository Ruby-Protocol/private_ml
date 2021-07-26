pub mod rand_utils;

use miracl_core::rand::{RAND, RAND_impl};
use miracl_core::hash256::HASH256;
use num_bigint::{BigInt, Sign};
use std::collections::HashMap;
use num_traits::Num;
use crate::rand::RngCore;
use miracl_core::bls12381::pair;

use crate::define::{BigNum, G1, G2, GT, CURVE_ORDER, MODULUS};

//pub fn get_rng() -> impl RAND {
    //let mut seed: [u8; 100] = [0; 100];
    //rand::thread_rng().fill_bytes(&mut seed);
    //return get_seeded_rng(&seed);
//}

//pub fn get_seeded_rng(seed: &[u8]) -> impl RAND {
    //let mut rng = RAND_impl::new();
    //rng.clean();
    //rng.seed(seed.len(), seed);
    //rng
//}

//pub fn uniform_sample(modulus: &BigNum, rng: &mut impl RAND) -> BigNum {
    //BigNum::randomnum(modulus, rng)
//}

//pub fn uniform_sample_vec(len: usize, modulus: &BigNum, rng: &mut impl RAND) -> Vec<BigNum> {
    //let mut v: Vec<BigNum> = Vec::with_capacity(len);
    //for _i in 0..len {
        //v.push(uniform_sample(modulus, rng));
    //}
    //v 
//}

pub fn hash_to_g1(data: &str) -> G1 {
    let mut hash256 = HASH256::new();
    hash256.process_array(data.as_bytes());
    let digest = hash256.hash();
    G1::mapit(&digest)
}

pub fn hash_to_g2(data: &str) -> G2 {
    let mut hash256 = HASH256::new();
    hash256.process_array(data.as_bytes());
    let digest = hash256.hash();
    G2::mapit(&digest)
}

pub fn reduce(x: &BigInt, m: &BigInt) -> BigInt {
    let mut y = x % m;
    if (y.sign() == Sign::Minus) {
        y = y + m;
    }
    y
}


use std::ops::Add;
pub fn baby_step_giant_step(h: &GT, g: &GT, bound: &BigNum) -> Option<BigInt> {
    let mut table = HashMap::new();
    let mut pow_zero = GT::new();
    pow_zero.one();
    if pow_zero.equals(&h) {
        return Some(BigInt::from(0));
    }

    let b = BigInt::from_str_radix(&bound.tostring(), 16).unwrap();
    let b_sqrt = b.sqrt();
    let temp: BigInt = b_sqrt.add(1);
    let m = BigNum::fromstring(temp.to_str_radix(16));

    // precompute the table
    let (mut x, mut z) = (GT::new(), GT::new_copy(&g));
    let mut i = BigNum::new_int(0);
    x.one();
    x.reduce();
    while BigNum::comp(&i, &m) <= 0 {
        table.insert(x.tostring(), i);
        x.mul(&g);
        x.reduce();
        i.inc(1);
    }

    // search for solution
    z.inverse();
    z = z.pow(&m);
    x = GT::new_copy(&h);
    let mut x_neg = GT::new_copy(&h);
    x_neg.inverse();
    i.zero();
    while BigNum::comp(&i, &m) <= 0 {
        // positive solution
        match table.get(&x.tostring()) {
            Some(value) => {
                let mut temp = BigNum::modmul(&i, &m, &CURVE_ORDER);
                temp = BigNum::modadd(&value, &temp, &CURVE_ORDER);
                let temp = BigInt::from_str_radix(&temp.tostring(), 16).unwrap();
                return Some(temp);
            }
            None => {
                x.mul(&z);
                x.reduce();
            }
        }
        // negative solution
        match table.get(&x_neg.tostring()) {
            Some(value) => {
                let mut temp = BigNum::modmul(&i, &m, &CURVE_ORDER);
                temp = BigNum::modadd(&value, &temp, &CURVE_ORDER);
                temp = BigNum::modneg(&temp, &CURVE_ORDER);
                let temp = BigInt::from_str_radix(&temp.tostring(), 16).unwrap() - (&*MODULUS);
                return Some(temp);
            }
            None => {
                x_neg.mul(&z);
                x_neg.reduce();
            }
        }
        i.inc(1);
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_baby_step_giant_step() {
        let g1 = G1::generator();
        let g2 = G2::generator();

        let mut g = pair::ate(&g2, &g1);
        g = pair::fexp(&g);

        let bound = BigNum::new_int(10024);
        let x = BigNum::new_int(1335);

        let h = g.pow(&x);
        if let Some(res) = baby_step_giant_step(&h, &g, &bound) {
            println!("res={}", res);
        }
        println!("g={}", g.tostring());
        println!("x={}", x.tostring());
    }

    #[test]
    fn test_bigint_bignum_conversion() {
        let a = BigNum::new_int(25500);
        println!("{:?} => {}", a, a.tostring());
        let a = BigInt::from_str_radix(&a.tostring(), 16);
        let aa = BigInt::from(25500);
        println!("{:?} => {:?}", a, aa);

        let b = BigInt::from(15500);
        println!("{:?} => {}", b, b.to_str_radix(16));
        let b = BigNum::fromstring(b.to_str_radix(16));
        let bb = BigNum::new_int(15500);
        println!("{:?} => {:?}", b, bb);
    }

}
