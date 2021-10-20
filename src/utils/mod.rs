pub mod rand_utils;

use miracl_core::hash256::HASH256;
use num_bigint::{BigInt, Sign};
use std::collections::HashMap;
use num_traits::Num;
use crate::num_traits::Zero;

use crate::define::{BigNum, G1, G2, Gt, CURVE_ORDER, MODULUS};
use crate::math::matrix::{BigIntMatrix};

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
    if y.sign() == Sign::Minus {
        y += m;
    }
    y
}


use std::ops::Add;
pub fn baby_step_giant_step(h: &Gt, g: &Gt, bound: &BigNum) -> Option<BigInt> {
    let mut table = HashMap::new();
    let mut pow_zero = Gt::new();
    pow_zero.one();
    if pow_zero.equals(&h) {
        return Some(BigInt::from(0));
    }

    let b = BigInt::from_str_radix(&bound.tostring(), 16).unwrap();
    let b_sqrt = b.sqrt();
    let temp: BigInt = b_sqrt.add(1);
    let m = BigNum::fromstring(temp.to_str_radix(16));

    // precompute the table
    let (mut x, mut z) = (Gt::new(), Gt::new_copy(&g));
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
    x = Gt::new_copy(&h);
    let mut x_neg = Gt::new_copy(&h);
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

pub fn baby_step_giant_step_g1(h: &G1, g: &G1, bound: &BigNum) -> Option<BigInt> {
    let mut table = HashMap::new();
    let pow_zero = G1::new();
    if pow_zero.equals(&h) {
        return Some(BigInt::from(0));
    }

    let b = BigInt::from_str_radix(&bound.tostring(), 16).unwrap();
    let b_sqrt = b.sqrt();
    let temp: BigInt = b_sqrt.add(1);
    let m = BigNum::fromstring(temp.to_str_radix(16));

    // precompute the table
    let (mut x, mut z) = (G1::new(), g.clone());
    let mut i = BigNum::new_int(0);
    while BigNum::comp(&i, &m) <= 0 {
        table.insert(x.tostring(), i);
        x.add(&g);
        i.inc(1);
    }

    // search for solution
    z.neg();
    z = z.mul(&m);
    x = h.clone();
    let mut x_neg = h.clone();
    x_neg.neg();
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
                x.add(&z);
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
                x_neg.add(&z);
            }
        }
        i.inc(1);
    }

    None
}


pub fn inner_product_result(x: &[BigInt], y: &[BigInt]) -> BigInt {
    if x.len() != y.len() {
        panic!("Malformed input: x.len ({}), y.len ({})", x.len(), y.len());
    }
    let mut res = BigInt::zero();
    for i in 0..x.len() {
        let tmp =  &(x[i]) * &(y[i]);
        res += tmp;
    }
    res
}

pub fn quadratic_result(x: &[BigInt], y: &[BigInt], f: &BigIntMatrix) -> BigInt {
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


