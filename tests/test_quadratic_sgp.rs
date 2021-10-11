/* use  miracl_core::bn254::big;
use miracl_core::bn254::big::BIG;
use miracl_core::bn254::ecp;
use miracl_core::bn254::ecp::ECP;
use miracl_core::bn254::ecp2::ECP2;
use miracl_core::bn254::fp12::FP12;
use miracl_core::bn254::pair;
use miracl_core::bn254::rom; */
use num_bigint::{BigInt, ToBigInt};

use ruby::math::matrix::{BigIntMatrix};
use ruby::utils::{quadratic_result};
use ruby::utils::rand_utils::{RandUtilsRng, Sample};
use ruby::quadratic_sgp::Sgp;

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
    use std::time::Instant;

    let mut rng = RandUtilsRng::new(); 
    const L: usize = 1;
    let bound: i32 = 100;
    let low = (-bound).to_bigint().unwrap();
    let high = bound.to_bigint().unwrap();

    let sgp = Sgp::new(L);

    let x: Vec<BigInt> = rng.sample_range_vec(L, &low, &high); 
    let y: Vec<BigInt> = rng.sample_range_vec(L, &low, &high);
    let f = BigIntMatrix::new_random(L, L, &low, &high);
    let plain_result = quadratic_result(&x, &y, &f);
    println!("Groud truth: {:?}", plain_result);

    let now = Instant::now();
    let cipher = sgp.encrypt(&x, &y);
    let elapsed = now.elapsed();
    println!("[Quadratic Encrypt]: {:.2?}", elapsed);

    let now = Instant::now();
    let dk = sgp.derive_fe_key(&f);
    let elapsed = now.elapsed();
    println!("[Quadratic Derive]: {:.2?}", elapsed);

    let now = Instant::now();
    let result = sgp.decrypt(&cipher, &dk, &BigInt::from(bound)); 
    let elapsed = now.elapsed();
    println!("[Quadratic Decrypt]: {:.2?}", elapsed);

    assert!(result.is_some());
    assert_eq!(result.unwrap(), plain_result);
}

