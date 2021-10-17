use num_bigint::{BigInt, ToBigInt};

use ruby::math::matrix::{BigIntMatrix};
use ruby::utils::{quadratic_result};
use ruby::utils::rand_utils::{RandUtilsRng, Sample};
use ruby::quadratic_sgp::{Sgp, SgpPlain};
use ruby::traits::FunctionalEncryption;

#[test]
fn test_sgp_1() {
    const L: usize = 2;
    let sgp = Sgp::<L>::new();

    let mut x: [BigInt; L] = Default::default();
    let mut y: [BigInt; L] = Default::default();
    for i in 0..2 {
        x[i] = BigInt::from(i);
        y[i] = BigInt::from(i+1);
    }

    let a: [i64; 4] = [1; 4];
    let f = BigIntMatrix::new_ints(&a[..], 2, 2);
    let plain_result = quadratic_result(&x, &y, &f);
    println!("Groud truth: {:?}", plain_result);

    let plain = SgpPlain {x, y};
    let cipher = sgp.encrypt(&plain);
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

    let sgp = Sgp::<L>::new();

    let x: [BigInt; L] = rng.sample_range_array::<L>(&low, &high); 
    let y: [BigInt; L] = rng.sample_range_array::<L>(&low, &high);
    let f = BigIntMatrix::new_random(L, L, &low, &high);
    let plain_result = quadratic_result(&x, &y, &f);
    println!("Groud truth: {:?}", plain_result);

    let now = Instant::now();
    let plain = SgpPlain {x, y};
    let cipher = sgp.encrypt(&plain);
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

