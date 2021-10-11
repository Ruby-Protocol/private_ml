/* use  miracl_core::bn254::big;
use miracl_core::bn254::big::BIG;
use miracl_core::bn254::ecp;
use miracl_core::bn254::ecp::ECP;
use miracl_core::bn254::ecp2::ECP2;
use miracl_core::bn254::fp12::FP12;
use miracl_core::bn254::pair;
use miracl_core::bn254::rom; */
use num_bigint::{BigInt, ToBigInt};

use ruby::simple_ip::Sip;
use ruby::traits::FunctionalEncryption;
use ruby::utils::inner_product_result;
use ruby::utils::rand_utils::{RandUtilsRng, Sample};

#[test]
fn test_sip() {
    use std::time::Instant;

    let mut rng = RandUtilsRng::new();
    const L: usize = 20;
    let bound: i32 = 100;
    let low = (-bound).to_bigint().unwrap();
    let high = bound.to_bigint().unwrap();

    let sip = Sip::<L>::new();

    let x: [BigInt; L] = rng.sample_range_array::<L>(&low, &high);
    let y: [BigInt; L] = rng.sample_range_array::<L>(&low, &high);
    let plain_result = inner_product_result(&x, &y);
    println!("Groud truth: {:?}", plain_result);

    let now = Instant::now();
    let cipher = sip.encrypt(&x);
    let elapsed = now.elapsed();
    println!("[SIP Encrypt]: {:.2?}", elapsed);

    let now = Instant::now();
    let dk = sip.derive_fe_key(&y);
    let elapsed = now.elapsed();
    println!("[SIP Derive FE Key]: {:.2?}", elapsed);

    let now = Instant::now();
    let result = sip.decrypt(&cipher, &y, &dk, &BigInt::from(bound));
    let elapsed = now.elapsed();
    println!("[SIP Decrypt]: {:.2?}", elapsed);

    assert!(result.is_some());
    assert_eq!(result.unwrap(), plain_result);
}
