/* use  miracl_core::bn254::big;
use miracl_core::bn254::big::BIG;
use miracl_core::bn254::ecp;
use miracl_core::bn254::ecp::ECP;
use miracl_core::bn254::ecp2::ECP2;
use miracl_core::bn254::fp12::FP12;
use miracl_core::bn254::pair;
use miracl_core::bn254::rom; */
use num_bigint::{BigInt, ToBigInt};

use ruby::utils::{inner_product_result};
use ruby::utils::rand_utils::{RandUtilsRng, Sample};
use ruby::simple_ip::Sip;


#[test]
fn test_sip() {
    let mut rng = RandUtilsRng::new(); 
    const L: usize = 10;
    let bound: i32 = 64;
    let low = (-bound).to_bigint().unwrap();
    let high = bound.to_bigint().unwrap();

    let sip = Sip::<L>::new();

    let x: [BigInt; L] = rng.sample_range_array::<L>(&low, &high); 
    let y: [BigInt; L] = rng.sample_range_array::<L>(&low, &high);
    let plain_result = inner_product_result(&x, &y);
    println!("Groud truth: {:?}", plain_result);

    let cipher = sip.encrypt(&x);
    let dk = sip.derive_fe_key(&y);
    let result = sip.decrypt(&cipher, &dk, &y, &BigInt::from(bound)); 

    assert!(result.is_some());
    assert_eq!(result.unwrap(), plain_result);
}

