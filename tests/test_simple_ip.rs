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

//#[test]
//fn test_sgp_1() {
    //const L: usize = 2;
    //let sip = Sip::<L>::new();

    //let mut x: [BigInt; L] = Vec::with_capacity(2);
    //let mut y: Vec<BigInt> = Vec::with_capacity(2);
    //for i in 0..2 {
        //x.push(BigInt::from(i));
        //y.push(BigInt::from(i+1));
    //}

    //let a: [i64; 4] = [1; 4];
    //let f = BigIntMatrix::new_ints(&a[..], 2, 2);
    //let plain_result = quadratic_result(&x, &y, &f);
    //println!("Groud truth: {:?}", plain_result);

    //let cipher = sgp.encrypt(&x, &y);
    //let dk = sgp.derive_fe_key(&f);
    //let result = sgp.decrypt(&cipher, &dk, &BigInt::from(100)); 

    //assert!(result.is_some());
    //assert_eq!(result.unwrap(), plain_result);
//}

#[test]
fn test_sip_2() {
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

