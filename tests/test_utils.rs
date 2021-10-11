use rand::{RngCore};
use num_bigint::{BigInt};
use num_traits::Num;
use miracl_core::bls12381::pair;
use ruby::define::{BigNum, G1, G2};
use ruby::utils::{baby_step_giant_step, baby_step_giant_step_g1};
use ruby::utils::rand_utils::{RandUtilsRAND, RandUtilsRng, Sample};
use ruby::define::{CURVE_ORDER};

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
        let result = baby_step_giant_step(&h, &g, &bound); 
        assert!(result.is_some());

        let x = BigInt::from_str_radix(&x.tostring(), 16).unwrap();
        assert_eq!(result.unwrap(), x);
    }

    #[test]
    fn test_baby_step_giant_step_g1() {
        let g1 = G1::generator();

        let bound = BigNum::new_int(1<<13);
        let y = -2149;
        let mut x = BigNum::new_int(y);
        x.add(&CURVE_ORDER);

        let h = g1.mul(&x);
        let result = baby_step_giant_step_g1(&h, &g1, &bound); 
        assert!(result.is_some());

        let y = BigInt::from(y);
        assert_eq!(result.unwrap(), y);
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

    #[test]
    fn test_rand_utils_rng () {
        let mut rand_utils = RandUtilsRng::new();
        println!("next u32: {:?}", rand_utils.rng.next_u32());
        println!("next big int mod: {:?}", rand_utils.sample(&BigInt::from(1000)));
        println!("next big int range: {:?}", rand_utils.sample_range(&BigInt::from(50), &BigInt::from(100)));
        println!("next big int mod vec: {:?}", rand_utils.sample_vec(5, &BigInt::from(1000)));
        println!("next big int range vec: {:?}", rand_utils.sample_range_vec(5, &BigInt::from(50), &BigInt::from(100)));
        println!("next bit int array: {:?}", rand_utils.sample_array::<5>(&BigInt::from(1000)));
    }

    #[test]
    fn test_rand_utils_rand () {
        let mut rand_utils = RandUtilsRAND::new();
        println!("next big int mod: {:?}", rand_utils.sample(&BigNum::new_int(1000)));
        println!("next big int range: {:?}", rand_utils.sample_range(&BigNum::new_int(50), &BigNum::new_int(100)));
        println!("next big int mod vec: {:?}", rand_utils.sample_vec(5, &BigNum::new_int(1000)));
        println!("next big int range vec: {:?}", rand_utils.sample_range_vec(5, &BigNum::new_int(50), &BigNum::new_int(100)));
        println!("next bit int array: {:?}", rand_utils.sample_array::<5>(&BigNum::new_int(1000)));
    }


}
