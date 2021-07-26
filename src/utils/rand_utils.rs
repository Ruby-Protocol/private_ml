use miracl_core::rand::{RAND, RAND_impl};
use rand::{Rng, RngCore, SeedableRng};
use rand::rngs::StdRng;
use rand::distributions::Uniform;
use num_bigint::{BigInt, RandBigInt};
use num_traits::Zero;
use crate::define::BigNum;

pub trait Sample<T> {
    fn sample(&mut self, modulus: &T) -> T; 
    fn sample_range(&mut self, low: &T, high: &T) -> T;
    fn sample_vec(&mut self, len: usize, modulus: &T) -> Vec<T>; 
    fn sample_range_vec(&mut self, len: usize, low: &T, high: &T) -> Vec<T>;
}

trait RandUtils {
    type Kernel;
    
    fn get_rng() -> Self::Kernel;
    fn get_seeded_rng(seed: &[u8; 32]) -> Self::Kernel;
}


pub struct RandUtilsRAND {
    // Keep an internal RNG member to avoid having to initiate a new one in every functionality call 
    rng: RAND_impl
}

impl RandUtilsRAND {
    pub fn new() -> Self {
        Self {
            rng: Self::get_rng()
        }
    }
}

impl RandUtils for RandUtilsRAND {
    type Kernel = RAND_impl;

    
    fn get_rng() -> Self::Kernel {
        let mut seed: [u8; 32] = [0; 32];
        rand::thread_rng().fill_bytes(&mut seed);
        return Self::get_seeded_rng(&seed);
    }

    fn get_seeded_rng(seed: &[u8; 32]) -> Self::Kernel {
        let mut rng = RAND_impl::new();
        rng.clean();
        rng.seed(seed.len(), seed);
        rng
    }

}

impl Sample<BigNum> for RandUtilsRAND {
    fn sample(&mut self, modulus: &BigNum) -> BigNum {
        BigNum::randomnum(modulus, &mut self.rng)
    }

    fn sample_vec(&mut self, len: usize, modulus: &BigNum) -> Vec<BigNum> {
        (0..len).map(|_| self.sample(modulus)).collect()
    }

    fn sample_range(&mut self, low: &BigNum, high: &BigNum) -> BigNum {
        let modulus = high.minus(low);
        let s = self.sample(&modulus); 
        s.plus(low)
    }

    fn sample_range_vec(&mut self, len: usize, low: &BigNum, high: &BigNum) -> Vec<BigNum> {
        let modulus = high.minus(low); 
        (0..len).map(|_| self.sample(&modulus).plus(low)).collect()
    }

}

#[derive(Debug)]
pub struct RandUtilsRng {
    // Keep an internal RNG member to avoid having to initiate a new one in every functionality call 
    rng: StdRng 
}

impl RandUtilsRng {
    pub fn new() -> Self {
        Self {
            rng: Self::get_rng()
        }
    }
}

impl RandUtils for RandUtilsRng {
    type Kernel = StdRng;

    fn get_rng() -> Self::Kernel {
        return StdRng::from_entropy();
    }

    fn get_seeded_rng(seed: &[u8; 32]) -> Self::Kernel {
        let rng = StdRng::from_seed(*seed);
        rng
    }

}

impl Sample<BigInt> for RandUtilsRng {
    fn sample(&mut self, modulus: &BigInt) -> BigInt {
        self.rng.gen_bigint_range(&BigInt::zero(), modulus)
    }

    fn sample_range(&mut self, low: &BigInt, high: &BigInt) -> BigInt {
        self.rng.gen_bigint_range(low, high)
    }

    fn sample_vec(&mut self, len: usize, modulus: &BigInt) -> Vec<BigInt> {
        let range = Uniform::from(BigInt::zero()..modulus.clone());
        /*
          The grammar '(&mut self.rng).sample_iter(...)' might seem a little difficult to understand. Check the following 3 links:
          https://rust-random.github.io/rand/rand/trait.Rng.html#method.sample_iter
          https://rust-random.github.io/rand/rand/trait.RngCore.html#impl-RngCore-for-%26%27a%20mut%20R
          https://stackoverflow.com/questions/28005134/how-do-i-implement-the-add-trait-for-a-reference-to-a-struct

          Basically, it is because RngCore is also implemented for the REFERENCE of any type that implements RngCore + Sized.
          Hence here we are taking the reference by value, which is just a simple copy of the reference, but not moving the ownership.
        */
        (&mut self.rng).sample_iter(&range).take(len).collect()
    }

    fn sample_range_vec(&mut self, len: usize, low: &BigInt, high: &BigInt) -> Vec<BigInt> {
        let range = Uniform::from(low.clone()..high.clone());
        (&mut self.rng).sample_iter(&range).take(len).collect()
    }
}



#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rand_utils_rng () {
        let mut rand_utils = RandUtilsRng::new();
        println!("next u32: {:?}", rand_utils.rng.next_u32());
        println!("next big int mod: {:?}", rand_utils.sample(&BigInt::from(1000)));
        println!("next big int range: {:?}", rand_utils.sample_range(&BigInt::from(50), &BigInt::from(100)));
        println!("next big int mod vec: {:?}", rand_utils.sample_vec(5, &BigInt::from(1000)));
        println!("next big int range vec: {:?}", rand_utils.sample_range_vec(5, &BigInt::from(50), &BigInt::from(100)));
    }

    #[test]
    fn test_rand_utils_rand () {
        let mut rand_utils = RandUtilsRAND::new();
        println!("next big int mod: {:?}", rand_utils.sample(&BigNum::new_int(1000)));
        println!("next big int range: {:?}", rand_utils.sample_range(&BigNum::new_int(50), &BigNum::new_int(100)));
        println!("next big int mod vec: {:?}", rand_utils.sample_vec(5, &BigNum::new_int(1000)));
        println!("next big int range vec: {:?}", rand_utils.sample_range_vec(5, &BigNum::new_int(50), &BigNum::new_int(100)));
    }

}
