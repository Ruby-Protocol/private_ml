//use lazy_static::lazy_static;
//use miracl_core::bls12381::ecp;
//use miracl_core::bls12381::rom;
/* use  miracl_core::bn254::big;
use miracl_core::bn254::big::BIG;
use miracl_core::bn254::ecp;
use miracl_core::bn254::ecp::ECP;
use miracl_core::bn254::ecp2::ECP2;
use miracl_core::bn254::fp12::FP12;
use miracl_core::bn254::pair;
use miracl_core::bn254::rom; */
//use miracl_core::rand::{RAND, RAND_impl};
use num_bigint::{BigInt};

use ruby::define::{G1, G1Vector, G2Vector};
use ruby::utils::{inner_product_result};
use ruby::utils::rand_utils::{RandUtilsRng, Sample};
use ruby::dmcfe_ip::Dmcfe;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dmcfe_5() {
        let mut rng = RandUtilsRng::new(); 
        let num_clients: usize = 5;
        let bound = BigInt::from(100);
        let low = -&bound;
        let high = bound.clone();
        let mut clients: Vec<Dmcfe> = Vec::with_capacity(num_clients);
        let mut pub_keys: Vec<G1> = Vec::with_capacity(num_clients);
        let mut ciphers: Vec<G1> = Vec::with_capacity(num_clients);
        let mut fe_key: Vec<G2Vector> = Vec::with_capacity(num_clients);
        let mut temp: G1;

        for i in 0..num_clients {
            clients.push(Dmcfe::new(i));
        }

        for i in 0..num_clients {
            temp = clients[i].client_pub_key.clone();
            pub_keys.push(temp);
        }

        for i in 0..num_clients {
            clients[i].set_share(&pub_keys);
        }

        let label = "dmcfe-label";
        let x: Vec<BigInt> = rng.sample_range_vec(num_clients, &low, &high); 
        let y: Vec<BigInt> = rng.sample_range_vec(num_clients, &low, &high);
        let plain_result = inner_product_result(&x, &y);
        println!("Groud truth: {:?}", plain_result);

        for i in 0..num_clients {
            ciphers.push(clients[i].encrypt(&x[i], label));
            fe_key.push(clients[i].derive_fe_key_share(&y[..]));
        }
        println!("decrypt starts");
        use std::time::Instant;
        let now = Instant::now();
        let dk = Dmcfe::key_comb(&fe_key);
        let xy = Dmcfe::decrypt(&ciphers, &y[..], &dk, label, &bound);
        let elapsed = now.elapsed();
        println!("Elapsed: {:.2?}", elapsed);

        assert!(xy.is_some());
        assert_eq!(xy.unwrap(), plain_result);
    }

    #[test]
    fn test_dmcfe_single_client() {
        let mut rng = RandUtilsRng::new(); 
        let n: usize = 5;
        let bound = BigInt::from(100);
        let low = -&bound;
        let high = bound.clone();

        let label = "dmcfe-label";
        let x: Vec<BigInt> = rng.sample_range_vec(n, &low, &high); 
        let y: Vec<BigInt> = rng.sample_range_vec(n, &low, &high);
        let plain_result = inner_product_result(&x, &y);
        println!("Groud truth: {:?}", plain_result);

        let client = Dmcfe::new(0);
        let ciphers: G1Vector = client.encrypt_vec(&x[..], label);
        let dk: G2Vector = client.derive_fe_key(&y[..]);
        
        println!("decrypt starts");
        use std::time::Instant;
        let now = Instant::now();
        let xy = Dmcfe::decrypt(&ciphers, &y[..], &dk, label, &bound);
        let elapsed = now.elapsed();
        println!("Elapsed: {:.2?}", elapsed);

        assert!(xy.is_some());
        assert_eq!(xy.unwrap(), plain_result);
    }
}

