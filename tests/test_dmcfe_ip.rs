use num_bigint::{BigInt};

use ruby::define::{G1, G1Vector, G2Vector};
use ruby::utils::{inner_product_result};
use ruby::utils::rand_utils::{RandUtilsRng, Sample};
use ruby::dmcfe_ip::Dmcfe;
use ruby::traits::FunctionalEncryption;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dmcfe_5() {
        let mut rng = RandUtilsRng::new(); 
        const L: usize = 5;
        let bound = BigInt::from(100);
        let low = -&bound;
        let high = bound.clone();
        let mut clients: Vec<Dmcfe<L>> = Vec::with_capacity(L);
        let mut pub_keys: Vec<G1> = Vec::with_capacity(L);
        let mut ciphers: Vec<G1> = Vec::with_capacity(L);
        let mut fe_key: Vec<G2Vector> = Vec::with_capacity(L);
        let mut temp: G1;

        for i in 0..L {
            clients.push(Dmcfe::<L>::new_single(i));
        }

        for i in 0..L {
            temp = clients[i].client_pub_key.clone();
            pub_keys.push(temp);
        }

        for i in 0..L {
            clients[i].set_share(&pub_keys);
        }

        let label = "dmcfe-label";
        let x: [BigInt; L] = rng.sample_range_array::<L>(&low, &high); 
        let y: [BigInt; L] = rng.sample_range_array::<L>(&low, &high);
        let plain_result = inner_product_result(&x, &y);
        println!("Groud truth: {:?}", plain_result);

        for i in 0..L {
            ciphers.push(clients[i].encrypt_single(&x[i], label));
            fe_key.push(clients[i].derive_fe_key_share(&y));
        }
        println!("decrypt starts");
        use std::time::Instant;
        let now = Instant::now();
        let dk = clients[0].key_comb(&fe_key, &y);
        let xy = clients[0].decrypt_with_label(&ciphers, &dk, &bound, label);
        let elapsed = now.elapsed();
        println!("Elapsed: {:.2?}", elapsed);

        assert!(xy.is_some());
        assert_eq!(xy.unwrap(), plain_result);
    }

    #[test]
    fn test_dmcfe_single_client() {
        use std::time::Instant;

        let mut rng = RandUtilsRng::new(); 
        const L: usize = 1;
        let bound = BigInt::from(100);
        let low = -&bound;
        let high = bound.clone();

        let x: [BigInt; L] = rng.sample_range_array::<L>(&low, &high); 
        let y: [BigInt; L] = rng.sample_range_array::<L>(&low, &high);
        let plain_result = inner_product_result(&x, &y);
        println!("Groud truth: {:?}", plain_result);

        let client = Dmcfe::<L>::new();

        let now = Instant::now();
        let ciphers: G1Vector = client.encrypt(&x);
        let elapsed = now.elapsed();
        println!("[DMCFE Encrypt]: {:.2?}", elapsed);

        let now = Instant::now();
        let dk = client.derive_fe_key(&y);
        let elapsed = now.elapsed();
        println!("[DMCFE Derive]: {:.2?}", elapsed);
        
        let now = Instant::now();
        let xy = client.decrypt(&ciphers, &dk, &bound);
        let elapsed = now.elapsed();
        println!("[DMCFE Decrypt]: {:.2?}", elapsed);

        assert!(xy.is_some());
        assert_eq!(xy.unwrap(), plain_result);
    }
}

