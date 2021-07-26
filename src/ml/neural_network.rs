use num_bigint::{BigInt};
use std::convert::TryInto;
use crate::define::{G1Vector};
use crate::dmcfe_ip::{Dmcfe};

use crate::quadratic_sgp::{Sgp, SgpCipher};
use crate::math::matrix::{BigIntMatrix};
use crate::utils::rand_utils::{RandUtilsRng, Sample};

/*
   The neural network application in the following papers:
   [MSHBM2019] Marc, T., Stopar, M., Hartman, J., Bizjak, M., & Modic, J. (2019, September). Privacy-Enhanced Machine Learning with Functional Encryption. In European Symposium on Research in Computer Security (pp. 3-21). Springer, Cham.
   [SGP2018] Sans, E.D., Gay, R., Pointcheval, D.: Reading in the dark: Classifying encrypted digits with functional encryption. IACR Cryptology ePrint Archive 2018, 206, (2018).
*/
pub struct NeuralNetwork {
    pub P: BigIntMatrix,
    pub Q: Vec<BigIntMatrix>,
    pub bound: BigInt,
    sgp: Sgp 
}

impl NeuralNetwork {
    pub fn new(P: &BigIntMatrix, Q: &Vec<BigIntMatrix>) -> Self {
        let bound = BigInt::from(256);
        let sgp = Sgp::new(P.n_rows); 
        Self {
            P: P.clone(),
            Q: Q.clone(),
            bound,
            sgp
        }
    }

    /* 
       Encrypt client's input: a vector of integer values
    */
    pub fn encrypt(&self, x: &[BigInt]) -> SgpCipher {
        let cipher = self.sgp.encrypt(x, x);
        cipher
    }

    /* 
       Compute the one-laye neural network model 
    */
    pub fn compute(&self, cipher: &SgpCipher) -> Vec<BigInt> {
        let new_cipher = self.sgp.project(cipher, &self.P);
        let mut res: Vec<BigInt> = Vec::with_capacity(self.Q.len());
        
        for i in 0..self.Q.len() {
            let dk_i = self.sgp.derive_fe_key_projected(&self.Q[i], &self.P);
            let res_i = self.sgp.decrypt(&new_cipher, &dk_i, &self.bound).unwrap();
            res.push(res_i);
        }
        res
    }

}


#[cfg(test)]
mod tests {
    use super::*;

    fn nn_result(x: &[BigInt], P: &BigIntMatrix, Q: &[BigIntMatrix]) -> Vec<BigInt> {
        if x.len() != P.n_rows {
            panic!("Malformed input: x.len ({}), P.dim ({} x {})", x.len(), P.n_rows, P.n_cols);
        }
        let mat_x: BigIntMatrix = BigIntMatrix::new_bigints(x, 1, x.len());
        let mut res: Vec<BigInt> = Vec::with_capacity(Q.len());
        for i in 0..Q.len() {
            let tmp = mat_x.matmul(P);
            let tmp_t = tmp.transpose();
            let tmp = tmp.matmul(&Q[i]);
            let tmp = tmp.matmul(&tmp_t);
            res.push(tmp.get_element(0, 0).clone());
        }
        res
    }

    #[test]
    fn test_neural_network() {
        let mut rng = RandUtilsRng::new();
        let n = 10;
        let d = 5;

        let P_low = BigInt::from(-2); 
        let P_high = BigInt::from(2);
        let P = BigIntMatrix::new_random(n, d, &P_low, &P_high);

        let Q_low = BigInt::from(-3);
        let Q_high = BigInt::from(3);
        let mut Q: Vec<BigIntMatrix> = Vec::with_capacity(2);
        for i in 0..Q.capacity() {
            Q.push(BigIntMatrix::new_random(d, d, &Q_low, &Q_high));
        }

        let service = NeuralNetwork::new(&P, &Q);

        let data_low = -&service.bound;
        let data_high = service.bound.clone();
        let x: Vec<BigInt> = rng.sample_range_vec(n, &data_low, &data_high);

        let cipher = service.encrypt(&x);
        let result = service.compute(&cipher);

        let ground_truth = nn_result(&x, &P, &Q);

        println!("Truth: {:?}", ground_truth);
        println!("Result: {:?}", result);
    }
}


