use num_bigint::{BigInt};
use std::convert::TryInto;
use crate::define::{G1Vector};
use crate::dmcfe_ip::{Dmcfe};
use crate::traits::FunctionalEncryption;

/// The disease prediction application in the following paper:
/// 
/// Marc, T., Stopar, M., Hartman, J., Bizjak, M., & Modic, J. (2019, September). Privacy-Enhanced Machine Learning with Functional Encryption. In European Symposium on Research in Computer Security (pp. 3-21). Springer, Cham.
pub struct DiseasePrediction<'a> {
    pub y1: [f32; 8],
    pub y2: [f32; 8],
    pub scale: f32,
    pub bound: f32,
    pub label: &'a str, 
    fe: Dmcfe<8>,
}

impl<'a> DiseasePrediction<'a> {

    /// Constructs a new `DiseasePrediction` application.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use ruby::ml::disease_prediction::DiseasePrediction;
    /// let service = DiseasePrediction::new();
    /// ```
    pub fn new() -> Self {
        let y1: [f32; 8] = [0.34362, 2.63588, 1.8803, 1.12673, -0.90941, 0.59397, 0.5232, 0.68602];
        let y2: [f32; 8] = [0.48123, 3.39222, 1.39862, -0.00439, 0.16081, 0.99858, 0.19035, 0.49756];
        let fe = Dmcfe::<8>::new();
        let scale: f32 = 100.0;
        let bound: f32 = 10.0;
        let label: &'static str = "disease prediction";
        Self {
            y1,
            y2,
            scale,
            bound,
            label,
            fe
        }
    }

    /// Encrypt client's input: a vector of floating point values.
    /// 
    /// # Examples
    ///
    /// ```no_run
    /// use ruby::ml::disease_prediction::DiseasePrediction;
    /// let service = DiseasePrediction::new();
    /// let x: [f32; 8] = [0.1, -0.23, 1.1, 0.98, 5.6, -0.9, -5.0, 2.4];
    /// let ciphers = service.encrypt(&x); 
    /// ```
    pub fn encrypt(&self, x: &[f32; 8]) -> G1Vector {
        let mut int_x: [BigInt; 8] = Default::default();
        for i in 0..8 {
            int_x[i] = BigInt::from((x[i] * self.scale).round() as i64);
        }
        let ciphers = self.fe.encrypt(&int_x);
        ciphers
    }

    /// Compute the inner product of client's input with the two parameter vectors in disease prediction.
    ///
    /// # Examples
    ///
    /// ```ignore
    /// // Following the examples of `encrypt`
    /// let result = service.compute(&ciphers); 
    /// ```
    pub fn compute(&self, ciphers: &G1Vector) -> Vec<f32> {
        let mut int_y1: [BigInt; 8] = Default::default();
        let mut int_y2: [BigInt; 8] = Default::default();
        for i in 0..8 {
            int_y1[i] = BigInt::from((self.y1[i] * self.scale).round() as i64);
            int_y2[i] = BigInt::from((self.y2[i] * self.scale).round() as i64);
        }

        let key1 = self.fe.derive_fe_key(&int_y1);
        let key2 = self.fe.derive_fe_key(&int_y2);

        let bound = BigInt::from((self.bound * self.scale).round() as i64);
        let x_mut_y1 = self.fe.decrypt(&ciphers, &key1, &bound).unwrap(); 
        let x_mut_y2 = self.fe.decrypt(&ciphers, &key2, &bound).unwrap(); 

        let x_mut_y1: i64 = x_mut_y1.try_into().unwrap();
        let x_mut_y2: i64 = x_mut_y2.try_into().unwrap();

        let x_mut_y1 = (x_mut_y1 as f32) / (self.scale * self.scale);
        let x_mut_y2 = (x_mut_y2 as f32) / (self.scale * self.scale);
        vec![x_mut_y1, x_mut_y2]
    }

}


#[cfg(test)]
mod tests {
    use super::*;

    fn inner_product_result(x: &[f32], y: &[f32]) -> f32 {
        if x.len() != y.len() {
            panic!("Malformed input: x.len ({}), y.len ({})", x.len(), y.len());
        }
        let mut res: f32 = 0.0;
        for i in 0..x.len() {
            let tmp =  x[i] * y[i];
            res = res + tmp;
        }
        res
    }

    #[test]
    fn test_disease_prediction() {
        let service = DiseasePrediction::new();
        let x: [f32; 8] = [0.1, -0.23, 1.1, 0.98, 5.6, -0.9, -5.0, 2.4];
        let ciphers = service.encrypt(&x);
        let result = service.compute(&ciphers);

        let ground_truth = [inner_product_result(&x, &service.y1), inner_product_result(&x, &service.y2)];

        println!("Truth: {:?}", ground_truth);
        println!("Result: {:?}", result);
    }
}

