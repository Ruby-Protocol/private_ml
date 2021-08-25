use num_bigint::{BigInt};

use ruby::math::matrix::{BigIntMatrix};
use ruby::utils::rand_utils::{RandUtilsRng, Sample};

use ruby::ml::neural_network::NeuralNetwork;

//#[cfg(test)]
//mod tests {
    //use super::*;

    fn nn_result(x: &[BigInt], p: &BigIntMatrix, q: &[BigIntMatrix]) -> Vec<BigInt> {
        if x.len() != p.n_rows {
            panic!("Malformed input: x.len ({}), P.dim ({} x {})", x.len(), p.n_rows, p.n_cols);
        }
        let mat_x: BigIntMatrix = BigIntMatrix::new_bigints(x, 1, x.len());
        let mut res: Vec<BigInt> = Vec::with_capacity(q.len());
        for i in 0..q.len() {
            let tmp = mat_x.matmul(p);
            let tmp_t = tmp.transpose();
            let tmp = tmp.matmul(&q[i]);
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

        let p_low = BigInt::from(-2); 
        let p_high = BigInt::from(2);
        let p = BigIntMatrix::new_random(n, d, &p_low, &p_high);

        let q_low = BigInt::from(-3);
        let q_high = BigInt::from(3);
        let mut q: Vec<BigIntMatrix> = Vec::with_capacity(2);
        for _i in 0..q.capacity() {
            q.push(BigIntMatrix::new_random(d, d, &q_low, &q_high));
        }

        let service = NeuralNetwork::new(&p, &q);

        let data_low = -&service.bound;
        let data_high = service.bound.clone();
        let x: Vec<BigInt> = rng.sample_range_vec(n, &data_low, &data_high);

        let cipher = service.encrypt(&x);
        let result = service.compute(&cipher);

        let ground_truth = nn_result(&x, &p, &q);

        println!("Truth: {:?}", ground_truth);
        println!("Result: {:?}", result);
    }
//}

