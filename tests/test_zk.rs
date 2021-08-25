use fawkes_crypto::{
    backend::bellman_groth16::{
        prover,
        verifier,
        engines::{Bn256, Bls12_381},
        setup::setup
    },
    circuit::cs::{CS},
    circuit::num::CNum,
    circuit::bitify::c_into_bits_le_strict,
    circuit::ecc::*,
    core::signal::Signal,
    core::sizedvec::SizedVec,
    engines::bn256::{JubJubBN256},
    engines::bls12_381::{JubJubBLS12_381},
    native::ecc::*,
    rand::{thread_rng, Rng},
    ff_uint::{Num, PrimeFieldParams},
    BorshSerialize,
};

use std::str::FromStr;
use num_bigint::{BigInt}; 
use num_bigint::ToBigInt;
use ruby::math::matrix::{BigIntMatrix};
use ruby::utils::{quadratic_result, reduce};
use ruby::zk::dlog::{ZkDlog};
use ruby::zk::qp::{ZkQp};
use std::time::Instant;
use ruby::zk::qp::{QPProofSecret, QPProofPublic, CQPProofSecret, CQPProofPublic};
use ruby::zk::ToEncoding;

pub type Bn256Fr = fawkes_crypto::engines::bn256::Fr;
pub type Bn12381Fr = fawkes_crypto::engines::bls12_381::Fr;

#[test]
fn test_circuit_edwards_mul_bn256() {

    fn circuit<C:CS<Fr = Bn256Fr>>(public: (CEdwardsPoint<C>, CEdwardsPoint<C>), secret: CNum<C>) {
        let jubjub_params = JubJubBN256::new();
        let cs = secret.get_cs();

        let signal_x_bits = c_into_bits_le_strict(&secret);

        let mut n_constraints = cs.borrow().num_gates();
        let signal_y = public.0.mul(&signal_x_bits, &jubjub_params);
        n_constraints = cs.borrow().num_gates() - n_constraints;

        signal_y.assert_eq(&public.1);

        println!("edwards_mul constraints = {}", n_constraints);
        println!("total constraints = {}", cs.borrow().num_gates());
    }

    let jubjub_params = JubJubBN256::new();
    let mut rng = thread_rng();

    let g = EdwardsPoint::<Bn256Fr>::rand(&mut rng, &jubjub_params)
            .mul(Num::from(8), &jubjub_params);
    let x: Num<Bn256Fr> = rng.gen();
    let y = g.mul(x.to_other_reduced(), &jubjub_params);

    let now = Instant::now();
    let params = setup::<Bn256, _, _, _>(circuit);
    let elapsed = now.elapsed();
    println!("Setup: {:.2?}", elapsed);

    let now = Instant::now();
    let (inputs, snark_proof) = prover::prove(&params, &(g, y), &x, circuit);
    let elapsed = now.elapsed();
    println!("Prove: {:.2?}", elapsed);

    let now = Instant::now();
    let res = verifier::verify(&params.get_vk(), &snark_proof, &inputs);
    assert!(res, "Verifier result should be true");
    let elapsed = now.elapsed();
    println!("Verify: {:.2?}", elapsed);


    println!("Inputs: ");
    println!("{}", base64::encode(BorshSerialize::try_to_vec(&inputs).unwrap()));

    println!("Proof: ");
    println!("{}", base64::encode(BorshSerialize::try_to_vec(&snark_proof).unwrap()));

    println!("vk: ");
    println!("{}", base64::encode(BorshSerialize::try_to_vec(&params.get_vk()).unwrap()));
}

#[test]
fn test_circuit_edwards_mul_bls12381() {

    fn circuit<C:CS<Fr = Bn12381Fr>>(public: (CEdwardsPoint<C>, CEdwardsPoint<C>), secret: CNum<C>) {
        let jubjub_params = JubJubBLS12_381::new();
        let cs = secret.get_cs();

        let signal_x_bits = c_into_bits_le_strict(&secret);

        let mut n_constraints = cs.borrow().num_gates();
        let signal_y = public.0.mul(&signal_x_bits, &jubjub_params);
        n_constraints = cs.borrow().num_gates() - n_constraints;

        signal_y.assert_eq(&public.1);

        println!("edwards_mul constraints = {}", n_constraints);
        println!("total constraints = {}", cs.borrow().num_gates());
    }

    let jubjub_params = JubJubBLS12_381::new();
    let params = setup::<Bls12_381, _, _, _>(circuit);
    let mut rng = thread_rng();

    let g: EdwardsPoint<Bn12381Fr> = EdwardsPoint::<Bn12381Fr> {
        x: Num::<Bn12381Fr>::from_str("8076246640662884909881801758704306714034609987455869804520522091855516602923").unwrap(),
        y: Num::<Bn12381Fr>::from_str("13262374693698910701929044844600465831413122818447359594527400194675274060458").unwrap()
    };
    let x: Num<Bn12381Fr> = rng.gen();
    let y = g.mul(x.to_other_reduced(), &jubjub_params);

    let (inputs, snark_proof) = prover::prove(&params, &(g, y), &x, circuit);
    let res = verifier::verify(&params.get_vk(), &snark_proof, &inputs);
    assert!(res, "Verifier result should be true");

}

#[test]
fn test_zico_num() {
    let a: Num<Bn12381Fr> = Num::<Bn12381Fr>::from_str("15").unwrap();
    println!("a: {}", a);

    let b: BigInt = BigInt::from_str(&a.to_string()).unwrap();
    println!("b: {}", b);

    let mut rng = thread_rng();
    let n = 5;
    let s: Vec<Num<Bn12381Fr>> = vec![rng.gen(); n];
    let bigint_s: Vec<BigInt> = s.iter().map(|x| BigInt::from_str(&x.to_string()).unwrap()).collect();
    println!("s: {:?}", s);
    println!("bigint_s: {:?}", bigint_s);

    println!("s[0]: {}", s[0]);
    println!("bigint_s[0]: {}", bigint_s[0]);
}



#[test]
fn test_circuit_qp () {
    //type Fr = Bn12381Fr;
    //type E = Bls12_381; 
    //type JJParams = JubJubBLS12_381;

    type Fr = Bn256Fr;
    type E = Bn256; 
    type JJParams = JubJubBN256;

    const L: usize = 1; 

    fn circuit<C:CS<Fr = Fr>>(public: CQPProofPublic<C, L>, secret: CQPProofSecret<C, L>) {
        let jubjub_params = JJParams::new();
        let cs = secret.get_cs();

        let f_st_bits = c_into_bits_le_strict(&secret.f_st);
        let r_bits = c_into_bits_le_strict(&secret.r);

        let c1 = public.g1.mul(&f_st_bits, &jubjub_params)
            .add(&public.h1.mul(&r_bits, &jubjub_params), &jubjub_params);
        c1.assert_eq(&public.c1);

        let c2 = public.g1.mul(&r_bits, &jubjub_params); 
        c2.assert_eq(&public.c2);

        let c3 = secret.s.iter()
            .map(|si| public.g1.mul(&c_into_bits_le_strict(si), &jubjub_params))
            .collect::<SizedVec<CEdwardsPoint<C>, L>>();
        c3.assert_eq(&public.c3);

        let c4 = secret.t.iter()
            .map(|ti| public.g1.mul(&c_into_bits_le_strict(ti), &jubjub_params))
            .collect::<SizedVec<CEdwardsPoint<C>, L>>();
        c4.assert_eq(&public.c4);

        println!("total constraints = {}", cs.borrow().num_gates());
    }


    let jubjub_params = JJParams::new();
    let mut rng = thread_rng();
    //let g1: EdwardsPoint<Fr> = EdwardsPoint::<Fr> {
        //x: Num::<Fr>::from_str("8076246640662884909881801758704306714034609987455869804520522091855516602923").unwrap(),
        //y: Num::<Fr>::from_str("13262374693698910701929044844600465831413122818447359594527400194675274060458").unwrap()
    //};
    let g1: EdwardsPoint<Fr> = EdwardsPoint::<Fr>::rand(&mut rng, &jubjub_params)
        .mul(Num::from(8), &jubjub_params);
    let sk: Num<Fr> = rng.gen(); 
    let h1 = g1.mul(sk.to_other_reduced(), &jubjub_params);

    let s: SizedVec<Num<Fr>, L> = (0..L).map(|_| rng.gen()).collect();
    let t: SizedVec<Num<Fr>, L> = (0..L).map(|_| rng.gen()).collect();
    let r: Num<Fr> = rng.gen();

    let bound: i32 = 64;
    let low = (-bound).to_bigint().unwrap();
    let high = bound.to_bigint().unwrap();
    let bigint_mod = BigInt::from_str(&Fr::MODULUS.to_string()).unwrap();
    let bigint_s: Vec<BigInt> = s.iter().map(|x| BigInt::from_str(&x.to_string()).unwrap()).collect(); 
    let bigint_t: Vec<BigInt> = t.iter().map(|x| BigInt::from_str(&x.to_string()).unwrap()).collect();
    let bigint_f = BigIntMatrix::new_random(L, L, &low, &high);
    let bigint_result = reduce(&quadratic_result(&bigint_s, &bigint_t, &bigint_f), &bigint_mod);
    let f_st = Num::<Fr>::from_str(&bigint_result.to_string()).unwrap();
    println!("bigint_f(s, t): {}", bigint_result);
    println!("f(s, t): {}", f_st);

    let c1 = g1.mul(f_st.to_other_reduced(), &jubjub_params)
        .add(&h1.mul(r.to_other_reduced(), &jubjub_params), &jubjub_params);
    let c2 = g1.mul(r.to_other_reduced(), &jubjub_params);
    let c3 = s.iter()
        .map(|si| g1.mul(si.to_other_reduced(), &jubjub_params))
        .collect::<SizedVec<_, L>>();
    let c4 = t.iter()
        .map(|ti| g1.mul(ti.to_other_reduced(), &jubjub_params))
        .collect::<SizedVec<_, L>>();

    let qp_proof_public = QPProofPublic {
        g1,
        h1,
        c1,
        c2,
        c3,
        c4
    };
    let qp_proof_secret = QPProofSecret {
        r,
        f_st,
        s,
        t
    };

    let params = setup::<E, _, _, _>(circuit);
    let (inputs, snark_proof) = prover::prove(&params, &qp_proof_public, &qp_proof_secret, circuit);
    let res = verifier::verify(&params.get_vk(), &snark_proof, &inputs);
    assert!(res, "Verifier result should be true");
}

#[test]
fn test_zk_discrete_log() {

    let mut rng = thread_rng();
    let jubjub_params = JubJubBN256::new();

    let g = EdwardsPoint::<Bn256Fr>::rand(&mut rng, &jubjub_params)
            .mul(Num::from(8), &jubjub_params);
    let x: Num<Bn256Fr> = rng.gen();

    let snark = ZkDlog::generate(&g, &x);

    let res = verifier::verify(&snark.vk, &snark.proof, &snark.inputs);
    assert!(res, "Verifier result should be true");

    println!("Inputs: ");
    println!("{}", snark.inputs.encode());

    println!("Proof: ");
    println!("{}", snark.proof.encode());

    println!("vk: ");
    println!("{}", snark.vk.encode());
}

#[test]
fn test_zk_quadratic_polynomial_zk() {

    const N: usize = 1;
    let mut rng = thread_rng();
    let jubjub_params = JubJubBN256::new();

    let g1 = EdwardsPoint::<Bn256Fr>::rand(&mut rng, &jubjub_params)
        .mul(Num::from(8), &jubjub_params);
    let sk: Num<Bn256Fr> = rng.gen();
    let h1 = g1.mul(sk.to_other_reduced(), &jubjub_params);

    let s: SizedVec<Num<Bn256Fr>, N> = (0..N).map(|_| rng.gen()).collect();
    let t: SizedVec<Num<Bn256Fr>, N> = (0..N).map(|_| rng.gen()).collect();

    let bound: i32 = 64;
    let low = (-bound).to_bigint().unwrap();
    let high = bound.to_bigint().unwrap();
    let bigint_f = BigIntMatrix::new_random(N, N, &low, &high);

    let snark = ZkQp::<N>::generate(&g1, &h1, &s, &t, &bigint_f);

    let res = verifier::verify(&snark.vk, &snark.proof, &snark.inputs);
    assert!(res, "Verifier result should be true");

    println!("Inputs: ");
    println!("{}", snark.inputs.encode());

    println!("Proof: ");
    println!("{}", snark.proof.encode());

    println!("vk: ");
    println!("{}", snark.vk.encode());
}

