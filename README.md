# Grants Program: Ruby Protocol

This repository contains various functional encryption schemes and several machine learning applications built on top of the schemes.

## Functional Encryption Schemes
Implementation of Few Selected Functional Encryption Schemes


- **Scheme 1 ** [Simple Functional Encryption Schemes for Inner Products](https://link.springer.com/content/pdf/10.1007/978-3-662-46447-2_33.pdf) 
    - - Implemented [here](src/simple_ip.rs)

- **Scheme 2 ** [Decentralized Multi-Client Functional Encryption for Inner Product](https://eprint.iacr.org/2017/989.pdf) by *Chotard, Dufour Sans, Gay, Phan and Pointcheval*
    - Implemented [here](src/dmcfe_ip.rs) (Attribution: This is mostly a refactoring of [this repo](https://github.com/dev0x1/functional-encryption-schemes). We avoid re-inventing the wheel, but include it here for completeness.)
    
- **Scheme 3** [Reading in the Dark: Classifying Encrypted Digits with Functional Encryption](https://eprint.iacr.org/2018/206.pdf)
    - Implemented [here](src/quadratic_sgp.rs)

## Machine Learning Applications
Implemenation of two machine learning applications:

- **Disease prediction** in the paper:
    - [MSHBM2019] Marc, T., Stopar, M., Hartman, J., Bizjak, M., & Modic, J. (2019, September). Privacy-Enhanced Machine Learning with Functional Encryption. In European Symposium on Research in Computer Security (pp. 3-21). Springer, Cham.

- **Neural network** in the papers:
    - [MSHBM2019] Marc, T., Stopar, M., Hartman, J., Bizjak, M., & Modic, J. (2019, September). Privacy-Enhanced Machine Learning with Functional Encryption. In European Symposium on Research in Computer Security (pp. 3-21). Springer, Cham.
    - [SGP2018] Sans, E.D., Gay, R., Pointcheval, D.: Reading in the dark: Classifying encrypted digits with functional encryption. IACR Cryptology ePrint Archive 2018, 206, (2018).


## Build and Run Instruction
### Environment setup
```sh
# Install Rust
curl --tlsv1.2 https://sh.rustup.rs -sSf | sh

# Build the project
cargo build
```

### Unit tests
```sh
# Test the inner product functional encryption
cargo test test_sip -- --show-output

# Test the quadratic polynomial functional encryption
cargo test test_sgp -- --show-output

# Run the test of disease prediction (using inner product functional encryption)
cargo test test_disease_prediction -- --show-output

# Run the test of neural network (using quadratic polynomial functional encryption)
cargo test test_neural_network -- --show-output
```


## Docker 

You need to first install [Docker](https://docs.docker.com/engine/install/) before moving on.

### Build docker image
```sh
docker build -t ruby-protocol .
```

### Start a docker container
```sh
docker run -it ruby-protocol /bin/bash
```

### Run tests
Inside the container, we can try the following tests:
```sh
# Test the inner product functional encryption
cargo test test_sip -- --show-output

# Test the quadratic polynomial functional encryption
cargo test test_sgp -- --show-output

# Run the test of disease prediction (using inner product functional encryption)
cargo test test_disease_prediction -- --show-output

# Run the test of neural network (using quadratic polynomial functional encryption)
cargo test test_neural_network -- --show-output
```

## Benchmark
We give a benchmark of the implemented functional encryption schemes below. Experiments are performed on a Macbook Pro with 2.5 GHz Dual-Core Intel Core i7. All tests are run in a single thread. We run the experiments for vectors of length 1, 5, 10, and 20.

[Scheme 1: Inner product encryption](https://link.springer.com/content/pdf/10.1007/978-3-662-46447-2_33.pdf)  | 1 | 5 | 10 | 20 
------ | ------ | ------ | ------ | ------
Encrypt | 56.1 ms | 153.3 ms | 273.9 ms | 545.7 ms
Derive Key | 0.9 ms | 3.6 ms | 5.9 ms | 11.0 ms
Decrypt | 436.5 ms | 730.5 ms | 1.1 s | 1.2 s


[Scheme 2: Distributed inner product encryption](https://eprint.iacr.org/2017/989.pdf) | 1 | 5 | 10 | 20 
------ | ------ | ------ | ------ | ------
Encrypt | 50.4 ms | 277.9 ms | 600.1 ms |  1.1 s
Derive Key | 186.4 ms | 663.6 ms | 1.2 s | 2.3 s
Decrypt | 947.2 ms | 1.1 s | 1.2 s | 1.5 s


[Scheme 3: Quadratic polynomial encryption](https://eprint.iacr.org/2018/206.pdf) | 1 | 5 | 10 | 20 
------ | ------ | ------ | ------ | ------
Encrypt | 320.7 ms | 1.5 s | 2.9 s |  5.6 s
Derive Key | 56.1 ms | 66.0 ms | 101.8 ms | 244.4 ms
Decrypt | 2.5 s | 16.8 s | 57.1 s | 179.0 s

## Tutorial

You can find usage of all public modules in `tests/`. We give further guides here.

### Functional encryption

#### Inner product

This will evaluate inner product for two vectors `x` and `y`. Basically, it works in thtree steps:

1. Alice encrypts vector `x`, creating `Enc(x)`.
2. Alice creates evaluation key `dk` for vector `y`.
3. Bob evaluates `xy` by using `Enc(x)` and `dk`.

```rust
use ruby::simple_ip::Sip;

// First prepare some necessary information
let mut rng = RandUtilsRng::new(); 
const L: usize = 20;
let bound: i32 = 100;
let low = (-bound).to_bigint().unwrap();
let high = bound.to_bigint().unwrap();

// Create an instance of the scheme
let sip = Sip::<L>::new();

// Generate two random vectors for testing
let x: [BigInt; L] = rng.sample_range_array::<L>(&low, &high); 
let y: [BigInt; L] = rng.sample_range_array::<L>(&low, &high);

// Alice encrypts vector x
let cipher = sip.encrypt(&x);

// Alice derives functional evaluation key dk
let dk = sip.derive_fe_key(&y);

// Bob evaluates the inner product
let result = sip.decrypt(&cipher, &dk, &y, &BigInt::from(bound));

// result should equal to xy
```



#### Quadratic polynomial

This will evaluate the quadratic polynomial: `xfy`, where `x` and `y` are vectors, `f` is a matrix. "Quadratic" means `x` and `y` are unknown variables for the evaluator. It works in three steps:

1. Alice encrypts `x` and `y` , creating a single ciphertext `Enc(x,y)`.
2. Alice derives functional evaluation key `dk` for matrix `f`.
3. Bob evaluates `xfy` by using `Enc(x,y)` and `dk`.

```rust
use ruby::quadratic_sgp::Sgp;

// Create an instance of the scheme. Parameter 2 means the vector length is 2.
let sgp = Sgp::new(2);

// Just create two example vectors of length 2
let mut x: Vec<BigInt> = Vec::with_capacity(2);
let mut y: Vec<BigInt> = Vec::with_capacity(2);
for i in 0..2 {
x.push(BigInt::from(i));
y.push(BigInt::from(i+1));
}

// Create the matrix f
let a: [i64; 4] = [1; 4];
let f = BigIntMatrix::new_ints(&a[..], 2, 2);

// Alice encrypts vectors x and y
let cipher = sgp.encrypt(&x, &y);

// Alice derives functional evaluation key dk
let dk = sgp.derive_fe_key(&f);

// Bob evaluates the quadratic polynomial
let result = sgp.decrypt(&cipher, &dk, &BigInt::from(100)); 

// result should equal to xfy
```



### Machine Learning

#### Disease prediction

This application comes from [this work](http://eprint.iacr.org/2019/1129). It evaluates a linear model which is transated to the evaluation of two inner products `xy_1` and `xy_2`.

```rust
// Create an instance of the application
let service = DiseasePrediction::new();

// Create a secret input vector x
let x: Vec<f32> = vec![0.1, -0.23, 1.1, 0.98, 5.6, -0.9, -5.0, 2.4];

// Encrypt the vector x
let ciphers = service.encrypt(&x);

// Evaluate the inner products xy_1 an xy_2. "y_1" and "y_2" are public vector parameters stored in the application.
let result = service.compute(&ciphers);
```



#### Neural network

The neural network evaluation is actually translated to a quadratic polynomial evaluation according to [this work](https://eprint.iacr.org/2018/206.pdf). Basically, one layer of evaluation is: `f(x) = (Px)'Q(Px)`, where `P` is a projection matrix (`d`x`n`) to reduce the dimensionality of `x`  from `n` to `d` (`d<n`), `Q` is the public model matrix, `x` is the secret input of length `n`.

```rust
use ruby::ml::neural_network::NeuralNetwork;

let mut rng = RandUtilsRng::new();
let n = 10;
let d = 5;

// Create the projection matrix
let p_low = BigInt::from(-2); 
let p_high = BigInt::from(2);
let p = BigIntMatrix::new_random(n, d, &p_low, &p_high);

// Create 3 model matrices
let q_low = BigInt::from(-3);
let q_high = BigInt::from(3);
let mut q: Vec<BigIntMatrix> = Vec::with_capacity(2);
for _i in 0..q.capacity() {
  q.push(BigIntMatrix::new_random(d, d, &q_low, &q_high));
}

// Create an instance of the application
let service = NeuralNetwork::new(&p, &q);

// Create some random data
let data_low = -&service.bound;
let data_high = service.bound.clone();
let x: Vec<BigInt> = rng.sample_range_vec(n, &data_low, &data_high);

// Encrypt the secret input x
let cipher = service.encrypt(&x);

// Evaluate one layer of neural network model
let result = service.compute(&cipher);
```



### Zero Knowledge Proof

We provide generation of zero knowledge proof of our functional encryption schemes. Since the math details are lengthy to explain here, we only provide generation of ZKP for discret logarithm in this tutorial. But the usage for generation of ZKP for our functional encryption schems can also be found in `tests/test_zk.rs`.

```rust
let mut rng = thread_rng();
let jubjub_params = JubJubBN256::new();

// Create the base point
let g = EdwardsPoint::<Bn256Fr>::rand(&mut rng, &jubjub_params).mul(Num::from(8), &jubjub_params);

// Create the secret exponent
let x: Num<Bn256Fr> = rng.gen();

// Generate proof for discrete logarithm y = g^x
let snark = ZkDlog::generate(&g, &x);

// Verify the proof
let res = verifier::verify(&snark.vk, &snark.proof, &snark.inputs);
```



### Use ZeroPool Substrate to Verify ZK Proof

After generating the ZK proof with our library, we can use a substrate pallet to verify it. To this regard, we use [zeropool-substrate](https://github.com/zeropoolnetwork/zeropool-substrate). To setup the environment, run:

```shell
git clone https://github.com/zeropoolnetwork/zeropool-substrate.git

# Build and run a substrate node
cd zeropool-substrate/zeropool-substrate-devnet
make init
make run

# Open another terminal, annd run
cd zeropool-substrate/zeropool-substrate-client
yarn install
yarn start
```

This should open a web page in the browser: http://localhost:8000

Next, we generate the necessary ZK information to send into the substrate pallet. Take the discret logarithm as an example. Following the above tutorial for "Zero Knowledge Proof", we get a variable named `snark`. Then we retrieve its verification key VK:

```rust
println!("{}", snark.vk.encode());
/* Suppose this prints:
vYboJjQVejlnkY0tJQIe3xELvUvvTUl7Fx14FLXH9QcgWH1PIobe1SroigBR67GqAWEIyMPBh65Dz+e2Ogv7JKT8/XZtFxZkilJs7su4sqQADP5WPrDYRjFJ8q1yc+sRXJM+GLSrAW4MDFZij7eLNmwjbAE7KXF6bVJiC64SSxWvQgIU29fD85crRNmS+IfLj6ww4BOxZcAgHcKIVz4fCZtq8qiq1SvRQpm99TzoSMqGPmh8UCKNx7khPEPVGm8oFakINi4oXwrcYTeoZYuOXO3i811u/3CKsiKnaKKcmCQWcushEYfN9rsT+/73czOZNLMK29Y1/CWVjl+l+61tA+YxxCpUfAo6OnWK3jRNH5lLkVJhTFZSDzNt8SHlEN4NOyNF9bNBrtQEKUUTtOHlB7N8cZiB45QZpKS1b6Vj0iWVjdg1kF9QLo45jMSd0fika+DmCCGYISRJq8guJSzVF63PDNRXkmgyoY7dJ0qQnuk4yinyyb9FT6cBYsQW7+Mg1dkbiDyt3UgYh/pf8LWAXfSZa6UD7vVqfVcCvUIR+AiHXsAnF0vOsAUG+GWI9VVJO9fr3vdJA8YDZQEt4CpELgUAAADjF+PbKCLUNkPK8We6WoFOwOaVwYtqIPkDuwYQmEDtDhqlSpsSGArOgjIsmRuMvrzK/WY/8N/9if8Q1qqrsvsFBL5nvC9okK5IaqG8cNOJZMcLvvHytlZ19IR+vzpEwxSeNCofzmvYLsLHkaoqaiFMXrSOyI4Gs7IN3MmxsKzzLfV2IrZjEFfYTevzlsmccFXZnlgFEniAdz0gZcWtKXgAwI2SmBI9+8EZPyfY9UKwUU8UvKnNBiiInzQxXzby0SJVbg5AWMnwGXMNakRz/Zs5nQg7GMKsRH/7pCevO8qcGydr7Kq4WHWzajPw1fQURJWn6JwQ+p03up1GqvahTbsomMVFfE28Jr5i6ie0pJ/exugzQ9lXeKEYSRrgHn9GEhDmjeF830sNTKdp8011CfPfWY9KKZAdDIZeks9k5EO7KQ
*/
```

On the web page, we select "Extrinsic-->zeropool-->setVk", then copy the above VK to the "vkb" input box, like the following image, and then click "Signed":

![alt](./imgs/vk.png?raw=true)

Next, we retrieve the proof content:

```rust
println!("{}", snark.to_substrate_proof());
/* Suppose this prints:
{"proof":"y1JU+ydkWUugaiHt1AVNVXkwpLkSVIRHsskb7EZ3sCeJZAfuVbkBaV2zKM7USl0IWJ0tbeaOFmSlFuoqUXqvK3g+Khb2CiCwjRtXeuiKi84fCjgSD7akwXPCs7l/0/YukqJwFh8T4harJXtFRYbjfNjw454NsgmvaL/xYYHcwi7LT1rNLnQl+9EhBbSwpMGBv9mZObGw53gJNXjWFZrTCwUKkxadEhcq26wI82cg7W3Aw2UJYYvC1JJbNeNNwjERZn4NXKpqAEpeW9Hobj3UOGtZtnB9UKHZWz3dsprDJSykzISr2dJtOiuhOKqPGUwx1yAO7oH2WB1pd8YJkSVjLQ==","input":"BAAAALBIdIdKZ/9UChwdOVrsN7z1Xlw1ebe351AVrVTZ5osir6vrxgY0SDlTBUFvdK6QhLpggUIJRecfJH7yYHctyCLFrGFEz9hv51cTDPsF239ZqrrLDRUxVMBx4yYf532BCo/RmIDf3oJ3CRC8OrMp1o3+69lKdWagAJeZ2WrrVUcS"}
*/
```

On the web page, we select "Extrinsic-->zeropool-->testGroth16Verify", then copy the above content to the "jproofinput" input box, like the following image, and then click "Signed":

![alt](./imgs/input.png?raw=true)



We should see corresponding events that say the VK is set and the proof is verified successfully.



## Documentation

Run the following to generate documentation in `target/doc/ruby/`:

```shell
cargo doc --no-deps
```



## Security Warnings

As of now, this project serves mainly proof-of-concepts, benchmarking and evaluation purpose and not for production use. Also implementation have not been fully-reviewed.

