# Functional Encryption Schemes
Implementation of Few Selected Functional Encryption Schemes


- **Scheme 1** [Simple Functional Encryption Schemes for Inner Products](https://link.springer.com/content/pdf/10.1007/978-3-662-46447-2_33.pdf) 
    - - Implemented [here](src/simple_ip.rs)

- **Scheme 2** [Decentralized Multi-Client Functional Encryption for Inner Product](https://eprint.iacr.org/2017/989.pdf) by *Chotard, Dufour Sans, Gay, Phan and Pointcheval*
    - Implemented [here](src/dmcfe_ip.rs) - this is reimplementation in Rust of C-implementation available in this awesome library [CiFEr](https://github.com/fentec-project/CiFEr). 
    - I have used BLS-12381 curve for pairing instead of BN-256 as in CiFEr.

- **Scheme 3** [Reading in the Dark: Classifying Encrypted Digits with Functional Encryption](https://eprint.iacr.org/2018/206.pdf)
    - Implemented [here](src/quadratic_sgp.rs)

# Machine Learning Applications
Implemenation of two machine learning applications:

- **Disease prediction** in the paper:
    - [MSHBM2019] Marc, T., Stopar, M., Hartman, J., Bizjak, M., & Modic, J. (2019, September). Privacy-Enhanced Machine Learning with Functional Encryption. In European Symposium on Research in Computer Security (pp. 3-21). Springer, Cham.

- **Neural network** in the papers:
    - [MSHBM2019] Marc, T., Stopar, M., Hartman, J., Bizjak, M., & Modic, J. (2019, September). Privacy-Enhanced Machine Learning with Functional Encryption. In European Symposium on Research in Computer Security (pp. 3-21). Springer, Cham.
    - [SGP2018] Sans, E.D., Gay, R., Pointcheval, D.: Reading in the dark: Classifying encrypted digits with functional encryption. IACR Cryptology ePrint Archive 2018, 206, (2018).


# Build and Run Instruction
### Environment setup
```sh
# Install Rust
curl --tlsv1.2 https://sh.rustup.rs -sSf | sh

# Build the project
cargo build
```

### Run tests
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


# Docker 

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

# Benchmark
We give a benchmark of the implemented functional encryption schemes below. Experiments are performed on a Macbook Pro with 2.5 GHz Dual-Core Intel Core i7. All tests are run in a single thread. We run the experiments for vectors of length 1, 5, 10, and 20.

Scheme 1 | 1 | 5 | 10 | 20 
------ | ------ | ------ | ------ | ------
Encrypt | 56.1 ms | 153.3 ms | 273.9 ms | 545.7 ms
Derive Key | 0.9 ms | 3.6 ms | 5.9 ms | 11.0 ms
Decrypt | 436.5 ms | 730.5 ms | 1.1 s | 1.2 s


Scheme 2 | 1 | 5 | 10 | 20 
------ | ------ | ------ | ------ | ------
Encrypt | 50.4 ms | 277.9 ms | 600.1 ms |  1.1 s
Derive Key | 186.4 ms | 663.6 ms | 1.2 s | 2.3 s
Decrypt | 947.2 ms | 1.1 s | 1.2 s | 1.5 s


Scheme 3 | 1 | 5 | 10 | 20 
------ | ------ | ------ | ------ | ------
Encrypt | 320.7 ms | 1.5 s | 2.9 s |  5.6 s
Derive Key | 56.1 ms | 66.0 ms | 101.8 ms | 244.4 ms
Decrypt | 2.5 s | 16.8 s | 57.1 s | 179.0 s


# Security Warnings

As of now, this project serves mainly proof-of-concepts, benchmarking and evaluation purpose and not for production use. Also implementation have not been fully-reviewed.

