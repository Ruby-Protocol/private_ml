# Functional Encryption Schemes
Implementation of Few Selected Functional Encryption Schemes



- **Scheme 1** [Decentralized Multi-Client Functional Encryption for Inner Product](https://eprint.iacr.org/2017/989.pdf) by *Chotard, Dufour Sans, Gay, Phan and Pointcheval*
    - Implemented [here](src/dmcfe_ip.rs) - this is reimplementation in Rust of C-implementation available in this awesome library [CiFEr](https://github.com/fentec-project/CiFEr). 
    - I have used BLS-12381 curve for pairing instead of BN-256 as in CiFEr.

- **Scheme 2** [Reading in the Dark: Classifying Encrypted Digits with Functional Encryption](https://eprint.iacr.org/2018/206.pdf)
    - Implemented [here](src/quadratic_sgp.rs)

# Machine Learning Applications
Implemenation of two machine learning applications:

- **Disease prediction** in the paper:
    - [MSHBM2019] Marc, T., Stopar, M., Hartman, J., Bizjak, M., & Modic, J. (2019, September). Privacy-Enhanced Machine Learning with Functional Encryption. In European Symposium on Research in Computer Security (pp. 3-21). Springer, Cham.

- **Neural network** in the papers:
    - [MSHBM2019] Marc, T., Stopar, M., Hartman, J., Bizjak, M., & Modic, J. (2019, September). Privacy-Enhanced Machine Learning with Functional Encryption. In European Symposium on Research in Computer Security (pp. 3-21). Springer, Cham.
    - [SGP2018] Sans, E.D., Gay, R., Pointcheval, D.: Reading in the dark: Classifying encrypted digits with functional encryption. IACR Cryptology ePrint Archive 2018, 206, (2018).


### Build and Run Instruction
```sh
# Build
cargo build

# Run the test of disease prediction (using inner product functional encryption)
cargo test test_disease_prediction -- --show-output

# Run the test of neural network (using quadratic polynomial functional encryption)
cargo test test_neural_network -- --show-output
```
## Security Warnings

As of now, this project serves mainly proof-of-concepts, benchmarking and evaluation purpose and not for production use. Also implementation have not been fully-reviewed.

