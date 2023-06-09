# VeriVoting
This repository is an simulation test for smart contract side, along with candidate and voter side in VeriVoting.

The development tools we empolyed are:
1. Online [**Remix**](https://remix.ethereum.org/) IDE environment is for the contract side, to verify voting transactions and decryption-key transactions;
2. [**Zokrates**](https://zokrates.github.io/) toolbox is for implementing the voting function;
3. Since Zokrates adpoted **BabyJubJub** ECC, we refer to two additional libraries:

   3.1 The BabyJubJub library written in **Solidity**, see <https://github.com/yondonfu/sol-baby-jubjub>, which we used for verifying decryption keys from candidates;
   
   3.2 For candidates, the corresponding BabyJubJub library written in **Python**, see [here](https://github.com/barryWhiteHat/baby_jubjub_ecc/blob/620dbb661a8a24b29eb92fd488201b988609db9e/tests/sapling_jubjub.py), is used to generate decryption keys and proofs.
   
   3.3 The parameters are based on: [here](https://github.com/HarryR/ethsnarks/tree/9cdf0117c2e42c691e75b98979cb29b099eca998/src/jubjub).
