// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.13;
import "./Pairing.sol";
import "./EdOnBN254.sol";
import "./Candidate.sol";


contract Voter{
    using Pairing for *;

    //declaration Candidate
    Candidate public candidate;
    constructor(address ContractAddress){
        candidate=Candidate(ContractAddress);
    }
    
    //Get the qualification coin commitment type of all voters from the blockchain
    bytes32[] comm_array;

    //Get all voter eligibility coin promises
    function getComm() public view returns (bytes32[] memory comm){
        return comm_array;
    }

    //Verify the validity of a qualification coin commitment
    function commVerify(string memory str, bytes32 comm) public returns(bool) {
        bytes32 hash = keccak256(abi.encodePacked(str));   
        if(hash == comm){           
            comm_array.push(comm);
            return true;
        } 
        return false;
    }


        //Vote ciphertext struct
    struct voteCt{
        EdOnBN254.Affine Ct0;
        EdOnBN254.Affine Ct1;
    }

    voteCt[] public voteCts;
    //Get the state variables of receiving partial decryption keys
    function getCtArray() public view returns (voteCt[] memory ctArr){
        return voteCts;
    }

    //Verify the Tx containing statement (ct,sn) and proof pi

    struct VerifyingKey {
        Pairing.G1Point alpha;
        Pairing.G2Point beta;
        Pairing.G2Point gamma;
        Pairing.G2Point delta;
        Pairing.G1Point[] gamma_abc;
    }
    struct Proof {
        Pairing.G1Point a;
        Pairing.G2Point b;
        Pairing.G1Point c;
    }
    function verifyingKey() pure internal returns (VerifyingKey memory vk) {
        vk.alpha = Pairing.G1Point(uint256(0x0bc0564d2d9e22cb2bed0ac1628543f550c26b47e0d86033521d26d1bd7ab08e), uint256(0x2e28dc9c6dc79f221bc5446bbaf3bac5900554dfed2be2a76b75a19702ef0609));
        vk.beta = Pairing.G2Point([uint256(0x225d4a5c4a67db115dad88e30c04d6bdb2ba02c0cbd97d365111057bf895702b), uint256(0x2ee67d7d951d73606a991a2486119b7528bc978ef70ea2c70c9eeba426126d4a)], [uint256(0x00303240ca60db381e22c8bf8994ab08cfa37df68787593419ca26c076b36f00), uint256(0x252a062308d593a4d548b7820f6fd978f010b95acd4042c1a3ad2cf6f02270ba)]);
        vk.gamma = Pairing.G2Point([uint256(0x2460712ed4f89c215f3b0f2a5c25448e977ce85ae56bd907dfac1dd7d65cffcb), uint256(0x24b9b0c0ff4ff4d640c47250711daa66ea3e13257c870d73ae3abc993159288c)], [uint256(0x1ac15952b2540d321a1c014d825678acd3f62f37b00a06c56add49525c9d1feb), uint256(0x035c2c3d29e029459d5d0a834710c4a7539f3c3f28155d960d70d0963677a13d)]);
        vk.delta = Pairing.G2Point([uint256(0x11909dc68f2e4ce1f8e89c6afe3908c46a5bd14e21e3d5d10236fd189b52ea10), uint256(0x09cfc43a7469faa17c1ac6c1dbd7e3596a656bf7160d0df5b8c3a89d2c05ab36)], [uint256(0x26eedc9cc03a40001f257e12aa7e6fb5b2ddd94c7405cde2c74f673d07a93564), uint256(0x135789cfea23b5f7bd4ba335661248ab207c7a0d115faf381751b66926f23ec2)]);
        vk.gamma_abc = new Pairing.G1Point[](21);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x2d37e08b4a1e69229e59bffae8b2812c5e40d80f86857b64d2f4408d43d8b88d), uint256(0x27eea3eb221e5f508941b283d8e195b4818797eec111ad43328c290dba46a769));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x1011bc7ecb601af2b1394c6b481e641420aa344936cf152a4aa779f756cb9665), uint256(0x0e4b2000cb35ce015e301a79682d91c7de8fb520d78d72b802fe3a2a3c091bf5));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x1601069ae17c4f12c3f53fa543b3a8e8158512b714fce892571dc0364729783e), uint256(0x1f78b79a64ebefeae2b930cbc60f9b8dbb73aacb2f211504c34148ed8974a247));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x14a94ba990a337c55f01743e637aacc2ab4c2de51feabd6a8c4a8f432e0a42f2), uint256(0x15fd32615feb2cf64e9a974a696a1fe35bf0c63857fb8d6f23f232989404c539));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x00bda3ec8147c0b13d06a35bebfc5cc4c8b5b585f6c3b245a96f35a74fd90e5f), uint256(0x2501060dec44804b5a166d344cf808059ffba20e02117606c3d2de2e9459c32a));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x11de7d655c5b29fc9fef829c367705e384b0de05f202155dd09ef9d96b9142dd), uint256(0x0c9ba7ac9b9c1a42e71f02af7496f6c585899a2a17908fa1231347bc63d808e2));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x20f20b0df3c59b04a5d8a2c152d59bce23cf58a84b33bf8261cc7ecdf9bca8d5), uint256(0x2eb115430945924d69013bfe8ebe8a10e2434c0f460ead9f0dd6fb263af35759));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x16eab959331445a3ea92cd2f4aea1ed4f25dc61874a4c9e97d656ab619834980), uint256(0x1cd3d077d6eef6f14c400b3d56ccb09382f29e7db4016f98e9b8098a9a384ce4));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x208d33cb5ab4a5a1b14d0f304f711ab054a1d2be00b8d0518b990fb0f965873e), uint256(0x1749839790bfe9665887e2ac23c9c4869933fec6822cb0805f343f614ac9f1c0));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x2f401983abe431f3f238d503c216dddb2e901e0d99201d7f35f757c2db0dd475), uint256(0x0de59c1d34e3535d3af5f8fe0f93df42c1e95a983c0b70661eefdac3feff4f39));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x17eedfae918c574111909b5f56de07df8db317ee93e99193d74f10241e586f0a), uint256(0x11b5c80f1d2716ceff72745bd849c0be0f5e8c870a432a29d3ce50208be67b9e));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x0b1c62c120b4f47f748d64a8be6be0d5c21d30d2634bf0c0474a80b168f44cfd), uint256(0x1c73aced2efa12b3e0493e64ee22e0eaed413558b117f056ac5e7d35efe67143));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x2ed147e074c90c502c3d330aaeacc106850b365ace2fd5af49357a8e1d59b445), uint256(0x2115895dfccd6ca22cc2eae229f461aeacb5cb3c1eed7cf124ed783eb5b3c187));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x276c2595821f42a33ca7df67aa5ae2747b0d1f40e0f105fb8ce31e9a33365651), uint256(0x2aee461c94e01c3b4ac7c2b2ebd7bcfcabb602c129a926cb1e38157d875acd25));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x0474a5b4eb89b3db0d865079f7f000bbfa80c913663a2814ba6fb8e0534d11f0), uint256(0x1e545b3616dbbaf6a5a96bdb8e402bd734072e39e11847029b8190aec67eeb80));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x170e700b735cf34450d44cec8e1a77d0c0c9a98de9c8629a9652fbef1c8adf2a), uint256(0x22591e9fbdcffd0d4f382af701362e4e0041166bdca5429c165b77a2012148b4));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x11f82d352b721bd20069ee71e43fea75bb42d4054a489fcb01f84f848f65cf2c), uint256(0x2873ab0cb0538e37694c27e0aa8110299771ccdc8a55fddf01e76c1d11d8216a));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x02f24e3dd8c430f599cbf935dfc195f5c90f814424a66be4e0fcfa5cb91fb1f7), uint256(0x20e7f4c1284d87a65cfe474c393db30e01d6ec536286339a48dab439df253393));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x166a1bc9a97904f2f81021d3ee5ca49ba267d14bb627cc34f83022b5a317cf1c), uint256(0x2523743d1e74ae1db99379f3de011cf412824841f51bd720877b28e6a002d228));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x29f83c9f2bb62ee0492e9dbc7aef29835235209de87da289bdb602a32cffc787), uint256(0x216c301bf71e895ed915f3a49ea9039aa73ca18c1ec5f0d15e4735a8ff1c5222));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x24ce15b6da1b38309362c2d9d9b2d0ad19d944f4d44e56f29c86193507392e96), uint256(0x2cf27b96594b92a05a7ae6fa3476e1ce98637aea3082f0d26bc59a411e567fe1));
    }
    function verify(uint[] memory input, Proof memory proof) internal view returns (uint) {
        uint256 snark_scalar_field = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        VerifyingKey memory vk = verifyingKey();
        require(input.length + 1 == vk.gamma_abc.length);
        // Compute the linear combination vk_x
        Pairing.G1Point memory vk_x = Pairing.G1Point(0, 0);
        for (uint i = 0; i < input.length; i++) {
            require(input[i] < snark_scalar_field);
            vk_x = Pairing.addition(vk_x, Pairing.scalar_mul(vk.gamma_abc[i + 1], input[i]));
        }
        vk_x = Pairing.addition(vk_x, vk.gamma_abc[0]);
        if(!Pairing.pairingProd4(
             proof.a, proof.b,
             Pairing.negate(vk_x), vk.gamma,
             Pairing.negate(proof.c), vk.delta,
             Pairing.negate(vk.alpha), vk.beta)) return 1;
        return 0;
    }
    function verifyTx(
            Proof memory proof, uint[20] memory input
        ) public returns (bool r) {
        uint[] memory inputValues = new uint[](20);
        
        for(uint i = 0; i < input.length; i++){
            inputValues[i] = input[i];
        }
        if (verify(inputValues, proof) == 0) {
            ctAgg(input);
            return true;
        } else {
            return false;
        }
    }


    //Aggregate ciphertext Function
    function ctAgg(uint[20] memory input) private returns(bool){ 
        //Convert the point to BabyJubJub cuve point   
        EdOnBN254.Affine[] memory C0_tmp = new EdOnBN254.Affine[](candidate.getCandidateNum() * 2);
        EdOnBN254.Affine[] memory C1_tmp = new EdOnBN254.Affine[](candidate.getCandidateNum() * 2);
        uint k = 0;
        for (uint i = 0; i < candidate.getCandidateNum() * 2; i++){
            (C0_tmp[i].x, C0_tmp[i].y) = (input[k], input[k+1]);
            k = k + 2;
            (C1_tmp[i].x, C1_tmp[i].y) = (input[k], input[k+1]);
            k = k + 2;
        }
        //Part I. Aggregation, i.e., CT_0
        for(uint i = 0; i < candidate.getCandidateNum(); i++){
            (voteCts[i].Ct0.x, voteCts[i].Ct0.y) = EdOnBN254.PointAdd(C0_tmp[i].x, C0_tmp[i].y, voteCts[i].Ct0.x, voteCts[i].Ct0.y);            
        }
        //Part Ⅱ.Aggregation, i.e., CT_1
        for(uint i = 0; i < candidate.getCandidateNum(); i++){
            (voteCts[i].Ct1.x, voteCts[i].Ct1.y) = EdOnBN254.PointAdd(C1_tmp[i].x, C1_tmp[i].y, voteCts[i].Ct1.x, voteCts[i].Ct1.y);
        }
        return true;
    }

}