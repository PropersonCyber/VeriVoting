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

        // Initializing voteCts
        EdOnBN254.Affine memory  Ct0 = EdOnBN254.Affine(0,0);
        EdOnBN254.Affine memory  Ct1 = EdOnBN254.Affine(0,0);
        for(uint i = 0; i < 3; i++){
            voteCts.push(voteCt({
                Ct0: Ct0,
                Ct1: Ct1
            }));
        }
    }
    
    //Get the qualification coin commitment type of all voters from the blockchain
    bytes32[] comm_array;

    //Get all voter eligibility coin promises
    function getComm() public view returns (bytes32[] memory comm){
        return comm_array;
    }

    uint[] sn_array;

    function getSn() public view returns (uint[] memory sn){
        return sn_array;
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
        vk.alpha = Pairing.G1Point(uint256(0x2f63e3741a1236284033c5457c7971a52d8b974a6f8bc70794c224cbc6167279), uint256(0x0c1b79ae754e5b94dc1e7b766387da36bc7aff58cfb7ca65ab687a1a81afcf73));
        vk.beta = Pairing.G2Point([uint256(0x0fa31ad226e2cdd32e2ef2ddf6d248d89ff1b98941731a16e285a587cc7bc36e), uint256(0x278a98cf66aecac49822f8b910123a015ded1a3ff116e0a7a46b0ef400cb115f)], [uint256(0x0fe998687b9fb3692c4ae26a059d389ad5679cc400ca101388fafebf722e1eb8), uint256(0x021f9a3c3fae7da638ad3383cec3e9f4136158422d8b7d57ae727084bbfe8233)]);
        vk.gamma = Pairing.G2Point([uint256(0x20909880e8dc437101145e867a7003c3c00948b12266f0469fdce0114a83913b), uint256(0x3046239c32411a265dcbc5b116e0eb80c1fc1ca5b56a8dd8662a8b7f5f173de2)], [uint256(0x0ec23ee560e9b3e3106d6287d8508b49c499547da90ba2975dc20d0e5dab6272), uint256(0x2868d068909f3a0a0a6a584fad777feec5da1d6154ceef54f416f90b250a3af2)]);
        vk.delta = Pairing.G2Point([uint256(0x2876730c0985a73df9f6016e20687601a06b879ef58cdce18a72ba8b1eaa2723), uint256(0x0fc30c96cc8b2b9be82f40271cb95cef6ec342013cc6ed1d0c930fc5eb83a119)], [uint256(0x1a29adec5cfbd27cc971f220f4b4f7b78fa64c8ab6595fa6e3c1e1e48fbf9415), uint256(0x0d373dd2f27bea5f384b99dca11e78a1986070e3cd444c33b9d36bbe36b558ba)]);
        vk.gamma_abc = new Pairing.G1Point[](31);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x10ca655cc0e506f29504b1e146b9343be7c873d57076d3918a45e76772e4a805), uint256(0x00c27801fe1e2906fec30221095898d72ccb1005b0cbe3bc5d6a085f978ac591));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x0462d0266af63ffbe98525042e1575b62b3515f38192c1a230f7e83f4e7078ab), uint256(0x19f2217cd971ab989ddc3b01368b35acd160ebad0254058343f010651b25d5da));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x283bcc592deee00c355417e916081a9e2c8f97769d470f488a6ae092fe2e6483), uint256(0x08afbda9bfd8962593c5245553212747e623c60ac4b00c2ea972e8cfa23c8b10));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x297df468fe0ac478619fb9ad050c5f8fdce9269590221d02e50f79886f8c2d22), uint256(0x11c64b57c87469e6d2ef8e2543632407fcfb8114bbb8207776feb29ac5f70bb5));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x2ad51dde6753796f0d973b04172939a3bb68116e6a4fbcb966bb7e77dc7f7b6d), uint256(0x282fa26fa08c0ff30bbb0e7b075bf824285e23a7d6f71fa4097f64473f9cdf58));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x1470b89c01425ad3541d11df47a85d80e361f1717db2e212cf4ec44a4217c875), uint256(0x12ac4a3ac14543c5f12897ffd15d33ab3551c1a6fe4e88989745ee20d55296fb));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x218ae464d572e47fca6ef136cf013a4bccf39d0077d227f6b0dc5106f511001c), uint256(0x19300b412b0d2fe4497abf8ce2137354ea14e5d3c63cb389b605540686c069cb));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x2fe8b30b1a32126d6055446711cf6c114722a751d3d3c675116eddb5ebb49f06), uint256(0x1ea475df2c003bb54bf33efb0fa52904d3070efb40c09921fcfed9de7f120d4d));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x094b80a88820462091f7a76f641f35f75a6a48c589d33a6b2507b5cdc9a66704), uint256(0x25785d9292cbe45123014066d8219b9086355763ff3497c6420862eb54d8a95e));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x2d18eb66c845dd025e89cbaf25ffbd4fc50e5371946fa86de8d31f28e30e4bbd), uint256(0x04c26b7c26845ac8d418e667ee0cc96698c707f3e0702b214f5625c40e19bcd3));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x26748831887a96526e57b25c6717dfc34f08eb4dc4cdde6884493e52dd13e378), uint256(0x19db3ad6585937736eadeb7a3e553ad5f288dfaa2a08b6bb0277851e753175dd));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x002be278775fc6ce9c4601efb0ca1c56e6782d19c68c16f18a2598eb904df421), uint256(0x2a63c8797bd7d38dc26b3ddd4c6f2a75ba85d0af4ede2c626401c37928c1a907));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x075100008faf5b5452827ff2a2de5e2a2748f01bb3e30423d20afc5729758a28), uint256(0x08e52fe40d021f0a257fd061449878eaa537cdd0d35aef10f511abc7ae89fb16));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x1b7a839a9904e55d576d3486dae84010e1a01c7c706e59b4e6a94cfe143776f1), uint256(0x05f63216de8fbbede3b5158963e51dc3b830ee2f17833b0d0774b0c2c79ce49e));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x2fea869315d3bfeb8eed1c1efcf88a0fab43f43a723ccdb37c66eda4ca44a446), uint256(0x10b5dd576ec75e44f633eda921a672181a6929fd3de04a46f31fce0a8ead06a8));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x122d8bdb133ea9bd9423d35fbacd961c73ac8795c9e8ad2aa6d0bee39e59f4e0), uint256(0x1ce91f3e160f0dcee37e50f7605dd3ae1249988a4f34254032745eebfa092e0d));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x2044f79de853dc149bd8c1dfb9b10207b803e56b3caf29c2c65fe2c9a6c42d76), uint256(0x2b193aca70c09d2e7f62876769e4869637d645a1c2ceb42c2e388b1ae0701b22));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x1f172a65720fdfc9866127e9c45118449d96f978c08892ee86a6a508e3c2ea8f), uint256(0x243d3c53b876c91e52e228910a9855c1bc41e4f7178cfe9d853bcc755de4fd9f));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x2a5e6b0965e7d050a1d5058d7c09742485227e5677e2af85746015775f698bee), uint256(0x213397a5858769179854590cc74516f3099a8b5c68d85f081e10ace7da8a37bb));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x1f1862ef8bd67ef8146971a8ca1c443b002d5082ab7492ad8cf4ed141c5251cc), uint256(0x23c8221646543e2eab205ebb01593271f3f7f6b5a05c4bda57fd04cc3516fd55));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x0b0c41f90cf244a9a3308f8a1fb82b18ecaf0ee77199afa13968fc80c3b1ce42), uint256(0x08e974e648e4eb55eba5af46fd7424a506b756bd18bb3cfc43a48ddc9a6b34c2));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x1d35036c1ce301ef9b5d795c0e45f60d4a1cc607e839821b082d636e87c1c71f), uint256(0x01e01cf53138357102346d34d6f4cb17689539a0c5195069c43ee90761f128aa));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x11124e38f37c00d0759ac8ef0be68fcc1907e99587fbfb4332d2e18dbf2936f8), uint256(0x1d78137f76b5ef70566940d78382add9fd6f03687c8cf36cc79cf410a303becb));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x2ad973a9d02eab89ae2ac5375d5533ce31fd9b84d1b1ac2fb85d3683b9d423c6), uint256(0x2bcebb60b3c1bfccba86cb282022f9c7d8aec4ea39bbe3019061875f05e92c6c));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x2c41cd25939459496d56f5e18019d6ad7a14ad8822f3f280cdfff03e857cd83d), uint256(0x0b07de0c2cf90709ee2862d672fafe7982e8bf6ec2dd532bde6ab3511ad7016a));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x275b71a9624489d8b89708413bc0e1b40d1f0f28c716e513e0bbe9d7406805db), uint256(0x2625ae5bacaf7158ae3915f4154ebebdb7c0edd774996695442b8114ec87132a));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x1d5a48be50cd0887356c654ee52690c805722603c3aa77566cda6723eae6db6b), uint256(0x16960b2fcbaea00b141f90706cfb86211fb89eedd012538ca5e20b4569291bb8));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x08eaf92876aaabf360e96f58698f4ce7dc985742f7bdabc0aab2830ac06490ba), uint256(0x16ea60e70f7237a47326df53b99b454a52ce4c14fc233c4ecff9c28824470de5));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x115534237c21b162fe91fca7e5d1b0680a6ba7fc833ab3eb2a64b4e8f42fd107), uint256(0x1a8e683c8f451074372571a9540fab10de34c1393ef2b9336d2d94ffc5829ba1));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x10f790eb65ac180d925c06cc7cde8b67e3fb6f39cbdd31a2f5ff41fbc6f5f4c0), uint256(0x133a08ddfc1d61e8f497befb0dee6891091a39f4ae5ce03ec10abe93a6c82cf3));
        vk.gamma_abc[30] = Pairing.G1Point(uint256(0x051b7bb61d13f970e73a4182631db5624ccefc6db52005ff1ef6a65f872bdf18), uint256(0x0ddff7b37c76e46684e98bfe43f2d4a19e81d0e373198eb5a383b8709719b080));
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
            Proof memory proof, uint[30] memory input
        ) public returns (bool r) {
        uint[] memory inputValues = new uint[](30);
        
        for(uint i = 0; i < input.length; i++){
            inputValues[i] = input[i];
        }
        if (verify(inputValues, proof) == 0) {
            ctAgg(input);
            judgeSn(input);
            return true;
        } else {
            return false;
        }
    }


    //Aggregate ciphertext Function
    // where root has 8 bits, ek has 2 bits
    function ctAgg(uint[30] memory input) private returns(bool){ 

        //Convert the point to BabyJubJub cuve point   
        EdOnBN254.Affine[] memory C0_tmp = new EdOnBN254.Affine[](candidate.getCandidateNum() * 2);
        EdOnBN254.Affine[] memory C1_tmp = new EdOnBN254.Affine[](candidate.getCandidateNum() * 2);
        uint k = 10;
        for (uint i = 0; i < candidate.getCandidateNum() && k < 30; i++){
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

    // Check whether sn is in the list of sn
    function judgeSn(uint[30] memory input) private returns (bool){
        uint k = 22;
        uint a =0;
        for(uint i = 0; i < 8; i++){ 
            sn_array.push(input[k]);
            k = k + 1;    
        }
        
    }

}
