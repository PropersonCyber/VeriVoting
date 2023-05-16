// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.13;
import "./Pairing.sol";
import "./EdOnBN254.sol";
import "./Candidate.sol";
import "https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/Strings.sol";

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

    bytes[] sn_array;
    
    function getSn() public view returns (bytes[] memory sn){
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
        vk.alpha = Pairing.G1Point(uint256(0x1a079745df4ee01204920d5a25f6b4bbf0eb247555c85849d124b7724ac5b043), uint256(0x2960791c4f137af3645694051b5f17e5a261cd91eda1e59debff7333997e43b7));
        vk.beta = Pairing.G2Point([uint256(0x2663de1735aa79cef9fccc5ede30d8b3f96aea841ea6fa522a8d8b66c500f43e), uint256(0x186f82686637ba168be8cc0fc72c4037c9840ebed1f590da45d3e2adf45345ec)], [uint256(0x128ccf8b5713a0a6ab46673d415dd68d95782d5176341f48b605ef8315ac250e), uint256(0x20434dc45c2360dcccd93f9d04fab171b287f86573e77ae6463576fd49cf86a8)]);
        vk.gamma = Pairing.G2Point([uint256(0x04e6143049ffa48d59023e34d222e790836628e211a89d7903b09758d44b6a9a), uint256(0x0941c5218cbcc0057e1337879610e73785bb5765f9e354779d335327b4011bfd)], [uint256(0x21c0eeb14322d45433a738d7cc435b34c0f727faef31f88c56b39aee64306390), uint256(0x1dfdf833c9c1020795bc69a7618d66540e144f1f56d99609bbd8244b5d2ed8d2)]);
        vk.delta = Pairing.G2Point([uint256(0x020d0fe385782be93dd95b482148c6464f76b97baf856d4eff26baf4667ff3c2), uint256(0x200661ad7f8a6a5cab88d26baec3fa16a8dedf3affd84007488fe6c4a1b11e0d)], [uint256(0x142a8c3f59dfc4e8d8607feef0dbf892789cadff5404109ab30ac3349c0bdf3a), uint256(0x07e7705cc46a563d2593ad5396ec26c3da178c276cba8e830f17ef823c5a80fb)]);
        vk.gamma_abc = new Pairing.G1Point[](31);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x015a7f310d24e84c43c3dec37a57048d5d8d5c19530c5565f875a7a458d06bc1), uint256(0x01acdf662c380f2b0aa32a572c770892b77e3f8a7cc969152d0492e8d3a16643));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x126663f98aa1f4f6e814e818679b88e552f6c73ba63a7f411d57575c27c12181), uint256(0x17f7140e41fd89531e32cd1961fac940e7ddb65040f4b60da4d05527d1c98df4));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x2e97db30e58772d96dc86cf6faed25fc2577de0a64c1706ccd7b4e92cc3a63b5), uint256(0x054613122a94f678fea26f966ae7b043efded493c9c59a58c8dd1c2399a97e85));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x230b1cb152c91d1c395cc806be0e3ecf517cf6c3a56eb2ce1f2871a977a20356), uint256(0x2ad896fe138b7a6c97b8d969166838f6453853c61f5d62fa8355f85f02d14ce7));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x1d6b39c5f37092881bc6b7e6b07b86d1d8f04c1a6e2fbe5f3a8e8abc547e2a2d), uint256(0x1506fce83feb0d178c82efa188365067c06c2707600b35de01ca129dfe12a7e9));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x0e55727c57c3a2015643fa4ed5f1485bb8f0dc81493c5dd38864a0a595ad9902), uint256(0x16f1053fd642e8612df719130e1218abe95dba01746bcfb1fef49b840ffc9d5f));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x2664b9ff034db2de6e424d599585625ea822fedfdaea8b451068dbc24cdf1fa2), uint256(0x04ead02c0382a2bf3271a671ff1e986f4fcc414a67730157855cc065d6633836));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x05210ca1d147bfe76696bd7511debde0b09a4bfe78da58b5bb9363b575f2d79d), uint256(0x0f7b58e9c96a1ea0ba77da95ca8e56a1b373e8c2c722acd33c944c0a53c9a65c));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x02cc1bbfbcfe9c8d194344b1b12aa78e5d230d22427b66511868a89b4d382eee), uint256(0x08b4129d81d869369ee815d0ae30fbaa943e8c3c1583a9312a4bb02deec4f2da));      
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x0bcc01df24af1979f4dadcbc97ecd78d603cdad259f5bd5e0fff48a9e0733994), uint256(0x0b9b1874eb8ede6fa85c330282f9e7ac826914d8417f2fda9d832be235048687));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x0ea8b1e25ba534f247a4801af697c74c404dcab4bf23be59ea3af736270636f6), uint256(0x2a9a76f47241382b36ff1886159abc2f409b9211edf71fca641b55d42dc62cc1));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x2124db200372a38dc7bf5e7fb8fcb285f46f72af54e61703d1743f3883459ef8), uint256(0x300d30eb1600b11071b5343769f97497ec4c0a92174e84549f3ac8502daf034a));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x238520170643d202cca3efe1e81e7ddda3dcacda5c14fd382ef890648ec73134), uint256(0x2fab9b176e6e1ebfeca9009bdbf6e238551fdb49865724fb93cf23f6d7817ff1));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x09c90f02238ae11e8fb020739ef8ae29b4bfa328800a73433ee8cc2cedf06f58), uint256(0x133a185f5c3398a9c94775297013d49faf178c75c9f87eeb9df83639ad4c78eb));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x07058d89ddbf50d5b4cd70729d84d904f4473c5e58be5d0be8b5d19490179666), uint256(0x10fa680d6c813c787530b9c275b04a648367ff83d63075c0eda29d976c9fb574));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x11b6653cea0e9c08039397967b486dfd6f7a711ffe481c2ec4e1e647f15abbcd), uint256(0x2c07a54d950162ecbfc06979a82829a72011cc25f637390f4b327882704fecf3));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x02fbc3b187b0c0ca63e8316319076b57a2cb0e32bbea5c52ac1817dfd7ebc9f8), uint256(0x176221f1482b569f1bc6f6d7d816c6e24d50f7637f26a2050aeff68b0f387fca));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x2a13d8dc7416e3b7dee12e0a7c1ef7a33a9a22b87c8e21d7f0dd043ae2291c86), uint256(0x1503558611d032557e481819f567ffda84447a3c4f417857fa659fc3cfa0e5c5));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x20baae6658687042556885ec2b4c7a6316d03e4443709dfe35273b78048a5c13), uint256(0x0603d6f3cc8af169da85eaced1efd65cf904cce6f4a478a9df39c4cb73aa01d6));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x2980446a62e1553f6905c432e3591181eb7c6f603b856850c30c7cd694620ca8), uint256(0x1fde90922438ff95089b07b8e75429d90b7259b0c5f6bcb26451013eedeb2d5d));
        vk.gamma_abc[20] = Pairing.G1Point(uint256(0x2fa4efeaaa2f6eac531e0b3f16d143fc5be15fae47b548af69bba6c081daf10d), uint256(0x008fc306d601a2a247260bd87aea8dd24e6f1d7183e09c4f9e39ba3843ccfeec));
        vk.gamma_abc[21] = Pairing.G1Point(uint256(0x2bb13b258b62908c40373d6b02cfee25df5ae18e7e482cec5dc2cdfc95b5c8c0), uint256(0x2a98edda99dffa33274597956c4ee542438681979ae32a689c45c64e5ac9e3a3));
        vk.gamma_abc[22] = Pairing.G1Point(uint256(0x17b982e7f4fc386da06d2117de8de40eb998e53f716a10a24fc85acec59cd5f5), uint256(0x07fccafa22628bc480a72c87bf46c00206117070f302d6c426334c63079b79fa));
        vk.gamma_abc[23] = Pairing.G1Point(uint256(0x273f2b8d09e698ca335aaaefbdc4c5c41473839d90da4dadb2e7ed25376048af), uint256(0x0130ae8664509c55b6c1759cd76464f4f075a209d3bd1e8b0f81d0a29de9f508));
        vk.gamma_abc[24] = Pairing.G1Point(uint256(0x2dce4560d7853222a02f57563db7cecc21fbd8cab534e9449e446c782123c363), uint256(0x0a9fbd56e4f8bf11ed8eae7f046aa4338a9b9373459b5eca8685d4a89c849d75));
        vk.gamma_abc[25] = Pairing.G1Point(uint256(0x00124342554e435cef7e25be424823e48ae0ee26e4ce33dbaa62a450df6360ea), uint256(0x08770843ee5264e9c824b626678a54b492c1dada195cbdb9b127013c34dd16e8));
        vk.gamma_abc[26] = Pairing.G1Point(uint256(0x00ee202b6a88a292d5ffca3d1d8bcd279a227e19832e3b9c5637b60ab959200d), uint256(0x25f1b293dc202875d3fee3082424fcdc256dc7621d3b09dc4f8dffd3ba98e10a));
        vk.gamma_abc[27] = Pairing.G1Point(uint256(0x0bad3d75889abcc8769dd106610b74cae24abccfbbfa6c04e47fe8d9eb97009a), uint256(0x2b25fcc15389563e8f9d89e650286fdda867c00ef94cd42a4e31a9704d575db5));
        vk.gamma_abc[28] = Pairing.G1Point(uint256(0x01d262b973bbba91a9ca392ff7084b9fadc14057698ec2c4f494105b499217b8), uint256(0x2b7012b8607f931ce180afd0604e2756e9b6f0c8c7ec3b377c88f05143cc9cd2));
        vk.gamma_abc[29] = Pairing.G1Point(uint256(0x226d76126e1b593e62f2b7869a9f894ad194b5fc3cd1ca2f5d6c0cb1f8c4bea8), uint256(0x298d07b8ed155707f4c49ca562e2121c4e86220c03b84611acb6827a78d1d989));
        vk.gamma_abc[30] = Pairing.G1Point(uint256(0x05d1f12d9583143d9fdcbf61fc782b2f7603888e8530f34cef2abb65489f07e2), uint256(0x2f8551b80dadc8a9b1591ff67fc75108f09dac293089bc87b74660f62638bc05));
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

    // Check whether sn is in the sn list
    function judgeSn(uint[30] memory input) private returns (bool){
        uint k = 22;
        bytes memory b;
        for(uint i = 0; i < 8 && k < 30; i++){  
            b = strConcat(toBytesNickJohnson(input[k]),b);
            k = k + 1;              
        }
        for(uint j = 0; j < sn_array.length; j++){
            if(keccak256(b) == keccak256(sn_array[j])){
                return false;
            }
        }
        sn_array.push(b);
        k = k + 1;
        return true;
                      
    }
    function toBytesNickJohnson(uint x) internal pure returns (bytes memory c) {
        c = new bytes(32);
        assembly { mstore(add(c, 32), x) }
    }

    function strConcat(bytes memory _a, bytes memory _b) internal returns (bytes memory){
        bytes memory _ba = bytes(_a);
        bytes memory _bb = bytes(_b);
        bytes memory ret = new bytes(_ba.length + _bb.length);
        bytes memory bret = bytes(ret);
        uint k = 0;
        for (uint i = 0; i < _ba.length; i++)bret[k++] = _ba[i];
        for (uint i = 0; i < _bb.length; i++) bret[k++] = _bb[i];
        return bytes(ret);
   }  

}