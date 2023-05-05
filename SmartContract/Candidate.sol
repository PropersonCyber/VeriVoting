// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.13;
import "./EdOnBN254.sol";
import "./Pairing.sol";
import "./Voter.sol";

contract Candidate{
    using Pairing for *;
    using EdOnBN254 for *;
    //CandidateNum denote the number of Candidate
    uint CandidateNum;

    //get Candidate number function
    function getCandidateNum() public view returns(uint Num){
        return CandidateNum;
    }


    //Decryption Key Array
    Pairing.G1Point[] public DkArray;
    
    //The method of get DkArray
    function getDk() public view returns (Pairing.G1Point[] memory dk){
        return DkArray;
    }
    
    //Set the type of ciphertext aggregation result obtained from the blockchain
    Pairing.G1Point[] A0_array;
    Pairing.G1Point[] A1_array;
    function setA0(Pairing.G1Point memory temp)public{
        A0_array.push(temp);
    }
    //Obtain the ciphertext aggregation result function
    function getA0() public view returns (Pairing.G1Point[] memory A0){
        return A0_array;
    }

    function setA1(Pairing.G1Point memory temp)public{
        A1_array.push(temp);
    }
    function getA1() public view returns (Pairing.G1Point[] memory A1){
        return A1_array;
    }

    //sets the count struct
     struct voteTally {
         uint name;
         Pairing.G1Point voteCount;
     }

    //Set up to fetch the vote count from the blockchain
    voteTally[] public t_array;

    //
    Pairing.G1Point[] SigArray;
    //获取验证通过的部分解密秘钥函数
    function getSig() public view returns (Pairing.G1Point[] memory Sig){
        return SigArray;
    }

    //constructor function -> Initialize the number of voters
    constructor(uint cand_num){
        CandidateNum=cand_num;

    }

    //Verify the partial decryption secret key
    function sigVerify(Pairing.G1Point[] memory Temp_A0_array, Pairing.G2Point memory g2,Pairing.G1Point[] memory candidateSig_array, Pairing.G2Point[] memory vk) public returns (bool){
        //Get the number of candidates
        bool[] memory res = new bool[](CandidateNum);                                      
        for(uint i = 0; i < CandidateNum; i++){
            res[i] = Pairing.pairingProd2(Temp_A0_array[i], g2,candidateSig_array[i], vk[i]);  
            SigArray.push(candidateSig_array[i]);       
        }
        for(uint i = 0; i < CandidateNum; i++){
            if(res[i]){
                return true;
            }
        }   
        return false;         
    }


    
    /*  
        Candidate Verify function:
        pubKey: public key of Prover
        H:
        h:
        c:
        s:
        R:
        g:
    */


    function CandVerify(EdOnBN254.Affine memory pubKey,EdOnBN254.Affine[] memory H,EdOnBN254.Affine[] memory h,uint c,uint s,EdOnBN254.Affine[] memory R,EdOnBN254.Affine memory g) public view returns (bool)
    {
       EdOnBN254.Affine[] memory temp_res=new EdOnBN254.Affine[](3);
       temp_res[0]=EdOnBN254.mul(pubKey,c);
       temp_res[1]=EdOnBN254.add(temp_res[0],R[0]);
       temp_res[2]=EdOnBN254.mul(g,s);

        require((temp_res[1].x==temp_res[2].x)&&(temp_res[1].y ==temp_res[2].y ),"Verify pubKey^c*R==g^s No Passed!");

        for (uint i = 0; i < H.length; i++) {
             temp_res[0]=EdOnBN254.mul(H[i],c);
             temp_res[1]=EdOnBN254.add(temp_res[0],R[i+1]);
             temp_res[2]=EdOnBN254.mul(h[i],s);
            require((temp_res[1].x==temp_res[2].x)&&(temp_res[1].y ==temp_res[2].y ),"Verify H_i^c*R_i==h_i^c No Passed!");
        }
        return true;
    }


    /*
        Candidate Aggregation function

    */
    function Agg() public{
        Pairing.G1Point[] memory dk = new Pairing.G1Point[](CandidateNum);   
        //judge length of dk_arry
        if(DkArray.length==0){
             for(uint i = 0; i < CandidateNum; i++){
                DkArray.push(SigArray[i]);          
            }  
        }else{
            
            for(uint i = 0; i < CandidateNum; i++){
               (dk[i].X , dk[i].Y) =EdOnBN254.PointAdd(dk[i].X,dk[i].Y,SigArray[i].X,SigArray[i].Y);
                DkArray[i]=dk[i];
            }
        }
    }




    /*
    Tally phase

    */
    function tallyVote() public returns (Pairing.G1Point[] memory t_res){
        //Defines an array to store the results of the ballot
        Pairing.G1Point[] memory t = new Pairing.G1Point[](CandidateNum);
        //Decluttering the decryption key
        for(uint i = 0; i < CandidateNum; i++){
            t[i] = Pairing.addition(A1_array[i], Pairing.negate(DkArray[i]));
            t_array.push(voteTally({
                name: i,
                voteCount: t[i]
            }));
        }
        return t;       
    }

}