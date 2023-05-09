// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.13;
import "./EdOnBN254.sol";
import "./Voter.sol";
import "https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/utils/Strings.sol";

contract Candidate{
    using EdOnBN254 for *;
    //CandidateNum denote the number of Candidate
    uint CandidateNum;
    Voter public voter;
    constructor( uint candi_num){
        CandidateNum = candi_num;
    }

    //Get the number of candidates
    function getCandidateNum() public view returns(uint Num){
        return CandidateNum;
    }


    //Decryption Key Array
    EdOnBN254.Affine[] public DkArray;
    
    //The method of get DkArray
    function getDk() public view returns (EdOnBN254.Affine[] memory dk){
        return DkArray;
    }

    //Received partial decryption keys
    EdOnBN254.Affine[] RecvDKArray;
     
    /*  
        Candidate's partial decryption keys Verify function:
        pubKey: Public key of the candidate
        decKeys: Partial decryption-keys array
        c: The hash result of partial decryption keys, i.e., the challange value from the random oracle
        s: The proof value, i.e., s = r + c * sk
        R: The commitment part in Fiat-Shamir-based NIZKs, i.e., R = G^r
    */


    function CandVerify(address VoterAddress,EdOnBN254.Affine memory pubKey,EdOnBN254.Affine[] memory decKeys,uint256  c,uint256  s,EdOnBN254.Affine[] memory R) public returns (bool)
    {
       //verify c==c_res ?
       bytes memory c_res="";
       for(uint i = 0; i < R.length; i++){
          bytes memory temp=abi.encodePacked(Strings.toString(R[i].x),Strings.toString(R[i].y));
          c_res=abi.encodePacked(temp,c_res);
       }
       require(bytes32(c)==keccak256(c_res),"C!=C_res");
       EdOnBN254.Affine[] memory temp_res=new EdOnBN254.Affine[](3);
       temp_res[0]=EdOnBN254.mul(pubKey,c);
       temp_res[1]=EdOnBN254.add(temp_res[0],R[0]);
       temp_res[2]=EdOnBN254.mul(EdOnBN254.primeSubgroupGenerator(),s);

       require((temp_res[1].x==temp_res[2].x)&&(temp_res[1].y ==temp_res[2].y ),"Verify pubKey^c*R==g^s No Passed!");
        voter = Voter(VoterAddress);
        for (uint i = 0; i < decKeys.length; i++) {
             temp_res[0]=EdOnBN254.mul(decKeys[i],c);
             temp_res[1]=EdOnBN254.add(temp_res[0],R[i+1]);
             temp_res[2]=EdOnBN254.mul(voter.getCtArray()[i].Ct0,s);
            require((temp_res[1].x==temp_res[2].x)&&(temp_res[1].y ==temp_res[2].y ),"Verify H_i^c*R_i==h_i^c No Passed!");
        }
        //Call the aggregation function.
        Agg();
        return true;
    }
        
    /*
        Candidate's partial decryption keys Aggregation function

    */
    function Agg() private returns(bool){
        EdOnBN254.Affine[] memory dk = new EdOnBN254.Affine[](CandidateNum);   
        //judge length of dk_arry
        if(DkArray.length==0){
             for(uint i = 0; i < CandidateNum; i++){
                DkArray.push(RecvDKArray[i]);          
            }  
        }else{
            
            for(uint i = 0; i < CandidateNum; i++){
               (dk[i].x , dk[i].y) =EdOnBN254.PointAdd(dk[i].x,dk[i].y,RecvDKArray[i].x,RecvDKArray[i].y);
                DkArray[i]=dk[i];
            }
        }

        return true;
    }


    function toString(uint value) internal pure returns (string memory) {
            if (value == 0) {
                return "0";
            }
            uint temp = value;
            uint digits;
            while (temp != 0) {
                digits++;
                temp /= 10;
            }
            bytes memory buffer = new bytes(digits);
            while (value != 0) {
                digits -= 1;
                buffer[digits] = bytes1(uint8(48 + uint(value % 10)));
                value /= 10;
            }
            return string(buffer);
    }
}