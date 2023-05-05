// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.13;
import "./Pairing.sol";
import "./Candidate.sol";


contract Voter{
    using Pairing for *;
    
    //Get the qualification coin commitment type of all voters from the blockchain
    bytes32[] comm_array;

    //Get all voter eligibility coin promises
    function getComm() public view returns (bytes32[] memory comm){
        return comm_array;
    }

    //Vote ciphertext struct
    struct voteCt{
        Pairing.G1Point Ct0;
        Pairing.G1Point Ct1;
    }
    voteCt[] public voteCts;

    //declaration Candidate
    Candidate public candidate;
    constructor(address ContractAddress){
        candidate=Candidate(ContractAddress);
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


    //Aggregate ciphertext Function
    function ctAgg(uint w) public returns (Pairing.G1Point[] memory A0, Pairing.G1Point[] memory A1){    
        A0 = new Pairing.G1Point[](candidate.getCandidateNum());
        A1 = new Pairing.G1Point[](candidate.getCandidateNum());
        //Part I. Aggregation
        for(uint i = 0; i < candidate.getCandidateNum(); i++){
            A0[i] = Pairing.addition(Pairing.scalar_mul(voteCts[i].Ct0,w),A0[i]);
            candidate.setA0(A0[i]);
        }
        //Part Ⅱ.Aggregation
        for(uint i = 0; i < candidate.getCandidateNum(); i++){
            A1[i] = Pairing.addition(Pairing.scalar_mul(voteCts[i].Ct1,w),A1[i]);
            candidate.setA1(A1[i]);
        }
        return (A0, A1);
    }

}