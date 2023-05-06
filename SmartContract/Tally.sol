// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.13;
import "./EdOnBN254.sol";
import "./Pairing.sol";
import "./Voter.sol";
import "./Candidate.sol";

contract Tally{
    using Pairing for *;
    using EdOnBN254 for *;
    //declaration Candidate and voter
    Candidate public candidate;
    Voter public voter;
    constructor(address ContractAddress, address VoterAddress){
        candidate = Candidate(ContractAddress);
        voter = Voter(VoterAddress);
    }

    //sets the tally struct
     struct voteTally {
         uint index;
         EdOnBN254.Affine voteCount;
     }

    //The tally result
    voteTally[] public t_array;

    
    /*
    Tally phase

    */
    function tallyVote() public returns (EdOnBN254.Affine[] memory t_res){
        //Defines an array to store the results of the ballot
        EdOnBN254.Affine[] memory t = new EdOnBN254.Affine[](candidate.getCandidateNum());

        //Decluttering the decryption key
        for(uint i = 0; i < candidate.getCandidateNum(); i++){
            //Get the inverse of decryption keys
            EdOnBN254.Affine memory inverse_tmp = EdOnBN254.Affine(0,0);
            (inverse_tmp.x, inverse_tmp.y) = (EdOnBN254.inverse(candidate.getDk()[i].x), EdOnBN254.inverse(candidate.getDk()[i].y));
            //Compute the decryption result
            t[i] = EdOnBN254.add(voter.getCtArray()[i].Ct1, inverse_tmp);
            t_array.push(voteTally({
                index: i,
                voteCount: t[i]
            }));
        }
        return t;       
    }
}