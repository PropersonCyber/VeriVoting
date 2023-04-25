// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.13;

// This file is MIT Licensed.
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
pragma solidity ^0.8.0;
library Pairing {
    
    struct G1Point {
        uint256 X;
        uint256 Y;
    }
    // Encoding of field elements is: X[0] * z + X[1]
    struct G2Point {
        uint[2] X;
        uint[2] Y;
    }
    
    /// @return the generator of G1
    function P1() pure internal returns (G1Point memory) {
        return G1Point(1, 2);
    }
    /// @return the generator of G2
    function P2() pure internal returns (G2Point memory) {
        return G2Point(
            [10857046999023057135944570762232829481370756359578518086990519993285655852781,
             11559732032986387107991004021392285783925812861821192530917403151452391805634],
            [8495653923123431417604973247489272438418190587263600148770280649306958101930,
             4082367875863433681332203403145435568316851327593401208105741076214120093531]
        );
    }
    /// @return the negation of p, i.e. p.addition(p.negate()) should be zero.
    function negate(G1Point memory p) pure internal returns (G1Point memory) {
        // The prime q in the base field F_q for G1
        uint q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
        if (p.X == 0 && p.Y == 0)
            return G1Point(0, 0);
        return G1Point(p.X, q - (p.Y % q));
    }
    /// @return r the sum of two points of G1
    function addition(G1Point memory p1, G1Point memory p2) internal view returns (G1Point memory r) {
        uint[4] memory input;
        input[0] = p1.X;
        input[1] = p1.Y;
        input[2] = p2.X;
        input[3] = p2.Y;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 6, input, 0xc0, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success);
    }

    /// @return r the product of a point on G1 and a scalar, i.e.
    /// p == p.scalar_mul(1) and p.addition(p) == p.scalar_mul(2) for all points p.
    function scalar_mul(G1Point memory p, uint s) internal view returns (G1Point memory r) {
        uint[3] memory input;
        input[0] = p.X;
        input[1] = p.Y;
        input[2] = s;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 7, input, 0x80, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require (success);
    }
    /// @return the result of computing the pairing check
    /// e(p1[0], p2[0]) *  .... * e(p1[n], p2[n]) == 1
    /// For example pairing([P1(), P1().negate()], [P2(), P2()]) should
    /// return true.
    function pairing(G1Point[] memory p1, G2Point[] memory p2) internal view returns (bool) {
        require(p1.length == p2.length);
        uint elements = p1.length;
        uint inputSize = elements * 6;
        uint[] memory input = new uint[](inputSize);
        for (uint i = 0; i < elements; i++)
        {
            input[i * 6 + 0] = p1[i].X;
            input[i * 6 + 1] = p1[i].Y;
            input[i * 6 + 2] = p2[i].X[1];
            input[i * 6 + 3] = p2[i].X[0];
            input[i * 6 + 4] = p2[i].Y[1];
            input[i * 6 + 5] = p2[i].Y[0];
        }
        uint[1] memory out;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 8, add(input, 0x20), mul(inputSize, 0x20), out, 0x20)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success);
        return out[0] != 0;
    }
    /// Convenience method for a pairing check for two pairs.
    function pairingProd2(G1Point memory a1, G2Point memory a2, G1Point memory b1, G2Point memory b2) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](2);
        G2Point[] memory p2 = new G2Point[](2);
        p1[0] = a1;
        p1[1] = b1;
        p2[0] = a2;
        p2[1] = b2;
        return pairing(p1, p2);
    }
    /// Convenience method for a pairing check for three pairs.
    function pairingProd3(
            G1Point memory a1, G2Point memory a2,
            G1Point memory b1, G2Point memory b2,
            G1Point memory c1, G2Point memory c2
    ) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](3);
        G2Point[] memory p2 = new G2Point[](3);
        p1[0] = a1;
        p1[1] = b1;
        p1[2] = c1;
        p2[0] = a2;
        p2[1] = b2;
        p2[2] = c2;
        return pairing(p1, p2);
    }
    /// Convenience method for a pairing check for four pairs.
    function pairingProd4(
            G1Point memory a1, G2Point memory a2,
            G1Point memory b1, G2Point memory b2,
            G1Point memory c1, G2Point memory c2,
            G1Point memory d1, G2Point memory d2
    ) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](4);
        G2Point[] memory p2 = new G2Point[](4);
        p1[0] = a1;
        p1[1] = b1;
        p1[2] = c1;
        p1[3] = d1;
        p2[0] = a2;
        p2[1] = b2;
        p2[2] = c2;
        p2[3] = d2;
        return pairing(p1, p2);
    }
}

//投票系统中智能合约部分的算法实现
contract voteSC{ 
    using Pairing for *;  
    //设置候选人数量
    uint c;
    //从区块链获取验证通过所有选民的资格硬币承诺类型
    bytes32[] comm_array;
    //获取所有选民资格硬币承诺
    function getComm() public view returns (bytes32[] memory comm){
        return comm_array;
    }
   //投票密文结构体
    struct voteCt{
        Pairing.G1Point Ct0;
        Pairing.G1Point Ct1;
    }
    voteCt[] public voteCts;

    //设置从区块链获取密文聚合结果类型
    Pairing.G1Point[] A0_array;
    Pairing.G1Point[] A1_array;
    //获取密文聚合结果函数
    function getA0() public view returns (Pairing.G1Point[] memory A0){
        return A0_array;
    }
    function getA1() public view returns (Pairing.G1Point[] memory A1){
        return A1_array;
    }

    //设置从区块链获取部分解密秘钥验证通过的数据类型
    Pairing.G1Point[] sig_array;
    //获取验证通过的部分解密秘钥函数
    function getSig() public view returns (Pairing.G1Point[] memory Sig){
        return sig_array;
    }
  
    //设置从区块链获取解密秘钥组件的数据类型
    Pairing.G1Point[] dk_array;
    //获取解密秘钥组件dk
    function getDk() public view returns (Pairing.G1Point[] memory dk){
        return dk_array;
    }

    //设置计票结果的结构体
     struct voteTally {
         uint name;
         Pairing.G1Point voteCount;
     }

    //设置从区块链获取计票结果
     voteTally[] public t_array;
  
//智能合约函数实现  ..............................................................
    
    //验证资格硬币承诺的有效性
    function commVerify(string memory str, bytes32 comm) public returns(bool) {
        bytes32 hash = keccak256(abi.encodePacked(str));   
        if(hash == comm){           
            comm_array.push(comm);
            return true;
        } 
    }

    //聚合密文函数
    function ctAgg(uint w) public returns (Pairing.G1Point[] memory A0, Pairing.G1Point[] memory A1){    
        Pairing.G1Point[] memory A0 = new Pairing.G1Point[](c);
        Pairing.G1Point[] memory A1 = new Pairing.G1Point[](c);
        //第一部分聚合
        for(uint i = 0; i < c; i++){
            A0[i] = Pairing.addition(Pairing.scalar_mul(voteCts[i].Ct0,w),A0[i]);
            A0_array.push(A0[i]);
        }
        //第二部分聚合
        for(uint i = 0; i < c; i++){
            A1[i] = Pairing.addition(Pairing.scalar_mul(voteCts[i].Ct1,w),A1[i]);
            A1_array.push(A1[i]);
        }
        return (A0, A1);
    }

    //验证部分解密秘钥
    function sigVerify(Pairing.G1Point[] memory A0_array, Pairing.G2Point memory g2,Pairing.G1Point[] memory candidateSig_array, Pairing.G2Point[] memory vk) public returns (bool){
        //获得候选人数量
        bool[] memory res = new bool[](c);                                      
        for(uint i = 0; i < c; i++){
            res[i] = Pairing.pairingProd2(A0_array[i], g2,candidateSig_array[i], vk[i]);  
            sig_array.push(candidateSig_array[i]);       
        }
        for(uint i = 0; i < c; i++){
            if(res[i]){
                return true;
            }
        }            
    }

    //聚合部分解密秘钥
    function dkAgg() public returns (Pairing.G1Point[] memory dk){
        Pairing.G1Point[] memory dk = new Pairing.G1Point[](c);       
        //将候选人验证通过的解密秘钥进行聚合
        for(uint i = 0; i < c; i++){
            dk[i] = Pairing.addition(dk[i], sig_array[i]); 
            dk_array.push(dk[i]);          
        }
    return dk;
    }

    //计票
    function tallyVote() public returns (Pairing.G1Point[] memory t){
        //定义存储选票结果的数组
        Pairing.G1Point[] memory t = new Pairing.G1Point[](c);
        //解密秘钥的整理
        for(uint i = 0; i < c; i++){
            t[i] = Pairing.addition(A1_array[i], Pairing.negate(dk_array[i]));
            t_array.push(voteTally({
                name: i,
                voteCount: t[i]
            }));
        }
        return t;       
    }

}
