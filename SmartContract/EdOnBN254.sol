// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

// A Twisted Edwards curve on scalar field of BN254. Also known as [Baby-Jubjub](https://github.com/barryWhiteHat/baby_jubjub).
// Modified from:
// https://github.com/yondonfu/sol-baby-jubjub/blob/master/contracts/CurveBabyJubJub.sol
// https://github.com/arkworks-rs/curves/tree/master/ed_on_bn254
//
// Curve information:
// * Base field: q = 21888242871839275222246405745257275088548364400416034343698204186575808495617
// * Scalar field: r = 2736030358979909402780800718157159386076813972158567259200215660948447373041
// * Valuation(q - 1, 2) = 28
// * Valuation(r - 1, 2) = 4
// * Curve equation: ax^2 + y^2 =1 + dx^2y^2, where
//    * a = 1
//    * d = 168696/168700 mod q
//        = 9706598848417545097372247223557719406784115219466060233080913168975159366771
library EdOnBN254 {
    uint256 public constant Q =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 public constant E_A = 1;
    uint256 public constant E_D =
        9706598848417545097372247223557719406784115219466060233080913168975159366771;

    struct Affine {
        uint256 x;
        uint256 y;
    }

    function primeSubgroupGenerator() public pure returns (Affine memory) {
        return
            Affine(
                0x2491ABA8D3A191A76E35BC47BD9AFE6CC88FEE14D607CBE779F2349047D5C157,
                0x2E07297F8D3C3D7818DBDDFD24C35583F9A9D4ED0CB0C1D1348DD8F7F99152D7
            );
    }

    function zero() public pure returns (Affine memory) {
        return Affine(0, 1);
    }

    function PointAdd(uint x1,uint y1,uint x2,uint y2)public view returns(uint x,uint y)
    {
        Affine memory a1=Affine(x1,y1);
        Affine memory a2=Affine(x2,y2);
        Affine memory res= add(a1,a2);
        return (res.x,res.y);
    }


    function add(
        Affine memory a1,
        Affine memory a2
    ) public view returns (Affine memory) {
        if (a1.x == 0 && a1.y == 0) {
            return a2;
        }

        if (a2.x == 0 && a2.y == 0) {
            return a1;
        }

        uint256 x1x2 = mulmod(a1.x, a2.x, Q);
        uint256 y1y2 = mulmod(a1.y, a2.y, Q);
        uint256 dx1x2y1y2 = mulmod(E_D, mulmod(x1x2, y1y2, Q), Q);
        uint256 x3Num = addmod(mulmod(a1.x, a2.y, Q), mulmod(a1.y, a2.x, Q), Q);
        uint256 y3Num = submod(y1y2, mulmod(E_A, x1x2, Q), Q);

        return
            Affine(
                mulmod(x3Num, inverse(addmod(1, dx1x2y1y2, Q)), Q),
                mulmod(y3Num, inverse(submod(1, dx1x2y1y2, Q)), Q)
            );
    }

    function double(Affine memory a) public view returns (Affine memory) {
        return add(a, a);
    }

    function mul(
        Affine memory a,
        uint256 s
    ) public view returns (Affine memory) {
        uint256 remaining = s;
        Affine memory p = Affine(a.x, a.y);
        Affine memory ret = Affine(0, 0);

        while (remaining != 0) {
            if ((remaining & 1) != 0) {
                ret = add(ret, p);
            }

            p = double(p);

            remaining = remaining / 2;
        }

        return ret;
    }

    function neg(Affine memory a) public pure returns (Affine memory) {
        if (a.x == 0 && a.y == 0) return a;
        return Affine(submod(0, a.x, Q), a.y);
    }

    function submod(
        uint256 _a,
        uint256 _b,
        uint256 _mod
    ) internal pure returns (uint256) {
        return addmod(_a, _mod - _b, _mod);
    }

    function inverse(uint256 _a) internal view returns (uint256) {
        return expmod(_a, Q - 2, Q);
    }

    function expmod(
        uint256 _b,
        uint256 _e,
        uint256 _m
    ) internal view returns (uint256 o) {
        assembly {
            let memPtr := mload(0x40)
            mstore(memPtr, 0x20)
            mstore(add(memPtr, 0x20), 0x20)
            mstore(add(memPtr, 0x40), 0x20)
            mstore(add(memPtr, 0x60), _b)
            mstore(add(memPtr, 0x80), _e)
            mstore(add(memPtr, 0xa0), _m)

            let success := staticcall(gas(), 0x05, memPtr, 0xc0, memPtr, 0x20)
            switch success
            case 0 {
                revert(0x0, 0x0)
            }
            default {
                o := mload(memPtr)
            }
        }
    }
}