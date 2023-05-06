'''   
    copyright 2018 to the baby_jubjub_ecc Authors

    This file is part of baby_jubjub_ecc.

    baby_jubjub_ecc is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    baby_jubjub_ecc is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with baby_jubjub_ecc.  If not, see <https://www.gnu.org/licenses/>.
'''




from sapling_jubjub import *
import hashlib

from ed25519 import *
import secrets

sk,pk=0,0
h_List=[]
H_List=[]
R_List=[]

import pdb
Bx=0x2B8CFD91B905CAE31D41E7DEDF4A927EE3BC429AAD7E344D59D2810D82876C32;
By=0x2AAA6C24A758209E90ACED1F10277B762A7C1115DBC0E16AC276FC2C671A861F;


def toBin(x):
    out = [ int(x) for x in bin(int(x, 16))[2:] ]
    out = [0] * (256 - len(out)) + out
    return(out) 

def Setup():
    # Private Key
    global sk
    sk=secrets.token_hex(32)#32bytes==256bits
    # Generating Public Key
    global pk
    pk=publickey(sk)

def KeyGen():
    # Determines whether the input is a number
    while True:
        try:
            CandidateNum = int(input("Please input candidates number>>"))
            break  # Input is a number,break loop
        except ValueError:
            print("Your Input is not a number！")
    # random generate generator h_i
    for i in range(CandidateNum):
        # random h_i
        temp=Point()
        global h_List,H_List,sk
        h_List.append(temp)
        H_List.append(scalarmult(temp,sk))
        print(i)

    print("KeyGen Successful!")

def Prove():
    HashString="";
    # generate 256-bit random number
    r=secrets.token_hex(32)#32bytes == 256bits
    # R=g^r
    R=publickey(r)
    HashString+=R
    for i in range(len(h_List)):
        temp_R_i=scalarmult(h_List[i],r)
        R_List.append(temp_R_i)
        print("R_"+i+"= ",temp_R_i)
        HashString+=temp_R_i
#     compute hash value
    c=hash(HashString)
    print("C= ",HashString)

#     S=r+cx
    s=r+c*sk
    print("S=",s)



    print("Prove Successful!")


if __name__ == "__main__":
    print("Hello from Verivoting!")

    KeyGen()
    '''
    while True:
        str=input("(VeriVoting) ZKP>>")
        if str.lower()=="quit" or str.lower()=="q":
            break
        elif str.lower()=="setup":
            Setup()
            print("Public Key:",pk)
            print("Private Key",sk)
        elif str.lower()=="keygen":
            KeyGen()
        elif str.startswith("prove"):
            if(sk.__eq__(ZERO)):
                print("Please Setup First!")
                continue
            Prove()
        else:
            print("Command not found. Try running 'help' to learn more.")
    '''






