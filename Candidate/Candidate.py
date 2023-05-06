from sapling_jubjub import *
import random

from ed25519 import *
import secrets
from hashlib import sha3_256

sk,pk=0,0
Ct0_List=[]
Dk_List=[]
R_List=[]
CandidateNum=0


Bx=0x2B8CFD91B905CAE31D41E7DEDF4A927EE3BC429AAD7E344D59D2810D82876C32
By=0x2AAA6C24A758209E90ACED1F10277B762A7C1115DBC0E16AC276FC2C671A861F
q=21888242871839275222246405745257275088548364400416034343698204186575808495617


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
    global CandidateNum,Dk_List,sk
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
        temp_x=int(input(f"please input h_{i+1} value x >>"))
        temp_y=int(input(f"please input h_{i+1} value y >>"))
        Ct0_List.append(Point(temp_x,temp_y))
        Dk_List.append(PmulX([temp_x,temp_y],sk))
        # print(i)

    print("KeyGen Successful!")

def Prove():
    global CandidateNum
    HashString="";
    # generate 256-bit random number
    r=secrets.token_hex(32)#32bytes == 256bits
    # R=g^r
    R=publickey(r)
    HashString+=str(R[0])+str(R[1])
    global Ct0_List,R_List,sk
    for i in range(CandidateNum):
        temp_R_i=PmulX([Ct0_List[i].u,Ct0_List[i].v],r)
        R_List.append(temp_R_i)
        print("R_",i,"= [",str(temp_R_i[0]),",",str(temp_R_i[1])," ]")
        HashString+=str(temp_R_i[0])+str(temp_R_i[1])
#     compute hash value
#     using sha3_256 to ensure that c have same value with  c' in solidity
    c=sha3_256(HashString.encode()).hexdigest()
    print("C=",c)

#     S=r+cx
    s = (int(r,16) + int(c,16) * int(sk,16)) % q
    print("S=",s)



    print("Prove Successful!")


if __name__ == "__main__":
    print("Hello from Verivoting!")
    '''
    KeyGen()
    '''
    while True:
        str_input=input("(VeriVoting) ZKP>>")
        if str_input.lower()=="quit" or str_input.lower()=="q":
            break
        elif str_input.lower()=="setup":
            Setup()
            print("Public Key:",pk)
            print("Private Key",sk)
        elif str_input.lower()=="keygen":
            KeyGen()
        elif str_input.startswith("prove"):
            if(sk==0):
                print("Please Setup First!")
                continue
            Prove()
        else:
            print("Command not found. Try running 'help' to learn more.")







