from sapling_jubjub import *
import random

from ed25519 import *
import secrets

sk,pk=0,0
h_List=[]
H_List=[]
R_List=[]


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
        temp=[random.randint(20,100),random.randint(20,100)]
        global h_List,H_List,sk
        h_List.append(Point(temp[0],temp[1]))
        H_List.append(PmulX(temp,sk))
        # print(i)

    print("KeyGen Successful!")

def Prove():
    HashString="";
    # generate 256-bit random number
    r=secrets.token_hex(32)#32bytes == 256bits
    # R=g^r
    R=publickey(r)
    HashString+=str(R[0])+str(R[1])
    global h_List,R_List,sk
    for i in range(len(h_List)):
        temp_R_i=PmulX([h_List[i].u,h_List[i].v],r)
        R_List.append(temp_R_i)
        print("R_",i,"= [",str(temp_R_i[0]),",",str(temp_R_i[1])," ]")
        HashString+=str(temp_R_i[0])+str(temp_R_i[1])
#     compute hash value
    c=hash(HashString)
    print("C=",c)

#     S=r+cx
    s = (int(r,16) + int(c) * int(sk,16)) % q
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







