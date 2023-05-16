from ed25519 import *
import secrets
from Cryptodome.Hash import SHA256

sk,pk=0,0
Ct0_List=[]
Dk_List=[]
R_List=[]
CandidateNum=0

Bx = 0x2491ABA8D3A191A76E35BC47BD9AFE6CC88FEE14D607CBE779F2349047D5C157
By = 0x2E07297F8D3C3D7818DBDDFD24C35583F9A9D4ED0CB0C1D1348DD8F7F99152D7
q = 21888242871839275222246405745257275088548364400416034343698204186575808495617
l = 2736030358979909402780800718157159386076813972158567259200215660948447373041
B = [Bx % q,By % q]
b = 126

def toBin(x):
    out = [ int(x) for x in bin(int(x, 16))[2:] ]
    out = [0] * (256 - len(out)) + out
    return(out) 

def Setup():
    # Private Key
    global sk
    sk = str(int(secrets.token_hex(32), 16) % q)#32bytes==256bits
    # Generating Public Key
    global pk
    pk = publickey(sk)

def KeyGen():
    global CandidateNum,Dk_List,sk
    h = H(sk)
    a = 2 ** (b - 2) + sum(2 ** i * bit(h, i) for i in range(3, b - 2))
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
        temp_x = int(input(f"please input h_{i+1} value x >>"))
        temp_y = int(input(f"please input h_{i+1} value y >>"))
        Ct0_List.append(Point(temp_x,temp_y))
        Dk_List.append(scalarmult([temp_x,temp_y],a))
        # print(i)
    print("deKey = ",Dk_List)
    print("KeyGen Successful!")

def Prove():
    global CandidateNum, Ct0_List,R_List,sk, pk
    HashString="";
    # generate 256-bit random number
    r_num = secrets.token_hex(32)#32bytes == 256bits
    h = H(sk)
    a = 2**(b-2) + sum(2**i * bit(h,i) for i in range(3,b-2))
    r = int(r_num, 16) % l
    R = scalarmult(B, r)
    print("R_ 0 =", R)
    HashString += str(R[0])+str(R[1])
    R_List.append(R)
    for i in range(CandidateNum):
        temp_R_i=scalarmult([Ct0_List[i].u,Ct0_List[i].v],r)
        R_List.append(temp_R_i)
        print("R_", i+1, "= [", str(temp_R_i[0]), ", ", str(temp_R_i[1]), " ]")
        HashString += str(temp_R_i[0]) + str(temp_R_i[1])
#     compute hash value
#     using SHA256 to ensure that c have same value with  c' in solidity
    c = int(SHA256.new(HashString.encode('utf-8')).hexdigest(), 16) % l
    print("C =",c)
    s = r + (c * a) % l
    print("S = ", s)

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
            print("Private Key:", sk)
        elif str_input.lower() == "keygen":
            KeyGen()
        elif str_input.startswith("prove"):
            if(sk == 0):
                print("Please Setup First!")
                continue
            Prove()
        else:
            print("Command not found. Try running 'help' to learn more.")

# input
# 1.setup
# 2.keygen
# 3.3
# 4>
    # h_1_x = 5167023621034891088399967874155148216376055020262814433731887285472848447908
    # h_1_y = 4815892135385938683649491232434544167871907834747597579667736710038082979514
    # h_2_x = 5167023621034891088399967874155148216376055020262814433731887285472848447908
    # h_2_y = 4815892135385938683649491232434544167871907834747597579667736710038082979514
    # h_3_x = 5167023621034891088399967874155148216376055020262814433731887285472848447908
    # h_3_y = 4815892135385938683649491232434544167871907834747597579667736710038082979514
# 5.prove