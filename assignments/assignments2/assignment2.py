import gmpy2 as mp
import numpy as np
import re
import math
from gmpy2 import mpz
from Crypto.Util import number
import sympy
import random
from Crypto.Util.number import getPrime
from Crypto.Random import get_random_bytes
import os

def char_to_num_dict():
    s = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    alphaDict = dict.fromkeys(s,0)
    for i in alphaDict.keys():
        alphaDict[i]=ord(i)-65
    alphaDict[' '] = 26
    alphaDict[','] = 27
    alphaDict['.'] = 28
    return alphaDict 
def num_to_char_dict():
    numDict=char_to_num_dict()
    numDict = {v: k for k, v in numDict.items()}  
    return numDict
def generate_strong_prime(primebits):
  #generating strong prime through gordon's algorithm
  
  s = getPrime(primebits,randfunc=get_random_bytes)
  t = getPrime(primebits,randfunc=get_random_bytes)

  isPrime=False
  i=random.randint(0,100)
  while (isPrime==False):
    r=2*i*t+1
    i=i+1
    if (sympy.isprime(r)==True): 
      isPrime=True
  p_0 = 2*(pow(s,r-2,r))*s-1
  isPrime=False
  j=random.randint(0,100)
  p=0
  while (isPrime==False):
    p=p_0+2*j*r*s
    j=j+1
    if (sympy.isprime(p)==True): 
      isPrime=True
      break
  prp = p    
  
  # is_strong_prp(n,a) will return True if n is an strong (also known as Miller-Rabin) probable prime to the base a here a=41
  notStrongPrime = True
  prp = mp.next_prime(2**primebits)
  count = 0
  while notStrongPrime:
      if mp.is_strong_prp(prp,41):
          notStrongPrime = False
      elif not mp.is_strong_prp(prp):
          prp = mp.next_prime(prp,41)
  return prp
def vigenere_encrypt(data, key):
    cipher= []
    n=len(key)
    length=len(data)
    for i in range(length):
        x = (charsTonum[data[i]] +
             charsTonum[key[i%n]]) % 26
        cipher.append(numToChars[x])
    return("" . join(cipher))  
def vigenere_decrypt(data,key):
  plain=[]
  n=len(key)
  length=len(data)
  for i in range(length):
    x = (charsTonum[data[i]] -
             charsTonum[key[i%n]]) % 26
    plain.append(numToChars[x])
  return ("".join(plain))
def RSAKeyGen(bits):
  # bits=bits//2
  p= generate_strong_prime(bits)
  bits+=1
  q = generate_strong_prime(bits)
  n=mp.mul(p,q)
  phi=mp.mul(p-1,q-1)
  e=random.randrange(1,phi)
  g=math.gcd(e,phi)
  while g!=1:
    e=random.randrange(1,phi)
    g=math.gcd(e,phi)
  d=mp.invert(e,phi)
  return e,n,d
def publishKeys():
  
  #CA's key generation 
  e_CA,n_CA,d_CA = RSAKeyGen(512)
  write_file(r"public_ca.txt", str(e_CA) + " " + str(n_CA))
  write_file(r"private_ca.txt",str(d_CA) + " " + str(n_CA))

  #A's key generation and digital Signature
  e_A,n_A,d_A = RSAKeyGen(512)
  e_A_DS,n_A_DS = digitalSign(e_A,n_A)
  """write the files in directory"""
  write_file(r"public_a.txt", str(e_A_DS) + " " + str(e_A) + " " + str(n_A))
  write_file(r"private_a.txt",str(d_A) + " " + str(n_A))

  #B's key generation and digital Signature
  e_B,n_B,d_B = RSAKeyGen(512)
  e_B_DS,n_B_DS = digitalSign(e_B,n_B)
  """write the files in directory"""
  write_file(r"public_b.txt", str(e_B_DS) + " " + str(e_B) + " " + str(n_B))
  write_file(r"private_b.txt",str(d_B) + " " + str(n_B))
def digitalSignRSA(text,sender):
  """Digitally sign the text by sender"""
  sender_prkey = read_file(r"private_"+str(sender)+".txt").split()
  d=mp.mpz(sender_prkey[0].strip())
  n=mp.mpz(sender_prkey[1].strip())
  blockLen = 100 
  total_char = 26          
  msg = 0
  for i in range(blockLen):
      msg += mp.mul(charsTonum[text[i]], mp.mpz(total_char)**(blockLen -1 -i))     

  eMsg = mp.powmod(msg, d, n) 
  return eMsg 
def digitalUnSignRSA(text,sender):
  """Digitally sign the text by sender"""
  e,n = getpublickey(sender)
  blockLen = 100
  dSign = mp.powmod(mp.mpz(text), e, n) 
  total_char = 26
  remainder = dSign
  m = []
  for i in range(blockLen):
      quot, remainder = mp.t_divmod(remainder, mp.mpz(total_char)**(blockLen -1 -i))
      m.append(numToChars[mp.t_mod(quot, total_char)])

  decryptedSign = ''.join(m)  
  return decryptedSign
def digitalSign(key_e,key_n):
  """Digitally sign the keys by CA"""
  ca_sk = read_file(r"private_ca.txt").split()
  d=mp.mpz(ca_sk[0].strip())
  n=mp.mpz(ca_sk[1].strip())
  temp1=mp.powmod(key_e,d,n)
  temp2=mp.powmod(key_n,d,n)
  return (temp1,temp2)    
def digitalUnsign(key_e,key_n):
  """Digitally Unsign the key by CA"""
  ca_pk = read_file(r"public_ca.txt").split()
  e=mp.mpz(ca_pk[0].strip())
  n=mp.mpz(ca_pk[1].strip())
  temp1=mp.powmod(key_e,e,n)
  temp2=mp.powmod(key_n,e,n)
  return (temp1,temp2)
def digitalsign_key(key,sender):
  """Digitally sign the keys by sender private key"""
  sender_prkey = read_file(r"private_"+str(sender)+".txt").split()
  d=mp.mpz(sender_prkey[0].strip())
  n=mp.mpz(sender_prkey[1].strip())
  key = mp.mpz(key)
  temp1=mp.powmod(key,d,n)
  return temp1
def digitalunsign_key(key,sender):
  """Digitally Unsign the key by sender public key"""
  e,n = getpublickey(sender)
  key = mp.mpz(key)
  temp1=mp.powmod(key,e,n)
  return temp1
def getpublickey(receiver):
  pk = read_file(r"public_"+str(receiver)+".txt").split()
  es=mp.mpz(pk[0].strip())
  e=mp.mpz(pk[1].strip())
  n=mp.mpz(pk[2].strip())
  ns = 0
  esu,nsu = digitalUnsign(es,ns)
  if(esu == e):
    return e,n
  else:
    print("Unverified keys")
def read_file(name):
  with open(name,'r') as openFile:  
    t = openFile.read().replace('\n','')
  openFile.close()
  t = t.replace("'", "")
  t = t.replace("?", "")
  return t.upper()
def write_file(name,text):
  f=open(name,"w")
  f.write(text)
  f.close()
  return
def charstonum_str(key):
    key_list = []
    for i in key:
        key_list.append(str(charsTonum[i]))
    key_str = ''.join(key_list)
    return key_str
def numstochar_str(key):
  key_list_a = []
  for i in str(key):
    key_list_a.append(numToChars[int(i)])
  key_str_a = ''.join(key_list_a)
  return key_str_a
def encryption(text,sender,receiver,key):
  
  """Encryption of Vigenere Cipher"""
  encrypted_vigenere=vigenere_encrypt(text,key)
  
  """Digtally sign the Vigenere key by senders private key"""
  key_str=charstonum_str(key)
  key_signed = digitalsign_key(key_str,sender)
  key_str_a =numstochar_str(key_signed)

  """Digitally Sign the encrypted_vigenere text by senders private key"""
  encrypted_vigenere_signed = digitalSignRSA(encrypted_vigenere,sender)
  
  text_str=numstochar_str(encrypted_vigenere_signed)
  lenth = len(text_str)
  len_str=numstochar_str(lenth)
  """Combining vigenere key and message"""

  message = key + " " + key_str_a + " " + encrypted_vigenere + " " + len_str + " " + text_str 
  """Encrypt whole message using the public key of receiver"""
  message_encrypted_pkr = RSA_encryption(message,sender,receiver)
  write_file(r"message_sent.txt",message_encrypted_pkr)
  return
def decryption(sender,receiver,key):

  received_message = read_file(r"message_sent.txt")

  """Recover vigenere key and the Encrypted vigenere message"""
  message = RSA_decryption(received_message,"a","b").split()

  key = message[0]
  key_signed = message[1]
  encrypted_text = message[2]
  lenth = message[3]
  signed_encrypted_text = message[4]

  """Converting the encrypted_vigenere key from character to numbers and 
     unsigning the key and again converting it into characters"""
  key_str=charstonum_str(key_signed)
  key_unsigned = str(digitalunsign_key(key_str,sender))
  key_str_check =charstonum_str(key) 
  
  """Converting the signed_encrypted_message into numbers and 
     unsigning the message and again converting it into characters"""
  text_str = charstonum_str(signed_encrypted_text)
  
  lenth_str = charstonum_str(lenth)

  text_str = text_str[0:int(lenth_str)]
  unsigned_encrypted_text = digitalUnSignRSA(text_str,sender)
  check_vig = encrypted_text[0:100]

  """Checking the unsigned key with the original vigenere key and the
    unsigned encrypted text with the vigenere encrypted text"""

  if (key_str_check == key_unsigned and unsigned_encrypted_text == check_vig ):
      decipher_str = vigenere_decrypt(encrypted_text,key)
      print(decipher_str)
  else:
    print(" Message or key has been tampered in between the channel ")
    
  return 
def BlockSize(n):
    a = mp.mpz(n)
    z = 0
    while mp.mpz(total_char)**z < a:
        z += 1
    return z
def Msgblock(text,l):
    msgBlocks = []
    aux=[]
    for char in text:
      aux.append(char)
      if(len(aux) == l):
            msgBlocks.append("".join(aux))
            aux.clear()
    #remaining auxiliary characters append        
    msgBlocks.append(aux) 
    return msgBlocks 
def RSA_encryption(text, sender, receiver):
    
    e,n = getpublickey(receiver)
    
    length_block = BlockSize(n)
    
    Blocks = Msgblock(text, length_block)
    
    if(len(Blocks[-1]) != length_block):
        remainder=length_block - len(Blocks[-1])
        for i in range(remainder):
            Blocks[-1] += numToChars[np.random.randint(0, 1)]
      
    encryptedMsg = []
    for block in Blocks:
        msg = 0
        for i in range(length_block):
            msg += mp.mul(charsTonum[block[i]], mp.mpz(total_char)**(length_block -1 -i))   
        
        eMsg = mp.powmod(msg, e, n)
        encryptedMsg.append(eMsg)
   
    enMsg = ""
    for msg in encryptedMsg:
        remainder = msg
        m = []
        for i in range(length_block):
            quot, remainder = mp.t_divmod(remainder, mp.mpz(total_char)**(length_block -1 -i))
            m.append(numToChars[quot])
        enMsg += ''.join(m)
        
    
    return enMsg
def RSA_decryption(text, sender, receiver):
    sk = read_file(r"private_" + receiver + ".txt").split()
    d = mp.mpz(sk[0].strip())
    n = mp.mpz(sk[1].strip())
    length_block = BlockSize(n)
    Blocks = Msgblock(text, length_block)
    decryptedMsg = []
    for block in Blocks:
        msg = 0
        if len(block) != 0:
            for i in range(length_block):
                msg += mp.mul(charsTonum[block[i]], mp.mpz(total_char)**(length_block -1 -i))
            
        
            decryptedMsg.append(msg)
    deBlocks = []  
    for block in decryptedMsg:
        
        remain = mp.powmod(block, d, n)
        deBlocks.append(remain)
    decryptedMsg = ""
    for msg in deBlocks:
        remainder = msg
        m = []
        for i in range(length_block):
            quot, remainder = mp.t_divmod(remainder, mp.mpz(total_char)**(length_block -1 -i))
            m.append(numToChars[mp.t_mod(quot, total_char)])
        decryptedMsg += ''.join(m)
        
    return decryptedMsg  
if __name__=="__main__":
  directory=os.getcwd()
  numToChars = num_to_char_dict()
  charsTonum = char_to_num_dict()
  data=read_file("message.txt")
  data=re.sub(r'[^a-zA-Z]',"",data).upper()
  total_char = 29
  key="DAENERYS".strip()
  sender = "a"
  receiver = "b"
  publishKeys()
  encryption(data,sender,receiver,key)
  decryption(sender,receiver,key)                                                    

