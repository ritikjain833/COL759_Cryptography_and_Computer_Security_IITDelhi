from collections import Counter
import decrypt as de
import numpy as np
import math
import re
#from string import digits

#character to number 1-1 mapping

def char_to_num_dict():
    s = 'abcdefghijklmnopqrstuvwxyz'
    alphaDict = dict.fromkeys(s,0)
    for i in alphaDict.keys():
        alphaDict[i]=ord(i)-97
    #print(alphaDict)
    return alphaDict  
    

# number to character 1-1 mapping    
def num_to_char_dict():
    numDict=char_to_num_dict()
    numDict = {v: k for k, v in numDict.items()}  
    #print(numDict)
    return numDict

# function to remove space,comma,dot from text
def remove_characters(text):
    text=text.lower()
    text=re.sub("[ ,.']", "", text)
    return text 

#check matrix is invertible and gcd(det,26)==1         
def checkInvertible(matrix):
    mat = np.array(matrix)
    determinant = int(round(np.linalg.det(mat)))
    #print(determinant)
    if (determinant!= 0) and (math.gcd(determinant, 26)== 1):
        return True
    else:
        return False

#function to calculate the inverse of a matrix
def inverse_matrix(mtx):
    det = np.linalg.det(mtx)
    adj_mtx = np.linalg.inv(mtx)*det
    mod_det = multplicative_inverse(round(det))
    adj_mtx = adj_mtx * mod_det
    adj_mtx = np.mod(adj_mtx, 26)
    return adj_mtx.round()
    
#function to get the multiplicative inverse of the determinant
def multplicative_inverse(mtx):
    m = 26
    for x in range(1, m):
        if (((mtx%m) * (x)) % m == 1):
            return x
    return -1

def get_key(plain,cipher):
    if checkInvertible(plain):
        inv_plain = inverse_matrix(plain)
        key = cipher @ inv_plain
        key = np.mod(key, 26)
        return key
    else:
        a = [[0,0],[0,0]]
        ar = np.array(a)
        return ar

# function to generate matrix of given text and append extra characters if required   

def generate_matrix_of_text(plain_text,key_length):
    alphaDict=char_to_num_dict()
    length_of_text=len(plain_text)
    plain_text=list(plain_text.split())
    #print(plain_text)
    remainder=length_of_text%key_length
    # extra character x is appended to matrix if required
    if remainder>0:
        charToAppend=key_length - remainder
        for i in range(charToAppend):
          
            plain_text.append("x")

    plain_text="".join(plain_text)
    length_of_text=len(plain_text)
    row=length_of_text//key_length
    textMatrix = np.zeros((row, key_length), dtype=int)
    count=0

    #print(row,key_length)
    for r in range(row):
      for c in range(key_length):
        textMatrix[r][c]=alphaDict[plain_text[count].lower()]
        #print(count)
        count+=1
    #print(textMatrix) 
    textMatrix=textMatrix.transpose() 
    return textMatrix
    

if __name__ == '__main__':
    
    name = input("Enter location of the file containing plain text: \n ")
    name1 = input("Enter location of the file to get encrypted text: \n ")
    file = open(name,"r")
    file1 = open(name1,"r")
    plain_text = file.read()
    cipher_text = file1.read()
    plain_text = remove_characters(plain_text)
    #main function for cryptanalysis using index of coincidence
    f = 0
    I = 0
    m = 1
    i = 0
    while I < 0.065 and m <= 10 :
        I = 0
        f = 0
        plain_text_temp = plain_text[i:i+m*m]
        cipher_text_temp = cipher_text[i:i+m*m]
        matrix_plain_text = generate_matrix_of_text(plain_text_temp,m)
        matrix_cipher_text = generate_matrix_of_text(cipher_text_temp,m)
        key = get_key(matrix_plain_text,matrix_cipher_text)
        #print(key)
        #key = np.transpose(key)
        
        det_key = np.linalg.det(key)
        if det_key == 0:
            i = i + m*m
            continue
        if det_key != 0:
            temp_plain_text = de.decryption(cipher_text,key)
            #print(temp_plain_text)
            tot_freq=Counter(temp_plain_text)
            n = len(temp_plain_text)
            n = n*(n-1)
            #print(n)
            #print(tot_freq)
            for ky,val in tot_freq.items():
                f = f + val*(val-1)
                #print(val)
            #print(f)
            I = f/n
        #print(I)
        if I>=0.065:
            print("Cheers ! \n Your Encrypted text has been decrypted")
            key = key. astype(int)
            print("Key length is :\n",len(key[0]))
            print("Key is :\n",key)
            
            print("Plain_text is :\n",temp_plain_text)
        m = m + 1
        i = 0
    file.close()
    file1.close()
        

