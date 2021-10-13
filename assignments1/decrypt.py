import math
import numpy as np
import re


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
    # matrix is generated row*key (p*n) but we require n*p for matrix multiplication

    textMatrix=textMatrix.transpose()       
    return textMatrix

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
 
#main function for decryption of plaintext      
def decryption(cipher_text,key):
    matrix_cipher_text = generate_matrix_of_text(cipher_text,len(key[0]))
    decript_key = inverse_matrix(key)
    #print(decript_key.dtype)
    matrix_plain_text= np.zeros((matrix_cipher_text.shape), dtype = int)
    for i in range(len(matrix_cipher_text[0])):
        matrix_plain_text[:,i] = decript_key.dot(matrix_cipher_text[:,i])
       
    matrix_plain_text=matrix_plain_text.transpose()
    ans=[]
    numDict=num_to_char_dict()
    for i in range(len(matrix_plain_text)):
        for j in range(len(matrix_plain_text[0])):
            temp=(matrix_plain_text[i][j])%26
            ans.append(numDict[temp])
    matrix_plain_text="".join(ans)
    return matrix_plain_text   

#check matrix is invertible and gcd(det,26)==1         
def checkInvertible(matrix):
    determinant=int(np.linalg.det(matrix))
    if (determinant!= 0) and (math.gcd(determinant, 26)== 1):
        return True
    else:
        return False

if __name__ == '__main__':
    #input cipher text
    name = input("Enter location of the file containing encrypted text: \n ")
    name1 = input("Enter location of the file to get decrypted text: \n ")
    file = open(name,"r")
    file1 = open(name1,"w")
    name2=input("Enter location of key\n")
    file2=open(name2,"r")
    key=file2.readlines()
    cipher_text = file.read()
    ans=key[0].split()
    ans = [int(i) for i in ans]
    #print(ans)
    order=int(math.sqrt(len(ans)))
    #order = int(input("Enter the size of the key"))
    #key=list(map(int, input("Enter key as a list (like )\n").split()))
    key = np.array(ans).reshape(order, order)
    #print(key)
    if checkInvertible(key):
        plain_text = decryption(cipher_text,key)
        #print("Decrypted Cipher text is :\n",plain_text)
        file1.write(plain_text)
    else:
        print("Matrix is singular or non-invertible")
    file.close()
    file1.close()
    file2.close()