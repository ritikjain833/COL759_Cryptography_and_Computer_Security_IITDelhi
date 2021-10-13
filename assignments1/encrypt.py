import math
import numpy as np
import re
#from string import digits

#character to number 1-1 mapping
def char_to_num_dict():
    s = 'abcdefghijklmnopqrstuvwxyz'
    alphaDict = dict.fromkeys(s,0)
    #print(alphaDict)
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
    text=re.sub("[ (),.']", "", text) 
    
    return text 

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
    
    textMatrix=textMatrix.transpose()       
    #print(textMatrix)
    return textMatrix


#main function for encryption of plaintext   
def encryption(plain_text,key):
    plain_text=remove_characters(plain_text)
    matrix_plain_text=generate_matrix_of_text(plain_text,len(key[0]))
    #print(matrix_plain_text)
    matrix_cipher_text= np.zeros((matrix_plain_text.shape), dtype = int)
  
    for i in range(len(matrix_plain_text[0])):
        matrix_cipher_text[:,i] = key.dot(matrix_plain_text[:,i])
    #print(matrix_cipher_text)
    
    matrix_cipher_text=matrix_cipher_text.transpose()
   
    ans=[]
    numDict=num_to_char_dict()
    for i in range(len(matrix_cipher_text)):
        for j in range(len(matrix_cipher_text[0])):
            temp=(matrix_cipher_text[i][j])%26
            ans.append(numDict[temp])
    matrix_cipher_text="".join(ans)
    return matrix_cipher_text  

 #check matrix is invertible and gcd(det,26)==1         
def checkInvertible(matrix):
    determinant=int(round(np.linalg.det(matrix)))
    print(determinant)
    if (determinant!= 0) and (math.gcd(determinant, 26)== 1):
        return True
    else:
        return False

if __name__ == '__main__':
    #input file location
    name = input("Enter location of the file containing plain text: \n ")
    name1 = input("Enter location of the file to get encrypted text: \n ")
    name2=input("Enter location of key\n")
    file = open(name,"r")
    file1 = open(name1,"w")
    file2=open(name2,"r")
    plain_text = file.read()
    key=file2.readlines()
    
    ans=key[0].split()
    ans = [int(i) for i in ans]
    #print(ans)
    order=int(math.sqrt(len(ans)))
    #order = int(input("Enter the size of the key"))
    #key=list(map(int, input("Enter key as a list (like )\n").split()))
    key = np.array(ans).reshape(order, order)

    #print(key)
    if checkInvertible(key):
        cipher_text=encryption(plain_text,key)
        #print("Encrypted Cipher text is :\n",cipher_text)
        file1.write(cipher_text)
    else:
        print("Matrix is singular or non-invertible") 
    file.close()
    file1.close()
    file2.close()  
