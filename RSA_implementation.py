"""
Implementation of RSA.
Primality check using miller rabin primality testing.
private key generation using extended GCD

Author: SAI KISHORE AKULA
UNIVERSITY OF CINCINNATI

"""

from random import randint

# This method computes power of two numbers using left - right binary iterative method
def binaryPowers(x,n):
    binary_value_n = "{0:b}".format(n)
    powers = x    
    for  i in binary_value_n[1:]:
        if(i=='1'):
            powers = (powers ** 2) * x
        else:
            powers = (powers ** 2)
    return powers

"""
    This method implements Miller Rabin theorem. In this method we pass a random number to check the primailty of the number.
     We use this function with 10 random numbers so the error would decrease by 1024 times
"""
def millerRabin_primalityTest(random_number):
    count = 0
    p = 0
    n = random_number-1
    while True:
        if(n%2) == 0:
            p = p+1
            n = n//2
        else:
            break
    for i in range(0,10):
        a = randint(100,999)
        for j in range(0,p+1):
            c = (binaryPowers(a,((2**j)*n)))%random_number
            if(c == (random_number-1) or c == 1):
                count+= 1
                break
    if count == 10:
        return random_number
    else:
        return chooseRandomPrimeNumber()

# This method returns large random prime number
def chooseRandomPrimeNumber():
        num = randint(1000,9999)
        if(num != p):
                return millerRabin_primalityTest(num)
        else:
                chooseRandomPrimeNumber()

# This method returns decimal value from bearcatii format/ base27 format 
def convertToDecimalFromBase27(ip_base27_list):
        counter = 0
        ip_decimal_list = []
        for x in reversed(ip_base27_list):
            temp = int(x) * pow(27,counter)
            ip_decimal_list.append(temp)
            counter += 1  
        ip_decimal_list.reverse()
        encoded_msg = sum(ip_decimal_list)
        return encoded_msg

# This method converts text and returns encoded msg
def changeTexttoDecimal(ip_msg):
        ip_decimal_list = []
        for i in ip_msg:
                if (i.islower()):
                    caseCheckFlag.append(0)
                else:
                    caseCheckFlag.append(1)
        lowerCase = ip_msg.lower()
        for j in lowerCase:
            ip_decimal_list.append(BEARCATII(j,'encode'))
            encoded_msg = convertToDecimalFromBase27(ip_decimal_list)
        return encoded_msg

# Static method which encodes/decodes a literal
def BEARCATII(ip,code):
        bearcat = {'a': '1', 'b': '2', 'c': '3', 'd': '4', 'e': '5', 'f': '6', 'g': '7', 'h': '8', 'i': '9', 'j': '10', 'k': '11', 'l': '12', 'm': '13',
                'n': '14', 'o': '15', 'p': '16', 'q': '17', 'r': '18', 's': '19', 't': '20', 'u': '21', 'v': '22', 'w': '23', 'x': '24', 'y': '25',
                'z': '26',' ': '0'}
        if(code=='encode'):
           for key, val in bearcat.items():
               if(key==ip):
                  return val
                                  
        if(code=='decode'):
           for key, val in bearcat.items():
               if(val==ip):
                  return key

# This method returns bearcatii value from decimal                 
def convertToBase27FromDecimal(ip):
        base_elements = []
        while(ip//27 != 0):
            base_elements.append(ip % 27)
            ip = ip //27
        base_elements.append(ip)
        return base_elements[::-1]
        
# This method returns decoded message 
def convertDecimalToText(ip):
        decoded_base_elements = convertToBase27FromDecimal(ip)
        output_msg=''
        for i in decoded_base_elements:
            output_msg += BEARCATII(str(i),'decode')
        count=0
        final_output_msg=''
        while (count<len(output_msg)):
                if (caseCheckFlag[count]==1):
                        final_output_msg += (output_msg[count].upper())
                else:
                        final_output_msg += (output_msg[count].lower())
                count= count+1
        return final_output_msg

# This method returns both public and private keys
def generateKeys(PhiOfN):
        e=choosePublicKey(PhiOfN)
        d=computePrivateKey(e,PhiOfN)
        return (e,d)

# This method returns a public key
def choosePublicKey(PhiOfN):
        while True:
                public_key = int(input('Enter your public key: '))
                if(checkGCD(public_key,PhiOfN)== 1 ):
                        return public_key
                else:
                        print("Sorry ! Enter another number")
                        return choosePublicKey(PhiOfN)

#This method computes Euclidean GCD of two numbers
def euclidGCD(a,b):
        if(b % a == 0):
                return a
        else:
                return euclidGCD(b%a,a)
            
#This method computes GCD of two numbers and check whether the GCD is 1
def checkGCD(public_key,PhiOfN):
        if(euclidGCD(public_key,PhiOfN)==1):
            return True
        else:
            return False

#This method computes Extended GCD to calculate 's' in sa+tb
def extendedGCD(a,b):
        if a == 0:
                return (b, 0, 1)
        else:
                g, y, x = extendedGCD(b % a, a)
                return (g, x - (b // a) * y, y)

# This method returns private key for the given public key               
def computePrivateKey(e,PhiOfN):
        g, y, x = extendedGCD(e, PhiOfN)
        return y % PhiOfN

# This method computes modular exponentiation
def modular_exponentiation(a,p,n):
    if p >1:
        if p%2==0:
            return modular_exponentiation((a*a)%n,p/2,n) % n
        elif p%2 ==1:
            return a*modular_exponentiation((a*a)%n,(p-1)/2,n) % n
    else:
        return a

# RSA Implementation
def RSA(PhiOfN,message):
    (e,d)=generateKeys(PhiOfN)
    msg_in_decimal=changeTexttoDecimal(message)
    cipher=modular_exponentiation(msg_in_decimal,e,n)
    print('Cipher is: ', cipher)
    print("D is: ",d)
    msg_before_decoding=modular_exponentiation(cipher,d,n)
    msg_final=convertDecimalToText(msg_before_decoding)
    return cipher,msg_final

# Code flow starts from here and enter your inputs from here
def main():
        print('Welcome to RSA world !')
        global p,q,caseCheckFlag,n,PhiOfN
        p=0
        p = chooseRandomPrimeNumber()
        q = chooseRandomPrimeNumber()
        n=p*q   # product of two prime numbers
        PhiOfN=(p-1)*(q-1)
        caseCheckFlag=[]
        message=input('Enter your message: ')
        C,P=RSA(PhiOfN,message)
        print('p = ',p)
        print('q = ',q)
        print('n = ', p * q)
        print("You entered: ",message)
        print('Encrypted message is: ',C)
        print('Decrypted message is: ',P)

if __name__ == '__main__':
    main()
