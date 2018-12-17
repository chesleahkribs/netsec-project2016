#Encryption File

#Need to put it in a file and then decrypt
#TODO: TEST EVERY COMBINATION (ENCRYPT AND DECRYPT)
#TODO: use time instead of timer!!


from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

import os
import signal
import sys
from timeit import default_timer as timer
import time

#Global Variables
algo = 0
mode = 0
keysize = 0
iv = os.urandom(16)
key = os.urandom(16)
backend = default_backend()
filename = ""
efile = ""
dfilename = ""
file2decrypt = ""
ind = 0 #cipher object index
efile_crypt_object = []

#initialize cipher object: mode type
def modeObject(mode):
    if(mode == 1): return modes.CBC(iv);   #requires padding
    elif(mode == 2): return  modes.OFB(iv) #stream cipher
    elif(mode == 3): return modes.CFB(iv)  #stream cipher
    elif(mode == 4): return modes.CTR(iv)  #stream cipher
    elif(mode == 5): return modes.ECB()          #requires padding


#initialize cipher object: algorithm type
def choicesS(algo):
    if(algo == 1): return algorithms.AES(key) #block size == 128 bits
    elif(algo == 2): return algorithms.TripleDES(key) #64 bits
    elif(algo == 3): return algorithms.Camellia(key) #128 bits
    elif(algo == 4): return algorithms.CAST5(key) #64 bits
    elif(algo == 5): return algorithms.SEED(key) #128 bits

#initialize iv to match block size:  CBC, CTR, OFB, CFB, ECB?
def ivSize(algo):
    if(algo == 1): return  16;
    elif(algo == 2): return 8;
    elif(algo == 3): return 16;
    elif(algo == 4): return 8;
    elif(algo == 5): return 16;



#efilename mode string
modeName = {
    1 : "CBC",
    2 : "OFB",
    3 : "CFB",
    4 : "CTR",
    5 : "ECB",
}

#efilename algo string
algoName = {
    1 : "AES",
    2 : "TripleDES",
    3 : "Camellia",
    4 : "CAST5",
    5 : "SEED",
}

#symmetric or asymmetric
def mainMenu():
    global algo, keysize;
    invalid = True
    while(invalid):
        print ("\n\
        Please Select Encryption Scheme:\n\
        Symmetric Encryption:\n\
        1. AES (key size: 128, 192 or 256 bits)\n\
        2. TripleDES (key size: 64 or 192 bits)\n\
        3. Camellia (key size: 128, 192 or 256 bits)\n\
        4. CAST5 (key size: 40 - 128 multiples of 8 bits)\n\
        5. SEED (key size: 128 bits)\n\
        Symmetric Decryption:\n\
        6. Decryption\n\
        7. Exit")
        algo = int(raw_input("\
        : "))
        if(algo == 6): return;
        if(algo == 7): return;
        if(algo == 5): print "Keysize = 128"; keysize = 128; return; 
        keysize = int(raw_input("Enter Keysize: "))
        invalid = checkAlgoKeyCombination()
        if(invalid): print "Please enter valid combination!"

#encryption mode?
def menuMode():
    global mode
    invalid = True
    while(invalid):
        print("\n\
        Please Select Mode of Operation:\n\
        1 : CBC(iv)\n\
        2 : OFB(iv)\n\
        3 : CFB(iv)\n\
        4 : CTR(iv)\n\
        5 : ECB\n\
        ")
        mode = int(raw_input("\
        : "))
        if(mode == 1 or mode == 2 or mode == 3 or mode == 4 or mode == 5):
            invalid =  False;
        else: invalid = True; print "Invalid Mode: Pick 1-5!"


#check combination is valid
def checkAlgoKeyCombination():
    global algo, keysize;
    #combination for symmetric
    if((algo == 1 or algo == 3)
        and (keysize == 128 or keysize == 192 or keysize == 256)):
        return False;
    elif((algo == 5) and keysize == 128):
        return False;
    elif(algo == 2 and (keysize == 64 or keysize == 192 )):
        return False;
    elif(algo == 4 and (keysize >= 40 and keysize <= 128 and keysize%8 == 0)):
        return False;
    elif(algo == 7): return False;
    else: return True



def main():
    global algo
    isExit = False
    while(not isExit):
        mainMenu()
        if(algo == 7): isExit = True;
        elif(algo <= 5): menuMode(); symmetricEncryption();
        elif(algo == 6): symmetricDecryption();
        else: print "Not a Valid Choice?"
    print "Encrypt/Decrypt Module exiting..."
    sys.exit();

#encrypt and save IV and key
def symmetricEncryption():
    #create key and iv
    global iv, key, keysize, filename, efile
    keysize /= 8;
    iv = os.urandom(ivSize(algo))
    key = os.urandom(keysize)
    #ask for filename + create encrypted file
    openCreateFile()
    fencrypted = open(efile, "w+")
    #create encryption object
    encryptor = createEncrypter()
    if(mode == 1 or mode == 5):
        symmetricEncryptionWPadding(encryptor, fencrypted); return;
    str1 = ""
    #encrypt line by line while TIMING
    with open(filename, "rb") as plainfile:
        start = timer()
        for line in plainfile:
            str1 += encryptor.update(line)

    str1 += encryptor.finalize()
    fencrypted.write(str1)
    stop = timer()
    print "time elapsed: %f" % (stop-start)
    fencrypted.close()

#adds padding to each line before encrypting
def symmetricEncryptionWPadding(encryptor, fencrypted):
    #padder object
    #block size == AES 128, TripleDES 64, Cam 128, CAST 64, SEED 128
    if(algo == 1 or algo == 3 or algo == 5): blocksize = 128;
    else: blocksize = 64;
    padder = padding.PKCS7(blocksize).padder()
    str1 = ""
    with open(filename, "rb") as plainfile:
        start = timer()
        for line in plainfile:
            line = padder.update(line)
            str1 += encryptor.update(line)
        line = padder.finalize()
        str1 += encryptor.update(line)
        str1 += encryptor.finalize()
        fencrypted.write(str1)
        # fencrypted.write(str1)
        stop = timer()
        print "time elapsed: %f" % (stop-start)
        fencrypted.close()

#returns cipher object and saves in list
def createEncrypter():
    global algo, mode;
    print "algo = %d" % algo
    cipher = Cipher(choicesS(algo), modeObject(mode), backend=backend)
    efile_crypt_object.append(cipher)
    return cipher.encryptor()

#check plaintext file, create encryption file
def openCreateFile():
    global filename, efile, efile_crypt_object, choicesS, modes;
    #open filename: error check
    invalid = True
    while invalid :
        filename = raw_input("Please enter a Filename: ").replace(" ","")
        try:
            f1 = open(filename, 'rb')
            f1.close()
            invalid = False
        except IOError:
            print "Invalid file name: try again!"
            invalid = True
    #create encrypted file
    print "algo = %d mode = %d" % (algo, mode)
    efile = filename + ".sym." + algoName[algo] + "." + modeName[mode] + \
    ".index" +  str(len(efile_crypt_object))
    print "efile = %s" % efile
    fencrypted = open(efile, "w+")
    fencrypted.close()


#creates new file, use decryptor object line by line and appends to file
def symmetricDecryption():
    global file2decrypt;
    #get filename and index
    openEncrypted()
    #create decrypted file, key from filename
    dfilename= file2decrypt + ".decr"
    print "decrypted filename = %s" % dfilename
    #open it for writing
    dfile = open(dfilename, "w+")
    #get cipher object using index at the end of the file!
    decryptor = efile_crypt_object[ind].decryptor()
    #decrypt line by line
    if("CBC" in file2decrypt or "ECB" in file2decrypt):
        symmetricDecryptionWPadding(dfilename, dfile, decryptor); return;

    str1 = ""
    with open(file2decrypt, "rb+") as plainfile:
        start = timer()
        for line in plainfile:
            str1 += decryptor.update(line)
    str1 += decryptor.finalize()
    dfile.write(str1)
    stop = timer()
    print "time elapsed: %f" % (stop-start)
    dfile.close()

#unpad and then decrypt
def symmetricDecryptionWPadding(dfilename, dfile, decryptor):
    global file2decrypt;
    if("AES" in file2decrypt or "Camellia" in file2decrypt or
    "SEED" in file2decrypt): blocksize = 128;
    else: blocksize = 64;
    line = ""
    str1 = ""
    unpadder = padding.PKCS7(blocksize).unpadder()
    with open(file2decrypt, "rb+") as plainfile:
        start = timer()
        for line in plainfile:
            line = decryptor.update(line)
            str1 += unpadder.update(line)

    str1 += decryptor.finalize()
    str1 += unpadder.finalize()
    dfile.write(str1)
    stop = timer()
    print "time elapsed: %f" % (stop-start)
    dfile.close()


#check if file2decrypt exists
def openEncrypted():
    global file2decrypt, ind, dfilename;
    invalid = True
    while invalid :
        file2decrypt = raw_input("Enter File to Decrypt: ").replace(" ","")
        try:
            f2 = open(file2decrypt, 'rb')
            f2.close()
            invalid = False
        except IOError:
            print "Invalid file name: try again!"
            invalid = True
    invalid = True
    #check index exists
    while invalid:
        #get the index from file name
        ind = int(file2decrypt[file2decrypt.find("index")+5:])
        if(ind >= 0 and ind < len(efile_crypt_object)): return False
        else: print "index doesn't exist!"; sys.exit();

#given index, returns cipher object to decrypt
def createDecrypter(ind):
    cipher = efile_crypt_object[index]
    return cipher.decryptor()


#signal handler
def sigint_handler(signal_num, frame):
    print >>sys.stderr, "exiting Encrypt/Decrypt module.",
    time.sleep(.2)
    print>>sys.stderr,".",
    time.sleep(.2)
    print>>sys.stderr,".",
    time.sleep(.3)
    print>>sys.stderr,".",
    time.sleep(.5)
    print>>sys.stderr,"."
    sys.exit()

#handles exit signal
signal.signal(signal.SIGINT, sigint_handler)
main()
