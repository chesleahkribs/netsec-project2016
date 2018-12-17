#FIXME: TEST SEVERAL TIMES OVER

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from timeit import default_timer as timer

import signal
import sys
import time

#Reads line by line, since reading entire file will consume too much ram

choice = 0;
numhashes = 0;
filename = "";
file1 = "";
encoded_string = "";
choices = {
    1 : hashes.SHA256(),
    2 : hashes.MD5(),
    3 : hashes.RIPEMD160(),
    4 : hashes.Whirlpool(),
}



def menu():
     global choice;
     invalid = True
     while invalid :
         print ("\n\
         Please Select a Hashing Algorithm:\n\
         1. sha2 (256-bit hash)\n\
         2. md5 (128-bit hash)\n\
         3. ripemd160 (160-bit hash)\n\
         4. whirlpool (512-bit hash)\n\
         5. Exit")
         choice = raw_input("\
         : ").replace(" ","")
         choice = int(choice)
         #check user input
         if(choice == 1 or choice == 2 or
          choice == 3 or choice == 4 or choice == 5):
            invalid = False;
         else:
            print "Invalid choice: try again!"


#filename
def menu2():
    global filename;
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


    #check file is valid

#numhashes
def menu3():
    global numhashes;
    invalid = True
    while invalid :
        numhashes = raw_input("Hash n times:  ").replace(" ","")
        numhashes = int(numhashes)
        if(numhashes > 0 and numhashes < 1000000):
            invalid = False
        else:
            print "Invalid hash number: try again!"

def main():
    global file1, choice, numhashes, filename;
    #loop choice, numhashes, filename
    while choice is not 5:
        menu()
        if(choice == 5): print "Exiting..."; sys.exit();
        menu2()
        menu3()
        hashSelector()

def hashSelector():
    global choice;
    if(choice == 1):
        hash(1)
    elif(choice == 2):
        hash(2)
    elif(choice == 3):
        hash(3)
    elif(choice == 4):
        hash(4)
    elif(choice == 5):
        return;

def hash(algo):
    #\x escape sequence next 2 interpreted as hex digits
    global file1, encoded_string, numhashes;
    digest = createHasher(algo)
    with open(filename, 'rb') as file1:
        start = timer()
        for line in file1:
            digest.update(line)

    encoded_string = digest.finalize().encode('hex')
    print "hashing %dnth  = %s" % (numhashes, encoded_string)
    numhashes = numhashes - 1;
    while(numhashes > 0 ):
        digest = createHasher(algo)
        digest.update(encoded_string)
        encoded_string = digest.finalize().encode('hex')
        print "hashing %dnth  = %s" % (numhashes, encoded_string)
        numhashes = numhashes - 1;
    #end timing and print!
    end = timer()
    print "time elapsed: %f" % (end-start)
    print ""
    print encoded_string

def createHasher(choice):
    #return object with choice algorithm
    return hashes.Hash(choices[choice], backend=default_backend())



#signal handler
def sigint_handler(signal_num, frame):
    print >>sys.stderr, "exiting Hasher.",
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
