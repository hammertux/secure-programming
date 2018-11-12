#!/usr/bin/python
#SET THIS LINE ABOVE TO THE CORRECT PYTHON 2 PATH!!

from __future__ import print_function
import sys
import subprocess

#PYTHON PATH AND SHEBANG MUST BE SUBSTITUTED WITH THE CORRECT PYTHON 2 VERSION!!
PYTHONPATH = "/usr/bin/python" #TRY /usr/bin/python for example



WELCOME_MESSAGE = """Playfair test script V0.1 by Ruben van der Ham, this is free software running python at {}
Requirement: Implementation must be exactly as in the assignment specified! (playfair.py -e/-d key plain/cipher)
Note: - Decryption officialy not supported by TA's as per canvas
      - Verbosity can be increased by appending -v to your command
      - PASSES if BOTH encryption and encryption pass, for individual tests, append -v\n""".format(PYTHONPATH)
TEST_MESSAGE = "'{}' <--'{}'--> '{}'"
ENCRYPTION = "\tEncryption ---> {}"
DECRYPTION = "\tDecryption <--- {}"
newline = False

data="""welcometosecureprogramming,crypto,zbuoalkeelotvcdtcamagvqgmh
thisisgoingtobealotoffun,helyea,panpnpotkoozjglhamztnybxsy
letusbeginwitharatherlonglonglonglognkey,abcdefghjklmnopqrstuvwxyz,pauqrcbkhoygsjbqdqkcqmpofmpofmpofmmjphdz
haveyounticedwecannotusethatlastcharacterinthealphabet,okhere,ocyovezuqmdhbyhdfggrupthsedpgctulcfobdydknmuercgsobcdy
andthatwecannotusetheletteriinthekey,yup,yrcvlyvxfdyroqvyqgynfkcwwcolhoynkqcp
cilgnnhcqoss,fdlnhkeo,gmdjlyhfqvjxxl
qlefhznvqpqmctmeimnw,lypuntkwhgsmrxofvdajczeb,cncdkbyjenzolsrzvopg
cdivcutea,gvrd,fvkgbwqhrz
lrtfpssw,bfpmtnhkurwglyoj,okbpfvqg
vrtndrkwyscvdohhcsgnt,zutqjogyvkmnrhcafwelds,yhurbmylgbhkzmcpcmunru
nvhpcvwdtocgapgvluzqaoerwy,qzrgahsubfvleckjxtyd,mlbmklaworybgwqcesrzrwtupd
bkubbvjqvzaojtnf,cslfwtjudzyvkpmbe,aytaeyuomjequjrc
jbhdjp,cdrovqulht,kauokj
jhkvziqtvzrceiljmkfzrf,bxrhmeswgqp,nblutoezytwlptnkxoommc
stmpupicrzkbthkyjusdumrkvqu,vefhnlqbatgkdyspocxrjzu,rsjxjcupowdqandszmgymwoselmc
oqzrsizdqfcvdasyjula,psjzo,jtdxjzdkmhbwebovpwfe
dughkaaoylajtpihp,vz,ethdlzvqwnvluondru
senqgnkuijowykpnciyr,xfeadugvsjrnmyzpwlkbt,vazcnwpsudsqknbwwfszpu
bwfbdnd,dzlt,eugcahtu
mauprziiwtfpcowlolsssjzuscqioweoevbyivz,kbcymuftjhelqxnrwogsdvzp,hmjdodxgfgjtzygoqwnwgnghdtomxtgoqrldcmfppq
fzzjdimtfcpzqzvhtbkoobroc,jqclatfhywrnkzpoxsugebv,ynrlelewhqrplnckfersxeoeqs
vluejvydypweifuughosvcyjaqhthrpbqvrqjg,jkpsexgfyamcqbtnrwoh,zuzpsdxvfshppxdflfnhysbgextwhzwktblompfg
hlfcgakenljzrgwk,jfhvegdouyktx,fmjlukbjpmeqqdqa
mupyjywmegqieqyq,rqlfdo,uztwkxzhomlhadwf
ofsocfbqqztbudnau,pf,lcumpaptuvyhqjmbsz
oiigqcuhltfv,vuoytmzgrepl,yhhrxlofcudu
uedynlrcnhpurrtfnjelyklvkigqkqceb,pknrecya,zpcaehpbaqcpbreshplrgdegkylhonmard
awrqbnswyo,kwabdxusjol,bazhapuazj
zdwujripibanuov,z,azxvgtetgdclykwy
hwevdrtmcczdlgiakvmy,hm,mvdweqrbazjcekjdhnwhzy"""

def test(program,key,plain, cipher, verbosity):

    #encrypt
    global newline
    result = run(program,"-e",key,plain)
    if result[-1] == "\n":
        newline = True
        result = result[:-1]
    encryptpass = result == cipher

    if encryptpass:
        encryptstatus = bcolors.OKGREEN+"PASSED"+bcolors.ENDC
    else:
        encryptstatus = bcolors.FAIL+"FAILED"+bcolors.ENDC

    message = TEST_MESSAGE.format(plain,key,cipher)
    if verbosity:
        print(message)
        print(str.format(ENCRYPTION.format(encryptstatus))+"  your result: '"+result+"'\n")


    plain = plain.replace("i","j")
    #We translate every i to j, because we can't distinguish from the cipher text


    #decrypt
    result = run(program,"-d",key,cipher)
    if result[-1] == "\n":
        newline = True
        result = result[:-1]
    decryptpass = result == plain
    if decryptpass:
        decryptstatus = bcolors.OKGREEN+"PASSED"+bcolors.ENDC
    else:
        decryptstatus = bcolors.FAIL+"FAILED"+bcolors.ENDC

    if verbosity:
        print(str.format(DECRYPTION.format(decryptstatus))+"  your result: '"+result+"'\n")
    else:
        if encryptpass and decryptpass:#decryptstatus == "PASSED" and encryptstatus == "PASSED":
            print(bcolors.OKGREEN+"PASS   "+bcolors.ENDC+message)
        else:
            print(bcolors.FAIL+"FAIL   "+bcolors.ENDC+message)



def run(program,mode,key,text):
    return subprocess.check_output(["{} {} {} {} {}".format(PYTHONPATH,program,mode,key,text)],shell=True).decode("UTF-8")

def main():
    print(bcolors.HEADER+WELCOME_MESSAGE+bcolors.ENDC)

    if sys.version_info > (3,0):
        print("Exiting: python 3 IS NOT SUPPORTED IN THIS ASSIGNMENT.... \n SET THE PYTHON PATH IN THE SOURCE CODE TO PYTHON 2")
        exit(1)

    if(len(sys.argv) < 2):
        print("Example usage: ./test_playfair playfairimplementation.py [-v]")
        exit(1)


    program = sys.argv[1]

    verbosity = False
    if len(sys.argv)==3 and sys.argv[2]=="-v":
        verbosity = True

    tests = data.split("\n")

    for line in tests:
        item = line.split(",")
        test(program,item[1],item[0],item[2],verbosity)

    if newline:
        print(bcolors.WARNING+"\nWARNING: your program prints '\\n' characters after the result. This program allows it, maybe your TA won't"+bcolors.ENDC)


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


if __name__ == '__main__':
    main()
