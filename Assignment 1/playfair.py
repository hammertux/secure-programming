#!/usr/bin/python

'''
Author: Andrea Di Dio
VUnet ID: ado380
Student Number: 2593888
E-Mail: andreadidio98@gmail.com
'''

import sys


class Playfair:
    '''
    This class contains the alphabet, the key_matrix (5x5) and the list of all the digrams, once the input string has
    been parsed.
    It contains functions that are both common to the decryption process and the encryption process.
    '''

    ALPHABET = "ABCDEFGHJKLMNOPQRSTUVWXYZ"
    key_matrix = []
    row = []
    input_string = ''
    digram_list = []

    def __init__(self, s):
        self.input_string = s

    '''
    @params: the key provided in the cmd line args
    @precondition: the key cannot be longer than 25 chars
    @postcondition: A 5x5 matrix to be used as the key when encrypting/decrypting has been created
    @short-description: given the input_key, it fills a list (row) with the characters in the key, if the key is 
    shorter than 25 chars, the rest will be characters from the alphabet that are missing from the key. Finally, the row
    list is split into lists of 5 elements each and appended to the list of lists (key_matrix).
    '''
    def fillMatrix(self, input_key):
        tmp_list = []
        for i in input_key:
            if i not in self.row: #avoids duplicates in key (e.g., "helyea")
                self.row.append(i)

        for letter in self.ALPHABET:
            if letter not in input_key:
                self.row.append(letter)
        i = 0
        while i < 25:
            for j in range(i, i + 5):
                tmp_list.append(self.row[j])
            self.key_matrix.append(tmp_list[:])
            tmp_list.__init__()
            i += 5

    '''
    @params: the input_string provided in the cmd line args. (Either ciphertext or plaintext)
    @precondition: N/A
    @postcondition: the input_string has been parsed into tuples of two characters (digrams) and appended to the list of
    digrams.
    @short-description: Given an input string of chars, the function packs a digram in a tuple and appends it to the list
    of tuples (digram_list)
    '''
    def parseText(self, input):
        for i in range(0, len(input) - 1):
            if i % 2 == 0:
                digram = (input[i], input[i + 1])
                self.digram_list.append(digram)

    '''
    @params: a digram tuple
    @precondition: N/A
    @postcondition: The row number (location in key_matrix) of the two letters has been returned, if the two letters are
    not in the same row, -1 is returned. 
    '''
    def isInSameRow(self, digram):
        first_letter = digram[0]
        second_letter = digram[1]
        for i in range(0, 5) :
            if first_letter in self.key_matrix[i] and second_letter in self.key_matrix[i]:
                return i
        return -1

    '''
    @params: a digram tuple
    @precondition: N/A
    @postcondition: The row number and column number (location in the key_matrix) of the two letters has been returned in
    a tuple in the format (<first_letter_row>, <second_letter_row>, <column>), if the two letters are not in the same
    column, a tuple (-1, -1, -1) is returned.
    '''
    def isInSameColumn(self, digram):
        first_letter = digram[0]
        second_letter = digram[1]
        for i in range(0, 5):
            for j in range(0, 5):
                if first_letter in self.key_matrix[i][j]:
                    for k in range(0, 5):
                        if second_letter in self.key_matrix[k][j]:
                            return (i, k, j)
        return (-1, -1, -1)

    '''
    @params: a digram tuple
    @precondition: N/A
    @postcondition: The row number and column number (location in the key_matrix) of the two letters has been returned in
    a tuple in the format (<first_letter_row>, <first_letter_column>, <second_letter_row>, <second_letter_column>).
    '''
    def findBox(self, digram):
        first_letter = digram[0]
        second_letter = digram[1]
        first_pos = -1
        second_pos = -1
        for i in range(0, 5):
            if first_letter in self.key_matrix[i]:
                first_pos = self.key_matrix[i].index(first_letter)
                break
        for j in range(0, 5):
            if second_letter in self.key_matrix[j]:
                second_pos = self.key_matrix[j].index(second_letter)
                break
        return (i, first_pos, j, second_pos)


class Encryption(Playfair):
    '''
    This class 'Encryption', inherits from the Playfair class. The constructor initialises a Playfair object with the
    plaintext to-be-encrypted.
    The class contains an encryptDigram function used to encrypt a single digram tuple.
    '''

    def __init__(self, input_str):
        Playfair.__init__(self, input_str)

    '''
    @params: a digram tuple
    @precondition: N/A
    @postcondition: An encrypted digram has been returned as a string based on the key given.
    @short-description: This function will be called in a loop for all the digrams in the digram_list. 
                        Case 1: Digram in the same row:
                                    If the two letters of the digram are in the same row, the column of the two letters
                                    is calculated using the index() list-function, if the column number is >=4, it has to
                                    wrap around, and therefore set it to -1, this is because when in the same row, to 
                                    encode, we return the letter to the right of the plaintext_letter ([column_num + 1]).
                        Case 2: Digram in the same column:
                                    If the two letters are in the same column, using the tuple returned by the function
                                    isInSameColumn(), the function just returns the encrypted digram which contains the 
                                    letters directly under it ([row_num + 1]) in the same column. If the row number is >= 4
                                    it has to wrap around and set it to -1, so first_pos + 1 evaluates to 0.
                        Case 3: Digram forms a box:
                                    If the above cases aren't satisfied, the two letters of the digram form a box. This 
                                    means that in order to encrypt the two letters, we have to take the letter at the
                                    opposite corner of the box (in the same row) and return.
    '''
    def encryptDigram(self, digram):
        first_letter = digram[0]
        second_letter = digram[1]
        row = self.isInSameRow(digram)
        column = self.isInSameColumn(digram)
        box = self.findBox(digram)

        if row != -1:
            first_pos = self.key_matrix[row].index(first_letter)
            second_pos = self.key_matrix[row].index(second_letter)
            if first_pos >= 4:
                first_pos = -1
            if second_pos >= 4:
                second_pos = -1
            first_encrypted = self.key_matrix[row][first_pos + 1]
            second_encrypted = self.key_matrix[row][second_pos + 1]
            encrypted = (first_encrypted, second_encrypted)
            s = ''.join(encrypted)
            return s
        elif column[0] != -1:
            first_pos = column[0]
            second_pos = column[1]
            if first_pos == 4:
                first_pos = -1
            elif second_pos == 4:
                second_pos = -1
            first_encrypted = self.key_matrix[first_pos + 1][column[2]]
            second_encrypted = self.key_matrix[second_pos + 1][column[2]]
            encrypted = (first_encrypted, second_encrypted)
            s = ''.join(encrypted)
            return s
        else:
            first_pos = (box[0], box[1])
            second_pos = (box[2], box[3])
            first_encrypted = self.key_matrix[first_pos[0]][second_pos[1]]
            second_encrypted = self.key_matrix[second_pos[0]][first_pos[1]]
            encrypted = (first_encrypted, second_encrypted)
            s = ''.join(encrypted)
            return s


class Decryption(Playfair):
    '''
        This class 'Decryption', inherits from the Playfair class. The constructor initialises a Playfair object with the
        ciphertext to-be-decrypted.
        The class contains an decryptDigram function used to decrypt a single digram tuple.
    '''

    def __init__(self, input_str):
        Playfair.__init__(self, input_str)

    '''
        @params: a digram tuple
        @precondition: N/A
        @postcondition: An decrypted digram has been returned as a string based on the key given.
        @short-description: This function will be called in a loop for all the digrams in the digram_list. 
                            Case 1: Digram in the same row:
                                        If the two letters of the digram are in the same row, the column of the two letters
                                        is calculated using the index() list-function, if the column number is <= 0, it has to
                                        wrap around, and therefore set it to 5, this is because when in the same row, to 
                                        decode, we return the letter to the left of the ciphertext_letter ([column_num - 1]).
                            Case 2: Digram in the same column:
                                        If the two letters are in the same column, using the tuple returned by the function
                                        isInSameColumn(), the function just returns the decrypted digram which contains the 
                                        letters directly above it ([row_num - 1]) in the same column. If the row number is <= 0
                                        it has to wrap around and set it to 5, so first_pos - 1 evaluates to 4.
                            Case 3: Digram forms a box:
                                        If the above cases aren't satisfied, the two letters of the digram form a box. This 
                                        means that in order to decrypt the two letters, we have to take the letter at the
                                        opposite corner of the box (in the same row) and return.
        '''
    def decryptDigram(self, digram):
        first_letter = digram[0]
        second_letter = digram[1]
        row = self.isInSameRow(digram)
        column = self.isInSameColumn(digram)
        box = self.findBox(digram)

        if row != -1:
            first_pos = self.key_matrix[row].index(first_letter)
            second_pos = self.key_matrix[row].index(second_letter)
            if first_pos <= 0:
                first_pos = 5
            if second_pos <= 0:
                second_pos = 5
            first_decrypted = self.key_matrix[row][first_pos - 1]
            second_decrypted = self.key_matrix[row][second_pos - 1]
            decrypted = (first_decrypted, second_decrypted)
            s = ''.join(decrypted)
            return s
        elif column[0] != -1:
            first_pos = column[0]
            second_pos = column[1]
            if first_pos <= 0:
                first_pos = 5
            if second_pos <= 0:
                second_pos = 5
            first_decrypted = self.key_matrix[first_pos - 1][column[2]]
            second_decrypted = self.key_matrix[second_pos - 1][column[2]]
            decrypted = (first_decrypted, second_decrypted)
            s = ''.join(decrypted)
            return s
        else:
            first_pos = (box[0], box[1])
            second_pos = (box[2], box[3])
            first_decrypted = self.key_matrix[first_pos[0]][second_pos[1]]
            second_decrypted = self.key_matrix[second_pos[0]][first_pos[1]]
            decrypted = (first_decrypted, second_decrypted)
            s = ''.join(decrypted)
            return s


'''
@params: the input_string in plaintext
@precondition: N/A
@postcondition: A string with the 'I' chars replaced with 'J' chars and padding chars 'X' in case of duplicate letters
in the same digram or odd length, has been returned.
'''
def adjustInput(input_str):

    for j in input_str:
        if j == 'I':
            input_str = input_str.replace('I', 'J')
    for i in range(0, len(input_str) - 1):
        if input_str[i] == input_str[i+1] and i % 2 == 0:
            input_str = input_str[:i+1] + 'X' + input_str[i+1:]
    if len(input_str) % 2 != 0:
        input_str += 'X'
    return input_str

'''
@params: the key inputted as cmd line arg
@precondition: The input_key should not be longer than 25 chars
@postcondition: A key with the 'I' chars replaced with 'J' chars has been returned
'''
def adjustKey(input_key):

    for i in input_key:
        if i == 'I':
            input_key = input_key.replace('I', 'J')
    return input_key


if (len(sys.argv) != 4):
    print("Encryption Usage: ./playfair.py -e <key> <plaintext>")
    print("Decryption Usage: ./playfair.py -d <key> <ciphertext>")
else:
    key = sys.argv[2].upper()
    adjustKey(key)

if (sys.argv[1] == '-e'):
    plaintext = sys.argv[3].upper()
    plaintext = adjustInput(plaintext)
    encrypt = Encryption(plaintext)
    encrypt.fillMatrix(key)
    encrypt.parseText(plaintext)
    encrypted_string = ''

    for digram in encrypt.digram_list:
        encrypted_string += (encrypt.encryptDigram(digram).lower())

    print(encrypted_string)

elif (sys.argv[1] == '-d'):
    ciphertext = sys.argv[3].upper()
    decrypt = Decryption(ciphertext)
    decrypt.fillMatrix(key)
    decrypt.parseText(ciphertext)
    decrypted_string = ''

    for digram in decrypt.digram_list:
        decrypted_string += (decrypt.decryptDigram(digram).lower())

    decrypted_string = decrypted_string.replace('x', '')#remove padding letters
    print(decrypted_string)
