#!/usr/bin/python

import sys


class Playfair:

    ALPHABET = "ABCDEFGHJKLMNOPQRSTUVWXYZ"
    key_matrix = []
    row = []
    input_string = ''
    digraph_list = []

    def __init__(self, s):
        self.input_string = s

    def fillMatrix(self, input_key):
        tmp_list = []
        for i in input_key:
            if i not in self.row:
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
        return self.key_matrix


    def printMatrix(self):#DEBUG
        print(self.key_matrix)
        print(len(self.key_matrix))

    def parseText(self, input):
        for i in range(0, len(input) - 1):
            if i % 2 == 0:
                digraph = (input[i], input[i + 1])
                #print digraph
                self.digraph_list.append(digraph)
        #print self.digraph_list

    def isInSameRow(self, digraph):
        first_letter = digraph[0]
        second_letter = digraph[1]
        for i in range(0, 5) :
            if first_letter in self.key_matrix[i] and second_letter in self.key_matrix[i]:
                return i
        return -1

    def isInSameColumn(self, digraph):
        first_letter = digraph[0]
        second_letter = digraph[1]
        for i in range(0, 5):
            for j in range(0, 5):
                if first_letter in self.key_matrix[i][j]:
                    for k in range(0, 5):
                        if second_letter in self.key_matrix[k][j]:
                            return (i, k, j)
        return (-1, -1, -1)

    def findBox(self, digraph):
        first_letter = digraph[0]
        second_letter = digraph[1]
        for i in range(0, 5):
            if first_letter in self.key_matrix[i]:
                first_pos = self.key_matrix[i].index(first_letter)
                break
        for j in range(0, 5):
            if second_letter in self.key_matrix[j]:
                second_pos = self.key_matrix[j].index(second_letter)
                return (i, first_pos, j, second_pos)
        return (-1, -1, -1, -1)

    def encryptDigraph(self, digraph):
        first_letter = digraph[0]
        second_letter = digraph[1]
        row = self.isInSameRow(digraph)
        #print row
        column = self.isInSameColumn(digraph)
        #print column
        box = self.findBox(digraph)
        #print box
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

    def decryptDigram(self, digram):
        first_letter = digram[0]
        second_letter = digram[1]
        row = self.isInSameRow(digram)
        # print row
        column = self.isInSameColumn(digram)
        # print column
        box = self.findBox(digram)
        # print box
        if row != -1:
            first_pos = self.key_matrix[row].index(first_letter)
            second_pos = self.key_matrix[row].index(second_letter)
            if first_pos <= 0:
                first_pos = 5
            if second_pos <= 0:
                second_pos = 5
            first_encrypted = self.key_matrix[row][first_pos - 1]
            second_encrypted = self.key_matrix[row][second_pos - 1]
            encrypted = (first_encrypted, second_encrypted)
            s = ''.join(encrypted)
            return s
        elif column[0] != -1:
            first_pos = column[0]
            second_pos = column[1]
            if first_pos <= 0:
                first_pos = 5
            if second_pos <= 0:
                second_pos = 5
            first_encrypted = self.key_matrix[first_pos - 1][column[2]]
            second_encrypted = self.key_matrix[second_pos - 1][column[2]]
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


def adjustKey(input_key):

    for i in input_key:
        if i == 'I':
            input_key = input_key.replace('I', 'J')
    return input_key


if (len(sys.argv) != 4):
    print("Encryption Usage: ./playfair.py -e <key> <plaintext>")
    print("Decryption Usage: ./playfair.py -d <key> <ciphertext>")
elif (sys.argv[1] == '-e'):
    key = sys.argv[2].upper()
    adjustKey(key)
    #print(key, " ", len(key))
    plaintext = sys.argv[3].upper()
    plaintext = adjustInput(plaintext)
    #print(plaintext, " ", len(plaintext))
    play = Playfair(plaintext)
    play.fillMatrix(key)
    #play.printMatrix()
    play.parseText(plaintext)
    encrypteds = ''
    for digram in play.digraph_list:
        encrypteds += (play.encryptDigraph(digram).lower())
    print(encrypteds)
elif (sys.argv[1] == '-d'):
    key = sys.argv[2].upper()
    #print(key, " ", len(key))
    adjustKey(key)
    ciphertext = sys.argv[3].upper()
    #adjustInput(key)
    play = Playfair(ciphertext)
    play.fillMatrix(key)
    #play.printMatrix()
    play.parseText(ciphertext)
    decrypteds = ''
    for digram in play.digraph_list:
        decrypteds += (play.decryptDigram(digram).lower())
    decrypteds = decrypteds.replace('x','')
    print(decrypteds)