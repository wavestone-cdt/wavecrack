#!/usr/bin/python
# coding: utf8

"""
Code inspired by the code put in the public domain by Didier Stevens, no Copyright
https://DidierStevens.com
"""

def newDict_generation(f_in, f_out):

    with open(f_in, 'r') as fin, open (f_out, 'w') as fout:
        words_to_write = ""
        fin_read=fin.read()

        for line in iter(fin_read.splitlines()):
            my_data = line.split()
            word=my_data[0]
            fout.write(word.lower() + '\n')
            l=len(word)
            toggles = [[i] for i in range(0, l)]

            while toggles != []:
                words_to_write = changeCase(toggles, l, word,)
                fout.write(words_to_write )
                toggles = TogglesPlusOne(toggles, l)

        fout.flush()

def changeCase(liste, l, word):

    char_list=[]
    ulist=[]
    wordlist = ''

    for i in range(len(liste)):
        uList=liste[i] 

        for i in range(l):
            if i in uList:
                char_list.append(word[i].upper())
            else:
                char_list.append(word[i].lower())
        wordlist += ''.join(char_list) + '\n'      
        char_list=[]

    return wordlist

def TogglesPlusOne(toggles, max):
    
    result = []
    for toggle in toggles:
        for i in range(toggle[-1] + 1, max):
            result.append(toggle + [i])

    return result          
