# run on python 311

# txt = 8787878787878787
# key = 0E329232EA6D0D73
# 0000000000000000
import tkinter as tk
import tkinter.font as tkfont
from tkinter import *
from tkinter.ttk import *
from tkinter.font import Font

root = tk.Tk()
page1 = Frame(root)
page2 = Frame(root)
page3 = Frame(root)
page4 = Frame(root)
page5 = Frame(root)
page1.grid(row=0, column=0, sticky="nsew")
page2.grid(row=0, column=0, sticky="nsew")
page3.grid(row=0, column=0, sticky="nsew")
page4.grid(row=0, column=0, sticky="nsew")
page5.grid(row=0, column=0, sticky="nsew")

# For changing the icon of the title bar
pic = PhotoImage(file=r'./\encrypt.png')
root.iconphoto(False, pic)
# For changing the title of the title bar
root.title("Encryption and Decryption")
# To set the dimensions of the window
root.geometry("500x500")  # width x height
# To set whether we can resize the window or not.The below line doesn't allow the resizing of the window.
root.resizable(width=FALSE, height=FALSE)
# Creating a canvas
canvas = tk.Canvas(page1, height=500, width=500, bg="#F3DFEC")
canvas2 = tk.Canvas(page2, height=500, width=500, bg="#f3dfec")
canvas3 = tk.Canvas(page3, height=500, width=500, bg="#F3DFEC")
canvas4 = tk.Canvas(page4, height=500, width=500, bg="#E4C59E")
canvas5 = tk.Canvas(page5, height=500, width=500, bg="#E4C59E")
# Attaching the canvas
canvas.pack()
canvas2.pack()
canvas3.pack()
canvas4.pack()
canvas5.pack()

bold_font = tkfont.Font(family='Gadugi', size=15, weight="bold")

labelHeart1 = tk.Label(page1, text="🤍", width=3, bg="#F3DFEC", foreground="#E1AFD1")#
labelHeart1.config(font=bold_font)
canvas.create_window(125, 50, window=labelHeart1)

labelChoose = tk.Label(page1, text="CHOOSE A CIPHER", width=15,pady=20, bg="#F3DFEC", foreground="#7469B6")
labelChoose.config(font=bold_font )
canvas.create_window(250, 50, window=labelChoose)

labelHeart1 = tk.Label(page1, text="🤍", width=3, bg="#F3DFEC", foreground="#E1AFD1")#
labelHeart1.config(font=bold_font)
canvas.create_window(370, 50, window=labelHeart1)

#كل زار ليه عرض ولون وبيقول اما يداس يخلي الصفحه بتاعته تون فوق
button1 = tk.Button(page1, text="Caesar Cipher", width=16, pady=20, command=lambda: page2.tkraise())
button1.config(background="#AD88C6", font=bold_font, foreground="#FFFFFF")
button2 = tk.Button(page1, text="Vigenère Cipher", width=16, pady=20, command=lambda: page3.tkraise())
button2.config(background="#AD88C6", font=bold_font, foreground="#FFFFFF")
button3 = tk.Button(page1, text="Playfair Cipher", width=16, pady=20, command=lambda: page4.tkraise())
button3.config(background="#AD88C6", font=bold_font, foreground="#FFFFFF")
button4 = tk.Button(page1, text="DES Cipher", width=16, pady=20, command=lambda: page5.tkraise())
button4.config(background="#AD88C6", font=bold_font, foreground="#FFFFFF")
button5 = tk.Button(page1, text="Exit", width=8, pady=1, command=root.destroy)
button5.config(background="white", font=bold_font, foreground="#7469B6")

#مكان كل زار فينx
canvas.create_window(125, 150, window=button1)
canvas.create_window(375, 150, window=button2)
canvas.create_window(125, 300, window=button3)
canvas.create_window(375, 300, window=button4)
canvas.create_window(250, 445, window=button5)

#********************************************************
#🌸.  ❤️  𓆩♡𓆪  ♥️  ✨  ♡  🔓 🤍 ♡💗🖤☹ ☾ ✧˚ ༘ ⋆｡˚☆ ૮꒰•༝ •。꒱ა
# #7469B6   #AD88C6  #E1AFD1  #FFE6E6
# green #4F6F52  #ABB669  #555C2D
#yelow #e7e218    #fcd203   #f3cb03
# ****************************page2*****************************

key_page2 = StringVar()
#ceaser txt
labelHeart = tk.Label(page2, text="🤍", width=3, bg="#f3dfec", foreground="#E1AFD1")#
labelHeart.config(font=bold_font)
canvas2.create_window(180, 50, window=labelHeart)

labelCeaser = tk.Label(page2, text="CAESER", width=9, bg="#f3dfec", foreground="#7469B6")#
labelCeaser.config(font=bold_font)
canvas2.create_window(250, 50, window=labelCeaser)

labelHeart1 = tk.Label(page2, text="🤍", width=3, bg="#f3dfec", foreground="#E1AFD1")#
labelHeart1.config(font=bold_font)
canvas2.create_window(320, 50, window=labelHeart1)

                                                                              #7469B6
label1 = tk.Label(page2, text="Enter the Text", width=15,pady=8, bg="#E1AFD1", foreground="#7469B6")
label1.config(font=bold_font)
canvas2.create_window(100, 100, window=label1)
user_text = tk.Entry(page2, width=20,foreground="#7469B6")
user_text.config(font=bold_font)
canvas2.create_window(350, 100, window=user_text)

label11 = tk.Label(page2, text="Enter Key number", width=15,pady=8, bg="#E1AFD1", foreground="#7469B6")
label11.config(font=bold_font)
canvas2.create_window(100, 180, window=label11)
key1 = tk.Entry(page2, textvariable=key_page2,show="*", width=20,foreground="#7469B6")
key1.config(font=bold_font)
canvas2.create_window(350, 180, window=key1)

label2 = tk.Label(page2, text="Choose", width=15,pady=8, bg="#E1AFD1", foreground="#7469B6")
label2.config(font=bold_font)
canvas2.create_window(100, 280, window=label2)

#holding integer values used in Radiobuttons,
v = tk.IntVar()
def choice():
    x = v.get()
    if (x == 1):
        encryption()
    elif (x == 2):
        decryption()

label3 = tk.Radiobutton(page2, text="Encryption", padx=20,width=15, variable=v, value=1, command=choice, bg="white",foreground="#7469B6")
label3.config(font=bold_font)
canvas2.create_window(350, 250, window=label3)
label4 = tk.Radiobutton(page2, text="Decryption", padx=20,width=15 ,variable=v, value=2, command=choice, bg="white",foreground="#7469B6")
label4.config(font=bold_font)
canvas2.create_window(350, 310, window=label4)

#__________________________caeser page 2_____________________________
def encryption():
    if key_page2.get():
        key = int(key1.get())
    else:
        key = 3
    plain_text = user_text.get()
    cipher_text = ""
    for i in range(len(plain_text)):
        letter = plain_text[i]
        if (letter == ' '):
            cipher_text += ' '
            continue
        if (letter.isupper()):
            cipher_text += chr((ord(letter) + int(key) - 65) % 26 + 65)
        else:
            cipher_text += chr((ord(letter) + int(key) - 97) % 26 + 65)
    label5 = tk.Label(page2, text=cipher_text, width=20, bg="white",foreground="#f3cb03")
    label5.config(font=bold_font)
    print("Caeser Encryption: " + cipher_text)
    canvas2.create_window(350, 375, window=label5)

def decryption():
    if key_page2.get():
        key = int(key1.get())
    else:
        key = 3
    cipher_text = user_text.get()
    plain_text = ""
    for i in range(len(cipher_text)):
        letter = cipher_text[i]
        if (letter == ' '):
            plain_text += ' '
            continue
        if (letter.isupper()):
            plain_text += chr((ord(letter) - key - 65) % 26 + 65)
        else:
            plain_text += chr((ord(letter) - key - 97) % 26 + 97)#foreground="#4f458e"
    label6 = tk.Label(page2, text=plain_text, width=20, bg="white",foreground="#f3cb03")
    label6.config(font=bold_font)
    print("Caeser Decryption: "+plain_text)
    canvas2.create_window(350, 375, window=label6)


label7 = tk.Label(page2, text="Converted Text ", width=15,pady=8, bg="#7469B6",foreground="#FFFFFF")
label7.config(font=bold_font)
canvas2.create_window(100, 375, window=label7)
button21 = tk.Button(page2, text="Back", width=8, pady=1, command=lambda: page1.tkraise())
button21.config(background="white", font=bold_font, foreground="#7469B6")
canvas2.create_window(250, 445, window=button21)

#___________________vigenere page3____________________
kaay_page3 = StringVar()
#ceaser lable 🤍VIGENERE🤍
labelHeart3 = tk.Label(page3, text="🤍", width=3, bg="#f3dfec", foreground="#E1AFD1")#
labelHeart3.config(font=bold_font)
canvas3.create_window(180, 50, window=labelHeart3)

labelVigener = tk.Label(page3, text="VIGENERE", width=9, bg="#f3dfec", foreground="#7469B6")#
labelVigener.config(font=bold_font)
canvas3.create_window(250, 50, window=labelVigener)

labelHeart31 = tk.Label(page3, text="🤍", width=3, bg="#f3dfec", foreground="#E1AFD1")#
labelHeart31.config(font=bold_font)
canvas3.create_window(320, 50, window=labelHeart31)

label31 = tk.Label(page3, text="Enter the Text", width=15,pady=8, bg="#E1AFD1",foreground="#7469B6")
label31.config(font=bold_font)
canvas3.create_window(100, 100, window=label31)
user_text3 = tk.Entry(page3, width=20,foreground="#7469B6")
user_text3.config(font=bold_font)
canvas3.create_window(350, 100, window=user_text3)

label322 = tk.Label(page3, text="Enter Key Text", width=15,pady=8, bg="#E1AFD1", foreground="#7469B6")
label322.config(font=bold_font)
canvas3.create_window(100, 180, window=label322)
key_text = tk.Entry(page3, textvariable=kaay_page3,show="*", width=20,foreground="#7469B6")
key_text.config(font=bold_font)
canvas3.create_window(350, 180, window=key_text)

label32 = tk.Label(page3, text="Choose", width=15,pady=8, bg="#E1AFD1", foreground="#7469B6")
label32.config(font=bold_font)
canvas3.create_window(100, 280, window=label32)

v3 = tk.IntVar()

def choice3():
    x3 = v3.get()
    if (x3 == 1):
        encryption3()
    elif (x3 == 2):
        decryption3()


label33 = tk.Radiobutton(page3, text="Encryption", padx=20,width=15, variable=v3, value=1, command=choice3, bg="white",foreground="#7469B6")
label33.config(font=bold_font)
canvas3.create_window(350, 250, window=label33)
label34 = tk.Radiobutton(page3, text="Decryption", padx=20,width=15 , variable=v3, value=2, command=choice3, bg="white",foreground="#7469B6")
label34.config(font=bold_font)
canvas3.create_window(350, 310, window=label34)

#__________vigenere en / dec_______________
def encryption3():
    if kaay_page3.get():
        key_text3 = kaay_page3.get()
        key_text3 = key_text3.lower()
    else:
        key_text3 = "deceptive"
    plain_text3 = user_text3.get()
    plain_text3 = plain_text3.lower()
    cipher_text3 = ""
    for i in range(len(plain_text3)):
        letter3 = plain_text3[i]
        if (letter3 == ' '):
            continue
        cipher_text3 += chr((ord(letter3) + (ord(key_text3[i % len(key_text3)]) - 97) - 97) % 26 + 65)
    label35 = tk.Label(page3, text=cipher_text3, width=20,  bg="white",foreground="#f3cb03")
    label35.config(font=bold_font)
    print("Vigenere Encryption: "+cipher_text3.lower())
    canvas3.create_window(350, 375, window=label35)


def decryption3():
    if kaay_page3.get():
        key_text3 = kaay_page3.get()
        key_text3 = key_text3.lower()
    else:
        key_text3 = "deceptive"
    cipher_text = user_text3.get()
    plain_text = ""
    for i in range(len(cipher_text)):
        letter = cipher_text[i]
        if (letter == ' '):
            continue
        plain_text += chr((ord(letter) - (ord(key_text3[i % len(key_text3)]) - 97) - 97) % 26 + 65)
    label36 = tk.Label(page3, text=plain_text, width=20, bg="white",foreground="#f3cb03")
    label36.config(font=bold_font)
    print("Vigenere decryption: " + plain_text)
    canvas3.create_window(350, 375, window=label36)


label37 = tk.Label(page3, text="Converted Text ", width=15,pady=8, bg="#7469B6",foreground="#FFFFFF")
label37.config(font=bold_font)
canvas3.create_window(100, 375, window=label37)
button31 = tk.Button(page3, text="Back", width=8, pady=1, command=lambda: page1.tkraise())
button31.config(background="white", font=bold_font, foreground="#7469B6")
canvas3.create_window(250, 445, window=button31)

# _________________page4_playfair________________________
palo_text = StringVar()
kayo_text = StringVar()

# lable ☆PLAYFAIR☆
labelHeart4 = tk.Label(page4, text="☆", width=3, bg="#E4C59E", foreground="#FFFF80")#
labelHeart4.config(font=bold_font)
canvas4.create_window(180, 50, window=labelHeart4)

labelCeaser = tk.Label(page4, text="PLAYFAIR", width=9, bg="#E4C59E", foreground="#803D3B")#
labelCeaser.config(font=bold_font)
canvas4.create_window(250, 50, window=labelCeaser)

labelHeart41 = tk.Label(page4, text="☆", width=3, bg="#E4C59E", foreground="#FFFF80")#
labelHeart41.config(font=bold_font)
canvas4.create_window(320, 50, window=labelHeart41)

label41 = tk.Label(page4, text="Enter the Text", width=15,pady=8, bg="#AF8260", foreground="#FFFFFF")
label41.config(font=bold_font)
canvas4.create_window(100, 100, window=label41)
user_text4 = tk.Entry(page4, textvariable=palo_text, width=20,foreground="#803D3B")
user_text4.config(font=bold_font)
canvas4.create_window(350, 100, window=user_text4)

label422 = tk.Label(page4, text="Enter Key Text",width=15,pady=8, bg="#AF8260", foreground="#FFFFFF")
label422.config(font=bold_font)
canvas4.create_window(100, 180, window=label422)
key_text2 = tk.Entry(page4, textvariable=kayo_text,show="*", width=20,foreground="#803D3B")
key_text2.config(font=bold_font)
canvas4.create_window(350, 180, window=key_text2)
label42 = tk.Label(page4, text="Choose", width=15,pady=8, bg="#AF8260", foreground="#FFFFFF")
label42.config(font=bold_font)
canvas4.create_window(100, 280, window=label42)

v4 = tk.IntVar()


def choice4():
    x4 = v4.get()
    if (x4 == 1):
        encrypt()
    elif (x4 == 2):
        decrypt()


label43 = tk.Radiobutton(page4, text="Encryption", padx=20,width=15, variable=v4, value=1, command=choice4, bg="white",foreground="#803D3B")
label43.config(font=bold_font)
canvas4.create_window(350, 250, window=label43)
label44 = tk.Radiobutton(page4, text="Decryption", padx=20,width=15, variable=v4, value=2, command=choice4,bg="white",foreground="#803D3B")
label44.config(font=bold_font)
canvas4.create_window(350, 310, window=label44)

#__________________playfair_______________________
def encrypt():
    key_play = str(kayo_text.get())
    key_play = key_play.replace(" ", "")
    key_play = key_play.upper()

    def matrix(x, y, initial):
        return [[initial for i in range(x)] for j in range(y)]

    result = list()
    for c in key_play:  # storing key
        if c not in result:
            if c == 'J':
                result.append('I')
            else:
                result.append(c)
    flag = 0
    for i in range(65, 91):  # storing other character
        if chr(i) not in result:
            if i == 73 and chr(74) not in result:
                result.append("I")
                flag = 1
            elif flag == 0 and i == 73 or i == 74:
                pass
            else:
                result.append(chr(i))
    k = 0
    my_matrix = matrix(5, 5, 0)  # initialize matrix
    for i in range(0, 5):  # making matrix
        for j in range(0, 5):
            my_matrix[i][j] = result[k]
            k += 1

    def locindex(c):  # get location of each character
        loc = list()
        if c == 'J':
            c = 'I'
        for i, j in enumerate(my_matrix):
            for k, l in enumerate(j):
                if c == l:
                    loc.append(i)
                    loc.append(k)
                    return loc

    e_text = ""
    msg = str(palo_text.get())
    msg = msg.upper()
    msg = msg.replace(" ", "")
    i = 0
    for s in range(0, len(msg) + 1, 2):
        if s < len(msg) - 1:
            if msg[s] == msg[s + 1]:
                msg = msg[:s + 1] + 'X' + msg[s + 1:]
    if len(msg) % 2 != 0:
        msg = msg[:] + 'X'
    print("CIPHER TEXT:", end=' ')
    while i < len(msg):
        loc = list()
        loc = locindex(msg[i])
        loc1 = list()
        loc1 = locindex(msg[i + 1])
        if loc[1] == loc1[1]:
            e_text += (my_matrix[(loc[0] + 1) % 5][loc[1]] + my_matrix[(loc1[0] + 1) % 5][loc1[1]])
        elif loc[0] == loc1[0]:
            e_text += (my_matrix[loc[0]][(loc[1] + 1) % 5] + my_matrix[loc1[0]][(loc1[1] + 1) % 5])
        else:
            e_text += (my_matrix[loc[0]][loc1[1]] + my_matrix[loc1[0]][loc[1]])
        i = i + 2
    print(e_text)

    label45 = tk.Label(page4, text=e_text, width=20, bg="white",foreground="#AF8260")
    label45.config(font=bold_font)
    canvas4.create_window(350, 375, window=label45)


def decrypt():
    key_play = str(kayo_text.get())
    key_play = key_play.replace(" ", "")
    key_play = key_play.upper()

    def matrix(x, y, initial):
        return [[initial for i in range(x)] for j in range(y)]

    result = list()
    for c in key_play:  # storing key
        if c not in result:
            if c == 'J':
                result.append('I')
            else:
                result.append(c)
    flag = 0
    for i in range(65, 91):  # storing other character
        if chr(i) not in result:
            if i == 73 and chr(74) not in result:
                result.append("I")
                flag = 1
            elif flag == 0 and i == 73 or i == 74:
                pass
            else:
                result.append(chr(i))
    k = 0
    my_matrix = matrix(5, 5, 0)  # initialize matrix
    for i in range(0, 5):  # making matrix
        for j in range(0, 5):
            my_matrix[i][j] = result[k]
            k += 1

    def locindex(c):  # get location of each character
        loc = list()
        if c == 'J':
            c = 'I'
        for i, j in enumerate(my_matrix):
            for k, l in enumerate(j):
                if c == l:
                    loc.append(i)
                    loc.append(k)
                    return loc

    plain_text = ""
    msg = str(palo_text.get())
    msg = msg.upper()
    msg = msg.replace(" ", "")
    print("PLAIN TEXT:", end=' ')
    i = 0
    while i < len(msg):
        loc = list()
        loc = locindex(msg[i])
        loc1 = list()
        loc1 = locindex(msg[i + 1])
        if loc[1] == loc1[1]:
            plain_text += (my_matrix[(loc[0] - 1) % 5][loc[1]] + my_matrix[(loc1[0] - 1) % 5][loc1[1]])
        elif loc[0] == loc1[0]:
            plain_text += (my_matrix[loc[0]][(loc[1] - 1) % 5] + my_matrix[loc1[0]][(loc1[1] - 1) % 5])
        else:
            plain_text += (my_matrix[loc[0]][loc1[1]] + my_matrix[loc1[0]][loc[1]])
        i = i + 2
    plain_text = plain_text.replace("X", "")
    print(plain_text)
    label46 = tk.Label(page4, text=plain_text, width=20, bg="white",foreground="#AF8260")
    label46.config(font=bold_font)
    canvas4.create_window(350, 375, window=label46)


label47 = tk.Label(page4, text="Converted Text ", width=15,pady=8, bg="#803D3B",foreground="#FFFFFF")
label47.config(font=bold_font)
canvas4.create_window(100, 375, window=label47)
button41 = tk.Button(page4, text="Back", width=8, pady=1, command=lambda: page1.tkraise())
button41.config(background="white", font=bold_font, foreground="#803D3B")
canvas4.create_window(250, 445, window=button41)

# _______________________page5 DES_______________________
kaay_page5 = StringVar()
#ceaser lable ☆DES☆
labelHeart5 = tk.Label(page5, text="☆", width=3, bg="#E4C59E", foreground="#FFFF80")#
labelHeart5.config(font=bold_font)
canvas5.create_window(180, 50, window=labelHeart5)

labelDes = tk.Label(page5, text="DES", width=9, bg="#E4C59E", foreground="#803D3B")#
labelDes.config(font=bold_font)
canvas5.create_window(250, 50, window=labelDes)

labelHeart51 = tk.Label(page5, text="☆", width=3, bg="#E4C59E", foreground="#FFFF80")#
labelHeart51.config(font=bold_font)
canvas5.create_window(320, 50, window=labelHeart51)

label51 = tk.Label(page5, text="Enter the Text", width=15,pady=8, bg="#AF8260", foreground="#FFFFFF")
label51.config(font=bold_font)
canvas5.create_window(100, 100, window=label51)
user_text5 = tk.Entry(page5 , width=20,foreground="#803D3B")
user_text5.config(font=bold_font)
canvas5.create_window(350, 100, window=user_text5)

label522 = tk.Label(page5, text="Enter Key Text",  width=15,pady=8, bg="#AF8260", foreground="#FFFFFF")
label522.config(font=bold_font)
canvas5.create_window(100, 180, window=label522)
key_text5 = tk.Entry(page5, textvariable=kaay_page5,show="*", width=20,foreground="#803D3B")
key_text5.config(font=bold_font)
canvas5.create_window(350, 180, window=key_text5)

label52 = tk.Label(page5, text="Choose", width=15,pady=8, bg="#AF8260", foreground="#FFFFFF")
label52.config(font=bold_font)
canvas5.create_window(100, 280, window=label52)

v5 = tk.IntVar()


def choice5():
    x5 = v5.get()
    if (x5 == 1):
        encryption5()
    elif (x5 == 2):
        decryption5()


label53 = tk.Radiobutton(page5, text="Encryption", padx=20,width=15, variable=v5, value=1, command=choice5, bg="white",foreground="#803D3B")
label53.config(font=bold_font)
canvas5.create_window(350, 250, window=label53)
label54 = tk.Radiobutton(page5, text="Decryption", padx=20,width=15, variable=v5, value=2, command=choice5, bg="white",foreground="#803D3B")
label54.config(font=bold_font)
canvas5.create_window(350, 310, window=label54)


def encryption5():
    def hex2bin(s):
        mp = {'0': "0000",
              '1': "0001",
              '2': "0010",
              '3': "0011",
              '4': "0100",
              '5': "0101",
              '6': "0110",
              '7': "0111",
              '8': "1000",
              '9': "1001",
              'A': "1010",
              'B': "1011",
              'C': "1100",
              'D': "1101",
              'E': "1110",
              'F': "1111"}
        bin = ""
        for i in range(len(s)):
            if (s[i] == '\n'):
                continue
            bin = bin + mp[s[i]]
        return bin

    # Binary to hexadecimal conversion

    def bin2hex(s):
        mp = {"0000": '0',
              "0001": '1',
              "0010": '2',
              "0011": '3',
              "0100": '4',
              "0101": '5',
              "0110": '6',
              "0111": '7',
              "1000": '8',
              "1001": '9',
              "1010": 'A',
              "1011": 'B',
              "1100": 'C',
              "1101": 'D',
              "1110": 'E',
              "1111": 'F'}
        hex = ""
        for i in range(0, len(s), 4):
            ch = ""
            ch = ch + s[i]
            ch = ch + s[i + 1]
            ch = ch + s[i + 2]
            ch = ch + s[i + 3]
            hex = hex + mp[ch]

        return hex

    # Binary to decimal conversion

    def bin2dec(binary):

        binary1 = binary
        decimal, i, n = 0, 0, 0
        while (binary != 0):
            dec = binary % 10
            decimal = decimal + dec * pow(2, i)
            binary = binary // 10
            i += 1
        return decimal

    # Decimal to binary conversion

    def dec2bin(num):
        res = bin(num).replace("0b", "")
        if (len(res) % 4 != 0):
            div = len(res) / 4
            div = int(div)
            counter = (4 * (div + 1)) - len(res)
            for i in range(0, counter):
                res = '0' + res
        return res

    # Permute function to rearrange the bits

    def permute(k, arr, n):
        permutation = ""
        for i in range(0, n):
            permutation = permutation + k[arr[i] - 1]
        return permutation

    # shifting the bits towards left by nth shifts

    def shift_left(k, nth_shifts):
        s = ""
        for i in range(nth_shifts):
            for j in range(1, len(k)):
                s = s + k[j]
            s = s + k[0]
            k = s
            s = ""
        return k

    # calculating xow of two strings of binary number a and b

    def xor(a, b):
        ans = ""
        for i in range(len(a)):
            if a[i] == b[i]:
                ans = ans + "0"
            else:
                ans = ans + "1"
        return ans

    # Table of Position of 64 bits at initial level: Initial Permutation Table
    initial_perm = [58, 50, 42, 34, 26, 18, 10, 2,
                    60, 52, 44, 36, 28, 20, 12, 4,
                    62, 54, 46, 38, 30, 22, 14, 6,
                    64, 56, 48, 40, 32, 24, 16, 8,
                    57, 49, 41, 33, 25, 17, 9, 1,
                    59, 51, 43, 35, 27, 19, 11, 3,
                    61, 53, 45, 37, 29, 21, 13, 5,
                    63, 55, 47, 39, 31, 23, 15, 7]

    # Expansion D-box Table
    exp_d = [32, 1, 2, 3, 4, 5, 4, 5,
             6, 7, 8, 9, 8, 9, 10, 11,
             12, 13, 12, 13, 14, 15, 16, 17,
             16, 17, 18, 19, 20, 21, 20, 21,
             22, 23, 24, 25, 24, 25, 26, 27,
             28, 29, 28, 29, 30, 31, 32, 1]

    # Straight Permutation Table
    per = [16, 7, 20, 21,
           29, 12, 28, 17,
           1, 15, 23, 26,
           5, 18, 31, 10,
           2, 8, 24, 14,
           32, 27, 3, 9,
           19, 13, 30, 6,
           22, 11, 4, 25]

    # S-box Table
    sbox = [[[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
             [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
             [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
             [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],

            [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
             [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
             [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
             [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],

            [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
             [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
             [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
             [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],

            [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
             [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
             [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
             [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],

            [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
             [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
             [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
             [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],

            [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
             [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
             [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
             [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],

            [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
             [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
             [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
             [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],

            [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
             [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
             [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
             [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]]

    # Final Permutation Table
    final_perm = [40, 8, 48, 16, 56, 24, 64, 32,
                  39, 7, 47, 15, 55, 23, 63, 31,
                  38, 6, 46, 14, 54, 22, 62, 30,
                  37, 5, 45, 13, 53, 21, 61, 29,
                  36, 4, 44, 12, 52, 20, 60, 28,
                  35, 3, 43, 11, 51, 19, 59, 27,
                  34, 2, 42, 10, 50, 18, 58, 26,
                  33, 1, 41, 9, 49, 17, 57, 25]

    def encrypt(pt, rkb, rk):
        pt = hex2bin(pt)

        # Initial Permutation
        pt = permute(pt, initial_perm, 64)
        print("After initial permutation", bin2hex(pt))

        # Splitting
        left = pt[0:32]
        right = pt[32:64]
        for i in range(0, 16):
            # Expansion D-box: Expanding the 32 bits data into 48 bits
            right_expanded = permute(right, exp_d, 48)

            # XOR RoundKey[i] and right_expanded
            xor_x = xor(right_expanded, rkb[i])

            # S-boxex: substituting the value from s-box table by calculating row and column
            sbox_str = ""
            for j in range(0, 8):
                row = bin2dec(int(xor_x[j * 6] + xor_x[j * 6 + 5]))
                col = bin2dec(
                    int(xor_x[j * 6 + 1] + xor_x[j * 6 + 2] + xor_x[j * 6 + 3] + xor_x[j * 6 + 4]))
                val = sbox[j][row][col]
                sbox_str = sbox_str + dec2bin(val)

            # Straight D-box: After substituting rearranging the bits
            sbox_str = permute(sbox_str, per, 32)

            # XOR left and sbox_str
            result = xor(left, sbox_str)
            left = result

            # Swapper
            if (i != 15):
                left, right = right, left
            print("Round ", i + 1, " ", bin2hex(left),
                  " ", bin2hex(right), " ", rk[i])

        # Combination
        combine = left + right

        # Final permutation: final rearranging of bits to get cipher text
        cipher_text = permute(combine, final_perm, 64)
        return cipher_text

    # pt = "123456ABCD132536"
    # key = "AABB09182736CCDD"
    pt = str(user_text5.get())
    key = str(kaay_page5.get())

    # Key generation
    # --hex to binary
    key = hex2bin(key)

    # --parity bit drop table
    keyp = [57, 49, 41, 33, 25, 17, 9,
            1, 58, 50, 42, 34, 26, 18,
            10, 2, 59, 51, 43, 35, 27,
            19, 11, 3, 60, 52, 44, 36,
            63, 55, 47, 39, 31, 23, 15,
            7, 62, 54, 46, 38, 30, 22,
            14, 6, 61, 53, 45, 37, 29,
            21, 13, 5, 28, 20, 12, 4]

    # getting 56 bit key from 64 bit using the parity bits
    key = permute(key, keyp, 56)

    # Number of bit shifts
    shift_table = [1, 1, 2, 2,
                   2, 2, 2, 2,
                   1, 2, 2, 2,
                   2, 2, 2, 1]

    # Key- Compression Table : Compression of key from 56 bits to 48 bits
    key_comp = [14, 17, 11, 24, 1, 5,
                3, 28, 15, 6, 21, 10,
                23, 19, 12, 4, 26, 8,
                16, 7, 27, 20, 13, 2,
                41, 52, 31, 37, 47, 55,
                30, 40, 51, 45, 33, 48,
                44, 49, 39, 56, 34, 53,
                46, 42, 50, 36, 29, 32]

    # Splitting
    left = key[0:28]  # rkb for RoundKeys in binary
    right = key[28:56]  # rk for RoundKeys in hexadecimal

    rkb = []
    rk = []
    for i in range(0, 16):
        # Shifting the bits by nth shifts by checking from shift table
        left = shift_left(left, shift_table[i])
        right = shift_left(right, shift_table[i])

        # Combination of left and right string
        combine_str = left + right

        # Compression of key from 56 to 48 bits
        round_key = permute(combine_str, key_comp, 48)

        rkb.append(round_key)
        rk.append(bin2hex(round_key))

    print("Encryption")
    cipher_text5 = bin2hex(encrypt(pt, rkb, rk))
    print("Cipher Text : ", cipher_text5)
    label55 = tk.Label(page5, text=cipher_text5, width=20, bg="white",foreground="#AF8260")
    label55.config(font=bold_font)
    canvas5.create_window(350, 375, window=label55)


def decryption5():
    def hex2bin(s):
        mp = {'0': "0000",
              '1': "0001",
              '2': "0010",
              '3': "0011",
              '4': "0100",
              '5': "0101",
              '6': "0110",
              '7': "0111",
              '8': "1000",
              '9': "1001",
              'A': "1010",
              'B': "1011",
              'C': "1100",
              'D': "1101",
              'E': "1110",
              'F': "1111"}
        bin = ""
        for i in range(len(s)):
            bin = bin + mp[s[i]]
        return bin

    # Binary to hexadecimal conversion

    def bin2hex(s):
        mp = {"0000": '0',
              "0001": '1',
              "0010": '2',
              "0011": '3',
              "0100": '4',
              "0101": '5',
              "0110": '6',
              "0111": '7',
              "1000": '8',
              "1001": '9',
              "1010": 'A',
              "1011": 'B',
              "1100": 'C',
              "1101": 'D',
              "1110": 'E',
              "1111": 'F'}
        hex = ""
        for i in range(0, len(s), 4):
            ch = ""
            ch = ch + s[i]
            ch = ch + s[i + 1]
            ch = ch + s[i + 2]
            ch = ch + s[i + 3]
            hex = hex + mp[ch]

        return hex

    # Binary to decimal conversion

    def bin2dec(binary):

        binary1 = binary
        decimal, i, n = 0, 0, 0
        while (binary != 0):
            dec = binary % 10
            decimal = decimal + dec * pow(2, i)
            binary = binary // 10
            i += 1
        return decimal

    # Decimal to binary conversion

    def dec2bin(num):
        res = bin(num).replace("0b", "")
        if (len(res) % 4 != 0):
            div = len(res) / 4
            div = int(div)
            counter = (4 * (div + 1)) - len(res)
            for i in range(0, counter):
                res = '0' + res
        return res

    # Permute function to rearrange the bits

    def permute(k, arr, n):
        permutation = ""
        for i in range(0, n):
            permutation = permutation + k[arr[i] - 1]
        return permutation

    # shifting the bits towards left by nth shifts

    def shift_left(k, nth_shifts):
        s = ""
        for i in range(nth_shifts):
            for j in range(1, len(k)):
                s = s + k[j]
            s = s + k[0]
            k = s
            s = ""
        return k

    # calculating xow of two strings of binary number a and b

    def xor(a, b):
        ans = ""
        for i in range(len(a)):
            if a[i] == b[i]:
                ans = ans + "0"
            else:
                ans = ans + "1"
        return ans

    # Table of Position of 64 bits at initial level: Initial Permutation Table
    initial_perm = [58, 50, 42, 34, 26, 18, 10, 2,
                    60, 52, 44, 36, 28, 20, 12, 4,
                    62, 54, 46, 38, 30, 22, 14, 6,
                    64, 56, 48, 40, 32, 24, 16, 8,
                    57, 49, 41, 33, 25, 17, 9, 1,
                    59, 51, 43, 35, 27, 19, 11, 3,
                    61, 53, 45, 37, 29, 21, 13, 5,
                    63, 55, 47, 39, 31, 23, 15, 7]

    # Expansion D-box Table
    exp_d = [32, 1, 2, 3, 4, 5, 4, 5,
             6, 7, 8, 9, 8, 9, 10, 11,
             12, 13, 12, 13, 14, 15, 16, 17,
             16, 17, 18, 19, 20, 21, 20, 21,
             22, 23, 24, 25, 24, 25, 26, 27,
             28, 29, 28, 29, 30, 31, 32, 1]

    # Straight Permutation Table
    per = [16, 7, 20, 21,
           29, 12, 28, 17,
           1, 15, 23, 26,
           5, 18, 31, 10,
           2, 8, 24, 14,
           32, 27, 3, 9,
           19, 13, 30, 6,
           22, 11, 4, 25]

    # S-box Table
    sbox = [[[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
             [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
             [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
             [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],

            [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
             [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
             [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
             [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],

            [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
             [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
             [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
             [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],

            [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
             [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
             [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
             [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],

            [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
             [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
             [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
             [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],

            [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
             [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
             [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
             [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],

            [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
             [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
             [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
             [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],

            [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
             [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
             [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
             [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]]

    # Final Permutation Table
    final_perm = [40, 8, 48, 16, 56, 24, 64, 32,
                  39, 7, 47, 15, 55, 23, 63, 31,
                  38, 6, 46, 14, 54, 22, 62, 30,
                  37, 5, 45, 13, 53, 21, 61, 29,
                  36, 4, 44, 12, 52, 20, 60, 28,
                  35, 3, 43, 11, 51, 19, 59, 27,
                  34, 2, 42, 10, 50, 18, 58, 26,
                  33, 1, 41, 9, 49, 17, 57, 25]

    def encrypt(pt, rkb, rk):
        pt = hex2bin(pt)

        # Initial Permutation
        pt = permute(pt, initial_perm, 64)
        print("After initial permutation", bin2hex(pt))

        # Splitting
        left = pt[0:32]
        right = pt[32:64]
        for i in range(0, 16):
            # Expansion D-box: Expanding the 32 bits data into 48 bits
            right_expanded = permute(right, exp_d, 48)

            # XOR RoundKey[i] and right_expanded
            xor_x = xor(right_expanded, rkb[i])

            # S-boxex: substituting the value from s-box table by calculating row and column
            sbox_str = ""
            for j in range(0, 8):
                row = bin2dec(int(xor_x[j * 6] + xor_x[j * 6 + 5]))
                col = bin2dec(
                    int(xor_x[j * 6 + 1] + xor_x[j * 6 + 2] + xor_x[j * 6 + 3] + xor_x[j * 6 + 4]))
                val = sbox[j][row][col]
                sbox_str = sbox_str + dec2bin(val)

            # Straight D-box: After substituting rearranging the bits
            sbox_str = permute(sbox_str, per, 32)

            # XOR left and sbox_str
            result = xor(left, sbox_str)
            left = result

            # Swapper
            if (i != 15):
                left, right = right, left
            print("Round ", i + 1, " ", bin2hex(left),
                  " ", bin2hex(right), " ", rk[i])

        # Combination
        combine = left + right

        # Final permutation: final rearranging of bits to get cipher text
        cipher_text = permute(combine, final_perm, 64)
        return cipher_text

    pt = "123456ABCD132536"
    key = str(kaay_page5.get())

    # Key generation
    # --hex to binary
    key = hex2bin(key)

    # --parity bit drop table
    keyp = [57, 49, 41, 33, 25, 17, 9,
            1, 58, 50, 42, 34, 26, 18,
            10, 2, 59, 51, 43, 35, 27,
            19, 11, 3, 60, 52, 44, 36,
            63, 55, 47, 39, 31, 23, 15,
            7, 62, 54, 46, 38, 30, 22,
            14, 6, 61, 53, 45, 37, 29,
            21, 13, 5, 28, 20, 12, 4]

    # getting 56 bit key from 64 bit using the parity bits
    key = permute(key, keyp, 56)

    # Number of bit shifts
    shift_table = [1, 1, 2, 2,
                   2, 2, 2, 2,
                   1, 2, 2, 2,
                   2, 2, 2, 1]

    # Key- Compression Table : Compression of key from 56 bits to 48 bits
    key_comp = [14, 17, 11, 24, 1, 5,
                3, 28, 15, 6, 21, 10,
                23, 19, 12, 4, 26, 8,
                16, 7, 27, 20, 13, 2,
                41, 52, 31, 37, 47, 55,
                30, 40, 51, 45, 33, 48,
                44, 49, 39, 56, 34, 53,
                46, 42, 50, 36, 29, 32]

    # Splitting
    left = key[0:28]  # rkb for RoundKeys in binary
    right = key[28:56]  # rk for RoundKeys in hexadecimal

    rkb = []
    rk = []
    for i in range(0, 16):
        # Shifting the bits by nth shifts by checking from shift table
        left = shift_left(left, shift_table[i])
        right = shift_left(right, shift_table[i])

        # Combination of left and right string
        combine_str = left + right

        # Compression of key from 56 to 48 bits
        round_key = permute(combine_str, key_comp, 48)

        rkb.append(round_key)
        rk.append(bin2hex(round_key))

    cipher_text = str(user_text5.get())

    print("Decryption")
    rkb_rev = rkb[::-1]
    rk_rev = rk[::-1]
    text5 = bin2hex(encrypt(cipher_text, rkb_rev, rk_rev))
    print("Plain Text : ", text5)

    # This code is contributed by Aditya Jain
    label56 = tk.Label(page5, text=text5, width=20, bg="white",foreground="#AF8260")
    label56.config(font=bold_font)
    canvas5.create_window(350, 375, window=label56)


label57 = tk.Label(page5, text="Converted Text ", width=15,pady=8, bg="#803D3B",foreground="#FFFFFF")
label57.config(font=bold_font)
canvas5.create_window(100, 375, window=label57)
button51 = tk.Button(page5, text="Back",  width=8, pady=1, command=lambda: page1.tkraise())
button51.config(background="white", font=bold_font, foreground="#803D3B")
canvas5.create_window(250, 445, window=button51)

page1.tkraise()
root.mainloop()

