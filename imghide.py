from PIL import Image
import os.path
from os import path
import math
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto import Random
import base64
from colorama import init
from termcolor import cprint 
from pyfiglet import figlet_format
from rich import print
from rich.console import Console
from rich.table import Table
import os
import getpass
from rich.progress import track
import sys
import tkinter as tk
from tkinter.filedialog import askopenfilename


DEBUG = False
console = Console()
headerText = "M6nMjy5THr2J"


def encrypt(key, source, encode=True):
    key = SHA256.new(key).digest()  # use SHA-256 over our key to get a proper-sized AES key
    IV = Random.new().read(AES.block_size)  # generate IV
    encryptor = AES.new(key, AES.MODE_CBC, IV)
    padding = AES.block_size - len(source) % AES.block_size  # calculate needed padding
    source += bytes([padding]) * padding  # Python 2.x: source += chr(padding) * padding
    data = IV + encryptor.encrypt(source)  # store the IV at the beginning and encrypt
    return base64.b64encode(data).decode() if encode else data

def decrypt(key, source, decode=True):
    if decode:
        source = base64.b64decode(source.encode())
    key = SHA256.new(key).digest()  # use SHA-256 over our key to get a proper-sized AES key
    IV = source[:AES.block_size]  # extract the IV from the beginning
    decryptor = AES.new(key, AES.MODE_CBC, IV)
    data = decryptor.decrypt(source[AES.block_size:])  # decrypt
    padding = data[-1]  # pick the padding value from the end; Python 2.x: ord(data[-1])
    if data[-padding:] != bytes([padding]) * padding:  # Python 2.x: chr(padding) * padding
        raise ValueError("Invalid padding...")
    return data[:-padding]  # remove the padding


def convertToRGB(img):
    try:
        rgba_image = img
        rgba_image.load()
        background = Image.new("RGB", rgba_image.size, (255, 255, 255))
        background.paste(rgba_image, mask = rgba_image.split()[3])
        print("[yellow]Converted image to RGB [/yellow]")
        return background
    except Exception as e:
	    print("[red]Couldn't convert image to RGB [/red]- %s"%e)

def getPixelCount(img):
    width, height = Image.open(img).size
    return width*height



def encodeImage(image,message,filename):

    with console.status("[green]Encoding image..") as status:
        try:

            pix = list(image.getdata())

            for ind, ch in enumerate(message):
                # converts to list of integer binary value.
                # Adds 0 or 1 bit depending on whether it is last character of not.
                
                binary_value = list(map(int, format(ord(ch), '08b'))) + [0 if ind != len(message)-1 else 1]
                
                # For each character, get 3 pixels at a time
                three_pixels = pix[ind*3: (ind+1)*3]
                three_pixels = [i for px in three_pixels for i in px]
                
                for index, (binary, pixel) in enumerate(zip(binary_value, three_pixels)):
                    # 0 - Even
                    # 1 - Odd

                    remainder = pixel%2
                    
                    if binary: # if message bit is 1
                        three_pixels[index] += 1 - remainder # make pixel odd

                    else: # if message bit is 0
                        three_pixels[index] -= remainder # make bit pixel even
                        

                if DEBUG:
                    print("Character: ",ch)
                    print("Binary: ",binary_value)
                    print("Three pixels before mod: ",three_pixels)
                    print("Three pixels after mod: ",three_pixels)

                
                pix[ind*3: (ind+1)*3] = [tuple(three_pixels[i*3:(i+1)*3]) for i in range(3)] # replaces 3 tuple of RGB values
                
            image.putdata(pix) 
    
            encoded_filename =  ".".join(filename.split('.')[:-1]) + "-enc.png"
            image.save(encoded_filename)
            print("\n")
            print("[yellow]Original File: [u]%s[/u][/yellow]"%filename)
            print("[green]Image encoded and saved as [u][bold]%s[/green][/u][/bold]"%encoded_filename)

        except Exception as e:
            print("[red]An error occured - [/red]%s"%e)
            sys.exit(0)



def decodeImage(image):
    with console.status("[green]Decoding image..") as status:
        try:
            pix = image.getdata()
            
            decoded=""
            binary_value=""
            for index,pixel in enumerate(pix):

                for channel in pixel:
                    binary_value += str(channel%2)

                #Convert binary value to ascii and add to string
                if index %3==2:
                    ascii_value = int(binary_value[:-1],2)
                    decoded+=chr(ascii_value)
                    if DEBUG:
                        print("Binary: ",binary_value)
                        print("Ascii: ",ascii_value)
                        print("Character: ",chr(ascii_value))

                    if int(binary_value[-1]):
                        break
                    
                    binary_value=""
            return decoded
        except Exception as e:
            print("[red]An error occured - [/red]%s"%e)
            sys.exit()




def test(img):
    image = Image.open(img)
    pix = image.load()
    print(pix[0])
    print(type(pix))

def print_credits():
    table = Table(show_header=True)
    table.add_column("Author",style="yellow")
    table.add_column("Contact",style="yellow")
    table.add_row("Teja Swaroop", "tejaswaroop156@gmail.com ")
    console.print(table)

def getfile():
    filename = ''
    try:
        window = tk.Tk()
        window.iconify()
        window.update()
        filename =  askopenfilename(filetypes=[("Image files", ".jpg .png .bmp"), ("All Files", "*.*")]) # show an "Open" dialog box and return the path to the selected file
    finally:
        window.destroy()
    return filename


def main():
    # insertHeaders(img)

    print("[cyan]Choose one: [/cyan]")
    op = int(input("1. Encode\n2. Decode\n>>"))
    if op==1:
        print("[cyan]Image path (with extension): [/cyan]")
##        img = input(">>")
        img = getfile()
        if(not path.isfile(img)):
            raise Exception("Image not found!")

        
        print("[cyan]Message to be hidden: [/cyan]")
        message = input(">>")
        message = headerText + message
        if((len(message)+len(headerText))*3 > getPixelCount(img)):
            raise Exception("Given message is too long to be encoded in the image.")

        password=""
        while 1:
            print("[cyan]Password to encrypt (leave empty if you want no password): [/cyan]")
            password = getpass.getpass(">>")
            if password=="":
                break
            print("[cyan]Re-enter Password: [/cyan]")
            confirm_password = getpass.getpass(">>")
            if(password!=confirm_password):
                print("[red]Passwords don't match try again [/red]")
            else:
                break

        cipher=""
        if password!="":
            cipher = encrypt(key=password.encode(),source=message.encode())
            # Add header to cipher
            cipher = headerText + cipher
        else:
            cipher = message

        if DEBUG:
            print("[yellow]Encrypted : [/yellow]",cipher)
            
        image = Image.open(img)
        print("[yellow]Image Mode: [/yellow]%s"%image.mode)
        if image.mode!='RGB':
            image = convertToRGB(image)
        newimg = image.copy()
        encodeImage(image=newimg,message=cipher,filename=image.filename)

    elif op==2:
        print("[cyan]Image path (with extension): [/cyan]")
##        img = input(">>")
        img = getfile()
        if(not path.isfile(img)):
                raise Exception("Image not found!")

        print("[cyan]Enter password (leave empty if no password): [/cyan]")
        password = getpass.getpass(">>")

        image = Image.open(img)

        cipher = decodeImage(image)

        header = cipher[:len(headerText)]

        if header.strip()!=headerText:
            print("[red]Invalid data![/red]")
            sys.exit(0)


        print()

        if DEBUG:
            print("[yellow]Decoded text: %s[/yellow]"%cipher)

        decrypted= cipher

        if password:
            cipher = cipher[len(headerText):]
            print("cipher : ",cipher)
            try:
                decrypted = decrypt(key=password.encode(),source=cipher).decode()
            except Exception as e:
                print("[red]Wrong password![/red]")
                sys.exit(0)


        header = decrypted[:len(headerText)]

        if header!=headerText:
            print("[red]Wrong password![/red]")
            sys.exit(0)

        decrypted = decrypted[len(headerText):]



        print("[green]Decoded Text: \n[bold]%s[/bold][/green]"%decrypted)






if __name__ == "__main__":
    os.system('cls' if os.name == 'nt' else 'clear')
    cprint(figlet_format('IMGHIDE!', font='starwars'),'yellow', attrs=['bold'])
    print_credits()
    print()
    print("[bold]IMGHIDE[/bold] allows you to hide texts inside an image. You can also protect these texts with a password using AES-256.")
    print()
    
    main()
