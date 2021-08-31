import os

try:
    os.system("chmod +x dprap.py")
    os.system("mkdir -p ~/bin")
    os.system("cp dprap.py ~/bin/")
    os.system("cp -r dprappkg/ ~/bin/")
    os.system("mv ~/bin/dprap.py ~/bin/dprap")
    os.system('export PATH=$PATH":$HOME/bin"')
    os.system('echo \'export PATH=$PATH":$HOME/bin"\' >> .profile')
    print("Successful installation")
except Exception as e:
    print(e)