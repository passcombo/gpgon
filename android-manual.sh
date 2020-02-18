# This app works in terminal as user interface - Termux app is required to use on Android

# Environment Setup:
# 1. install Termux app
# 2. Open Termux and run following commands:
#    - "pkg install wget" # [must have] to donwload scripts
#    - "pkg install gnupg" # [must have] for encryptions
#    - "pkg install python" # [must have] for app to run
#    - "pkg install pip" # [must have] for app to install additional module
#    - "pip install psutil" # [must have] for app additional library

# [ERRORS?] If psutil python library won't install try this:
#    - "apt-get update --fix-missing" 
#    - "pkg install binutils"
#    - "pkg install clang"
#    - "pip install psutil"

# Download app [here example second version]:
# "wget https://github.com/passcombo/gpgon/archive/6.tar.gz"

# Extract:
# "tar xfvz 6.tar.gz"

# See intro.pdf for mailbox config
# Every Android user should have gmail box that works with the app
# Just need to configure 2FA and app password in google account setup

# Run app:
# "cd gpgon-6"
# "python gpgon.py"

# Optional:
#    - "pkg install nano" # [optional] useful easy text editor
#    - "termux-setup-storage" # [optional] for external storage access - see termux manual

