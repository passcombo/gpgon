

# secure auth https://support.google.com/accounts/answer/185833?authuser=2
# from google just enough to allow 2 step verification
# then generate custom app password
# use that password as replacement for regular password



# clear terminal if needed os.system('clear')
# os.system('cls')
# clear mem history terminal windows linux 


	

# import time
import re
# import multiprocessing
import os
import datetime
import psutil
import traceback
import subprocess
import json
# import keyboard # req installation

import pylib.ioprocessing as iop
import pylib.mailbox as mbox
import pylib.cmd_loop as cmdl
os.system('color')



if __name__=='__main__':

	iop.check_already_running()

	newest_date, newest_file, filed = iop.get_config_file()	

	
	if not os.path.exists('archive'):# ensure correct folder exists:
		os.mkdir('archive')

	if not os.path.exists('tmp'):
		os.mkdir('tmp')
		
	if not os.path.exists('my_files'):
		os.mkdir('my_files')
		
	if not os.path.exists( os.path.join('archive','sent') ):
		os.mkdir( os.path.join('archive','sent') )

	while True:
		print('reading app settings')
		json_obj, pswd, newest_file=iop.read_app_settings() #json_conf["wallet_secret_key"]
		

		mail_from=json_obj["email_addr"]	
		mail_from_pswd=json_obj["email_password"]
		imap_addr=json_obj["imap_addr"]
			
		print('*** Testing mailbox connection.')
			
		new_msgs=mbox.search_incoming(mail_from , mail_from_pswd , imap_addr ,  def_opt_init={'last_msg_limit':7, 'only_new':'yes', 'date_since':'2020-01-01'} )

		if "Error" in new_msgs.keys(): # test imap conf	

			print('*** Ensure your internet connection is good and you did not make any mistakes in credentials.')
			print('*** IMAP connection failed - if you are sure password and email address is correct please check your mailbox settings and get proper imap address. Some mailbox accounts may require special confirmation to allow 3rd party connection (e.g. gmail).')
			print(new_msgs)
			# exit()
			ync=iop.optional_input('Exit app? ', ['y','n'], True) #'Enter value or quit [q]: '
			if ync=='y':
				exit()
			else:
				edit_app_settings(json_obj,pswd)
				print('App settings changed - rechecking imap connection...')
			
		else:
			print('IMAP OK')
			iop.display_msg_dict(new_msgs,'... zero unseen messages ...','\nUnseen messages:')
			break

		
	cmdl.cmd_loop(pswd, newest_file) 
