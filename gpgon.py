# secure auth https://support.google.com/accounts/answer/185833?authuser=2
# from google just enough to allow 2 step verification
# then generate custom app password
# use that password as replacement for regular password


# TOTO FINAL:
# manual

# optional reply
# optional send public


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



if __name__=='__main__':

	iop.check_already_running()

	newest_date, newest_file, filed = iop.get_config_file()	

	# ensure correct folder exists:

	if not os.path.exists('archive'):
		os.mkdir('archive')

	if not os.path.exists('tmp'):
		os.mkdir('tmp')
		
	# if not os.path.exists('keys_export_import'):
		# os.mkdir('keys_export_import')
		
	if not os.path.exists('my_files'):
		os.mkdir('my_files')
		
	if not os.path.exists( os.path.join('archive','sent') ):
		os.mkdir( os.path.join('archive','sent') )


	print('\n*** Selected config file ['+newest_file+']\n\n All options: '+str(filed))

	confd_example={"email_addr":"my@email",
					"imap_addr":"imap.gmail.com", 
					"smtp_addr":"smtp.gmail.com", 
					"email_password":"", 
					"gpg_password":"", 
					"address_book":{}, 
					"send_internal_id":"0",
					# "consumer_key":"",
					# "consumer_secret":"",
					# "refresh_token":""
					}

	# jednak do google mozna zalogowac sie bez oauth! app key only 	- option suspended ...			
	hidden_par=["send_internal_id","address_book"] #,"refresh_token","consumer_key","consumer_secret"]

	json_conf_example=json.dumps(confd_example)
	json_conf=json_conf_example

	pswd=''

	if 	newest_file!='': # proces config file - decrypt or create new

		try_decr=True
		decr_str=''
		
		while try_decr:
			pp=iop.ask_password(newest_file)
			# gpg_tmp=simple_gpg+pp+ " -d "+newest_file
			try:
				# print(gpg_tmp)
				str_rep=iop.decrypt_cred(pp,newest_file) #subprocess.getoutput(gpg_tmp)
				# print(str_rep)
				if 'failed' in str_rep:
					print("Your password didn't match the config file ... Try another password or quit [q]")
					continue
				else:
					# print('\n\n\n',lorem_ipsum.replace('.','\.'),'\n\n\n')
					decr_str=str_rep.split(iop.lorem_ipsum()) #re.sub( "^.*" + lorem_ipsum.replace('.','\.') , "", str_rep)
					if len(decr_str)<2:
						print("Your password didn't match the config file ... Try another password or quit [q]")
						continue
						
					decr_str=decr_str[1]
					try_decr=False
					pswd=pp
			except:
				err_track = traceback.format_exc()
				print(err_track)
				print("Your password didn't match the config file ... Try another password or quit [q]")
			
		if try_decr==False:
			json_conf=json.loads(json_conf)
			json_conf_tmp=json.loads(decr_str)
			for jct,vv in json_conf_tmp.items():
				# print(jct,jct in hidden_par)
				
				if jct in json_conf: # and jct not in ["consumer_key",	"consumer_secret"]:
					json_conf[jct]=vv #overwirte defaults - safe way in case of adding some ne def in confd here above
					# print(jct,vv)
			
			# print(str(json_conf))
			# iop.saving_encr_cred(json.dumps(json_conf), newest_file, pp)
			# exit()
					
	else:
		
		print('\nCreate initial config')
		
		pp=iop.ask_password()
			
		for kk in filed.keys():
			# print('asdf',kk)
			pswd=pp
			newest_file=kk
			iop.saving_encr_cred(json_conf_example, newest_file, pp)
			break
			
		encr_str=iop.lorem_ipsum()
		iop.createtmpfile(encr_str) # maybe nnot needed at this point - later when true credentials in 
				

	# EDIT config ??	
				
	if json_conf==json_conf_example: # first time must edit
		
		json_obj=json.loads(json_conf)
		print('\nEditing new config ... ') #,json_obj[kk])
		for kk in json_obj.keys():
			if kk in hidden_par: #["send_internal_id" ,"address_book"]:
				continue
				
			json_obj[kk]=iop.input_prompt('> Enter '+str(kk)+' : ',True,True) # ??editing gpg pass conflicting when empty with soft quit ... 
			
		print('Editing done, accepted values:\n'+str(json_obj) )
		
		# os.remove(newest_file)
		json_conf=json.dumps(json_obj)
		iop.saving_encr_cred( json_conf, newest_file, pswd)
		
		encr_str=iop.lorem_ipsum()
		iop.createtmpfile(encr_str)

	else:
		# HERE %password% replace with stars !!! 
		print('\nCurrent credentials: ') #, json_conf
		
		for ccr,vvr in json_conf.items():
			
			if ccr=="address_book":
				# print(ccr+': '+str(vvr))
				continue # dont print address book ... 
			elif 'password' not in ccr:
				print(ccr+': '+str(vvr))
			else:
				if len(vvr)<2:
					vvr='**'
				print(ccr+': '+vvr[0]+'****'+vvr[-1])
				
		# iop.print_addr_book(json_conf)	

		# iop.edit_addr_book(json_conf , newest_file, pswd)
		# exit()
		
		ync=iop.optional_input('\nEdit credentials? [y/n] or quit [q]:  ', ['y','n','Y','N']) #'Enter value or quit [q]: '
				
		if ync.lower()=='y': # if so iterate over credentials
			
			# json_obj=json.loads(json_conf)
			edited_values=0
			for kk in json_conf.keys():
				
				if kk in hidden_par: #["send_internal_id" ,"address_book"]:
					continue
				# ask edit every one separately
				ync=iop.optional_input('Edit '+str(kk)+' ? [y/n] or quit editing [q]:  ', ['y','n','Y','N'], True) #'Enter value or quit [q]: '
				if ync=='':
					break
					
				if ync.lower()=='y':
					tmpr=iop.input_prompt('> Enter '+str(kk)+' : ',True,True)
					if tmpr=='':
						break
						
					json_conf[kk]=tmpr
					edited_values+=1
			
			if edited_values>0:
				print('New credentials:\n'+str(json_conf))
				# os.remove(newest_file)
				json_conf=json.dumps(json_conf)
				iop.saving_encr_cred( json_conf, newest_file, pswd)
		
		
	json_obj=json_conf
	if type(json_obj)==type('asd'):
		json_obj=json.loads(json_conf)	


	mail_from=json_obj["email_addr"]	
	mail_from_pswd=json_obj["email_password"]
	imap_addr=json_obj["imap_addr"]
		

	new_msgs=mbox.search_incoming(mail_from , mail_from_pswd , imap_addr ,  def_opt_init={'last_msg_limit':7, 'only_new':'yes', 'date_since':'2020-01-01'} )

	if "Error" in new_msgs.keys(): # test imap conf	

		print('*** Ensure your internet connection is good and you did not make any mistakes in credentials.')
		print('*** IMAP connection failed - if you are sure password and email address is correct please check your mailbox settings and get proper imap address. Some mailbox accounts may require special confirmation to allow 3rd party connection (e.g. gmail).')
		print(new_msgs)
		exit()
		
	else:
		print('IMAP OK')
		iop.display_msg_dict(new_msgs,'... zero unseen messages ...','\nUnseen messages:')

	# wait min 5 min since last activity

		
	cmdl.cmd_loop(pswd, newest_file) 
