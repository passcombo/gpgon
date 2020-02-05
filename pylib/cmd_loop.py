
# add clear archive, files, 

import re
import os
import datetime
import psutil
import traceback
import subprocess
import json

import pylib.ioprocessing as iop

import pylib.workflow as wrk
import pylib.mailbox as mbox

#select_msg_id ,'send_public','reply'
mailing_cmds=['help','search','id','disp_msg','decr_msg','get_att','disp_att','disp_att_list','decr_att','clear_my_files','clear_archive','send','save_addr','edit_addr_book','print_addr_book','key_generate','key_import','key_export','key_export_secret','key_delete','key_delete_secret','key_list','key_list_secret','list_my_files','send_file']
# ["gen-key","import","export","export-secret","delete-pub-key","delete-priv-key"]
# those require id selected:
mailing_cmds_req_id=['disp_msg','decr_msg','disp_att','get_att','disp_att_list','decr_att','reply','save_addr']

mailing_cmd_options={'id':'111', 'disp_msg':['decr'], 'disp_att':[['decr'],['all','fname_str']] }

# tmpcmd=''

def print_commands():
	print('\n\n Available commands:\n')
	for cc in mailing_cmds:
		tmp=''
		if cc in mailing_cmd_options:
			tmp=str(mailing_cmd_options[cc])
			print(cc+' - with options and/or arguments '+tmp)
		else:
			print(cc+' - no arguments needed ')
			
	print('\n* Example 1 [command]: [disp_msg]')
	print('* Example 2 [command message_id]: [id 144]')
	print('* Example 3 [command option file_name]: [disp_att decr all]\n')

	
	
	
# credentials can be updated in loop - need reread
def reread_cred(pp,newest_file):

	try:
		str_rep=iop.decrypt_cred(pp,newest_file) 
		
		if 'failed' in str_rep:
			print("Could not reread updated credentials ... exiting ... ")
			exit()
		else:
		
			decr_str=str_rep.split(iop.lorem_ipsum()) #re.sub( "^.*" + lorem_ipsum.replace('.','\.') , "", str_rep)
			if len(decr_str)<2:
				print("Could not remove lorem ipsum in updated credentials ... exiting ... ")
				exit()
				
			decr_str=decr_str[1]
			# print('Reread config - success')
			
			return json.loads(decr_str)
	except:
		err_track = traceback.format_exc()
		print(err_track)
		print("Could not reread updated credentials ... exiting ... ")
		exit()
		
		
		

# gpg pass for gpg access - what if no pass?
# aes256pp - this comes from addr book or ? input if not defined ?
# aes256pp - delete and move to decr function for input if needed !

def send_input(json_obj , newest_file, pp, send_file=False):

	# get aliases:
	addr_alia=iop.print_addr_book(json_obj)

	# 1. prompt for subject / or default
	subj='' #iop.input_prompt(propmtstr='\n Enter message subject: ', confirm=True, soft_quite=True)
	# 2. prompt for receiver / check key or pass exist ...
	msg_receiver=iop.input_prompt(propmtstr='\n Enter receiver address or alias: ', confirm=True, soft_quite=True) # if empty - quit sending ... 
	
	msg_receiver=msg_receiver.strip().lower()
	
	if msg_receiver=='q' or msg_receiver=='':
		print('Quitting message...')
		return '', '', '', ''
		
	# process alias:
	if '@' not in msg_receiver and msg_receiver not in addr_alia.keys():
		print('Extracting alias address...')
		tmp=0
		for kk in addr_alia.keys():
			if addr_alia[kk]==msg_receiver:
				msg_receiver=kk
				tmp=1
				print('Matched alias to '+kk)
				break
				
		if tmp==0:
			print('... alias not matched!...')
			return '', '', '', ''
	
	msg_content=''
	
	if send_file:
		msg_content=iop.select_file(tmppath='my_files')
		# if msg_content=='':
			# return '', '', '', ''		
	else:	
		# 3. prompt for content -> save to attachment
		msg_content=iop.input_prompt(propmtstr='\n Enter message text/content: ', confirm=True, soft_quite=True) # if empty - quit sending ... 
	
	if msg_content=='':
		print('Quitting message - empty content...')
		return '', '', '', ''
	
	pubkeys=iop.gpg_uids()
	# print( type(pubkeys), len(pubkeys) )
	keytype=''
	key=''
	
	# if msg_receiver in str(pubkeys):
		
		# keytype='pgp'
		# key=msg_receiver
	
	# el
	if json_obj["address_book"][msg_receiver]["encryption_type"]=='pgp':
		if json_obj["address_book"][msg_receiver]["pgp_id"] in str(pubkeys):
			keytype='pgp'
			key=json_obj["address_book"][msg_receiver]["pgp_id"]
		
	elif msg_receiver in json_obj["address_book"].keys():
		# print('got symetric key',str( json_obj["address_book"][msg_receiver] ) )
		keytype='aes256'
		key=json_obj["address_book"][msg_receiver]["password"]
		
	else:
		print('First add address to address book using command save_addr and set proper password for message encryption and decryption.')
		return '', '', '', ''
		
		# sym_pass=iop.input_prompt(propmtstr='\n Enter password to encrypt message with AES256: ', confirm=True, soft_quite=True) # if empty - quit sending ... 
		# if sym_pass=='':
			# return
		
		# iop.add_email_addr_book( msg_receiver , json_obj , newest_file, pp, 'password', sym_pass)
		# keytype='aes256'
		# key=sym_pass
			
	# print('subj,msg_receiver, msg_content', subj,msg_receiver, msg_content)
	# now encrypt msg, set file place, attach to msg and send ... 
	
	# cacl fname for sent with id and encrypt ... 
	str_new_id_send=str(0)
	try:
		str_new_id_send=str( int(json_obj["send_internal_id"]) +1 )
	except:
		print()
		
	json_obj["send_internal_id"]=str_new_id_send
	iop.saving_encr_cred( json.dumps(json_obj), newest_file, pp)	
	# print('done?')

	return iop.encr_msg(msg_content,keytype,key,internal_id_str=str_new_id_send), subj, msg_receiver, str_new_id_send  # file to attach to msg ... 
	

	


def cmd_loop(pp, newest_file):	#json_obj, 
		
	json_obj=reread_cred(pp,newest_file)
		
	iter=0	
	selected_id=''
	gpgpass=json_obj["gpg_password"]
		
	while True:

		if iter==0:
			print_commands()

		cmd_inp=iop.optional_input(propmtstr='\nEnter command or quit [q]: ', options_list=mailing_cmds, soft_quite=False)
		cmd_lower=cmd_inp.lower()
					
		cmd_arr=cmd_inp.split(' ')
		cmd_arr[0]=cmd_arr[0].lower()
		
		if 'help' in cmd_lower:
			print_commands()
			print('\n>>To exit app enter q or quit or exit<<\n')
		else:
			for cc in mailing_cmds:
			
				if cc==cmd_arr[0]: # in cmd_lower:
					# cur_cmd=cc
					
					if cmd_arr[0]=='save_addr':
						if len(cmd_arr)<2 and selected_id=='':
							print('This command requires to have selected id first or additional argument - email address.')
							continue
					
					elif cc in mailing_cmds_req_id and selected_id=='': # OK
						print('This command requires to have selected id first. Use command [id]')
						continue
					
					if 'id' in cc: # OK
						# tmp=str(mailing_cmd_options[cc])
						if len(cmd_arr)<2:
							print('This command requires to have at least 1 additional argument - message id.')
							continue
							
						### RUN 
						selected_id=str(cmd_arr[1])
						wrk.download_msg(json_obj,selected_id, pp, print_short=True)
						
					elif cmd_arr[0]=='search': #OK
						
						mail_from=json_obj["email_addr"]	
						mail_from_pswd=json_obj["email_password"]
						imap_addr=json_obj["imap_addr"]
						sres=mbox.search_incoming(mail_from, mail_from_pswd, imap_addr)
						iop.display_msg_dict(sres,'... no messages found ...',header='\nFound messages:',raw=False)
							
					elif cmd_arr[0]=='disp_msg':  # OK
						if len(cmd_arr)==1:
							wrk.print_msg(json_obj,gpgpass, '', selected_id,pp,decrypted=False)
						elif cmd_arr[1]=='decr':
							wrk.print_msg(json_obj,gpgpass, '',selected_id,pp,decrypted=True)
						else:
							wrk.print_msg(json_obj,gpgpass, '', selected_id,pp,decrypted=False)
							
					
					elif cmd_arr[0]=='decr_msg': # OK
						dm=wrk.decrypt_msg(json_obj,selected_id, pp, gpgpass, aes256pp='')		
						# print('\n\n\n'+dm+'\n\n\n')
						json_obj=reread_cred(pp,newest_file)
						
					elif cmd_arr[0]=='disp_att': #OK
					
						if len(cmd_arr)==1:
							wrk.display_att(json_obj,gpgpass,'', selected_id,pp,att_name='all',decrypted=False)
						elif cmd_arr[1]=='decr':
							if len(cmd_arr)>2:
								wrk.display_att(json_obj,gpgpass,'', selected_id,pp,att_name=cmd_arr[2],decrypted=True)
							else:
								wrk.display_att(json_obj,gpgpass,'', selected_id,pp,att_name='all',decrypted=True)
						else:
							wrk.display_att(json_obj,gpgpass,'', selected_id,pp,att_name=cmd_arr[1],decrypted=False)
					
					elif cmd_arr[0]=='decr_att': # OK
						
						
						att_name='all'
						if len(cmd_arr)>1:
							att_name=cmd_arr[1]
							if att_name.lower()=='all':
								att_name='all'
						wrk.decrypt_attachment(json_obj,gpgpass,'',selected_id,pp,att_name,print_content=True)
					
					elif cmd_arr[0]=='get_att': # multip arg
						
						att_name='all'
						if len(cmd_arr)>1:
							att_name=cmd_arr[1]
							if att_name.lower()=='all':
								att_name='all'
						wrk.download_att(json_obj,selected_id,pp,att_name,print_content=False)
					
					elif cmd_arr[0]=='save_addr': # OK
						# print("add_email_addr_book(emadr, json_conf , newest_file, pswd)")
						if len(cmd_arr)>1:
							iop.add_email_addr_book(cmd_arr[1], json_obj , newest_file, pp)
						else:
							tmpobj=wrk.load_from_archive(selected_id,pp)
							emadr=tmpobj["from"]
							iop.add_email_addr_book(emadr, json_obj , newest_file, pp)
							
						json_obj=reread_cred(pp,newest_file)
						
					elif cmd_arr[0]=='print_addr_book':
						iop.print_addr_book(json_obj)
						
					elif cmd_arr[0]=='edit_addr_book': # OK
						if len(cmd_arr)>1:
							iop.edit_addr_book(json_obj , newest_file, pp,cmd_arr[1])
						else:
							iop.edit_addr_book(json_obj , newest_file, pp )
					
						iop.edit_addr_book(json_obj , newest_file, pp)
						json_obj=reread_cred(pp,newest_file)
						
					elif cmd_arr[0]=='clear_archive': # OK
						# print("clear_local_mails(json_obj, newest_file, pswd)")
						# iop.clear_local_mails(json_obj, newest_file, pp)
						iop.clear_archive()
						json_obj=reread_cred(pp,newest_file)
						
					# clear_my_files
					elif cmd_arr[0]=='clear_my_files': # OK
						iop.clear_archive('clear_my_files')
					elif cmd_arr[0]=='list_my_files':
						iop.list_files('my_files',True)
					
					elif cmd_arr[0]=='disp_att_list': # OK
						wrk.print_msg_att_list(json_obj,selected_id,pp)
						
					elif cmd_arr[0] in ['send','send_file']:
						file_att, subj, msg_receiver, text_part='','','',''
						
						if cmd_arr[0]=='send':
							file_att, subj, msg_receiver, text_part=send_input(json_obj , newest_file, pp)
						else:
							file_att, subj, msg_receiver, text_part=send_input(json_obj , newest_file, pp, True)
							
						# json_obj=reread_cred(pp,newest_file)
						if msg_receiver=='':
							continue
							
						elif file_att=='':
							print("Some error - could not encrypt file ... ")
							
						else:
						
							mail_from=json_obj["email_addr"]	
							mail_from_pswd=json_obj["email_password"]
							
							# smpt_cred_dict={'smtp_addr':json_obj["smtp_addr"], 
											# 'sender_email':json_obj["email_addr"], 
											# 'sender_name':json_obj["email_addr"],
											# 'password':json_obj["email_password"], 
											# 'consumer_key':json_obj["consumer_key"], 
											# 'consumer_secret':json_obj["consumer_secret"], 
											# 'refresh_token':json_obj["refresh_token"] }
							
							# ref_token=mbox.send_email(smpt_cred_dict, msg_receiver, [file_att] , subj , text_part )
							
							# if ref_token not in ['','q']:
								# json_obj["refresh_token"]=ref_token
								# iop.saving_encr_cred( json.dumps(json_obj), newest_file, pp)
								# json_obj=reread_cred(pp,newest_file)
							
							retv=mbox.send_email(json_obj["smtp_addr"],mail_from, mail_from_pswd, mail_from, msg_receiver, [file_att] , subj, text_part)
							print(retv)
							
						# exit()
					elif cmd_arr[0]=='reply':
						print('Option not yet available')
						# exit()
					elif cmd_arr[0]=='send_public':
						print('Option not yet available')
						# exit()	
					elif 'key_' in cmd_arr[0]:
					
						if cmd_arr[0]=='key_list':
							iop.gpg_uids(False,True)
						elif cmd_arr[0]=='key_list_secret':
							iop.gpg_uids(True,True)						
						else:						
							key_dict={'key_generate':"gen-key",'key_import':"import",'key_export':"export",'key_export_secret':"export-secret",'key_delete':"delete-pub-key",'key_delete_secret':"delete-priv-key"}
							if cmd_arr[0] in key_dict:
								print(cmd_arr[0],key_dict[cmd_arr[0]])
								iop.manage_keys(gpgpass,key_dict[cmd_arr[0]])

				
		json_obj=reread_cred(pp,newest_file)
		
		
		iter+=1
	
	