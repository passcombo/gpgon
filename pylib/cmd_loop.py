# TODO:
# [ok] simplify commands _
# [ok] check decr pgp is ok ?
# [ok] add send many
# [ok] add send public
# [ok] new commands search top5 top5new
# [TEST->] add reply
# test send many secret 
# [ok]zip in place of .pgp ?

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
mailing_cmds=['help','search','id','dispmsg','decrmsg','getatt','dispatt','dispattlist','decratt','clearmyfiles','cleararchive','send','saveaddr','editaddrbook','printaddrbook','key_generate','key_import','key_export','key_export_secret','key_delete','key_delete_secret','key_list','key_list_secret','listmyfiles','sendfile','send_public','reply','replyfile','reply_public','top7','top7new']
# ["gen-key","import","export","export-secret","delete-pub-key","delete-priv-key"]
# those require id selected:
mailing_cmds_req_id=['dispmsg','decrmsg','dispatt','getatt','dispattlist','decratt','reply','saveaddr']

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
			
	print('\n* Example 1 [command]: [dispmsg]')
	print('* Example 2 [command message_id]: [id 144]')
	print('* Example 3 [command option file_name]: [dispatt decr all]\n')
	# print('TIP: you can use commands without underscore character _\n')

	
	
	
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
		
		
		
# reply = send_input with subj, receivers predefined
# receivers take from email to
# 

def send_input(json_obj , newest_file, pp, send_file=False, send_public=False, msg_receiver_s='',subj=''):

	# get aliases:
	addr_alia=iop.print_addr_book(json_obj)

	# 1. prompt for subject / or default
	# subj='' #iop.input_prompt(propmtstr='\n Enter message subject: ', confirm=True, soft_quite=True)
	# 2. prompt for receiver / check key or pass exist ...
	if msg_receiver_s=='':
		msg_receiver_s=iop.input_prompt(propmtstr='\n Enter receiver address or alias - multiple after comas: ', confirm=False, soft_quite=True) 	
	
	if msg_receiver_s=='q' or msg_receiver_s=='':
		print('Quitting message...')
		return '', '', '', ''
		
	msg_receiver_s=msg_receiver_s.split(',')
		
	msg_receivers_list=[] #msg_receiver.strip().lower()
	for msg_receiver in msg_receiver_s:
	
		if msg_receiver in addr_alia.keys():
			msg_receivers_list.append(msg_receiver.strip())
			
		elif '@' in msg_receiver and send_public:
			msg_receivers_list.append(msg_receiver.strip())
			
		else : # if not full mail try match alias
			print('Extracting alias address...')
			tmp=0
			for kk in addr_alia.keys():
				if addr_alia[kk]==msg_receiver:
					# msg_receiver=kk
					tmp=1
					print('Matched alias '+msg_receiver+' to '+kk)
					msg_receivers_list.append(kk)
					break
					
	
	if len(msg_receivers_list)==0:
		print('...no proper address found - quitting message!...')
		return '', '', '', ''
	else:
		print('Sending to '+str(msg_receivers_list))
	
	same_keys=True
	keytype=[]
	key=[]
	if send_public==False:
	
		pubkeys=iop.gpg_uids()
		
		for ijk, msg_receiver in enumerate(msg_receivers_list):
			if json_obj["address_book"][msg_receiver]["encryption_type"]=='pgp':
				if json_obj["address_book"][msg_receiver]["pgp_id"] in str(pubkeys):
					keytype.append('pgp')
					key.append(json_obj["address_book"][msg_receiver]["pgp_id"])
				else:
					print('Wrong key '+json_obj["address_book"][msg_receiver]["pgp_id"]+' for address '+msg_receiver)
					print('Available keys: '+str(pubkeys))
					return '', '', '', ''
				
			elif json_obj["address_book"][msg_receiver]["encryption_type"]=='password': #msg_receiver in json_obj["address_book"].keys():
				keytype.append('aes256')
				key.append(json_obj["address_book"][msg_receiver]["password"])
				
			else:
				print('Address '+msg_receiver+' missing key or password! First add the address to address book using command saveaddr and set proper password for message encryption and decryption.')
				return '', '', '', ''
				
			if same_keys and ijk>0:
				if keytype[ijk]!=keytype[ijk-1] or key[ijk]!=key[ijk-1]:
					same_keys=False
					print('[!] Provided addresses have different keys/passwords - will send multiple messages if you continue...')
				
		
	msg_content=''
	
	if send_public:
		subj=iop.input_prompt(propmtstr='\n Enter message subject: ', confirm=True, soft_quite=True) # if empty - quit sending ... 
		
	if send_file:
		msg_content=iop.select_file(tmppath='my_files')	
	else:	
		# 3. prompt for content -> save to attachment
		msg_content=iop.input_prompt(propmtstr='\n Enter message text/content: ', confirm=True, soft_quite=True) # if empty - quit sending ... 
	
	
	
	if msg_content in ['','q']:
		if msg_content=='':
			print('Quitting message - empty content...')
		else:
			print('Quitting message.')
			
		return '', '', '', ''
		
	str_new_id_send=str(0)
	new_id_send=0
	try:
		new_id_send=int(json_obj["send_internal_id"]) +1
		str_new_id_send=str( new_id_send )
	except:
		print()
	
	ret_list=[]
	
	if send_public:
		
		fname='' #os.path.join('archive','sent','sent_'+str_new_id_send+'.txt')
		if send_file:
			fname=msg_content
		# else:
			# iop.save_file(fname,msg_content )
			
		ret_list.append([fname, subj, msg_receivers_list, msg_content]) 
	
	elif same_keys:
		
		ret_list.append([iop.encr_msg(msg_content,keytype[0],key[0],internal_id_str=str_new_id_send), subj, msg_receivers_list, str_new_id_send])  		
	else:
		
		for ijk in range(len(keytype)):
			ret_list.append([iop.encr_msg(msg_content,keytype[ijk],key[ijk],internal_id_str=str_new_id_send), subj, msg_receivers_list[ijk], str_new_id_send])
			new_id_send+=1
			str_new_id_send=str( new_id_send )
			
	json_obj["send_internal_id"]=str_new_id_send
	iop.saving_encr_cred( json.dumps(json_obj), newest_file, pp)
	
	return ret_list

	


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
					
					if cmd_arr[0]=='saveaddr':
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
						
					elif cmd_arr[0] in ['search','top7','top7new']: #OK
						
						mail_from=json_obj["email_addr"]	
						mail_from_pswd=json_obj["email_password"]
						imap_addr=json_obj["imap_addr"]
						dopt={}
						
						if cmd_arr[0]=='top7':
							dopt={'last_msg_limit':7, 'only_new':'no', 'date_since':'2020-01-01'}
						elif cmd_arr[0]=='top7new':
							dopt={'last_msg_limit':7, 'only_new':'yes', 'date_since':'2020-01-01'}
						
						sres=mbox.search_incoming(mail_from, mail_from_pswd, imap_addr,  def_opt_init=dopt )
						iop.display_msg_dict(sres,'... no messages found ...',header='\nFound messages:',raw=False)
							
					elif cmd_arr[0]=='dispmsg':  # OK
						if len(cmd_arr)==1:
							wrk.print_msg(json_obj,gpgpass, '', selected_id,pp,decrypted=False)
						elif cmd_arr[1]=='decr':
							wrk.print_msg(json_obj,gpgpass, '',selected_id,pp,decrypted=True)
						else:
							wrk.print_msg(json_obj,gpgpass, '', selected_id,pp,decrypted=False)
							
					
					elif cmd_arr[0]=='decrmsg': # OK
						dm=wrk.decrypt_msg(json_obj,selected_id, pp, gpgpass, aes256pp='')		
						# print('\n\n\n'+dm+'\n\n\n')
						json_obj=reread_cred(pp,newest_file)
						
					elif cmd_arr[0]=='dispatt': #OK
					
						if len(cmd_arr)==1:
							wrk.display_att(json_obj,gpgpass,'', selected_id,pp,att_name='all',decrypted=False)
						elif cmd_arr[1]=='decr':
							if len(cmd_arr)>2:
								wrk.display_att(json_obj,gpgpass,'', selected_id,pp,att_name=cmd_arr[2],decrypted=True)
							else:
								wrk.display_att(json_obj,gpgpass,'', selected_id,pp,att_name='all',decrypted=True)
						else:
							wrk.display_att(json_obj,gpgpass,'', selected_id,pp,att_name=cmd_arr[1],decrypted=False)
					
					elif cmd_arr[0]=='decratt': # OK
						
						
						att_name='all'
						if len(cmd_arr)>1:
							att_name=cmd_arr[1]
							if att_name.lower()=='all':
								att_name='all'
						wrk.decrypt_attachment(json_obj,gpgpass,'',selected_id,pp,att_name,print_content=True)
					
					elif cmd_arr[0]=='getatt': # multip arg
						
						att_name='all'
						if len(cmd_arr)>1:
							att_name=cmd_arr[1]
							if att_name.lower()=='all':
								att_name='all'
						wrk.download_att(json_obj,selected_id,pp,att_name,print_content=False)
					
					elif cmd_arr[0]=='saveaddr': # OK
						# print("add_email_addr_book(emadr, json_conf , newest_file, pswd)")
						if len(cmd_arr)>1:
							iop.add_email_addr_book(cmd_arr[1], json_obj , newest_file, pp)
						else:
							tmpobj=wrk.load_from_archive(selected_id,pp)
							emadr=tmpobj["from"]
							iop.add_email_addr_book(emadr, json_obj , newest_file, pp)
							
						json_obj=reread_cred(pp,newest_file)
						
					elif cmd_arr[0]=='printaddrbook':
						iop.print_addr_book(json_obj)
						
					elif cmd_arr[0]=='editaddrbook': # OK
						if len(cmd_arr)>1:
							iop.edit_addr_book(json_obj , newest_file, pp,cmd_arr[1])
						else:
							iop.edit_addr_book(json_obj , newest_file, pp )
					
						iop.edit_addr_book(json_obj , newest_file, pp)
						json_obj=reread_cred(pp,newest_file)
						
					elif cmd_arr[0]=='cleararchive': # OK
						# print("clear_local_mails(json_obj, newest_file, pswd)")
						# iop.clear_local_mails(json_obj, newest_file, pp)
						iop.clear_archive()
						json_obj=reread_cred(pp,newest_file)
						
					# clear_my_files
					elif cmd_arr[0]=='clearmyfiles': # OK
						iop.clear_archive('clear_my_files')
					elif cmd_arr[0]=='listmyfiles':
						iop.list_files('my_files',True)
					
					elif cmd_arr[0]=='dispattlist': # OK
						wrk.print_msg_att_list(json_obj,selected_id,pp)
						
					elif cmd_arr[0] in ['send','sendfile','send_public','reply','replyfile','reply_public']:
						file_att, subj, msg_receiver, text_part='','','',''
						potlist=[]
						if cmd_arr[0]=='send':
							potlist=send_input(json_obj , newest_file, pp)
						elif cmd_arr[0]=='sendfile':
							potlist=send_input(json_obj , newest_file, pp, True)							
						elif cmd_arr[0]=='send_public':
							potlist=send_input(json_obj , newest_file, pp, False, True)				
						elif cmd_arr[0]=='reply':
							msg_obj=wrk.get_msg(json_obj,selected_id,pp)
							potlist=send_input(json_obj , newest_file, pp, False, False, msg_receiver_s=','.join(msg_obj["to"]),subj='RE: '+msg_obj['subj'])		
						elif cmd_arr[0]=='replyfile':
							msg_obj=wrk.get_msg(json_obj,selected_id,pp)
							potlist=send_input(json_obj , newest_file, pp, True, False, msg_receiver_s=','.join(msg_obj["to"]),subj='RE: '+msg_obj['subj'])			
						elif cmd_arr[0]=='reply_public':
							msg_obj=wrk.get_msg(json_obj,selected_id,pp)
							potlist=send_input(json_obj , newest_file, pp, False, True, msg_receiver_s=','.join(msg_obj["to"]),subj='RE: '+msg_obj['subj'])
							
							
						
						
						
						for pt in potlist:
							
							msg_receiver=pt[2]
							file_att=pt[0]
							subj=pt[1]
							text_part=pt[3]
							# json_obj=reread_cred(pp,newest_file)
							if msg_receiver=='':
								continue
								
							elif cmd_arr[0]!='send_public' and file_att=='':
								print("Some error sending file - could not encrypt file ... ? ")
								
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
					elif cmd_arr[0] in ['reply','replyfile','reply_public']:
						# get current mail emails:
						# wrk.print_msg(json_obj,gpgpass, '', selected_id,pp,decrypted=False)
						msg_obj=wrk.get_msg(json_obj,selected_id,pp)
						
						send_input(json_obj , newest_file, pp, False, False, msg_receiver_s=','.join(msg_obj["to"]),subj='RE: '+msg_obj['subj'])
						
					
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
								# print(cmd_arr[0],key_dict[cmd_arr[0]])
								iop.manage_keys(gpgpass,key_dict[cmd_arr[0]])

				
		json_obj=reread_cred(pp,newest_file)
		
		
		iter+=1
	
	