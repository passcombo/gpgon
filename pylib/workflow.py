

# archive files: raw_msg={"from":, "subj":, "body":, "attachments":[]}, body_decr, attachments[n], der_att[n]



import re
import os
import datetime
import psutil
import traceback
import subprocess
import json

import pylib.ioprocessing as iop
import pylib.mailbox as mbox
	
def get_msg(json_obj,msg_id,pp):#OK

	msg_obj=load_from_archive(msg_id,pp)
	
	if msg_obj=={}:# if not in local archive yet ... 
	
		msg_obj=download_msg(json_obj,msg_id,pp,False)
		
	if msg_obj=={}:
		
		print('No such message exist, msg_id=['+msg_id+']...')
		return {}
		
	return msg_obj
	


def save_file_to_archive(msg_id,fname,fcont,pp):#OK
	
	gpgstr="gpg --cipher-algo AES256 -a --pinentry loopback --passphrase "
	fname=os.path.join('archive',str(msg_id),fname)
	
	if not os.path.exists('archive'):
		os.mkdir('archive')
	
	if not os.path.exists(os.path.join('archive',str(msg_id)) ):
		os.mkdir(os.path.join('archive',str(msg_id)))

	if os.path.exists(fname):
		os.remove(fname)

	# print('Saving encrypted credentials')
	tmpfile=iop.createtmpfile(fcont)
	gpg_tmp=gpgstr+pp+" -o "+fname+" -c "+tmpfile
	# print('Encrypting using gnupg')
	str_rep=subprocess.getoutput(gpg_tmp)
	# print(str_rep)
	llll=iop.lorem_ipsum()
	iop.createtmpfile(encr_str=llll+llll+llll) #overwrite
	print(fname+' ['+msg_id+'] saved to archive.')	
	
	

	
def load_decr_body(msg_id,pp):#OK
	# print('load_from_archive')
	tmppath=os.path.join('archive',str(msg_id),'decr_body.txt')
	# decr_body=iop.readfile(tmppath)
	
	if not os.path.exists(tmppath):
		return 'err'
	
	gpgstr="gpg --cipher-algo AES256 -a --pinentry loopback --passphrase "
	js_str=subprocess.getoutput(gpgstr+pp+" -d "+tmppath)
	
	decr_str=js_str.split(iop.lorem_ipsum()) #re.sub( "^.*" + lorem_ipsum.replace('.','\.') , "", str_rep)
	if len(decr_str)<2:
		print("Your password didn't match the config file ... Try another password or quit [q]")
		return {"err":"could not load file "+tmppath}
		
	decr_str=decr_str[1]	
	
	return decr_str
	
	
	
	
def decrypt_msg(json_obj,msg_id, pp, gpgpass, aes256pp): # decr body content ...
	msg_obj=get_msg(json_obj,msg_id,pp)
	
	
	
	if msg_obj["from"] in json_obj["address_book"]:
		try:
			aes256pp=json_obj["address_book"][msg_obj["from"]]["decryption_password"]
		except:
			print()
			
	# print(msg_obj)
	# 1. check is alread decrypted:
	# decr_body='' 
	
	iop.decr_msg2(msg_id,pp,  msg_obj["body"],gpgpass,aes256pp,True)
	# dm=iop.decr_msg( [ msg_obj["body"] ],gpgpass,aes256pp)
	# print(';;;',dm)
	# if dm!='':
		# decr_body="\n\n> Subject: "+msg_obj["subj"]+"\n> From: "+msg_obj["from"]+'\n\n'+dm
		
		# decr_body+='\n\n> Attachments: '
		# for ij in msg_obj["attachments"]:
			# decr_body+='\n * '+ij
			
		# save_file_to_archive(msg_id,'decr_body.txt',decr_body,pp)
		
		# print('\n\n\n'+decr_body+'\n\n\n')
		
	# else:
		# print('Loaded from archive...\n'+decr_body)
	
	# return decr_body
		
	
	



def print_msg(json_obj,gpgpass, aes256pp, msg_id,pp,decrypted=False): #ok
	msg_obj=get_msg(json_obj,msg_id,pp)
		
	if msg_obj!={}:
		if decrypted:
			# if already decrypted ... 
			decr_body=load_decr_body(msg_id,pp)
			if decr_body!='err':
				print(decr_body)
			else:
				print(decrypt_msg(json_obj,msg_id, pp, gpgpass, aes256pp) )
		else:
			msg_obj_to_txt(msg_obj,short=False)
		

	
	
	
# simply printing raw message	
def msg_obj_to_txt(mobj,short=True):#[OK]
	print("> Subject: "+mobj["subj"])
	print("> From: "+mobj["from"])
	print("> To: "+str(mobj["to"]))
	
	if short:
		# print('limit 10 lines and 1000 chars, att names, subj, from, id')
		msg_lines=mobj["body"].split('\n')
		msg_short='> Body - short (limit 10 lines, 1000 chars):\n'
		for ij in range( min( 10,len(msg_lines) )):
			tmp=msg_short+msg_lines[ij].strip()
			if len(tmp)>999:
				break
			msg_short=tmp+'\n'
		print(msg_short)	
	# raw_msg={"from":"ktostam", "subj":"jakis", "body":body, "attachments":[attname]}
	else:
		print(mobj["body"])	
	
	print('\n> Attachments: ')
	for ij in mobj["attachments"]:
		print(' * '+ij)
	print(' ')
	
	
	
# loading raw msg from archive ... 
def load_from_archive(msg_id,pp):#[OK]
	# print('load_from_archive')
	fname=os.path.join('archive',str(msg_id),'raw_msg.txt')

	if not os.path.exists(fname):
		return {}
		
	# js_str=iop.readfile(fname)
	gpgstr="gpg --cipher-algo AES256 -a --pinentry loopback --passphrase "
	js_str=subprocess.getoutput(gpgstr+pp+" -d "+fname)
	
	decr_str=js_str.split(iop.lorem_ipsum()) #re.sub( "^.*" + lorem_ipsum.replace('.','\.') , "", str_rep)
	if len(decr_str)<2:
		print("Your password didn't match the config file ... Try another password or quit [q]")
		return {"err":"could not load file "+fname}
		
	decr_str=decr_str[1]
	
	js_obj={}
	try:
		# print('\n***\n',type(decr_str),decr_str)
		js_obj=json.loads(decr_str)
		# print('Loaded from archive')
		return js_obj
	except:
		return {"err":"could not load file "+fname}
	
	
	
# saving raw msg to archive ... 
# raw_msg={"from":, "subj":, "body":, "attachments":[]}
def save_to_archive(msg_id,msg_obj,pp):#[OK]

	json_obj=msg_obj.copy()
	if type(json_obj)!=type('asd'):
		json_obj=json.dumps(json_obj)	# ensure we have string ready to write ... 
	
	
	gpgstr="gpg --cipher-algo AES256 -a --pinentry loopback --passphrase "
	fname=os.path.join('archive',str(msg_id),'raw_msg.txt')
	
	if not os.path.exists('archive'):
		os.mkdir('archive')
	
	if not os.path.exists(os.path.join('archive',str(msg_id)) ):
		os.mkdir(os.path.join('archive',str(msg_id)))

	if os.path.exists(fname):
		os.remove(fname)

		
	tmpfile=iop.createtmpfile(json_obj)
	gpg_tmp=gpgstr+pp+" -o "+fname+" -c "+tmpfile
	
	str_rep=subprocess.getoutput(gpg_tmp)
	
	iop.createtmpfile(encr_str=iop.lorem_ipsum()) #overwrite
	print('Message id ['+msg_id+'] saved to archive.')

	
	
# check message available local - if not download and archive ... 	
def download_msg(json_obj,msg_id, pp, print_short=True): #[OK]

	msg_obj=load_from_archive(msg_id,pp)
	
	mail_from=json_obj["email_addr"]	
	mail_from_pswd=json_obj["email_password"]
	imap_addr=json_obj["imap_addr"]
	
	
	if msg_obj=={}:
		
		
		msg_obj=mbox.read_msg_id(mail_from , mail_from_pswd , imap_addr, msg_id)
		
		save_to_archive(msg_id,msg_obj,pp)
	
	if print_short:
		msg_obj_to_txt(msg_obj)	
		
	return msg_obj


##################################################################### ATTACHMENTS ##########
############
#####	

	
# display files attached	
def print_msg_att_list(json_obj,msg_id,pp): # DONE
	msg_obj=get_msg(json_obj,msg_id,pp)
	# print('init if ... ')
	if "attachments" in msg_obj:
		if len(msg_obj["attachments"])>0:
			print('Attachments list for msg_id=['+msg_id+']:')
			for fn in msg_obj["attachments"]:
				print(fn)
		
	

	
# TODO: w pierwszej opcji jesli jest juz odszyfrowany - wyswietlic load ... 
# if txt file - show decrypted
# otherwise decrypt and move to my files ... 

def disp_file(fpath,pp): # locally file encrypte with localc pass 

	headtail=os.path.split(fpath)
	
	if len(headtail)>1:
		if '.txt' in headtail[1].lower(): # local decrypt return content
			
			outputfile=os.path.join('tmp','z.txt')
			if os.path.exists(outputfile):
				os.remove(outputfile)
			gpgstr="gpg -a --pinentry loopback --passphrase "+pp+" -o "+outputfile+" -d "+fpath
			print(subprocess.getoutput(gpgstr))
			
			msg=iop.readfile(outputfile).replace(iop.lorem_ipsum(),'')
			os.remove(outputfile)
			
			return '\n------- DECRYPTED MESSAGE START -------\n'+msg+'\n------- DECRYPTED MESSAGE END -------\n'
		
		else: # decr copy to my files 
			outputfile='d_'+headtail[1]
			outputfile=os.path.join('my_files',outputfile) 
			if os.path.exists(outputfile):
				os.remove(outputfile)
			gpgstr="gpg -a --pinentry loopback --passphrase "+pp+" -o "+outputfile+" -d "+fpath
			print(subprocess.getoutput(gpgstr))

			return 'File extension different then .txt - saved file copy to ['+outputfile+']\n Delete the file after usage to stay safe!'
		
	return 'Wrong file path? No file ? '+fpath


def display_att(json_obj,gpgpass,aes256pp,msg_id,pp,att_name,decrypted=False): # OK

	msg_obj=get_msg(json_obj,msg_id,pp)
	
	if decrypted:
				
		# spr jesli all czy juz wszystkie sa ok ?
		if att_name=='all':
			
			# change here : get att list and try display one by one ... 
			# att_list=[]
			# if len(msg_obj["attachments"])>0:
				# for fn in msg_obj["attachments"]:
					# att_list.append(fn)
			
			for fa in msg_obj["attachments"]:
				# print('fa',fa)
				lda=load_decr_att(msg_id,pp,fa)
				if lda==None:
					print('Decrypted attachment ['+fa+'] of msg id ['+str(msg_id)+'] does not yet exist... try decrypt...')
					decrypt_attachment(json_obj,gpgpass,aes256pp,msg_id,pp,att_name,True)
				else:
					print('\nDecrypted attachment ['+fa+'] of msg id ['+str(msg_id)+'] :')
					print(lda)
		elif att_name in msg_obj["attachments"]:
		
			lda=load_decr_att(msg_id,pp,att_name)
			if lda==None:
				print('Decrypted attachment ['+att_name+'] of msg id ['+str(msg_id)+'] does not yet exist... try decrypt...')
				decrypt_attachment(json_obj,gpgpass,aes256pp,msg_id,pp,att_name,True)
			else:
				print('\nDecrypted attachment ['+att_name+'] of msg id ['+str(msg_id)+'] :')
				print(lda)
		else:
			print('Attachment ['+att_name+'] does not exist!')
			
	else:
		# print('fgfhghgfh')
		if att_name=='all' or att_name in msg_obj["attachments"]:
			# print(msg_obj["attachments"],'lkjlkjlkj',att_name,att_name==msg_obj["attachments"][0])
			for fn in msg_obj["attachments"]:
				if att_name==fn or att_name=='all':
		
					tmppath=os.path.join('archive',str(msg_id),fn)
					if os.path.exists(tmppath):
						print('Read from archive ... 2')
						if '.txt' in tmppath.lower():
							print(iop.readfile(tmppath))
						else:
							print('Cannot display non-txt file! Try disp_att decr')
					else: #if att_name!='all':
						print('Download ... ')
						download_att(json_obj,msg_id,pp,att_name,True)
				# else:
					# print('asdasdad',att_name,fn)
			# download_att(json_obj,msg_id,pp,att_name,True)
		else:
			print('Attachment ['+att_name+'] does not exist!')
		
			
	
	
def decrypt_attachment(json_obj,gpgpass,aes256pp,msg_id,pp,att_name,print_content=False): # OK

	msg_obj=get_msg(json_obj,msg_id,pp)
	cc=0
	if att_name=='all' or att_name in msg_obj["attachments"]:
	
		for fn in msg_obj["attachments"]:
			if att_name==fn or att_name=='all':
	
				tmppath=os.path.join('archive',str(msg_id),fn)
				if os.path.exists(tmppath):
					cc+=1
					continue
				else: 
					cc+=download_att(json_obj,msg_id,pp,fn,True)
	else:
		print('Attachment ['+att_name+'] does not exist!')

	if msg_obj["from"] in json_obj["address_book"]:
		try:
			aes256pp=json_obj["address_book"][msg_obj["from"]]["decryption_password"]
		except:
			print()
	# cc=download_att(json_obj,msg_id,pp,att_name) # ensure it's there ... 
		
	iter=0
	if cc>0:
		# same if checks again in case in the meantime it was deleted ...
		
		if "attachments" in msg_obj:
			if len(msg_obj["attachments"])>0:
			
				for fn in msg_obj["attachments"]:
				
					# dm=''
				
					if att_name.lower()=='all' or att_name==fn:
						print('Decrypting ['+fn+']...')
						
						tmppath=os.path.join('archive',str(msg_id),fn)
						if not os.path.exists(tmppath):
							print('Smth went wrong ... ?')
							continue
							
						# dm=iop.decr_msg( [ iop.readfile(tmppath) ],gpgpass,aes256pp)
						iop.decr_msg2(msg_id,pp, tmppath,gpgpass,aes256pp,print_content)
						
						# tmppath_decr=os.path.join('archive',str(msg_id),'decr_'+fn)
						# save_file_to_archive(msg_id,'decr_'+fn,dm,pp)
					else:
						print('Attachment ['+att_name+'] does not exist!')
						
					# if print_content:
						# print(dm)
					
					iter+=1
	return iter


def load_decr_att(msg_id,pp,att_name):#OK

	# if .gpg in the end - remove:
	gpgsplit=att_name.split('.')
	if len(gpgsplit)>2:
		att_name=gpgsplit[0]+'.'+gpgsplit[1]
	
	
	tmppath=os.path.join('archive',str(msg_id),'decr_'+att_name)
	print('Loading path '+tmppath)
	
	if not os.path.exists(tmppath):
		# print('not found',tmppath)
		return None #'err - no decrytpted att ... '+tmppath
	
	return disp_file(tmppath,pp)
	
	# gpgstr="gpg --cipher-algo AES256 -a --pinentry loopback --passphrase "
	# js_str=subprocess.getoutput(gpgstr+pp+" -d "+tmppath)

	# decr_str=js_str.split(iop.lorem_ipsum()) #re.sub( "^.*" + lorem_ipsum.replace('.','\.') , "", str_rep)

	# if len(decr_str)<2:
		# print("Your password didn't match the file ... Try another password.")
		# return {"err":"could not load file "+tmppath}
		
	# decr_str=decr_str[1]	
	
	# return decr_str
		

		
	
# check message available local - if not download and archive ... 	
def download_att(json_obj,msg_id,pp,att_name,print_content=False): # OK

	# 1. if 1 att- check if already downloaded
	# 2. if all - check 1 by 1 if downloaded ... 
	mail_from=json_obj["email_addr"]	
	mail_from_pswd=json_obj["email_password"]
	imap_addr=json_obj["imap_addr"]

	msg_obj=get_msg(json_obj,msg_id,pp)		
	# print(msg_obj)
	iter=0
		
	if "attachments" in msg_obj:
		if len(msg_obj["attachments"])>0:
			print('Attachments list for msg_id=['+msg_id+']:')
			if att_name.lower()=='all':
				att_downloaded_list=mbox.download_msg_id_att(mail_from , mail_from_pswd , imap_addr, msg_id)
				if print_content:
					for ijk in att_downloaded_list:
						asdf=ijk.lower().split('.')
						# print(asdf,len(asdf),asdf[-1])
						if asdf[-1]=='txt' :
							print('File content:\n',iop.readfile(ijk))
				
			else:
			
				for fn in msg_obj["attachments"]:
					if att_name==fn:
						print('Processing ['+fn+']...')
						# check att already in archive:
						tmppath=os.path.join('archive',str(msg_id),fn)
						
						
						att_downloaded_list=mbox.download_msg_id_att(mail_from , mail_from_pswd , imap_addr, msg_id, att_name)
						
						
						iter+=1
						
						asdf=tmppath.lower().split('.')
						# print(asdf,len(asdf),asdf[-1])
						
						if print_content and 'txt' ==asdf[-1]:
							print('File content:\n',iop.readfile(tmppath))
	
	return iter # number of attachments downloaded to archive - total
	
	
