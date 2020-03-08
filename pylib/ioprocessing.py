
	

import re
import os
import datetime
import psutil
import traceback
import subprocess
import json
import shutil
import random
import time
from termcolor import colored


def alias_mapping(allist): # address_aliases(get_wallet(True))
	alias_map={}
	for aa in allist:
		# if value contains '_' split
		xx=aa.split('_')
		
		tmpa=''
		if len(xx)>1:
			lll=3
			if len(xx)>2:
				lll=2
				
			for xi in xx:
				tmpa+=xi[:min([len(xi), lll])]
		else:
			tmpa=aa[:max([len(aa), 5])] 
			
		while len(tmpa)<5: # safer
			tmpa+=tmpa
			
		iter=1
		while tmpa in alias_map.values():
			tmpa+=str(iter)
			iter+=1
		
		alias_map[aa]=tmpa #.append([aa, tmpa])
		
	return alias_map	


def print_current_settings(set_name,json_conf,set_name_alia=[]):
	
	hidden_par=["send_internal_id","address_book"] #,"refresh_token","consumer_key","consumer_secret"]

	if len(set_name_alia)>0:
		print('\nCurrent app settings [Alias][Name][Value]:')
	else:
		print('\nCurrent app settings [Name][Value]:')
		
	for kkk in set_name: #jct,vv in json_conf.items():
		if kkk in hidden_par:
			continue
	
		if kkk in json_conf:
			vv=json_conf[kkk]
			jct=kkk
			
			if len(set_name_alia)>0:
				print('['+set_name_alia[jct]+']['+jct+']['+vv+']')
			else:
				print('['+jct+']['+vv+']')
			
			

def edit_app_settings(json_conf,pswd):

	set_name=['email_addr',"email_password","imap_addr","smtp_addr","default_title","gpg_password"]
	
	set_name_alia=alias_mapping(set_name)
	
	newest_date, newest_file, filed = get_config_file()	
	
	toedit=''
	
	while True:
		print_current_settings(set_name,json_conf,set_name_alia)
		
		toedit=optional_input('Enter alias to edit value or quite [q] or quite and save [S]: ', options_list=list(set_name_alia.values())+['S'], soft_quite=True)
		if toedit=='S':
			saving_encr_cred( json.dumps(json_conf) , newest_file, pswd)
			break
		elif toedit in ['q','']:
			break
			
		nameii = [key  for (key, value) in set_name_alia.items() if value == toedit]
		print('Editing '+nameii[0]+', current value = '+json_conf[nameii[0]])
		newvv=''
		newvv=input_prompt('Type new value (enter for empty): ', confirm=True, soft_quite=True)
			
		json_conf[nameii[0]]=newvv

	if toedit=='':
		print('\n! Exit editing without saving, current setup:')
		print_current_settings(set_name,json_conf,set_name_alia)
	else:
		json_conf=json.dumps(json_conf)
		saving_encr_cred( json_conf, newest_file, pswd)
		# print('App settings changed - exiting. Please start the app again.')
		# exit()
		
		

def read_app_settings():
		
	set_name=['email_addr',"email_password","imap_addr","smtp_addr","default_title","gpg_password","address_book","send_internal_id"]
	
	set_value=["my@email","*****","imap.gmail.com","smtp.gmail.com","__RANDOM__","semioptional",{},"0"]
	
	musthave=['email_addr',"email_password","imap_addr","smtp_addr"]
	
	DEAMON_DEFAULTS={}
	for ij,sn in enumerate(set_name):
		if type(set_value)==type('asdf'):
			DEAMON_DEFAULTS[sn]=set_value[ij].replace("optional","").replace("semioptional","")
		else:
			DEAMON_DEFAULTS[sn]=set_value[ij]
			
	json_conf=''	
	
	newest_date, newest_file, filed = get_config_file()	
	pswd=''
	
	if newest_file!='':
		# print('read file - edit in options then exit and force enter again ... ')
		
		try_decr=True
		decr_str=''
		
		while try_decr:
			pp=ask_password(newest_file)
			
			try:
				str_rep=decrypt_cred(pp,newest_file) 
				if 'failed' in str_rep:
					print("Your password didn't match the config file ... Try another password or quit [q]")
					continue
				else:
					decr_str=str_rep.split(lorem_ipsum())
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
			json_conf=json.loads(json.dumps(DEAMON_DEFAULTS))
			json_conf_tmp=json.loads(decr_str)
			for jct,vv in json_conf_tmp.items():
				# print(jct,jct in hidden_par)
				
				if jct in json_conf: # and jct not in ["consumer_key",	"consumer_secret"]:
					json_conf[jct]=vv
					if jct in musthave:
						musthave.remove(jct)
					
			if len(musthave)>0:
				print('Elements missing in config file ',str(musthave))
				exit()
				
			saving_encr_cred( json.dumps(json_conf), newest_file, pswd)
	else:
		
		pp=ask_password()
		pswd=pp
		
		json_obj=json.loads(json.dumps(DEAMON_DEFAULTS))
		print('\nCreating new generic config ... ') 
		
		for kk in set_name: #json_obj.keys():
			
			if kk in musthave:
				strtmp=''
				
				while strtmp=='':
					strtmp=input_prompt('> Type '+str(kk)+' : ',True,True)
					if strtmp=='':
						print('This value cannot be empty - try again...')
					
					else:
						json_obj[kk]=strtmp
			else:
				json_obj[kk]=input_prompt('> Type value for '+str(kk)+' or hit enter for empty: ',True,True) 
		
		#iop
		print('Creating done, accepted values:\n'+str(json_obj) )
		
		newest_file=list(filed.keys())
		newest_file=newest_file[0]
		
		json_conf=json.dumps(json_obj)
		saving_encr_cred( json_conf, newest_file, pswd)
		
	
	return json_conf, pswd, newest_file
	































def lorem_ipsum(): 

	litmp="""
Lorem ipsum dolor sit amet, consectetur adipiscing elit. Ut gravida, nisi sit amet bibendum commodo, mi nulla elementum sapien, rhoncus tempor dui mi ut dolor. Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed sollicitudin pulvinar porta. Praesent viverra laoreet accumsan. Sed accumsan mollis diam, quis sollicitudin arcu accumsan non. Proin gravida iaculis sapien ut placerat. Sed vehicula magna in quam interdum aliquet. Nam tempor metus id dui molestie maximus.
"""

	return litmp
	
	
def get_rand_lorem(maxl=21):
	strtmp=list(set(  lorem_ipsum().replace(',','').replace('\n',' ').replace('.','').lower().split(' ') ))
	# print(strtmp)
	vmin=0
	vmax=len(strtmp)-1
	randii=[]
	rtitle=''
	
	while len(rtitle)<maxl:
		r1 = random.randint(vmin, vmax)
		if r1 not in randii:
			randii.append(r1)
			if rtitle=='':
				rtitle=strtmp[r1][0].upper()+strtmp[r1][1:]
			else:
				rtitle+=' '+strtmp[r1]
				
	return rtitle
	
	
def list_files(dirpath,toprint=False):

	fl=[]
	
	dir_content=os.listdir(dirpath)
	
	for dd in dir_content:
		if os.path.isdir( os.path.join(dirpath,dd) ):
			continue # pass dirs
		fl.append(dd)
		if toprint:
			print(dd)
		
	return fl

	
	
	
	
	
	
def is_int(ii):
	try: 
		int(ii)
		return True
	except :
		return False
	
	

# available uids ... 
def gpg_uids(secret=False,toprint=False):

	# print('stri 11',stri)
	stri='gpg -k'
	if secret:
		stri='gpg -K'
	# print('stri',stri)
	str_rep=subprocess.getoutput(stri)
	s1=str_rep.split('<')
	# for si in s1:
		# print('si',si)
	uids=[]
	for ij in range(len(s1)-1):
		
		s2=s1[ij+1].split('>')
		if len(s2)>1:
			uids.append(s2[0])
			
			if toprint:
				print(s2[0])
				
	return uids
	

	
def match_pgp_uid(avuids):

	while True:
		tmpr2=input_prompt('> Enter gpg id - email address should be good enough if it is contained in gpg id: ', True, True)
		
		if tmpr2 in ['','q']:
			return ''
		
		tmpr3=''
		cc=0
		for av in avuids:
			if tmpr2 in av:
				tmpr3=av
				cc+=1
				# break
				
			if cc>1:
				print("Your string ["+tmpr2+"] matches multiple gpg uid - choose a unique one!")
				tmpr3=''
				break
		
		if tmpr3!='':
			print('Matched uid '+tmpr3)
			return tmpr3
		else:
			print('Wrong gpg uid, try again one of: '+str(avuids) )		
		

def select_file(tmppath='my_files'):
	imp_dir_file=''
	while True:
		print('Available files:')
		list_files(tmppath,True)
		imp_dir_file=input_prompt('> Enter file name to import - must be be found inside ['+tmppath+'] director: ', True, True)
		tmp=imp_dir_file
		if imp_dir_file in ['','q']:
			return ''
		
		if tmppath not in imp_dir_file:
			imp_dir_file=os.path.join(tmppath,imp_dir_file)
			
		if os.path.exists(imp_dir_file):
			return imp_dir_file
		else:
			print('No such file ['+tmp+'] in ['+tmppath+'] directory!')
	
#gpg --export-secret-keys $ID > my-private-key.asc
#kgk -K
def manage_keys(passphrase,selcmd): #["gen-key","import","export","export-secret","delete-pub-key","delete-priv-key"]

	imp_dir_file=''
	gpguid=''
	exp_dir_file=''
	pgpkey_ext='.x'
	
	# print('120',selcmd)

	if selcmd =="import":
		# check any file available in the folder
		# print('125')
		imp_dir_file=select_file(tmppath='my_files')
		if imp_dir_file=='':
			return
		
		
	elif selcmd in ["export","export-secret","delete-pub-key","delete-priv-key"]:
		
		if selcmd in ["export","delete-pub-key"]:
			# print('144',selcmd)
			avuid=gpg_uids(False,True)
			# print('145',selcmd)
			gpguid=match_pgp_uid(avuid)
			if gpguid=='':
				return
			exp_dir_file=os.path.join('my_files',gpguid.replace('@','').replace('.','')+pgpkey_ext)
			
		elif selcmd in ["export-secret","delete-priv-key"]:
			avuid=gpg_uids(True,True)
			gpguid=match_pgp_uid(avuid)
			if gpguid=='':
				return
			exp_dir_file=os.path.join('my_files','secret_'+gpguid.replace('@','').replace('.','')+pgpkey_ext)
			
		
	elif selcmd=="gen-key":
		print('')

	cmddict={"gen-key":'gpg --pinentry loopback --passphrase '+passphrase+' --gen-key', 
			"export":'gpg --export --armor '+gpguid+' > '+exp_dir_file, 
			"export-secret":'gpg --pinentry loopback --passphrase '+passphrase+' --export-secret-keys '+gpguid+' > '+exp_dir_file, 
			"import":'gpg --pinentry loopback --passphrase '+passphrase+' --import '+imp_dir_file, 
			"delete-pub-key":'gpg --delete-keys '+gpguid, 
			"delete-priv-key":'gpg --passphrase '+passphrase+' --delete-secret-keys '+gpguid}
	print(cmddict[selcmd])
	str_rep=subprocess.getoutput(cmddict[selcmd])
	print('Exported key '+gpguid+' to my_files directory: '+exp_dir_file)
	
	
def retspaces(nn):

	if nn<=0:
		return ''
		
	strr=''
	for ii in range(nn):
		strr+=' '
		
	return strr
	
	
	
	
def display_msg_dict2(msgdict,nomsgfound='',header='\nFound messages:'):

	printclr(header)
	printclr("  ID  |   Date   | Att# | Email |              From              | Subject ")
	        # ID: 76   2020-03-05   1 EmailSize: 0.0 MB From: kbednarek418@gmail.com Subject: Cogito ergo sum
		
	if len(msgdict)<1:
		print(nomsgfound)
		return
		
	ids=[ii for ii in msgdict.keys() ]
	ids.sort(reverse = True) 
	
	for ii in ids : #rr,rv in msgdict.items():
		# print(rr,rv)
		rr=ii
		rv=msgdict[ii]
		strid=str(rv["ID"])
		strid=retspaces(6-len(strid))+strid
		strdate=str(rv["Date"])
		# strid=retspaces(6-len(strdate))+strdate
		strarrc=str(rv["Attachments"])
		strarrc=retspaces(4-len(strarrc))+strarrc+'  '
		strmb=str(rv["EmailSize"])
		# print(len(strmb))
		strmb=retspaces(7-len(strmb))+strmb
		strfrom=xtract_email(rv["From"])
		strfrom=strfrom+retspaces(32-len(strfrom))
		
		# printclr("  ID  |   Date   | Att# | Email[MB] |          From          | Subject ")
		printclr(strid+'|'+strdate+'|'+strarrc+'|'+strmb+'|'+strfrom+'|'+str(rv["Subject"]) )
		# print('ID: '++' Date: '++' Attachments: '++' EmailSize: '++' From: '++' Subject: '+str(rv["Subject"]) )
			
			
			

def display_msg_dict(msgdict,nomsgfound='',header='\nFound messages:',raw=False):
	
	print(header)
		
	if len(msgdict)<1:
		print(nomsgfound)
		return
		
	ids=[ii for ii in msgdict.keys() ]
	ids.sort(reverse = True) 
	# for rr,rv in msgdict.items():
		# ids.append(int(rv["ID"]))
		
	for ii in ids : #rr,rv in msgdict.items():
		# print(rr,rv)
		rr=ii
		rv=msgdict[ii]
		if raw:
			print(rr,rv)
		else:
			print('ID: '+str(rv["ID"])+' Date: '+str(rv["Date"])+' Attachments: '+str(rv["Attachments"])+' EmailSize: '+str(rv["EmailSize"])+' From: '+xtract_email(rv["From"])+' Subject: '+str(rv["Subject"]) )
		
# def clear_local_mails(json_obj, newest_file, pswd):
	# json_obj["decrypted_mails"]={}
	# saving_encr_cred( json.dumps(json_obj), newest_file, pswd)
	# return json_obj
			
def clear_archive(myfiles=''):
	
	toclear='archive'
	if myfiles=='clear_my_files':
		toclear='my_files'
	
	if os.path.exists(toclear):
		# os.removedirs('archive')
		try:
			shutil.rmtree(toclear, ignore_errors=False)
			time.sleep(3)
			print('Directory cleared!')
			os.mkdir(toclear)
		except:
			print('[!] Could not clear archive.')
	
	
def printclr(strpr,clr='grey',attrs=['bold']):
	# print(type(strpr),type(clr),type(attrs) )
	print(colored(strpr,clr,attrs=attrs) )	

		
def print_addr_book(json_conf,only_return=False):
	
	if not only_return:
		printclr('\n=============== Address book ===============')
		printclr('[ALIAS] : [FULL EMAIL ADDRESS] : [ENCRYPTION TYPE] : [ENCRYPTION KEY] : [DECRYPTION KEY]\n')
	
	if len(json_conf["address_book"].keys())==0:
		printclr('\n ... book is empty ... \n')
		return {}
	
	addr_list=json_conf["address_book"].keys()
	addr_alia=email_address_aliases(addr_list)
	
	for kk in addr_list:
		# ask edit every one separately
		tmp_addr=kk #json_conf["address_book"][kk]
		tmp_alias=addr_alia[kk]
		tmp_encr=json_conf["address_book"][kk]["encryption_type"]
		tmp_decr=''
		try:
			tmp_decr=json_conf["address_book"][kk]["decryption_password"]
		except:
			tmp_decr=''
		# tmp_active='* Not active - encryption missing'
		encr_key=''
		if tmp_encr=='password':
			encr_key=json_conf["address_book"][kk]["password"]
		elif tmp_encr=='pgp':
			encr_key='pgp_id '+json_conf["address_book"][kk]["pgp_id"]
		# if tmp_encr in ['password','pgp']:
			# tmp_active='Yes'
		
		if not only_return:
			printclr("["+tmp_alias+"] : ["+tmp_addr+"] : ["+tmp_encr+"] : ["+encr_key+"] : ["+tmp_decr+"]")
		
	return addr_alia
		

def email_address_aliases(addr_list): # address_aliases(get_wallet(True))
	alias_map={}
	for aa in addr_list:
		tmpa=aa.replace('@','').replace('.','').lower()
		tmpa=tmpa[:5] #.lower() #+aa[-3:].lower()
		iter=1
		while tmpa in alias_map.values():
			tmpa+=str(iter)
			iter+=1
		
		alias_map[aa]=tmpa #.append([aa, tmpa])
		
	return alias_map		
		
	
def edit_addr_book(json_conf , newest_file, pswd, addroralia=''):

	addr_alia=print_addr_book(json_conf)
	if addr_alia=={}:
		printclr('Book is empty - cannot edit - first add some addresses ...','red')
		return #json_conf
	
	avuids=gpg_uids()
	printclr('\nINFO: Available public keys [gpg uids]: '+str(gpg_uids()),'green')
			
	ync=addroralia

	if ync=='':
		ync=input_prompt("\nEnter alias or address to edit or quit: ", False, True) #'Enter value or quit [q]: '
	
	if ync in ['','q']:
		return
	
	set_key=''
	
	if ync in addr_alia.keys():
		set_key=ync
		
	else:
		for kk in addr_alia.keys():
			if addr_alia[kk]==ync:
				set_key=kk
				break
	
	if set_key!='':
		printclr("Editing "+set_key,'red')
	
		encr_type=optional_input('> Enter encryption type [none,password,pgp]? Type "del" to remove entire record or quit: ', ['none','password','pgp','del','q'], True)
		
		if encr_type=='del':
			del json_conf["address_book"][set_key]
			
		elif encr_type=='q':
			return
		
		elif encr_type=='password':
			tmpr2=input_prompt('> Enter password: ', True, True)
			json_conf["address_book"][set_key]={"encryption_type": encr_type, "password":tmpr2}
			
		elif encr_type=='pgp' and len(avuids)>0:
			# tmpr2=input_prompt('> Enter pgp id - email address should be good enough if it is contained in pgp id: ', True, True)
			tmpr3=match_pgp_uid(avuids)
			
			
			json_conf["address_book"][set_key]={"encryption_type": encr_type, "pgp_id":tmpr3}
			
		elif encr_type=='pgp':
			printclr('To use PGP first you need to add some public keys... Try again later.','yellow')
			
		# else:
			# json_conf["address_book"][set_key]={"encryption_type": encr_type}
		if encr_type!='del':
			tmpr2=input_prompt('> Enter decryption password [or enter for default pgp]: ', True, True)
			json_conf["address_book"][set_key]["decryption_password"]=tmpr2
			
		saving_encr_cred( json.dumps(json_conf), newest_file, pswd)
	else:
		printclr("Address or alias ["+ync+"] not found in book...",'yellow')
	
	
	
	
	


def add_email_addr_book(emadr, json_conf , newest_file, pswd, encr_type='', sym_pass='', decr_pass=''):

	emadr=emadr.strip().lower()
	if encr_type=='password' and sym_pass!='':
		json_conf["address_book"][emadr]={"encryption_type": encr_type, "password":sym_pass}
		saving_encr_cred( json.dumps(json_conf), newest_file, pswd)	
		
	elif encr_type=='pgp':
		json_conf["address_book"][emadr]={"encryption_type": encr_type, "pgp_id":emadr}
		saving_encr_cred( json.dumps(json_conf), newest_file, pswd)	
		
	else:

		ync=optional_input('\nAdd ['+emadr +'] to local address book [y/n]? : ', ['y','n','Y','N']) 
		
		if ync.lower()=='y':
			
			avuids=gpg_uids()
			printclr('Available public keys [gpg uids]: '+str(avuids),'green')
			
			encr_type=optional_input('> Enter encryption type [none,password,pgp]? ', ['none','password','pgp'], True)
				
			if encr_type=='password':
				tmpr2=input_prompt('> Enter password for encryption: ', True, True)
				json_conf["address_book"][emadr]={"encryption_type": encr_type, "password":tmpr2}
				
			elif encr_type=='pgp' and len(avuids)>0:
				tmpr3=match_pgp_uid(avuids)
				
				
				json_conf["address_book"][emadr]={"encryption_type": encr_type, "pgp_id":tmpr3}
			
			elif encr_type=='pgp':
				printclr('To use PGP first you need to add some public keys... Try again later.','yellow')	
			else:
				json_conf["address_book"][emadr]={"encryption_type": encr_type}
				
			
			# decr_type=optional_input('> Enter decryption password [or enter for default pgp]? ', ['none','password','pgp'], True)
			tmpr2=input_prompt('> Enter decryption password [or enter for default pgp]: ', True, True)
			json_conf["address_book"][emadr]["decryption_password"]=tmpr2
			
			
			printclr('Added to local address book:\n'+str(json_conf["address_book"][emadr]),'green')
			# json_conf=json.dumps(json_conf)
			saving_encr_cred( json.dumps(json_conf), newest_file, pswd)	
		
	return json_conf #json.loads(json_conf)
	
	


def xtract_email(strt): 
	x=strt.split("<")
	if len(x)>1:
		
		x=x[1].split(">")
		return x[0]
	else:
		return strt
		


def readfile(ff):
		
	tmpstr='err'
	try:
		with open(ff, 'r') as f:
						
			tmpstr=f.read()
			f.close()	
			
		return tmpstr
	except:
		return tmpstr
		
		

def save_file(ff,tmpstr,binary=False): #ensure full path exist ... 

	headtail=os.path.split(ff)
	try:
		if not os.path.exists(headtail[0]):
			# print('create path',headtail[0])
			os.makedirs(headtail[0])
	except:
		print("Could not create path ... save file failed ... ")

	try:
	# if True:
		# print(ff)
		wstr='w'
		if binary:
			wstr='wb'
			
		with open(ff, wstr) as f:
						
			f.write(tmpstr)
			f.close()	
			
		return True
	except:
		return False
		
		

def createtmpfile(encr_str='thisissecret'): # used in encrypting via gpg


	if not os.path.isdir( 'tmp' ): # test path is folder
		os.mkdir('tmp')
		
	tmpn=os.path.join('tmp','x.txt')
	with open(tmpn,'w+') as ff:
		ff.write(lorem_ipsum()+encr_str)
		ff.close()
	return tmpn

	
	

def check_already_running(): # ... 

	main_script_name=os.path.basename(__file__)

	script_counts=0
	
	for proc in psutil.process_iter():
		try:
			# Get process name & pid from process object.
			processName = proc.name()
			processID = proc.pid
			if 'python' in processName:
				zxc=proc.as_dict(attrs=['pid', 'memory_percent', 'name', 'cpu_times', 'create_time', 'memory_info', 'cmdline','cwd'])
				
				if main_script_name in str(zxc['cmdline']):
					script_counts+=1
					
		except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
			pass

	if script_counts>1:
		helpers.log_file(log_file_path,'\n\n__ '+main_script_name+' ALREADY RUNNING __\n\n')
		exit()
	else:
		print('Starting...')
		
		
		
		


def clear_whites(strt): # replace multiple spaces with single space
	x=re.sub("\s+", " ", strt)
	x=x.strip()
	return x
	
	
	
	

def get_config_file():

	if not os.path.isdir( 'config' ): # test path is folder
		os.mkdir('config')


	filelist=os.listdir('config')
	filed={}
	newest_date=datetime.datetime.strptime('1981-01-01','%Y-%m-%d')
	newest_file=''
	
	for ff in filelist:

		if os.path.isdir( os.path.join('config',ff) ): # test path is folder
			continue		
		
		if "gnupg_mail_cfg_" in ff:
			# print(ff)
			x=re.sub(".*gnupg_mail_cfg_", "", ff)
			# print(x)
			x=re.sub("\.txt*", "", x)
			
			# print(x,'\n\n\n') # now should be date 2019-12-10
			try:
				
				strdate=datetime.datetime.strptime(x,'%Y-%m-%dh%Hm%Ms%S')

				filed[ff]=strdate
				if strdate>newest_date:
					newest_date=strdate
					newest_file=os.path.join('config',ff)
				elif strdate==newest_date:
					print('WARNING! Another config file with the same date! ['+ff+'] Keeping previous one ['+newest_file+']')
				
			except ValueError:
				print('Wrong date string '+x)
				
	if newest_file=='': # makre proposeed file - first one
		ddate=datetime.datetime.now()
		newfname=os.path.join('config',"gnupg_mail_cfg_"+ddate.strftime('%Y-%m-%dh%Hm%Ms%S')+".txt")
		filed[newfname]=ddate

	return 	newest_date, newest_file, filed

	
		
def testpassbasic(strpass):

	if strpass.lower()==strpass:
		return 'Password should contain some UPPER CAPS!'
	elif strpass.upper()==strpass:
		return 'Password should contain some lower caps!'
	elif len(strpass)<12:
		return 'Password shorter then 12 signs is not allowed!'
	else:
		for ii in range(1,10):
			if str(ii) in strpass:
				return ''
		
		return 'Password should contain at least one number!'
			
			
def input_multiline(propmtstr,endstr='endedit',quitmail='quitmail'):
	strcont=''
	# lastline=str(input(propmtstr))
	# strcont+=lastline
	tmptxt=propmtstr
	while True: #
		
		lastline=str(input(tmptxt))
		tmpll=lastline.lower().strip()
		if tmpll==quitmail:
			return ''
		elif tmpll==endstr :
			break
			
		tmptxt='Next line:'
		strcont+='\n'+lastline
		
	if strcont=='':
		strcont=get_rand_lorem(64)
		
	return strcont
	
	
	
			
# if str contains password - forbid chars are "'|-			
def input_prompt(propmtstr, confirm=False, soft_quite=False): # input_test should be function returning '' if ok		
	
	propmtstr=colored(propmtstr, 'cyan',attrs=['bold'])	
	pp=''
	forbidpass=["'",'"',"|","-"]
	while True: # confirmation loop
		# print(637)
		pp=str(input(propmtstr)  )
		pp=clear_whites(pp)	
		# print(pp)
		if pp=='q' or pp=='': # default quit option always avail
			# print(642)
			if soft_quite:
				# print(644)
				return ''
			else:
				exit()
				
		if 'password' in propmtstr.lower():
			tmpt=False
			for zzz in forbidpass:
				if zzz in pp:
					printclr('Your password contains forbidden character from list'+str(forbidpass)+':'+zzz+' Try avoiding very special characters - best to use very long alphanumeric passwords.','red')
					tmpt=True
					break
			if tmpt:
				continue
					
					
				
		if confirm:
			ync=optional_input('Confirm value ['+pp+']? [y/n] or quit [q]:  ', ['y','n','Y','N'],soft_quite) #'Enter value or quit [q]: '
			
			if ync.lower()=='y':
				return pp
			elif ync=='': # soft quit
				return ''
			else: 
				continue
		
		return pp
	
	
	
def optional_input(propmtstr, options_list, soft_quite=False):

	propmtstr=colored(propmtstr, 'cyan',attrs=['bold'])	
	
	while True:
		
		pp=str(input(propmtstr) ) 
		
		pp=clear_whites(pp)	
		
		if pp.lower()=='q' or pp.lower()=='quit' or pp.lower()=='exit': # default quit option always avail
			if soft_quite:
				return ''
			else:
				printclr('Exiting app','yellow')
				exit()
			
		splp=pp.split(' ')
		if splp[0] in options_list:
			return pp
		else:
			printclr('[!] Enterred value must match one of:\n'+str(options_list),'yellow')
			printclr('    Try again...' ,'green')
			
			

			
def ask_password(config_file=''): # mode = wallet or deamon

	propmtstr='Enter strong main password to encrypt your email credentials on this device: '
	if config_file!='':
		propmtstr='Enter relevant main password to decrypt config file ['+config_file+']: '
		
	propmtstr=colored(propmtstr, 'cyan',attrs=['bold'])	
		
	while True: 
		pp=input(propmtstr)  
		
		if pp=='q':
			exit()
		
		strt='' #testpassbasic(pp)
		if strt=='':
			return pp
			
		else:
			printclr(strt+ '\nTry again or quit [q]...','green')
			
encr_ext='.targz'
# also encrypts file if str_cont is a file!
def encr_msg(str_cont,encr_type,keyorpass,internal_id_str): # fnam should be indexed file ... to not have simmilar names ... save in folder sent ...
	
	fname=os.path.join('archive','sent','sent_'+internal_id_str+'.txt'+encr_ext)
	
	str_rep=''
	tmpfile=''
	
	if os.path.exists(str_cont): # if file!!  if tmpfile!='':
		tmpfile=str_cont
		
		headtail=os.path.split(tmpfile)
		fname=os.path.join('archive','sent',headtail[1]+encr_ext)
		
	# print('fname '+fname)
	
	if os.path.exists(fname):
		os.remove(fname)
		
	if not os.path.exists('archive'):
		os.mkdir('archive')
		
	if not os.path.exists( os.path.join('archive','sent') ):
		os.mkdir(os.path.join('archive','sent'))
		
	if encr_type=='aes256':
		gpgstr="gpg --cipher-algo AES256 --pinentry loopback --passphrase " # was "gpg --cipher-algo AES256 -a --pinentry loopback --passphrase "
		if tmpfile=='':
			tmpfile=createtmpfile(str_cont)
		gpg_tmp=gpgstr+keyorpass+" -o "+fname+" -c "+tmpfile
		
		# print('encrypting ... 760 '+gpg_tmp)
		str_rep=subprocess.getoutput(gpg_tmp)
		
	elif encr_type=='pgp':
		# gpg -a -r konrad.kwaskiewicz@gmail.com -o zxcvzxcv.txt -e cel.py
		if tmpfile=='':
			tmpfile=createtmpfile(str_cont)
		gpg_tmp="gpg -r "+keyorpass+" -o "+fname+" -e "+tmpfile # was "gpg -a -r "
		str_rep=subprocess.getoutput(gpg_tmp)
		
	print(str_rep)
	
	if os.path.exists(fname):
		return fname
	
	return '' # if error
	
	


def saving_encr_cred(json_str,fname,pp):

	#gpg --cipher-algo AES256 
	gpgstr="gpg --cipher-algo AES256 -a --pinentry loopback --passphrase "

	if os.path.exists(fname):
		os.remove(fname)

	# print('Saving encrypted credentials')
	tmpfile=createtmpfile(json_str)
	gpg_tmp=gpgstr+pp+" -o "+fname+" -c "+tmpfile
	# print('Encrypting using gnupg')
	str_rep=subprocess.getoutput(gpg_tmp)
	# print(str_rep)
	llll=lorem_ipsum()
	createtmpfile(encr_str=llll+llll+llll) #overwrite



# can als odecrypt file if it is legit path [msg_cont]	
def ensure_clear_path(ppath):
	
	if os.path.exists(ppath):
		os.remove(ppath)	

# [ok]test 1: normal msg using attachment (correct encrypted final? load att works ?)
# [ok]test 2: body msg
# test 3: diff att - pubkey
# test 4: diff att but still txt
# test 5: diff att image ... 		
		
		
		
### replace decr_msg to decrypt file and ... ?
# if arg = file path - decrypt file
# if content - create file to decrypt 
# w zasadzie to plik w folderze archive powinien zostac od razu ponownie zaszyfrowany po skopiowaniu! 

# teraz test czy ok - pobiera plik, dekoduje, ponownie szyfruje, zostawia tylko kopie zaszyfrowana lokalnie
# a ponowne ladowanie powinno byc load from archive... ?

# todo: wylaczyc save t oarchive w decr msg oraz decr attach
# test load att oraz load decr msg
# ... 

def decr_msg2(msg_id,pp,msg_cont,gpgpass='',aes256pp='',print_content=False):

	tryaes=False
	outputfile=''
	decr_file_path=''
	save_copy=''
	fileext=''
	fname='' # encrypted decrypted
	
	if os.path.exists(msg_cont):
	
		decr_file_path=msg_cont
		
		headtail=os.path.split(decr_file_path)
		split_ext=headtail[1].split('.')
		
		if len(split_ext)>2:
			fileext=split_ext[1].lower()
			outputfile='d_'+split_ext[0]+'.'+fileext
			
			if fileext!='txt':# file diff then txt always decrypted to 2 locations? 1. archive 2. my_files
				save_copy=os.path.join('my_files',outputfile)
				
			outputfile=os.path.join(headtail[0],outputfile)
			fname=os.path.join(headtail[0],'decr_'+split_ext[0]+'.'+fileext)
		else:
			outputfile=os.path.join(headtail[0],'d_'+decr_file_path)  # if no extension
			fname=os.path.join(headtail[0],'decr_'+decr_file_path)
			
	else: # create file with content
		fileext='txt'
		decr_file_path=createtmpfile(encr_str=msg_cont)
		outputfile=os.path.join('tmp','z.txt')		
		fname=os.path.join('archive',str(msg_id),'decr_body.txt')
	
	ensure_clear_path(outputfile)
	
			
	if aes256pp==''  or aes256pp=='pgp': # if no decrypt pass - first try pgp
		try:
			gpgstr="gpg -o "+outputfile+" -d "+decr_file_path
			if gpgpass!='':
				gpgstr="gpg --pinentry loopback --passphrase "+gpgpass+" -o "+outputfile+" -d "+decr_file_path
								
			str_rep=subprocess.getoutput(gpgstr)
			
			if '@' in str_rep: 
				print('Decrypted using asymetric key file ['+decr_file_path+'] to ['+outputfile+']\n Delete the file after usage to stay safe!')
				
			else:
				tryaes=True
		except:
			tryaes=True
	else:
		tryaes=True	
		
		
	if tryaes:		
		
		if aes256pp=='':
			aes256pp=input_prompt(propmtstr="Enter password to decrypt message: ", confirm=False, soft_quite=True)
		
		if aes256pp!='':
			gpgstr="gpg -a --pinentry loopback --passphrase "+aes256pp+" -o "+outputfile+" -d "+decr_file_path
			# gpgstr="gpg --cipher-algo AES256 -a --pinentry loopback --passphrase "+aes256pp_ajd+" -o "+tmpdecr+" -d "+msg_cont
			
			str_rep=subprocess.getoutput(gpgstr)
			if 'failed:' not in str(str_rep):
				print(str_rep)
			
				print('Decrypted using password to ['+outputfile+']')
			else:
				tryaes=False
		else:
			print("No password provided - quit decryption...")
			tryaes=False
	# print('os.path.exists(outputfile)',os.path.exists(outputfile))
	
	
	
	if os.path.exists(outputfile):

		if save_copy!='':
			shutil.copyfile(outputfile, save_copy)
			print('Saved file copy to ['+save_copy+']\n Delete the file after usage to stay safe!')
		
		# print(fileext,print_content)
		if fileext=='txt' and print_content:
			decr_msg=readfile(outputfile)
			# print('844')
			printclr('\n------- DECRYPTED MESSAGE START -------\n'+decr_msg.replace(lorem_ipsum(),'')+'\n------- DECRYPTED MESSAGE END -------\n','grey')
			
		# now encrypt  outputfile to local aes
			
		gpgstr="gpg --cipher-algo AES256 -a --pinentry loopback --passphrase "
		# fname=os.path.join('archive',str(msg_id),fname)
		
		# if not os.path.exists('archive'):
			# os.mkdir('archive')
		
		# if not os.path.exists(os.path.join('archive',str(msg_id)) ):
			# os.mkdir(os.path.join('archive',str(msg_id)))

		if os.path.exists(fname):
			os.remove(fname)

		gpg_tmp=gpgstr+pp+" -o "+fname+" -c "+outputfile
		# print('Encrypting using gnupg')
		str_rep=subprocess.getoutput(gpg_tmp)
		
		print(fname+' ['+msg_id+'] saved to archive.')	
			
		
		# cleaning
		createtmpfile() #overwrite
			
		# if os.path.exists(outputfile):
		# if outputfile==os.path.join('tmp','z.txt'):
		os.remove(outputfile)
		
	return tryaes # if False failed to decrypt ... 


		
	

def decrypt_cred(pp,newest_file):

	gpgstr="gpg --cipher-algo AES256 -a --pinentry loopback --passphrase "

	return subprocess.getoutput(gpgstr+pp+" -d "+newest_file)

	
	
