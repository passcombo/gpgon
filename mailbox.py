

# oauth if ever needed
# https://github.com/joestump/python-oauth2/wiki/XOAUTH-for-IMAP-and-SMTP
# https://stackoverflow.com/questions/5193707/use-imaplib-and-oauth-for-connection-with-gmail
# http://rakeshmukundan.in/2013/01/23/access-gmail-python-imaplib-and-python-with-oauth2/

import ssl
import smtplib
import imaplib
from email import encoders
import email

from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.image import MIMEImage
from email.mime.base import MIMEBase

import time
import datetime
import traceback

import pylib.ioprocessing as iop
import re
import os

# import oauth2 as oauth
# import oauth2.clients.smtp as oauth_smtplib
# import oauth2.clients.imap as imaplib



# must save refresh! token !
## oauth suspended !
# def oauth_authorize_secure_app(smpt_cred_dict):
	# perm_url=oauth.GeneratePermissionUrl(smpt_cred_dict['consumer_key'])
	# print('[!!!!!] To authorize secure connection visit following url and follow the directions '+perm_url)
	
	# authorization_code=input_prompt('Enter verification code to authorize secure connection: ', True, True)
	
	# if authorization_code in ['q','']:
		# print('Resigned authentication ...')
		# return
	
	# auth_resp = oauth.AuthorizeTokens(smpt_cred_dict['consumer_key'],smpt_cred_dict['consumer_secret'],authorization_code)

	# return auth_resp
	
# def oauth_refresh_access_token(smpt_cred_dict): # refresh_token serves to refresh access token!
	# return oauth.RefreshToken(smpt_cred_dict['consumer_key'],smpt_cred_dict['consumer_secret'],smpt_cred_dict['refresh_token'])



# def smtp_connect_send(message, receiver_email, smpt_cred_dict={'smtp_addr':'', 'sender_email':'', 'password':'', 'consumer_key':'', 'consumer_secret':'', 'refresh_token':'' }):
	
	# context = ssl.create_default_context() # Create secure connection with server and send email
	# refresh_token=''
	
	# if smpt_cred_dict['consumer_key']=='' and smpt_cred_dict['consumer_secret']=='':
	
		# with smtplib.SMTP_SSL(smpt_cred_dict['smtp_addr'] , 465, context=context) as server:
			# server.login(smpt_cred_dict['sender_email'], smpt_cred_dict['password'])
			# server.send_message( message, smpt_cred_dict['sender_email'],  receiver_email )		
			# server.close()
	
	# else:
	
	
		# with oauth_smtplib.SMTP(smpt_cred_dict['smtp_addr'] , 465) as server:
			# server.starttls()

			# if smpt_cred_dict['refresh_token']=='' and smpt_cred_dict['consumer_key']!='' and smpt_cred_dict['consumer_secret']!='': 
			
				# print('First time connecting using secure connection - need to validate ... ')
				
				# resp=oauth_authorize_secure_app(smpt_cred_dict)
				# if resp is None:
					# return ''
					
				# refresh_token=resp['refresh_token']
				# smpt_cred_dict['refresh_token']=resp['refresh_token']
				# auth_string = oauth.GenerateOAuth2String(smpt_cred_dict['sender_email'],resp['access_token'],base64_encode=False) 
				# server.authenticate('XOAUTH2', lambda x: auth_string)
		
			# elif smpt_cred_dict['refresh_token']!='':
				# resp=oauth_refresh_access_token(smpt_cred_dict)
				# auth_string = oauth.GenerateOAuth2String(smpt_cred_dict['sender_email'],resp['access_token'],base64_encode=False) 
				# server.authenticate('XOAUTH2', lambda x: auth_string)
				
			# else:
				# print('Empty password or email...')
				# return ''
				
			# server.send_message( message, smpt_cred_dict['sender_email'],  receiver_email )		
			# server.close()
		
	# print('Message sent!')
		
	# return refresh_token


# lorem_ipsum()
# def delete_draft():
	# print('delete_fraft')

# def mark_read_draft(): # when fetching - change draft_new na draft_read ... = 
	# print('mark read')


# def create_draft(mail_from , mail_from_pswd , imap_addr, file_attach=[] , subj='Lorem ipsum ut gravida - draft_new', text_part=''): #mail_from , mail_from_pswd , imap_addr
	
	# mail=None
	
	# try:
		# mail = imaplib.IMAP4_SSL(imap_addr)
		# mail.login(mail_from,mail_from_pswd)
		# mail.select('INBOX.Drafts') 
	# except:
		# err_track = traceback.format_exc()
		# return {"Error":err_track}, []
	
	# message=prepare_message_email( '', file_attach, subj, text_part)
	
	# if type(message)==type('asdf'):
		# return message
		
	# mail.append('INBOX.Drafts', '', imaplib.Time2Internaldate(time.time()), message)
	
	# mail.close()
	# mail.logout()


def prepare_message_email(sender_name, file_attach=[] , subj='', text_part=''):
	
	def_subject='Lorem ipsum ut gravida'
	if subj=='':
		subj=def_subject
		
	def_content='GDPR protected customer data update.'
	if text_part=='':
		text_part=def_content

	message = MIMEMultipart("alternative") #html
	message.set_charset('utf8')
	message["Subject"] = subj
	message["From"] = sender_name
	
	msgText = MIMEText(text_part, 'plain')
	message.attach(msgText)			
	att_added=0
	if len(file_attach)>0:
		for file in file_attach:
		
			cas=check_att_size(file)
			if len(cas)>20:		
				print(cas)
				continue
			
			h_head,t_tail=os.path.split(file)
			part_file = MIMEBase('application', 'octet-stream') #MIMEBase('multipart', 'mixed; name=%s' % t_tail)   #MIMEBase('application', 'octet-stream')
			part_file.set_payload(open(file, 'rb').read())
			encoders.encode_base64(part_file)
			part_file.add_header('Content-Disposition', 'attachment; filename="%s"' % t_tail)
			message.attach(part_file)
			att_added+=1
			
	if att_added==0 and subj==def_subject and text_part==def_content:
		return '[!] No attachment - only default content - not sending message... Change message subject or content or add attachment to be able to send.'
		
	return message



def check_att_size(att_file_path,max_bytes=1024*1024*8):
	bytes_size = os.path.getsize(att_file_path)
	if bytes_size>max_bytes:
		return 'Attachment too big. Byte size '+str(bytes_size)+' bigger then max '+str(max_bytes)
	else :
		return str(bytes_size)
		
		
# file attach - place sent files in sent folder in archive - ensure folder exist !
# add method clear attach folder ? clear archive enough
# reply option use the same just enter default email receiver, subject - rest enter manual ...


# def send_email(smpt_cred_dict,receiver_email, file_attach=[] , subj='', text_part=''):
def send_email(smtp_addr,sender_email, password, sender_name, receiver_email, file_attach=[] , subj='', text_part=''):

	text_part='GDPR protected customer data update. Part '+text_part
	
	message=prepare_message_email(sender_name, file_attach , subj, text_part)
	
	if type(message)==type('asdf'):
		return message
		
	
	# return smtp_connect_send(message, receiver_email, smpt_cred_dict)	
		
		
		
	
	context = ssl.create_default_context() # Create secure connection with server and send email
	
	with smtplib.SMTP_SSL(smtp_addr, 465, context=context) as server:
	
		server.login(sender_email, password)		
		server.send_message( message, sender_email,  receiver_email )		
		server.close()
		
	return 'Message sent!'















######
##########
#####################################################3
## IMAP:

		
		
		
		
def msg_cont_extr_pgp(msg_content):

	pgp_start='-----BEGIN PGP MESSAGE-----'
	pgp_end='-----END PGP MESSAGE-----'
	
	msg_list=[]

	if pgp_start in msg_content:
	
		split1=msg_content.split(pgp_start)
		
		for s1 in split1:
		
			if pgp_end in s1:
			
				split2=s1.split(pgp_end)
				
				for s2 in split2:
				
					if len(iop.clear_whites(s2))>1: # check if hites only but save orig! len(s2)>1: #len(iop.clear_whites(s2))>1:
					
						tmpmsg=pgp_start+s2+pgp_end
						msg_list.append(tmpmsg)
						
	return msg_list
		
		
		

# if att>0 allow read att for last message? or per id ?
def download_msg_id_att(mail_from , mail_from_pswd , imap_addr, id,att_name='all'): # check if not already downloaded!
		
	print('\n\nDownloading attachments for message ID=['+str(id)+']:\n')
	
	mail=None
	
	try:
		mail = imaplib.IMAP4_SSL(imap_addr)
		mail.login(mail_from,mail_from_pswd)
		mail.select('inbox')
	except:
		err_track = traceback.format_exc()
		return {"Error":err_track}, []
				
	typ, dd = mail.fetch(str(id), '(RFC822)' ) # '(BODY.PEEK[TEXT])'
	
	attfolder='archive' #'attachments'
	downl=[]
	
	for response_part in dd:
		if isinstance(response_part, tuple):
		
			msg = email.message_from_string(response_part[1].decode('utf-8'))			
			
			if msg.is_multipart():
			
				for part in msg.walk():
				
					if 'attachment' in str(part.get('Content-Disposition')).lower(): #part.get_content_type() == 'application/octet-stream':
					
						fname=part.get_filename()
						file_name_str=os.path.join(attfolder,id,fname) #os.path.join(attfolder,'id'+id+fname)
						
						if fname!=att_name and att_name.lower()!='all':
							continue
						# download either selected file or all 
						
						# if 'attachment' in str(part.get('Content-Disposition')).lower():
						
						# if os.path.exists(file_name_str):
							# print('File ['+fname+'] already in!')
						# else:
						print('Downloading file ['+fname+'] ...')
						
						if fname : #and fname.endswith(fileformat):
							file_content= part.get_payload(decode=1)
							
							if iop.save_file(file_name_str,file_content,True):
								print('... saved to '+file_name_str)
								downl.append(file_name_str)
							else:
								print('Failed to save to '+file_name_str)
								
						else:
							print('Wrong attachmentf file format? ['+fname+']')
							
	mail.close()
	mail.logout()
	
	print('Downloaded '+str(downl))
	
	return downl
		
		
		
		
		
		
		
		
		
		
		
		
		
# laos detects attachment files to process
def read_msg_id(mail_from , mail_from_pswd , imap_addr, id)	:
	
	mail=None
	
	try:
		mail = imaplib.IMAP4_SSL(imap_addr)
		mail.login(mail_from,mail_from_pswd)
		mail.select('inbox')
	except:
		err_track = traceback.format_exc()
		return {"Error":err_track}, []
				
	# print(id,type(id),str(id))			
				
	typ, dd = mail.fetch(str(id), '(RFC822)' ) # '(BODY.PEEK[TEXT])'
	
	printstr='\n\n Message ID=['+str(id)+'] content:\n'
	msgraw=''
	msghtml=''
	files_att=[]
	sender_email=''
	subj=''
	date=''
	
	for response_part in dd:
		if isinstance(response_part, tuple):
		
			msg = email.message_from_string(response_part[1].decode('utf-8'))			
			
			tmpdate=email.utils.parsedate(msg["Date"])
			tmpdate=datetime.datetime.fromtimestamp(time.mktime(tmpdate))
			tmpdate=tmpdate.strftime('%Y-%m-%d')
			
			subj=msg["Subject"]
			date=tmpdate
				
			printstr+='Date: '+tmpdate+' From: '+msg["From"]+' Subject: '+msg["Subject"]+'\n'
			sender_email=iop.xtract_email(msg["From"])
			# print(msg["From"],iop.xtract_email(msg["From"]))
			# exit()
			
			if msg.is_multipart():
				for part in msg.walk():
				
					if part.get_content_type()=='text/plain':
					
						tmp=str(part.get_payload())
						msgraw+=tmp
						printstr+=tmp+'\n'
					
					elif part.get_content_type()=='text/html':
					
						tmp=str(part.get_payload())
						msghtml+=tmp
						printstr+=tmp+'\n'
					elif 'attachment' in str(part.get('Content-Disposition')).lower():
						# part.get_content_type() == 'application/octet-stream':
						files_att.append(part.get_filename())
						# file_name_datetime_str=file_name.replace(rep_fname,'').replace(rep_fname2,'')
						# str_file_date=file_name_datetime_str[0:4]+'-'+file_name_datetime_str[4:6]+'-'+file_name_datetime_str[6:8]
						
			else:
				# print('optsdf')
				printstr+=str(msg.get_payload())+'\n'
			

	print(printstr)
	
	
	mail.close()
	mail.logout()
	# raw_msg={"from":"ktostam", "subj":"jakis", "body":body, "attachments":[attname]}
	return {"from":sender_email, "subj":subj, "body":msgraw, "attachments":files_att, "body_html":msghtml}
	# return {"msg_text":msgraw, "msg_html":msghtml, "from":sender_email, "subject":subj, "date":date}, files_att

	# return msg_to_process
		
		
		
		

# search criteria: dates, from, title, 
# def opt init - when needed auto, example def_opt_init={'last_msg_limit':-1, 'only_new':'yes'}
def search_incoming(mail_from , mail_from_pswd , imap_addr, def_opt_init={} ): 

	mail=None
	try:
		mail = imaplib.IMAP4_SSL(imap_addr)
		mail.login(mail_from,mail_from_pswd)
		mail.select('inbox')
	except:
		err_track = traceback.format_exc()
		return {"Error":err_track}


	def_opt={'date_before':'any','date_since':'any', 'from':'any', 'subject':'any', 'last_msg_limit':5, 'only_new':'yes'}
	
	def_opt_set={'date_before':['*','any','all','9912-12-12'], 'date_since':['*','any','all','1912-12-12'], 'from':['*','any','all'], 'subject':['*','all','any']}
	
	def_opt_usr=def_opt.copy() #{'date_before':'2019-09-01','date_since':'any', 'from':'*', 'subject':'any', 'last_msg_limit':5, 'only_new':'no'} #def_opt
	
	## tutaj prompter - user wybier i potwierdza dane ... 6 danych ... 
	
	
	if def_opt_init!={}:
		for kk, vv in def_opt_usr.items():
			if kk in def_opt_init:
				def_opt_usr[kk]=def_opt_init[kk] #overwrite with init value
	
	else: # manual enter values
	
		print('\nSet mail search params ... ') #,json_obj[kk])
		for kk in def_opt_usr.keys():
		
			opt=''
			if kk in def_opt_set.keys():
				opt=' Options: '+str(def_opt_set[kk])
		
			tmpv=iop.input_prompt('> Enter ['+str(kk)+'] current: ['+str(def_opt_usr[kk])+'] '+opt+' OR end editing [e] : ',False,True)
			tmpv=tmpv.strip()
			
			if tmpv=='e':
				break
			
			elif tmpv=='':
				continue
			
			elif kk=='last_msg_limit':
				try:
					tmpv=int(tmpv)
				except:
					print('Wrong mail search value - should be int number: '+tmpv)
					continue
			
			def_opt_usr[kk]=tmpv #propmtstr,confirm=False, soft_quite=False
	
	
	print('Mail search params: ', def_opt_usr)
	
	# print('def_opt',def_opt)
	
	
	
	
	
	total_str=''
	
	if True: #def_opt_usr!=def_opt:
	
		for kk, vv in def_opt_usr.items():
				
			if kk=='only_new': #,'only_new':['yes','no','y','n']
				if vv in ['yes','y']:
					total_str+='(UNSEEN) '
					
			elif kk=='last_msg_limit': # def_opt_usr['last_msg_limit']
				continue
		
			elif vv not in def_opt_set[kk]: # if not default option:
				
				if vv in ['*','any','all']:
					continue
				
				if kk=='date_since':
					
					tmpdate=datetime.datetime.strptime(vv,'%Y-%m-%d')
					tmpdate=tmpdate.strftime("%d-%b-%Y")
					
					total_str+='(SENTSINCE {0})'.format(tmpdate)+' '
				
				elif kk=='date_before':
					
					tmpdate=datetime.datetime.strptime(vv,'%Y-%m-%d')
					tmpdate=tmpdate.strftime("%d-%b-%Y")
					
					total_str+='(SENTBEFORE {0})'.format(tmpdate)+' '
						
				elif kk=='from':
					
					total_str+='(FROM {0})'.format(vv.strip())+' '
					
				elif kk=='subject':
					
					total_str+='(SUBJECT "{0}")'.format(vv.strip())+' '
			
				
			# elif kk=='last_msg_limit':
				# if vv>1
	
	total_str=total_str.strip()
	if total_str=='':
		total_str='ALL'
		
	# now seelect top N msg ... 
	print('Search string: ['+total_str+']')
	ttype, data = mail.search(None,  total_str ) #'(SENTSINCE {0})'.format(date), '(FROM {0})'.format(sender_email.strip())
	
	if ttype !='OK':
		mail.close()
		mail.logout()
		return {} #'no msg found'
			
	mail_ids = data[0]
	id_list = mail_ids.split()   
	# print(id_list)
	
	inter_indxi=[int(x) for x in id_list]
	# print('inter_indxi',str(inter_indxi))
	inter_indxi.sort(reverse = True) 
	# print('sorted inter_indxi',str(inter_indxi))
	
	msg_to_process={}
	
	# def_opt_usr['last_msg_limit']
	max_iter=def_opt_usr['last_msg_limit']
	if max_iter<1:
		max_iter=min(999,len(inter_indxi))
		# print('Search [last_msg_limit]<1, setting max '+str(max_iter)+' messages')
		# max_iter=999
	
	
	print('... processing messages ... count ',str(len(inter_indxi)))
	
	for i in inter_indxi: #[25]
	
		if max_iter<1:
			break
	
		# first fetch body structure to count attachments! and email size
		typ, dd = mail.fetch(str(i), 'BODYSTRUCTURE' )
		
		att_count=0
		msg_size=0
		
		if len(dd)>0: #count att:
			# print('\n***'+str(email.message_from_bytes(dd[0] ))+'***\n')
			bstr=str(email.message_from_bytes(dd[0] )) #.lower()
			tmpstr=bstr.split("\"ATTACHMENT\"") #'attachment')
			att_count+=len(tmpstr)-1
			# print('att_count',att_count)
			# exit()
			
		
		typ, dd = mail.fetch(str(i), '(RFC822.SIZE)' )
		tmps=str(email.message_from_bytes(dd[0] ))
		tmps=tmps.replace('(','').replace(')','')
		tmps=tmps.split()
		if len(tmps)>2:
			if 'RFC822.SIZE' in tmps[1]:
				# print('size?',tmps[2])
				msg_size=tmps[2]
				if iop.is_int(msg_size):
					msg_size= str( round(float(msg_size)/1024/1024,1) )+' MB'
		# print('\n email size')
		# exit()
	
		# (FLAGS BODY[HEADER.FIELDS (SUBJECT DATE FROM)]
		# Besides BODY.PEEK, you could fetch ENVELOPE
		# BODYSTRUCTURE (BODY ENVELOPE)
		
		typ, dd = mail.fetch(str(i), '(BODY.PEEK[] FLAGS)' ) # FIRST READ FLAGS TO RESTORE THEM !
		# is_unseen=False
		# for response_part in dd:
			# if isinstance(response_part, tuple):
			
				# tmpflag=email.message_from_bytes(response_part[0])
				# if not tmpflag.is_multipart():
					# tmpflag=str(tmpflag.get_payload()) # str
					# reid = re.search("FLAGS\s\(.*\)"  , tmpflag) 
					# if reid:
						# if 'unseen' in reid.group(0).lower(): #NEEDED FOR READING AUTO ATTACHMENT TO NOT 
							# is_unseen=True
	
	
	
		# typ, dd = mail.fetch(str(i), '(RFC822)' ) # '(BODY.PEEK[TEXT])' '(BODY.PEEK[])'  (RFC822) (BODY.PEEK[] FLAGS)
		
		for response_part in dd:
			if isinstance(response_part, tuple):
			
				msg = email.message_from_string(response_part[1].decode('utf-8'))
				
				# print(msg["Date"]+'|'+msg["From"]+'|'+msg["Subject"])
				
				tmpdate=email.utils.parsedate(msg["Date"]) 
				tmpdate=datetime.datetime.fromtimestamp(time.mktime(tmpdate))
				tmpdate=tmpdate.strftime('%Y-%m-%d')
				
				# att_count=0
				
				# if msg.is_multipart():
					# for part in msg.walk():
						
						# if 'attachment' in str(part.get('Content-Disposition')).lower():
							# att_count+=1
				
				tmpdict={ "Date":tmpdate, "From":msg["From"], "Subject":msg["Subject"], "ID":str(i), "Attachments":att_count, "EmailSize":msg_size} #, "Nr":max_iter 
				msg_to_process[max_iter]=tmpdict #.append(tmpdict)
				max_iter-=1
		
		# if is_unseen: # niepotrzebne ale zachowam na przyszlosc ... 
			# mail.store(str(i),'+FLAGS','\\Unseen')
		
	mail.close()
	mail.logout()
	
	return msg_to_process
	
	
	
	


def is_imap_conn_bad( mail_from, mail_from_pswd, imap_addr):

	print('\nVeryfing IMAP credentials...')
	try:
	# if True:
		with imaplib.IMAP4_SSL(imap_addr) as mail:
			# mail = 
			mail.login(mail_from,mail_from_pswd)
			mail.select('inbox')
			mail.close()
			mail.logout()
		# return False # OK
	except:
		return True	
		
		

def is_smtp_conn_bad(smtp_addr,sender_email,password):
	
	print('\nVeryfing SMTP credentials...')
	context = ssl.create_default_context()
	with smtplib.SMTP_SSL(smtp_addr, 465, context=context) as server:
	
		try:
			server.login(sender_email, password)
			server.close()
			return False
		except:
			server.close()
			return True