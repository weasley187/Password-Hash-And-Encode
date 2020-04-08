#password hashed with salt and encoded with base64, super secured made by: weasley :P

import bcrypt
import base64

passwd = b'pass123' # your password
data = open('data.tmp', 'w')

salt = bcrypt.gensalt() # generate salt hash
hashed = bcrypt.hashpw(passwd, salt) # hash the password
encoded = base64.b64encode(hashed) # encode the password with base64

def check_passwd():
	if bcrypt.checkpw(passwd, hashed):
		print('{}\n{}\n{}'.format(base64.b64encode(encoded).decode('utf-8'), hashed.decode('utf-8'), passwd.decode('utf-8'))) # print the values 
		data.write('{}\n{}\n{}'.format(base64.b64encode(encoded).decode('utf-8'), hashed.decode('utf-8'), passwd.decode('utf-8'))) # save the values in a data file
		return()
	else:
		return ValueError

check_passwd()
