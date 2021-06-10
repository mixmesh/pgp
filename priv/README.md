# generate test files

## generate password encrypted file

    echo "Hello world" | gpg -c --armour
	
## without mdc

    echo "Hello world" | gpg --rfc2440 -c --armour

## Import private.key

    gpg --import private.key

## Import existing ssh key to PGP

	(from https://opensource.com/article/19/4/gpg-subkeys-ssh-multiples )

	1 - convert SSH key to new "old" format	  
	  $ ssh-keygen -p -m PEM -f <private-key-file>

	2 - Back up your existing GPG key. 	
	  $ gpg2 -a --export-secret-keys THE-KEY  > my_gpg_key.asc
	  
	3 - import your existing GPG key into new keyring dir	
	  $ mkdir temp_gpg
	  $ chmod go-rwx temp_gpg/
      $ gpg2 --homedir temp_gpg --import my_gpg_key.asc
	  
	4 - Import the SSH key as a new standalone GPG key. 	
	  $ pem2openpgp temporary_id < .ssh/my_fancy_key  | gpg2 --import --homedir temp_gpg/
	 
	5 - Add the SSH key as a subkey of your GPG key. 	
	  $ gpg2 --homedir temp_gpg  --expert --edit-key THE-KEY
gpg> addkey

	6 - Export your existing GPG key with the new subkey. 
      $ gpg2 --homedir temp_gpg -a --export-secret-keys THE-KEY > my_new_gpg_key.asc
		
	7 - Import your existing GPG key with the new subkey into your customary keyring (only the subkey will import). 

	   $ gpg2 --import my_new_gpg_key.asc 

	8 - Optionally, you may want to pre-specify that this key is to be used for SSH
	  $ gpg2 -K --with-keygrip
	  $ echo {THE-KEY-GRIP} >> ~/.gnupg/sshcontrol

	9 - Make sure gpg-agent.conf contains
	
	   enable-ssh-support
