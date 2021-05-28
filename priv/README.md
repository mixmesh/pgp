# generate test files

## generate password encrypted file

    echo "Hello world" | gpg -c --armour
	
## without mdc

    echo "Hello world" | gpg --rfc2440 -c --armour
