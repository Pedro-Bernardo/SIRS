
# Server API

## Endpoints:
- /login
- /submit
- /score
- /show
- /admin
- /keygen


{ c_id=0, content="asdxfscgasvfhgzcasjk" }  
{ username=user1, content="asdxfscgasvfhgzcasjk"}

## /keygen
- POST over TLS {username=user1, token=Cspubk{passwd}}
tamanho da pass pode ser um problema?
- POST response {key:AES256-key1, secret:256-bit secret}

servidor mantem tabela:


```
| user1 | key | secret | 
| user2 | key | secret |
| user3 | key | secret |
```

secret usado para HMAC
key para cifrar pedidos HTTP

## /register
- POST over TLS {username, password, CPubKey}
servidor pode ter acesso a dados sensiveis em plaintext?

## /login
- POST {user='usr', password='passwd'}

## /submit
- POST { fp='fp', vuln='vuln' }

## /score
- return all scores (JSON???)

## /show
if admin:
	return all exploits
else:
	return own exploits


{cookie, action=}
## /admin
actions:
- remove_user				-> username='user'
	- remove a user form the DB
- remove_submission			-> submission_id
	- remove a user submission (which will subtract points from the user)
