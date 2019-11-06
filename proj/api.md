
# Server API

## Endpoints:
- /login
- /submit
- /score
- /show
- /admin

## /register

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
