# The Tangle -- a git based Blockchain

## Concept

People store data in blocks in the tangle:

- Creating accounts works by storing USERNAME / Argonsd(Password) in a block in the tangle
- Data gets encrypted under pk_service and stored together with the owning username in the tangle
- If you can provide the wassword for the username you can retrieve the data for that user
- the right username:password is the oldes mention (counted in blocks between HEAD and account creation)
- the tangle is implemented by git hooks. all commits need to feature a small number of leading zeros (proof-of-work!).

## Implementation

Completely implemented as git hooks. Probably https as transport for
git. Every interaction is a commit, mergecommits are accepted (it's a
acyclic graph!). All commits are required to have a certain number of
leading `6` in their hex representation to be accepted. `master` is
publicly readable.

The genesis-commit contains the public key (`openssl rsa` or similar)
of the service.

All other non-Merge commits have a tree-ish attached. The file
`action` describes which type of tree-ish / tangle transaction this
is:

 - 'register': The tree-ish contains two more files `username` and
   `password`. `username` is a username freely choosen. `password` is
   a Password hash (e.g. Argon2d but salted sha256 works as well)

 - 'store': The tree-ish contains two more files: `username` and
   `data` where `username` specifies the owner and `data` is 
   `<username>\n<user's data>` encrypted under the service's public key.

 - 'retrieve': pushed to the `get/<nonce>` branch (which is not
   readable. Contains a file labeled `password` containing the
   unhashed password. If the password matches for the owner of the
   parent commit (a 'store'), the receive hook prints the encrypted
   data.

## Vulnerability

What exactly is the correct password for the user -- especially if
there are multiple 'register' commits? Two options (the second is implemented):

 - The oldes (e.g. longest chain from HEAD). Attack: fork of the
   repository before the register and create a longer chain,
   merge. Downside: prevents the game server from getting the data
   once exploitet

 - Additional 'account' file in the 'retrieve' commit referencing the
   'register'. It's valid if the register is reachable from
   `HEAD`. receive hook prevents multiple registrations for a single
   username: for each register commit: allow if none of the parents
   registered the same username. Obviously hackable by having the two
   registers on separate forks and merge later the attacker's register
   with the "main" chain. FIX: don't allow merge commits

Second vulnerability: only the last commit of each push is checked. This way you can also register a user that already exists. FIX: check all commits in a loop
