# better-auth-go

golang implementation of [better-auth](https://github.com/jasoncolburne/better-auth)

only the server side so far.

# getting started

there are two sets of interfaces you must implement, storage and cryptographic. you'll find them
in `/pkg`. in memory/software examples are provided, but nothing stops you from hooking this
authentication system up to HSMs, databases, key-value stores, etc.

for now, check `/api/api_test.go` for the flow.
