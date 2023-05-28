# Computer-Security

Alice send her pid, time at transfer, and GPS data.
Bob receive these data.

James send his json file including pid, time at transfer, and GPS data.
Jbob receive the json file.

# running
You can run server with "run_server [name] [port]"
The name is bob or jbob.

And then run client with "client [alice or james] [port]"
The name is alice or james.

The name pairs are (bob, alice) and (jbob, james).
In other words, if you set server to bob, you should set client to alice.
Also, if you set server to jbob, you should set client to james.

#key
The default keys are:
encryption key: AAAAAAAAAAAAAAAA
MAC key: BBBBBBBBBBBBBBBB
initialized vector: CCCCCCCCCCCCCCCC

You can change the encryption and MAC key, and initial vector in run_server and client.
