# UMD BitCamp Hackathon Custom Python BitTorrent Client

**BitTorrent Summary**

Group Members: Annie Zhou, Jonathan Camberos, Sadia Nourin, Saar Cohen

**Supported Features:**

● Communicate with the tracker (with support for compact format):
○ We are able to talk to the tracker given a torrent file and can do so in both normal
and compact mode.

● Download a file from official Bittorrent Client:
○ We can download both the flatland and the debian files using the torrents
provided on the web. The flatland file is downloaded perfectly, and we are able to
download all of the debian file except for the last piece.

● Download a file from other instances of clients:
○ We hosted our own tracker and had one of our clients as a designated seeder for
the flatland file. We had five other clients as leechers and all five clients were
able to download the file successfully.

● UDP tracker support:
○ We were able to implement one of the extra credit features and are able to talk to
the tracker via UDP.

Design and Implementation Choices
We implemented our bittorrent client in python because we had two people on our team (Sadia
and Saar) for which that was the most comfortable language while the other two people decided
to learn the language first before starting the project (Annie and Jonathan, props to them!). This
was only possible for us because they decided to learn python during Thanksgiving break. The
python libraries that we imported within our project include the following:

● socket, time, select, sys, os, re, io, os.path, struct, codecs, bencode, Hashlib, math, urllib.parse, argparse, random, datetime, collections

Tracker.py: We decided to implement our Tracker as a separate class in python for
organization purposes (it helps so that the main file is not cluttered). The Tracker class has the
necessary methods to read from the .torrent file provided, and has methods and attributes that
help us with provide values for that are extremely important for our bittorrent client, such as the
maximum number of pieces, the size of the file that we are supposed to download in bytes, the
length of each piece, etc. We create an instance of the Tracker when we first execute our
bittorrent client and just call all of these methods and attributes as needed.
Peer.py: The Peer was also implemented as a separate class in python, also for organization
purposes. Essentially, each peer that our client connected to was assigned a new Peer
instance. This instance would be responsible for keeping state for the Peer, such as the id
number for the peer, the pieces that they currently have, the download rate, whether or not any
pieces were already requested from them, etc. In addition, the Peer class has all of the methods
that our bittorrent client can call to send any message they want to the peer. This is only
possible because we made the Peer objects keep state on the socket that they are currently
connected to.
mult_peers_test/bittorrent_client.py: This is our main bittorrent client file. We had another file
that is in the root repository named bittorrent_client.py, however, after testing with multiple
clients using our own tracker, we decided to move it into this mult_peers_test directory. This
main file is organized similarly to our previous projects in this class. We have one main function
that starts us off where we call the tracker, get the list of peers, and then connect to all of the
peers that we are able to. Then, we hop into an infinite while loop where we have a select call in
order to wait for messages from our peers. We also bind our own client to a socket and put this
socker within our select call as well to make sure that when we become a seeder, we can start
uploading to other peers when they initiate a handshake from us and request a piece from us.
Before we enter the select call however, there are a few things that we do. We first check
whether we have finished downloading the entire file, the setup for our top-4 and optimistic
unchoking strategy, calls to functions that requests pieces for our client when we have received
bitfields from our peers, a call to a function that removes any state that we have held on any
currently requested pieces if those pieces do not arrive by a specified time, and a call to function
that validates the current peer list (if they have not closed their sockets on us and if they are
sending keep-alive messages) that also replenishes the peer list by going back to the tracker to
get more if the peer list dips below a threshold value. Only after all of this is taken care of do we
enter the select call.

After we enter the select call, we simply wait for a socket to be ready for reading. When a socket
is ready, we first check whether it is our own socket and if so, we receive a handshake, send a
handshake back, and send our own bitfield before storing the peer’s socket into our next select
call. For all other sockets, we first check whether the peers closed the socket on us, and then
proceed to check which message the peer had sent. There’s nothing much interesting
afterwards, as we simply handle each message accordingly (if they unchoke we simply change
the client state and wait for our piece selection algorithm to request a piece from them in the
next iteration of the while loop, if they are interested in us we run our top-4/optimistic unchoking
strategy to check whether or not we want to unchoke them, etc.)
The connection management and file system components are all within this main bittorrent
client file, as this file has the select call, keep alive messages, handshaking, reading and writing
to the file, hash checking, etc. all inside of it as different functions.
A few important implementation details that we think we would design differently next time would
actually be to move the file system component out of the main file, because it caused a lot of
clutter. In addition, we were heavily reliant on global variables within our bittorrent client, we
declared a total of 19 of them, which is probably well above the standard amount when it comes
to coding best practices. This is actually why we decided to keep the file system component
within the main file, because many of its functions needed access to global variables. We tried
to figure out a method to just import all of the global variables to different files, but alas, it took
too long and took away time from meaningful progress and we decided to stuff everything within
a file.
Piece Selection Strategy: Our final bittorrent client implementation simply implemented the
random piece selection strategy. Essentially, before we block for our select call, we iterate
through each peer, comparing their bitfields with ours and check to see what pieces they have
that we do not have. We then iterate through these pieces and check whether or not the peer
has already been asked for a different piece that has not fully arrived yet OR if the piece was
already requested to a different client. If any of these are true, we don’t do anything and move
onto the next piece. If these are false, we check if the client is choking us and if so, we send an
interested message (in hopes that they will unchoke us by the time we come across a situation
where we have to request them for another piece). If they have already unchoked us, we
request them for the pieces. It’s crucial to us that we receive a piece from a peer fully before
requesting another piece from them because we are following the strict priority policy.
Choking Strategy: Each time that we receive a block of a piece from a peer, we record the
time. Once we have at least two blocks that a peer returns to us, we have a “download speed”,
or at least a proxy for it, by subtracting the two values. This is what we use to implement a top-4
and optimistic unchoking strategy, which is still not working entirely (which will be discussed in
the next section). Before the select call, we iterate through our peer list and select the top-4
peers that have the best download strategy and are interested in us and unchoke them.
However, we also create a candidate list of peers that are uploaders with better rates that are
not interested in us which we unchoke. We iterate through this candidate list and see whether a

peer has become interested in us, and if so, we transfer this peer to the top-4 list and remove
one of the top-4 peers. For the optimistic unchoking, we time ourselves for 30 seconds before
unchoking a random peer and replace the peer within the top-4 if it is interested and faster than
the slowest downloader.

Problems We Encountered
Some of the major problems that we encountered include:
● File Modification Mode from Seeder and Leecher, Bitfield Conversion, Download Speed

File Modification Mode from Seeder and Leecher: One frustrating problem that we ran into is
that when we had one of our clients act as a seeder while other instances of our client were
acting as leechers when hosting our own tracker, we noticed that the file that the leechers
downloaded was complete (as in all of the pieces were downloaded) but that the order of the
pieces were wrong. This was baffling for us because it was only happening sometimes and was
not consistent. After debugging, we figured out that this was occurring because of the mode that
our seeder and leechers were opening the file in: append mode. In append mode, the seek()
function will cease to work (because append assumes that you will always write at the end of
the file). This was also why sometimes the files were in order and sometimes it wasn’t –
because sometimes the pieces were written to the file in order since that’s the order they arrived
and sometimes they didn’t. We ended up solving this bug by using read and write mode (r+) in
order to seek, write, and read to the appropriate spot. We tried to use write and read mode (w+),
but realized that our file would be empty everytime we opened it for writing (deleting the
contents of the entire file and with it, any pieces we had written to it before), so we scrapped it.
Bitfield Conversion: In our code, instead of converting the bitfield into numbers every single
time we want to use it, we convert the bitfield into a list of numbers when we initially receive it
from a peer and then update the last every single time we receive a have message from a peer.
However, we also needed to add in a function that converted a list of pieces that we had into a
bitfield, because we need to send our own bitfield message whenever we connect to a new peer
or a new peer initiates a handshake with us. Although this bug seems trivial looking back, we
were not counting the number of bytes properly within the bitfield (and adding the appropriate
number of padded zeros) within these functions, which caused us a lot of headache when trying
to retrieve the debian file, as the bitfields that we were receiving from other peers were
completely wrong when we converted them into a list of numbers. We fixed this issue by just
tracing through out code and removing a while loop that was buggy.
Download Speed: Our flatland file was able to be downloaded within a minute (probably
because it had only 7 pieces) while the debian file took us approximately 20-30 minutes. We
initially blamed this on the swarm. We thought that because we were not uploading to anyone,
because there was not a single peer that was interested in us, that we were receiving the worst

upload rate possible. However, after conversations with Bobby on piazza, we noticed that our
poor download speed was due to the fact that we were not holding onto the maximum amount
of peer connections possible and requesting a piece from each of these peers. We modified our
code to go back to the tracker to get more peers until we had the maximum amount and just like
that, we were able to reduce our speed to approximately 1-2 minutes.

Known Bugs/Issues
Some known bugs/issues that still exist in our implementation include:
● Debian File Last Piece Download, Broken Pipe Error
Debian File Last Piece Download: While testing the torrenting capabilities of our BitTorrent
Client with the debian torrent files, a recurring issue is that when our client requests the last
piece from a peer, that peer sends back in response, a block of the correct length in null bytes
(\x00). This in turn leads to our hash being computed incorrectly and thus us not writing it to the
file and re-requesting it from another different peer. The interesting thing to note, is that when
we send a re-request to a separate peer, that peer also sends back in response, a block of the
correct length in null bytes. Currently, our code is able to overcome this issue by asking multiple
peers until one eventually returns the correct value for the last piece, however, this
implementation is not ideal and we would like to request for the last piece just as we would for
any other piece and have the whole file downloaded.
Broken Pipe Error: This bug goes hand-in-hand with the previous bug about downloading the
last piece from the debian files. Essentially, when we request the last piece up front, we are able
to receive it and write it to the file, but now, whenever the last piece needed to complete the file
arrives (by last piece here, we mean the finishing piece of the “puzzle”, not exactly the piece
with the last index), we always end up with a broken pipe error. We do not understand why this
occurs because we always go back to the tracker to ask for more peers in case any of our
current peers leave. We tried to fix this bug by catching the Broken Pipe Error and moving onto
the next peer in order to request the piece, however, we end up in an infinite loop, so it appears
that all of the peers that we have connected to have just decided to close the socket just as we
are about to receive the last piece needed to finish downloading the file. This is still an active
bug.
In addition, we still have a bug within our top-4 and optimistic unchoking strategy, but we do not
have enough time to fix it right now. Essentially, we are able to unchoke four of the peers when
we run multiple instances of our client, but we are unsure whether our optimistic unchoking is
changing this up every 30 seconds (as it should unchoke randomly), which we do not observe.
We also have several features that we have decided to scrap since we do not have enough time
to go through testing these features thoroughly and integrating them into our main
implementation. These features include endgame mode and the rarest first piece selection
strategy.

Member Contributions
The implementation of the tracker was done by Saar, including the extra credit UDP tracker.
This included connecting to the HTTP tracking, getting the list of peers, connecting to each of
the peers, implementing timeouts for connecting to the peers (because a lot of peers did not
want to talk to our bittorrent client), replenishing the peer list, going back to the tracker to get
more peers in order to have the maximum number of connections to download the debian
torrent file quickly, etc. In addition, Saar also implemented the extra credit end game mode,
however it was never integrated into our working bittorrent client due to time constraints.
The peer implementation was done by Sadia. This included all of the messages that the client
would send to its peers as well as receiving all of the messages that the peer sent the client,
implementing the random piece selection strategy, the rarest first piece selection strategy (which
unfortunately is not included in the final bittorrent client because we were never able to integrate
the rarest piece strategy completely without an bugs), comparing the bitfields between the peers
and the client, adding to the bitfields, determining which peers the client had already requested
pieces from, and which peers the client could request pieces from next.
The file system component implementation was done by Jonathan. This included reading from
the file, writing to the file (after seeking the correct offset), checking the hash of the piece as the
entire piece came in from the peer, and setting up a dictionary that would store the blocks of a
piece as they came in.
Annie was in charge of the connection management component. She handled sending keep
alive messages to all of the peers that the client was connected to, implemented top-4 and
optimistic unchoking (both of which are working, but have some bugs within it), validating the
peer list in case any peers stopped responding to us or closed their sockets, and receiving the
handshake from another instance of our client that wanted to connect to our main seeder client.
The above only details the individual implementations of the code. However, we also also
worked in pair programming teams to combine and integrate our code together. Sadia and
Jonathan worked together to integrate the peer and the file system component and were able to
successfully download the flatland torrent. Afterwards, Jonathan and Annie worked as a pair to
successfully upload the file to only one other instance of our client. We realized that we needed
to test the uploading to other instances of our client in a more methodological manner, so Saar
downloaded a Tracker implementation, created a torrent file for it with Jonathan, and was able
to host multiple instances of our client as seeders and one instance of our client as a leecher
and upload to all of our clients.
We then tried to move onto downloading the debian torrent file and integrate all of the extra
credit into our bittorrent client with all four or working on debugging separate parts of it together.
First, Jonathan and Saar found the bug that caused the pieces to be written out of order on the

file that they fixed together. Sadia and Annie tried to determine why the top-4 and optimistic
unchoking strategies were not unchoking the proper peers consistently, which unfortunately,
was not able to be fixed by the time of the project deadline. In addition, Sadia and Jonathan
worked on attempting to get the rarest first piece selection strategy to work, however a bug was
left in the strategy.
The most significant amount of time was spent on debugging the debian file, specifically, why
the last piece’s hash was incorrect and why it was not being written to the file properly. All four
members worked on this problem and debugged it together. Overall, all four members
contributed to the bittorrent client equally.and Saar) for which that was the most comfortable language while the other two people decided
to learn the language first before starting the project (Annie and Jonathan, props to them!). This
was only possible for us because they decided to learn python during Thanksgiving break. The
python libraries that we imported within our project include the following:

● socket, time, select, sys, os, re, io, os.path, struct, codecs, bencode, Hashlib, math, urllib.parse, argparse, random, datetime, collections

Tracker.py: We decided to implement our Tracker as a separate class in python for
organization purposes (it helps so that the main file is not cluttered). The Tracker class has the
necessary methods to read from the .torrent file provided, and has methods and attributes that
help us with provide values for that are extremely important for our bittorrent client, such as the
maximum number of pieces, the size of the file that we are supposed to download in bytes, the
length of each piece, etc. We create an instance of the Tracker when we first execute our
bittorrent client and just call all of these methods and attributes as needed.
Peer.py: The Peer was also implemented as a separate class in python, also for organization
purposes. Essentially, each peer that our client connected to was assigned a new Peer
instance. This instance would be responsible for keeping state for the Peer, such as the id
number for the peer, the pieces that they currently have, the download rate, whether or not any
pieces were already requested from them, etc. In addition, the Peer class has all of the methods
that our bittorrent client can call to send any message they want to the peer. This is only
possible because we made the Peer objects keep state on the socket that they are currently
connected to.

mult_peers_test/bittorrent_client.py: This is our main bittorrent client file. We had another file
that is in the root repository named bittorrent_client.py, however, after testing with multiple
clients using our own tracker, we decided to move it into this mult_peers_test directory. This
main file is organized similarly to our previous projects in this class. We have one main function
that starts us off where we call the tracker, get the list of peers, and then connect to all of the
peers that we are able to. Then, we hop into an infinite while loop where we have a select call in
order to wait for messages from our peers. We also bind our own client to a socket and put this
socker within our select call as well to make sure that when we become a seeder, we can start
uploading to other peers when they initiate a handshake from us and request a piece from us.
Before we enter the select call however, there are a few things that we do. We first check
whether we have finished downloading the entire file, the setup for our top-4 and optimistic
unchoking strategy, calls to functions that requests pieces for our client when we have received
bitfields from our peers, a call to a function that removes any state that we have held on any
currently requested pieces if those pieces do not arrive by a specified time, and a call to function
that validates the current peer list (if they have not closed their sockets on us and if they are
sending keep-alive messages) that also replenishes the peer list by going back to the tracker to
get more if the peer list dips below a threshold value. Only after all of this is taken care of do we
enter the select call.

After we enter the select call, we simply wait for a socket to be ready for reading. When a socket
is ready, we first check whether it is our own socket and if so, we receive a handshake, send a
handshake back, and send our own bitfield before storing the peer’s socket into our next select
call. For all other sockets, we first check whether the peers closed the socket on us, and then
proceed to check which message the peer had sent. There’s nothing much interesting
afterwards, as we simply handle each message accordingly (if they unchoke we simply change
the client state and wait for our piece selection algorithm to request a piece from them in the
next iteration of the while loop, if they are interested in us we run our top-4/optimistic unchoking
strategy to check whether or not we want to unchoke them, etc.)
The connection management and file system components are all within this main bittorrent
client file, as this file has the select call, keep alive messages, handshaking, reading and writing
to the file, hash checking, etc. all inside of it as different functions.
A few important implementation details that we think we would design differently next time would
actually be to move the file system component out of the main file, because it caused a lot of
clutter. In addition, we were heavily reliant on global variables within our bittorrent client, we
declared a total of 19 of them, which is probably well above the standard amount when it comes
to coding best practices. This is actually why we decided to keep the file system component
within the main file, because many of its functions needed access to global variables. We tried
to figure out a method to just import all of the global variables to different files, but alas, it took
too long and took away time from meaningful progress and we decided to stuff everything within
a file.

Piece Selection Strategy: Our final bittorrent client implementation simply implemented the
random piece selection strategy. Essentially, before we block for our select call, we iterate
through each peer, comparing their bitfields with ours and check to see what pieces they have
that we do not have. We then iterate through these pieces and check whether or not the peer
has already been asked for a different piece that has not fully arrived yet OR if the piece was
already requested to a different client. If any of these are true, we don’t do anything and move
onto the next piece. If these are false, we check if the client is choking us and if so, we send an
interested message (in hopes that they will unchoke us by the time we come across a situation
where we have to request them for another piece). If they have already unchoked us, we
request them for the pieces. It’s crucial to us that we receive a piece from a peer fully before
requesting another piece from them because we are following the strict priority policy.
Choking Strategy: Each time that we receive a block of a piece from a peer, we record the
time. Once we have at least two blocks that a peer returns to us, we have a “download speed”,
or at least a proxy for it, by subtracting the two values. This is what we use to implement a top-4
and optimistic unchoking strategy, which is still not working entirely (which will be discussed in
the next section). Before the select call, we iterate through our peer list and select the top-4
peers that have the best download strategy and are interested in us and unchoke them.
However, we also create a candidate list of peers that are uploaders with better rates that are
not interested in us which we unchoke. We iterate through this candidate list and see whether a
peer has become interested in us, and if so, we transfer this peer to the top-4 list and remove
one of the top-4 peers. For the optimistic unchoking, we time ourselves for 30 seconds before
unchoking a random peer and replace the peer within the top-4 if it is interested and faster than
the slowest downloader.

Problems We Encountered
Some of the major problems that we encountered include:
● File Modification Mode from Seeder and Leecher, Bitfield Conversion, Download Speed
File Modification Mode from Seeder and Leecher: One frustrating problem that we ran into is
that when we had one of our clients act as a seeder while other instances of our client were
acting as leechers when hosting our own tracker, we noticed that the file that the leechers
downloaded was complete (as in all of the pieces were downloaded) but that the order of the
pieces were wrong. This was baffling for us because it was only happening sometimes and was
not consistent. After debugging, we figured out that this was occurring because of the mode that
our seeder and leechers were opening the file in: append mode. In append mode, the seek()
function will cease to work (because append assumes that you will always write at the end of
the file). This was also why sometimes the files were in order and sometimes it wasn’t –
because sometimes the pieces were written to the file in order since that’s the order they arrived
and sometimes they didn’t. We ended up solving this bug by using read and write mode (r+) in
order to seek, write, and read to the appropriate spot. We tried to use write and read mode (w+),
but realized that our file would be empty everytime we opened it for writing (deleting the
contents of the entire file and with it, any pieces we had written to it before), so we scrapped it.
Bitfield Conversion: In our code, instead of converting the bitfield into numbers every single
time we want to use it, we convert the bitfield into a list of numbers when we initially receive it
from a peer and then update the last every single time we receive a have message from a peer.
However, we also needed to add in a function that converted a list of pieces that we had into a
bitfield, because we need to send our own bitfield message whenever we connect to a new peer
or a new peer initiates a handshake with us. Although this bug seems trivial looking back, we
were not counting the number of bytes properly within the bitfield (and adding the appropriate
number of padded zeros) within these functions, which caused us a lot of headache when trying
to retrieve the debian file, as the bitfields that we were receiving from other peers were
completely wrong when we converted them into a list of numbers. We fixed this issue by just
tracing through out code and removing a while loop that was buggy.
Download Speed: Our flatland file was able to be downloaded within a minute (probably
because it had only 7 pieces) while the debian file took us approximately 20-30 minutes. We
initially blamed this on the swarm. We thought that because we were not uploading to anyone,
because there was not a single peer that was interested in us, that we were receiving the worst
upload rate possible. However, after conversations with Bobby on piazza, we noticed that our
poor download speed was due to the fact that we were not holding onto the maximum amount
of peer connections possible and requesting a piece from each of these peers. We modified our
code to go back to the tracker to get more peers until we had the maximum amount and just like
that, we were able to reduce our speed to approximately 1-2 minutes.

Known Bugs/Issues
Some known bugs/issues that still exist in our implementation include:
● Debian File Last Piece Download, Broken Pipe Error
Debian File Last Piece Download: While testing the torrenting capabilities of our BitTorrent
Client with the debian torrent files, a recurring issue is that when our client requests the last
piece from a peer, that peer sends back in response, a block of the correct length in null bytes
(\x00). This in turn leads to our hash being computed incorrectly and thus us not writing it to the
file and re-requesting it from another different peer. The interesting thing to note, is that when
we send a re-request to a separate peer, that peer also sends back in response, a block of the
correct length in null bytes. Currently, our code is able to overcome this issue by asking multiple
peers until one eventually returns the correct value for the last piece, however, this
implementation is not ideal and we would like to request for the last piece just as we would for
any other piece and have the whole file downloaded.
Broken Pipe Error: This bug goes hand-in-hand with the previous bug about downloading the
last piece from the debian files. Essentially, when we request the last piece up front, we are able
to receive it and write it to the file, but now, whenever the last piece needed to complete the file
arrives (by last piece here, we mean the finishing piece of the “puzzle”, not exactly the piece
with the last index), we always end up with a broken pipe error. We do not understand why this
occurs because we always go back to the tracker to ask for more peers in case any of our
current peers leave. We tried to fix this bug by catching the Broken Pipe Error and moving onto
the next peer in order to request the piece, however, we end up in an infinite loop, so it appears
that all of the peers that we have connected to have just decided to close the socket just as we
are about to receive the last piece needed to finish downloading the file. This is still an active
bug.
In addition, we still have a bug within our top-4 and optimistic unchoking strategy, but we do not
have enough time to fix it right now. Essentially, we are able to unchoke four of the peers when
we run multiple instances of our client, but we are unsure whether our optimistic unchoking is
changing this up every 30 seconds (as it should unchoke randomly), which we do not observe.
We also have several features that we have decided to scrap since we do not have enough time
to go through testing these features thoroughly and integrating them into our main
implementation. These features include endgame mode and the rarest first piece selection
strategy.

Member Contributions
The implementation of the tracker was done by Saar, including the extra credit UDP tracker.
This included connecting to the HTTP tracking, getting the list of peers, connecting to each of
the peers, implementing timeouts for connecting to the peers (because a lot of peers did not
want to talk to our bittorrent client), replenishing the peer list, going back to the tracker to get
more peers in order to have the maximum number of connections to download the debian
torrent file quickly, etc. In addition, Saar also implemented the extra credit end game mode,
however it was never integrated into our working bittorrent client due to time constraints.
The peer implementation was done by Sadia. This included all of the messages that the client
would send to its peers as well as receiving all of the messages that the peer sent the client,
implementing the random piece selection strategy, the rarest first piece selection strategy (which
unfortunately is not included in the final bittorrent client because we were never able to integrate
the rarest piece strategy completely without an bugs), comparing the bitfields between the peers
and the client, adding to the bitfields, determining which peers the client had already requested
pieces from, and which peers the client could request pieces from next.
The file system component implementation was done by Jonathan. This included reading from
the file, writing to the file (after seeking the correct offset), checking the hash of the piece as the
entire piece came in from the peer, and setting up a dictionary that would store the blocks of a
piece as they came in.
Annie was in charge of the connection management component. She handled sending keep
alive messages to all of the peers that the client was connected to, implemented top-4 and
optimistic unchoking (both of which are working, but have some bugs within it), validating the
peer list in case any peers stopped responding to us or closed their sockets, and receiving the
handshake from another instance of our client that wanted to connect to our main seeder client.
The above only details the individual implementations of the code. However, we also also
worked in pair programming teams to combine and integrate our code together. Sadia and
Jonathan worked together to integrate the peer and the file system component and were able to
successfully download the flatland torrent. Afterwards, Jonathan and Annie worked as a pair to
successfully upload the file to only one other instance of our client. We realized that we needed
to test the uploading to other instances of our client in a more methodological manner, so Saar
downloaded a Tracker implementation, created a torrent file for it with Jonathan, and was able
to host multiple instances of our client as seeders and one instance of our client as a leecher
and upload to all of our clients.
We then tried to move onto downloading the debian torrent file and integrate all of the extra
credit into our bittorrent client with all four or working on debugging separate parts of it together.
First, Jonathan and Saar found the bug that caused the pieces to be written out of order on the

file that they fixed together. Sadia and Annie tried to determine why the top-4 and optimistic
unchoking strategies were not unchoking the proper peers consistently, which unfortunately,
was not able to be fixed by the time of the project deadline. In addition, Sadia and Jonathan
worked on attempting to get the rarest first piece selection strategy to work, however a bug was
left in the strategy.
The most significant amount of time was spent on debugging the debian file, specifically, why
the last piece’s hash was incorrect and why it was not being written to the file properly. All four
members worked on this problem and debugged it together. Overall, all four members
contributed to the bittorrent client equally.'
