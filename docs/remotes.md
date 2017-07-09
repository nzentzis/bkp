remotes and remote groups
-------------------------
Data in bkp is stored on one or more backup destinations, referred to as 
*remotes*. Remotes can be used as backup targets on their own, or grouped along
with other destinations into a *remote group* to provide redundancy. Note that a
remote can be used as both a backup target *and* as a member of a remote group
simultaneously.

The basic guarantee that bkp provides is as follows: if the remote or remote
group used as a backup destination for a given snapshot remains intact, then
that snapshot can be restored. If the remote configuration of the source machine
was lost in the meantime, it will have to be reconstructed before bkp can access
the remote and recover the backups stored there.

Further, since backups are encrypted, the user will have to enter the master
password in order to retrieve the bkp keystore from the remote. All remotes keep
an copy of the bkp keystore, encrypted with the master password. In the
unfortunate event that all hosts are lost, the backup keys can be recovered from
any remote.

remote groups
=============
Multiple remotes can be composed together for redundancy purposes into a *remote
group*. For backup, remote groups act just like a normal remote: you can store
snapshots to them, restore from them, and so on. However, the group layer
replicates the snapshots and data stored on the group to all its member remotes.
When restoring a snapshot, bkp may transfer data from multiple remotes
concurrently to speed up the restore operation.

One useful effect of this is that you can restore any snapshot stored on a
remote group from any of its member nodes. When doing a restore, any member node
of the remote group is equivalent to the group as a whole aside from the faster
transfers mentioned earlier. For example, imagine you back your system up to a
NAS, Amazon S3, and an external hard drive. If the NAS, HDD, and your system all
fail simultaneously, you can still recover your data by adding the S3 bucket as
a remote on another system and performing a restore from it.
