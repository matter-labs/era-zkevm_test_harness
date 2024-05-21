# Kzg crate

This crate contains functions related to kzg commitment that is used for 4844 blobs.

There are 3 methods that are used by era from this crate:

* pubdata_to_blob_commitments - computes the blob commitments for given pub data
* KzgInfo - holds all the methods for converting bytes into blobs
* ZK_SYNC_BYTES_PER_BLOB - information on how much data is stored per blob.