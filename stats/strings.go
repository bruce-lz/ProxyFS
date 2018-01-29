// Package stats provides a simple statsd client API.
package stats

// These variables are used to eliminate string allocation and manipulation when
// calling stats APIs. Some APIs take a pointer to a string, and these strings
// are what to use instead of building your strings on the fly.
//
// e.g. stats.IncrementOperations(&stats.FsMountOps)

// NOTE: If you change the name of any stat, check api_test.go to make sure
//       that a change there is not required as well.
var (
	FsBasenameValidateOps             = "proxyfs.fs.statName_validate.operations"
	FsFullpathValidateOps             = "proxyfs.fs.fullpath_validate.operations"
	FsVolumeValidateOps               = "proxyfs.fs.volume_validate.operations"
	FsValidateFixedLinkCountOps       = "proxyfs.fs.validate_fixed_link_count_operations"
	FsValidateDirectoryFailedOps      = "proxyfs.fs.validate_directory_failed_operations"
	FsValidateNonDirectoryFailedOps   = "proxyfs.fs.validate_non_directory_failed_operations"
	FsMountOps                        = "proxyfs.fs.mount.operations"
	FsRenameOps                       = "proxyfs.fs.rename.operations"
	FsStatvfsOps                      = "proxyfs.fs.statvfs.operations"
	FsPathLookupOps                   = "proxyfs.fs.path_lookup.operations"
	FsCreateOps                       = "proxyfs.fs.create.operations"
	FsFlushOps                        = "proxyfs.fs.flush.operations"
	FsGetstatOps                      = "proxyfs.fs.getstat.operations"
	FsIsdirOps                        = "proxyfs.fs.isdir.operations"
	FsIsfileOps                       = "proxyfs.fs.isfile.operations"
	FsIssymlinkOps                    = "proxyfs.fs.issymlink.operations"
	FsLinkOps                         = "proxyfs.fs.link.operations"
	FsLookupOps                       = "proxyfs.fs.lookup.operations"
	FsMkdirOps                        = "proxyfs.fs.mkdir.operations"
	FsReadOps                         = "proxyfs.fs.read.operations"
	FsMwDeleteOps                     = "proxyfs.fs.middleware_delete.operations"
	FsMwPostOps                       = "proxyfs.fs.middleware_post.operations"
	FsMwHeadResponseOps               = "proxyfs.fs.middleware_head_response.operations"
	FsMwPutCompleteOps                = "proxyfs.fs.middleware_put_complete.operations"
	FsMwGetAccountOps                 = "proxyfs.fs.middleware_get_account.operations"
	FsMwGetContainerOps               = "proxyfs.fs.middleware_get_container.operations"
	FsMwPutContainerOps               = "proxyfs.fs.middleware_put_container.operations"
	FsMwGetObjOps                     = "proxyfs.fs.middleware_get_object.operations"
	FsReaddirOps                      = "proxyfs.fs.readdir.operations"
	FsReaddirOneOps                   = "proxyfs.fs.one_readdir.operations"
	FsReaddirPlusOps                  = "proxyfs.fs.plus_readdir.operations"
	FsReaddirOnePlusOps               = "proxyfs.fs.plus_one_readdir.operations"
	FsSymlinkReadOps                  = "proxyfs.fs.symlink_read.operations"
	FsSetsizeOps                      = "proxyfs.fs.setsize.operations"
	FsSetstatOps                      = "proxyfs.fs.setstat.operations"
	FsSymlinkOps                      = "proxyfs.fs.symlink.operations"
	FsGetTypeOps                      = "proxyfs.fs.get_type.operations"
	FsUnlinkOps                       = "proxyfs.fs.unlink.operations"
	FsRmdirOps                        = "proxyfs.fs.rmdir.operations"
	FsWriteOps                        = "proxyfs.fs.write.operations"
	FsValidateOps                     = "proxyfs.fs.validate.operations"
	FsProvisionObjOps                 = "proxyfs.fs.provision_object.operations"
	FsAcctToVolumeOps                 = "proxyfs.fs.acct_to_volume.operations"
	FsVolumeToActivePeerOps           = "proxyfs.fs.volume_to_active_peer.operations"
	FsGetXattrOps                     = "proxyfs.fs.get_xattr.operations"
	FsListXattrOps                    = "proxyfs.fs.list_xattr.operations"
	FsRemoveXattrOps                  = "proxyfs.fs.remove_xattr.operations"
	FsSetXattrOps                     = "proxyfs.fs.set_xattr.operations"
	FsFlockOps                        = "proxyfs.fs.flock.operations"
	DirCreateOps                      = "proxyfs.inode.directory.create.operations"
	DirCreateSuccessOps               = "proxyfs.inode.directory.create.success.operations"
	DirLinkOps                        = "proxyfs.inode.directory.link.operations"
	DirLinkSuccessOps                 = "proxyfs.inode.directory.link.success.operations"
	DirUnlinkOps                      = "proxyfs.inode.directory.unlink.operations"
	DirUnlinkSuccessOps               = "proxyfs.inode.directory.unlink.success.operations"
	DirRenameOps                      = "proxyfs.inode.directory.rename.operations"
	DirRenameSuccessOps               = "proxyfs.inode.directory.rename.success.operations"
	DirLookupOps                      = "proxyfs.inode.directory.lookup.operations"
	DirReaddirOps                     = "proxyfs.inode.directory.readdir.operations"
	DirReadOps                        = "proxyfs.inode.directory.read.operations"
	DirReadEntries                    = "proxyfs.inode.directory.read.entries"
	DirReadBytes                      = "proxyfs.inode.directory.read.bytes"
	FileCreateOps                     = "proxyfs.inode.file.create.operations"
	FileCreateSuccessOps              = "proxyfs.inode.file.create.success.operations"
	FileWritebackHitOps               = "proxyfs.inode.file.writeback.hit.operations"
	FileWritebackMissOps              = "proxyfs.inode.file.writeback.miss.operations"
	FileReadcacheHitOps               = "proxyfs.inode.file.readcache.hit.operations"
	FileReadcacheMissOps              = "proxyfs.inode.file.readcache.miss.operations"
	FileReadOps                       = "proxyfs.inode.file.read.operations"
	FileReadOps4K                     = "proxyfs.inode.file.read.operations.size-up-to-4KB"
	FileReadOps8K                     = "proxyfs.inode.file.read.operations.size-4KB-to-8KB"
	FileReadOps16K                    = "proxyfs.inode.file.read.operations.size-8KB-to-16KB"
	FileReadOps32K                    = "proxyfs.inode.file.read.operations.size-16KB-to-32KB"
	FileReadOps64K                    = "proxyfs.inode.file.read.operations.size-32KB-to-64KB"
	FileReadOpsOver64K                = "proxyfs.inode.file.read.operations.size-over-64KB"
	FileReadBytes                     = "proxyfs.inode.file.read.bytes"
	FileReadplanOps                   = "proxyfs.inode.file.readplan.operations"
	FileReadplanOps4K                 = "proxyfs.inode.file.readplan.operations.size-up-to-4KB"
	FileReadplanOps8K                 = "proxyfs.inode.file.readplan.operations.size-4KB-to-8KB"
	FileReadplanOps16K                = "proxyfs.inode.file.readplan.operations.size-8KB-to-16KB"
	FileReadplanOps32K                = "proxyfs.inode.file.readplan.operations.size-16KB-to-32KB"
	FileReadplanOps64K                = "proxyfs.inode.file.readplan.operations.size-32KB-to-64KB"
	FileReadplanOpsOver64K            = "proxyfs.inode.file.readplan.operations.size-over-64KB"
	FileReadplanBytes                 = "proxyfs.inode.file.readplan.bytes"
	FileWriteOps                      = "proxyfs.inode.file.write.operations"
	FileWriteOps4K                    = "proxyfs.inode.file.write.operations.size-up-to-4KB"
	FileWriteOps8K                    = "proxyfs.inode.file.write.operations.size-4KB-to-8KB"
	FileWriteOps16K                   = "proxyfs.inode.file.write.operations.size-8KB-to-16KB"
	FileWriteOps32K                   = "proxyfs.inode.file.write.operations.size-16KB-to-32KB"
	FileWriteOps64K                   = "proxyfs.inode.file.write.operations.size-32KB-to-64KB"
	FileWriteOpsOver64K               = "proxyfs.inode.file.write.operations.size-over-64KB"
	FileWriteBytes                    = "proxyfs.inode.file.write.bytes"
	FileWriteAppended                 = "proxyfs.inode.file.write.appended"
	FileWriteOverwritten              = "proxyfs.inode.file.write.overwritten"
	FileWroteOps                      = "proxyfs.inode.file.wrote.operations"
	FileWroteOps4K                    = "proxyfs.inode.file.wrote.operations.size-up-to-4KB"
	FileWroteOps8K                    = "proxyfs.inode.file.wrote.operations.size-4KB-to-8KB"
	FileWroteOps16K                   = "proxyfs.inode.file.wrote.operations.size-8KB-to-16KB"
	FileWroteOps32K                   = "proxyfs.inode.file.wrote.operations.size-16KB-to-32KB"
	FileWroteOps64K                   = "proxyfs.inode.file.wrote.operations.size-32KB-to-64KB"
	FileWroteOpsOver64K               = "proxyfs.inode.file.wrote.operations.size-over-64KB"
	FileWroteBytes                    = "proxyfs.inode.file.wrote.bytes"
	DirSetsizeOps                     = "proxyfs.inode.directory.setsize.operations"
	FileFlushOps                      = "proxyfs.inode.file.flush.operations"
	LogSegCreateOps                   = "proxyfs.inode.file.log-segment.create.operations"
	GcLogSegDeleteOps                 = "proxyfs.inode.garbage-collection.log-segment.delete.operations"
	GcLogSegOps                       = "proxyfs.inode.garbage-collection.log-segment.operations"
	DirDestroyOps                     = "proxyfs.inode.directory.destroy.operations"
	FileDestroyOps                    = "proxyfs.inode.file.destroy.operations"
	SymlinkDestroyOps                 = "proxyfs.inode.symlink.destroy.operations"
	InodeGetMetadataOps               = "proxyfs.inode.get_metadata.operations"
	InodeGetTypeOps                   = "proxyfs.inode.get_type.operations"
	SymlinkCreateOps                  = "proxyfs.inode.symlink.create.operations"
	SymlinkReadOps                    = "proxyfs.inode.symlink.read.operations"
	JrpcfsIoWriteOps                  = "proxyfs.jrpcfs.write.operations"
	JrpcfsIoWriteOps4K                = "proxyfs.jrpcfs.write.operations.size-up-to-4KB"
	JrpcfsIoWriteOps8K                = "proxyfs.jrpcfs.write.operations.size-4KB-to-8KB"
	JrpcfsIoWriteOps16K               = "proxyfs.jrpcfs.write.operations.size-8KB-to-16KB"
	JrpcfsIoWriteOps32K               = "proxyfs.jrpcfs.write.operations.size-16KB-to-32KB"
	JrpcfsIoWriteOps64K               = "proxyfs.jrpcfs.write.operations.size-32KB-to-64KB"
	JrpcfsIoWriteOpsOver64K           = "proxyfs.jrpcfs.write.operations.size-over-64KB"
	JrpcfsIoWriteBytes                = "proxyfs.jrpcfs.write.bytes"
	JrpcfsIoReadOps                   = "proxyfs.jrpcfs.read.operations"
	JrpcfsIoReadOps4K                 = "proxyfs.jrpcfs.read.operations.size-up-to-4KB"
	JrpcfsIoReadOps8K                 = "proxyfs.jrpcfs.read.operations.size-4KB-to-8KB"
	JrpcfsIoReadOps16K                = "proxyfs.jrpcfs.read.operations.size-8KB-to-16KB"
	JrpcfsIoReadOps32K                = "proxyfs.jrpcfs.read.operations.size-16KB-to-32KB"
	JrpcfsIoReadOps64K                = "proxyfs.jrpcfs.read.operations.size-32KB-to-64KB"
	JrpcfsIoReadOpsOver64K            = "proxyfs.jrpcfs.read.operations.size-over-64KB"
	JrpcfsIoReadBytes                 = "proxyfs.jrpcfs.read.bytes"
	SwiftAccountDeleteOps             = "proxyfs.swiftclient.account-delete"
	SwiftAccountGetOps                = "proxyfs.swiftclient.account-get"
	SwiftAccountHeadOps               = "proxyfs.swiftclient.account-head"
	SwiftAccountPostOps               = "proxyfs.swiftclient.account-post"
	SwiftAccountPutOps                = "proxyfs.swiftclient.account-put"
	SwiftContainerDeleteOps           = "proxyfs.swiftclient.container-delete"
	SwiftContainerGetOps              = "proxyfs.swiftclient.container-get"
	SwiftContainerHeadOps             = "proxyfs.swiftclient.container-head"
	SwiftContainerPostOps             = "proxyfs.swiftclient.container-post"
	SwiftContainerPutOps              = "proxyfs.swiftclient.container-put"
	SwiftObjContentLengthOps          = "proxyfs.swiftclient.object-content-length"
	SwiftObjCopyOps                   = "proxyfs.swiftclient.object-copy"
	SwiftObjDeleteOps                 = "proxyfs.swiftclient.object-delete"
	SwiftObjGetOps                    = "proxyfs.swiftclient.object-get.operations"
	SwiftObjGetOps4K                  = "proxyfs.swiftclient.object-get.operations.size-up-to-4KB"
	SwiftObjGetOps8K                  = "proxyfs.swiftclient.object-get.operations.size-4KB-to-8KB"
	SwiftObjGetOps16K                 = "proxyfs.swiftclient.object-get.operations.size-8KB-to-16KB"
	SwiftObjGetOps32K                 = "proxyfs.swiftclient.object-get.operations.size-16KB-to-32KB"
	SwiftObjGetOps64K                 = "proxyfs.swiftclient.object-get.operations.size-32KB-to-64KB"
	SwiftObjGetOpsOver64K             = "proxyfs.swiftclient.object-get.operations.size-over-64KB"
	SwiftObjGetBytes                  = "proxyfs.swiftclient.object-get.bytes"
	SwiftObjHeadOps                   = "proxyfs.swiftclient.object-head"
	SwiftObjLoadOps                   = "proxyfs.swiftclient.object-load.operations"
	SwiftObjLoadOps4K                 = "proxyfs.swiftclient.object-load.operations.size-up-to-4KB"
	SwiftObjLoadOps8K                 = "proxyfs.swiftclient.object-load.operations.size-4KB-to-8KB"
	SwiftObjLoadOps16K                = "proxyfs.swiftclient.object-load.operations.size-8KB-to-16KB"
	SwiftObjLoadOps32K                = "proxyfs.swiftclient.object-load.operations.size-16KB-to-32KB"
	SwiftObjLoadOps64K                = "proxyfs.swiftclient.object-load.operations.size-32KB-to-64KB"
	SwiftObjLoadOpsOver64K            = "proxyfs.swiftclient.object-load.operations.size-over-64KB"
	SwiftObjLoadBytes                 = "proxyfs.swiftclient.object-load.bytes"
	SwiftObjReadOps                   = "proxyfs.swiftclient.object-read.operations"
	SwiftObjReadOps4K                 = "proxyfs.swiftclient.object-read.operations.size-up-to-4KB"
	SwiftObjReadOps8K                 = "proxyfs.swiftclient.object-read.operations.size-4KB-to-8KB"
	SwiftObjReadOps16K                = "proxyfs.swiftclient.object-read.operations.size-8KB-to-16KB"
	SwiftObjReadOps32K                = "proxyfs.swiftclient.object-read.operations.size-16KB-to-32KB"
	SwiftObjReadOps64K                = "proxyfs.swiftclient.object-read.operations.size-32KB-to-64KB"
	SwiftObjReadOpsOver64K            = "proxyfs.swiftclient.object-read.operations.size-over-64KB"
	SwiftObjReadBytes                 = "proxyfs.swiftclient.object-read.bytes"
	SwiftObjTailOps                   = "proxyfs.swiftclient.object-tail.operations"
	SwiftObjTailBytes                 = "proxyfs.swiftclient.object-tail.bytes"
	SwiftObjPutCtxFetchOps            = "proxyfs.swiftclient.object-put-context.fetch.operations"
	SwiftObjPutCtxBytesPutOps         = "proxyfs.swiftclient.object-put-context.bytes-put.operations"
	SwiftObjPutCtxCloseOps            = "proxyfs.swiftclient.object-put-context.close.operations"
	SwiftObjPutCtxReadOps             = "proxyfs.swiftclient.object-put-context.read.operations"
	SwiftObjPutCtxReadOps4K           = "proxyfs.swiftclient.object-put-context.read.operations.size-up-to-4KB"
	SwiftObjPutCtxReadOps8K           = "proxyfs.swiftclient.object-put-context.read.operations.size-4KB-to-8KB"
	SwiftObjPutCtxReadOps16K          = "proxyfs.swiftclient.object-put-context.read.operations.size-8KB-to-16KB"
	SwiftObjPutCtxReadOps32K          = "proxyfs.swiftclient.object-put-context.read.operations.size-16KB-to-32KB"
	SwiftObjPutCtxReadOps64K          = "proxyfs.swiftclient.object-put-context.read.operations.size-32KB-to-64KB"
	SwiftObjPutCtxReadOpsOver64K      = "proxyfs.swiftclient.object-put-context.read.operations.size-over-64KB"
	SwiftObjPutCtxReadBytes           = "proxyfs.swiftclient.object-put-context.read.bytes"
	SwiftObjPutCtxRetryOps            = "proxyfs.swiftclient.object-put-context.retry.operations"
	SwiftObjPutCtxSendChunkOps        = "proxyfs.swiftclient.object-put-context.send-chunk.operations"
	SwiftObjPutCtxSendChunkOps4K      = "proxyfs.swiftclient.object-put-context.send-chunk.operations.size-up-to-4KB"
	SwiftObjPutCtxSendChunkOps8K      = "proxyfs.swiftclient.object-put-context.send-chunk.operations.size-4KB-to-8KB"
	SwiftObjPutCtxSendChunkOps16K     = "proxyfs.swiftclient.object-put-context.send-chunk.operations.size-8KB-to-16KB"
	SwiftObjPutCtxSendChunkOps32K     = "proxyfs.swiftclient.object-put-context.send-chunk.operations.size-16KB-to-32KB"
	SwiftObjPutCtxSendChunkOps64K     = "proxyfs.swiftclient.object-put-context.send-chunk.operations.size-32KB-to-64KB"
	SwiftObjPutCtxSendChunkOpsOver64K = "proxyfs.swiftclient.object-put-context.send-chunk.operations.size-over-64KB"
	SwiftObjPutCtxSendChunkBytes      = "proxyfs.swiftclient.object-put-context.send-chunk.bytes"
	SwiftChunkedConnsCreateOps        = "proxyfs.swiftclient.chunked-connections-create.operations"
	SwiftChunkedConnsReuseOps         = "proxyfs.swiftclient.chunked-connections-reuse.operations"
	SwiftNonchunkedConnsCreateOps     = "proxyfs.swiftclient.non-chunked-connections-create.operations"
	SwiftNonchunkedConnsReuseOps      = "proxyfs.swiftclient.non-chunked-connections-reuse.operations"
	SwiftChunkedStarvationCallbacks   = "proxyfs.swiftclient.chunked-connections-starved-callback.operations"

	SwiftAccountDeleteRetryOps        = "proxyfs.swiftclient.account-delete.retry.operations"         // failed operations that were retried (*not* number of retries)
	SwiftAccountDeleteRetrySuccessOps = "proxyfs.swiftclient.account-delete.retry.success.operations" // failed operations where retry fixed the problem
	SwiftAccountGetRetryOps           = "proxyfs.swiftclient.account-get.retry.operations"
	SwiftAccountGetRetrySuccessOps    = "proxyfs.swiftclient.account-get.retry.success.operations"
	SwiftAccountHeadRetryOps          = "proxyfs.swiftclient.account-head.retry.operations"
	SwiftAccountHeadRetrySuccessOps   = "proxyfs.swiftclient.account-head.retry.success.operations"
	SwiftAccountPostRetryOps          = "proxyfs.swiftclient.account-post.retry.operations"
	SwiftAccountPostRetrySuccessOps   = "proxyfs.swiftclient.account-post.retry.success.operations"
	SwiftAccountPutRetryOps           = "proxyfs.swiftclient.account-put.retry.operations"
	SwiftAccountPutRetrySuccessOps    = "proxyfs.swiftclient.account-put.retry.success.operations"

	SwiftContainerDeleteRetryOps        = "proxyfs.swiftclient.container-delete.retry.operations"
	SwiftContainerDeleteRetrySuccessOps = "proxyfs.swiftclient.container-delete.retry.success.operations"
	SwiftContainerGetRetryOps           = "proxyfs.swiftclient.container-get.retry.operations"
	SwiftContainerGetRetrySuccessOps    = "proxyfs.swiftclient.container-get.retry.success.operations"
	SwiftContainerHeadRetryOps          = "proxyfs.swiftclient.container-head.retry.operations"
	SwiftContainerHeadRetrySuccessOps   = "proxyfs.swiftclient.container-head.retry.success.operations"
	SwiftContainerPostRetryOps          = "proxyfs.swiftclient.container-post.retry.operations"
	SwiftContainerPostRetrySuccessOps   = "proxyfs.swiftclient.container-post.retry.success.operations"
	SwiftContainerPutRetryOps           = "proxyfs.swiftclient.container-put.retry.operations"
	SwiftContainerPutRetrySuccessOps    = "proxyfs.swiftclient.container-put.retry.success.operations"

	SwiftObjContentLengthRetryOps        = "proxyfs.swiftclient.object-content-length.retry.operations"         // failed content-length operations that were retried (*not* number of retries)
	SwiftObjContentLengthRetrySuccessOps = "proxyfs.swiftclient.object-content-length.retry.success.operations" // failed content-length operations where retry fixed the problem
	SwiftObjDeleteRetryOps               = "proxyfs.swiftclient.object-delete.retry.operations"
	SwiftObjDeleteRetrySuccessOps        = "proxyfs.swiftclient.object-delete.retry.success.operations"
	SwiftObjFetchPutCtxtRetryOps         = "proxyfs.swiftclient.object-fetch-put-ctxt.retry.operations"
	SwiftObjFetchPutCtxtRetrySuccessOps  = "proxyfs.swiftclient.object-fetch-put-ctxt.retry.success.operations"
	SwiftObjPutCtxtCloseRetryOps         = "proxyfs.swiftclient.object-put-ctxt-close.retry.operations"
	SwiftObjPutCtxtCloseRetrySuccessOps  = "proxyfs.swiftclient.object-put-ctxt-close.retry.success.operations"
	SwiftObjGetRetryOps                  = "proxyfs.swiftclient.object-get.retry.operations"
	SwiftObjGetRetrySuccessOps           = "proxyfs.swiftclient.object-get.retry.success.operations"
	SwiftObjHeadRetryOps                 = "proxyfs.swiftclient.object-head.retry.operations"
	SwiftObjHeadRetrySuccessOps          = "proxyfs.swiftclient.object-head.retry.success.operations"
	SwiftObjLoadRetryOps                 = "proxyfs.swiftclient.object-load.retry.operations"
	SwiftObjLoadRetrySuccessOps          = "proxyfs.swiftclient.object-load.retry.success.operations"
	SwiftObjReadRetryOps                 = "proxyfs.swiftclient.object-read.retry.operations"
	SwiftObjReadRetrySuccessOps          = "proxyfs.swiftclient.object-read.retry.success.operations"
	SwiftObjTailRetryOps                 = "proxyfs.swiftclient.object-tail.retry.operations"
	SwiftObjTailRetrySuccessOps          = "proxyfs.swiftclient.object-tail.retry.success.operations"
)
