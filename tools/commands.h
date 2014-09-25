/*
 * Copyright (C) 2001-2004 Sistina Software, Inc. All rights reserved.
 * Copyright (C) 2004-2013 Red Hat, Inc. All rights reserved.
 *
 * This file is part of LVM2.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU Lesser General Public License v.2.1.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

/***********  Replace with script?
xx(e2fsadm,
   "Resize logical volume and ext2 filesystem",
   "e2fsadm "
   "[-d|--debug] " "[-h|--help] " "[-n|--nofsck]" "\n"
   "\t{[-l|--extents] [+|-]LogicalExtentsNumber |" "\n"
   "\t [-L|--size] [+|-]LogicalVolumeSize[bBsSkKmMgGtTpPeE]}" "\n"
   "\t[-t|--test] "  "\n"
   "\t[-v|--verbose] "  "\n"
   "\t[--version] " "\n"
   "\tLogicalVolumePath" "\n",

    extents_ARG, size_ARG, nofsck_ARG, test_ARG)
*********/

xx(devtypes,
   "Display recognised built-in block device types",
   PERMITTED_READ_ONLY,
   "devtypes" "\n"
   "\t[--aligned]\n"
   "\t[-d|--debug]\n"
   "\t[-h|--help]\n"
   "\t[--nameprefixes]\n"
   "\t[--noheadings]\n"
   "\t[--nosuffix]\n"
   "\t[-o|--options [+]Field[,Field]]\n"
   "\t[-O|--sort [+|-]key1[,[+|-]key2[,...]]]\n"
   "\t[--rows]\n"
   "\t[--separator Separator]\n"
   "\t[--unbuffered]\n"
   "\t[--unquoted]\n"
   "\t[-v|--verbose]\n"
   "\t[--version]" "\n",

   aligned_ARG, nameprefixes_ARG,
   noheadings_ARG, nosuffix_ARG, options_ARG,
   rows_ARG, separator_ARG, sort_ARG,
   unbuffered_ARG, unquoted_ARG)

xx(dumpconfig,
   "Dump configuration",
   PERMITTED_READ_ONLY,
   "dumpconfig\n"
   "\t[-f|--file filename] \n"
   "\t[--type {current|default|diff|missing|new|profilable} \n"
   "\t[--atversion version]] \n"
   "\t[--ignoreadvanced] \n"
   "\t[--ignoreunsupported] \n"
   "\t[--mergedconfig] \n"
   "\t[--validate]\n"
   "\t[--withcomments] \n"
   "\t[--withversions] \n"
   "\t[ConfigurationNode...]\n",
   atversion_ARG, configtype_ARG, file_ARG, ignoreadvanced_ARG,
   ignoreunsupported_ARG, mergedconfig_ARG, validate_ARG,
   withcomments_ARG, withversions_ARG)

xx(formats,
   "List available metadata formats",
   PERMITTED_READ_ONLY,
   "formats\n")

xx(help,
   "Display help for commands",
   PERMITTED_READ_ONLY,
   "help <command>" "\n")

/*********
xx(lvactivate,
   "Activate logical volume on given partition(s)",
   "lvactivate "
   "\t[-d|--debug]\n"
   "\t[-h|--help]\n"
   "\t[-v|--verbose]\n"
   "Logical Volume(s)\n")
***********/

xx(lvchange,
   "Change the attributes of logical volume(s)",
   CACHE_VGMETADATA | PERMITTED_READ_ONLY,
   "lvchange\n"
   "\t[-A|--autobackup y|n]\n"
   "\t[-a|--activate [a|e|l]{y|n}]\n"
   "\t[--addtag Tag]\n"
   "\t[--alloc AllocationPolicy]\n"
   "\t[-C|--contiguous y|n]\n"
   "\t[-d|--debug]\n"
   "\t[--deltag Tag]\n"
   "\t[--detachprofile]\n"
   "\t[-f|--force]\n"
   "\t[-h|--help]\n"
   "\t[--discards {ignore|nopassdown|passdown}]\n"
   "\t[--ignorelockingfailure]\n"
   "\t[--ignoremonitoring]\n"
   "\t[--ignoreskippedcluster]\n"
   "\t[-k|--setactivationskip {y|n}]\n"
   "\t[-K|--ignoreactivationskip] \n"
   "\t[--monitor {y|n}]\n"
   "\t[--poll {y|n}]\n"
   "\t[--noudevsync]\n"
   "\t[-M|--persistent y|n] [--major major] [--minor minor]\n"
   "\t[-P|--partial] " "\n"
   "\t[-p|--permission r|rw]\n"
   "\t[--profile ProfileName\n"
   "\t[--[raid]minrecoveryrate Rate]\n"
   "\t[--[raid]maxrecoveryrate Rate]\n"
   "\t[--[raid]syncaction {check|repair}\n"
   "\t[--[raid]writebehind IOCount]\n"
   "\t[--[raid]writemostly PhysicalVolume[:{t|n|y}]]\n"
   "\t[-r|--readahead ReadAheadSectors|auto|none]\n"
   "\t[--refresh]\n"
   "\t[--resync]\n"
   "\t[--sysinit]\n"
   "\t[-t|--test]\n"
   "\t[-v|--verbose]\n"
   "\t[--version]\n"
   "\t[-y|--yes]\n"
   "\t[-Z|--zero {y|n}]\n"
   "\tLogicalVolume[Path] [LogicalVolume[Path]...]\n",

   addtag_ARG, alloc_ARG, autobackup_ARG, activate_ARG, available_ARG,
   contiguous_ARG, deltag_ARG, discards_ARG, detachprofile_ARG, force_ARG,
   ignorelockingfailure_ARG, ignoremonitoring_ARG, ignoreactivationskip_ARG,
   ignoreskippedcluster_ARG,
   major_ARG, minor_ARG, monitor_ARG, minrecoveryrate_ARG, maxrecoveryrate_ARG,
   noudevsync_ARG, partial_ARG, permission_ARG, persistent_ARG, poll_ARG,
   profile_ARG, raidminrecoveryrate_ARG, raidmaxrecoveryrate_ARG,
   raidsyncaction_ARG, raidwritebehind_ARG, raidwritemostly_ARG, readahead_ARG,
   resync_ARG, refresh_ARG, setactivationskip_ARG, syncaction_ARG, sysinit_ARG,
   test_ARG, writebehind_ARG, writemostly_ARG, zero_ARG,
   lockgl_ARG, lockvg_ARG, locklv_ARG)

xx(lvconvert,
   "Change logical volume layout",
   0,
   "lvconvert "
   "[-m|--mirrors Mirrors [{--mirrorlog {disk|core|mirrored}|--corelog}]]\n"
   "\t[--type SegmentType]\n"
   "\t[--repair [--use-policies]]\n"
   "\t[--replace PhysicalVolume]\n"
   "\t[-R|--regionsize MirrorLogRegionSize]\n"
   "\t[--alloc AllocationPolicy]\n"
   "\t[-b|--background]\n"
   "\t[-d|--debug]\n"
   "\t[-f|--force]\n"
   "\t[-h|-?|--help]\n"
   "\t[-i|--interval seconds]\n"
   "\t[--stripes Stripes [-I|--stripesize StripeSize]]\n"
   "\t[--noudevsync]\n"
   "\t[-v|--verbose]\n"
   "\t[-y|--yes]\n"
   "\t[--version]" "\n"
   "\tLogicalVolume[Path] [PhysicalVolume[Path]...]\n\n"

   "lvconvert "
   "[--splitmirrors Images --trackchanges]\n"
   "[--splitmirrors Images --name SplitLogicalVolumeName]\n"
   "\tLogicalVolume[Path] [SplittablePhysicalVolume[Path]...]\n\n"

   "lvconvert "
   "--splitsnapshot\n"
   "\t[-d|--debug]\n"
   "\t[-h|-?|--help]\n"
   "\t[--noudevsync]\n"
   "\t[-v|--verbose]\n"
   "\t[--version]" "\n"
   "\tSnapshotLogicalVolume[Path]\n\n"
   
   "lvconvert "
   "[-s|--snapshot]\n"
   "\t[-c|--chunksize]\n"
   "\t[-d|--debug]\n"
   "\t[-h|-?|--help]\n"
   "\t[--noudevsync]\n"
   "\t[-v|--verbose]\n"
   "\t[-Z|--zero {y|n}]\n"
   "\t[--version]" "\n"
   "\tOriginalLogicalVolume[Path] SnapshotLogicalVolume[Path]\n\n"

   "lvconvert "
   "--merge\n"
   "\t[-b|--background]\n"
   "\t[-i|--interval seconds]\n"
   "\t[-d|--debug]\n"
   "\t[-h|-?|--help]\n"
   "\t[-v|--verbose]\n"
   "\tLogicalVolume[Path]\n\n"

   "lvconvert "
   "--thinpool ThinPoolLogicalVolume[Path]\n"
   "\t[--chunksize size]\n"
   "\t[--discards {ignore|nopassdown|passdown}]\n"
   "\t[--poolmetadata ThinMetadataLogicalVolume[Path] |\n"
   "\t [--poolmetadatasize size]\n"
   "\t [--poolmetadataspare {y|n}]\n"
   "\t [-r|--readahead ReadAheadSectors|auto|none]\n"
   "\t [--stripes Stripes [-I|--stripesize StripeSize]]]\n"
   "\t[-T|--thin ExternalLogicalVolume[Path]\n"
   "\t [--originname NewExternalOriginVolumeName]]\n"
   "\t[-Z|--zero {y|n}]\n"
   "\t[-d|--debug] [-h|-?|--help] [-v|--verbose]\n\n"

   "lvconvert "
   "--type cache-pool\n"
   "\t[--cachemode CacheMode]\n"
   "\t[--chunksize size]\n"
   "\t[--poolmetadata CacheMetadataLogicalVolume[Path] |\n"
   "\t [--poolmetadatasize size]\n"
   "\t [--poolmetadataspare {y|n}]]\n"
   "\tCacheDataLogicalVolume[Path]\n\n"

   "lvconvert "
   "--type cache\n"
   "\t--cachepool CachePoolLogicalVolume[Path]\n"
   "\tLogicalVolume[Path]\n\n",

   alloc_ARG, background_ARG, cachemode_ARG, cachepool_ARG, chunksize_ARG,
   corelog_ARG, discards_ARG, force_ARG, interval_ARG, merge_ARG, mirrorlog_ARG,
   mirrors_ARG, name_ARG, noudevsync_ARG, originname_ARG, poolmetadata_ARG,
   poolmetadatasize_ARG, poolmetadataspare_ARG, readahead_ARG, regionsize_ARG,
   repair_ARG, replace_ARG, snapshot_ARG, splitmirrors_ARG, splitsnapshot_ARG,
   stripes_long_ARG, stripesize_ARG, test_ARG, thin_ARG, thinpool_ARG,
   trackchanges_ARG, type_ARG, use_policies_ARG, zero_ARG,
   lockgl_ARG, lockvg_ARG, locklv_ARG)

xx(lvcreate,
   "Create a logical volume",
   0,
   "lvcreate " "\n"
   "\t[-A|--autobackup {y|n}]\n"
   "\t[-a|--activate [a|e|l]{y|n}]\n"
   "\t[--addtag Tag]\n"
   "\t[--alloc AllocationPolicy]\n"
   "\t[--cachemode CacheMode]\n"
   "\t[-C|--contiguous {y|n}]\n"
   "\t[-d|--debug]\n"
   "\t[-h|-?|--help]\n"
   "\t[--ignoremonitoring]\n"
   "\t[--monitor {y|n}]\n"
   "\t[-i|--stripes Stripes [-I|--stripesize StripeSize]]\n"
   "\t[-k|--setactivationskip {y|n}]\n"
   "\t[-K|--ignoreactivationskip] \n"
   "\t{-l|--extents LogicalExtentsNumber[%{VG|PVS|FREE}] |\n"
   "\t -L|--size LogicalVolumeSize[bBsSkKmMgGtTpPeE]}\n"
   "\t[-M|--persistent {y|n}] [--major major] [--minor minor]\n"
   "\t[-m|--mirrors Mirrors [--nosync] [{--mirrorlog {disk|core|mirrored}|--corelog}]]\n"
   "\t[-n|--name LogicalVolumeName]\n"
   "\t[--noudevsync]\n"
   "\t[-p|--permission {r|rw}]\n"
   "\t[--[raid]minrecoveryrate Rate]\n"
   "\t[--[raid]maxrecoveryrate Rate]\n"
   "\t[-r|--readahead ReadAheadSectors|auto|none]\n"
   "\t[-R|--regionsize MirrorLogRegionSize]\n"
   "\t[-T|--thin  [-c|--chunksize  ChunkSize]\n"
   "\t  [--discards {ignore|nopassdown|passdown}]\n"
   "\t  [--poolmetadatasize MetadataSize[bBsSkKmMgG]]]\n"
   "\t  [--poolmetadataspare {y|n}]\n"
   "\t[--thinpool ThinPoolLogicalVolume{Name|Path}]\n"
   "\t[-t|--test]\n"
   "\t[--type VolumeType]\n"
   "\t[-v|--verbose]\n"
   "\t[-W|--wipesignatures {y|n}]\n"
   "\t[-Z|--zero {y|n}]\n"
   "\t[--version]\n"
   "\tVolumeGroupName [PhysicalVolumePath...]\n\n"

   "lvcreate \n"
   "\t{ {-s|--snapshot} OriginalLogicalVolume[Path] |\n"
   "\t  [-s|--snapshot] VolumeGroupName[Path] -V|--virtualsize VirtualSize}\n"
   "\t  {-T|--thin} VolumeGroupName[Path][/PoolLogicalVolume] \n"
   "\t              -V|--virtualsize VirtualSize}\n"
   "\t[-c|--chunksize]\n"
   "\t[-A|--autobackup {y|n}]\n"
   "\t[--addtag Tag]\n"
   "\t[--alloc AllocationPolicy]\n"
   "\t[-C|--contiguous {y|n}]\n"
   "\t[-d|--debug]\n"
   "\t[--discards {ignore|nopassdown|passdown}]\n"
   "\t[-h|-?|--help]\n"
   "\t[--ignoremonitoring]\n"
   "\t[--monitor {y|n}]\n"
   "\t[-i|--stripes Stripes [-I|--stripesize StripeSize]]\n"
   "\t[-k|--setactivationskip {y|n}]\n"
   "\t[-K|--ignoreactivationskip] \n"
   "\t{-l|--extents LogicalExtentsNumber[%{VG|FREE|ORIGIN}] |\n"
   "\t -L|--size LogicalVolumeSize[bBsSkKmMgGtTpPeE]}\n"
   "\t[--poolmetadatasize MetadataVolumeSize[bBsSkKmMgG]]\n"
   "\t[-M|--persistent {y|n}] [--major major] [--minor minor]\n"
   "\t[-n|--name LogicalVolumeName]\n"
   "\t[--noudevsync]\n"
   "\t[-p|--permission {r|rw}]\n"
   "\t[-r|--readahead ReadAheadSectors|auto|none]\n"
   "\t[-t|--test]\n"
   "\t[--thinpool ThinPoolLogicalVolume[Path]]\n"
   "\t[-v|--verbose]\n"
   "\t[--version]\n"

   "\t[PhysicalVolumePath...]\n\n",

   addtag_ARG, alloc_ARG, autobackup_ARG, activate_ARG, available_ARG,
   cachemode_ARG, chunksize_ARG, contiguous_ARG, corelog_ARG, discards_ARG,
   extents_ARG, ignoreactivationskip_ARG, ignoremonitoring_ARG, major_ARG,
   minor_ARG, mirrorlog_ARG, mirrors_ARG, monitor_ARG, minrecoveryrate_ARG,
   maxrecoveryrate_ARG, name_ARG, nosync_ARG, noudevsync_ARG,
   permission_ARG, persistent_ARG, poolmetadatasize_ARG, poolmetadataspare_ARG,
   raidminrecoveryrate_ARG, raidmaxrecoveryrate_ARG, readahead_ARG,
   regionsize_ARG, setactivationskip_ARG, size_ARG, snapshot_ARG, stripes_ARG,
   stripesize_ARG, test_ARG, thin_ARG, thinpool_ARG,
   type_ARG, virtualoriginsize_ARG, virtualsize_ARG,
   wipesignatures_ARG, zero_ARG,
   lockgl_ARG, lockvg_ARG, locklv_ARG)

xx(lvdisplay,
   "Display information about a logical volume",
   PERMITTED_READ_ONLY | ENABLE_ALL_VGS | DLOCK_VG_SH,
   "lvdisplay\n"
   "\t[-a|--all]\n"
   "\t[-c|--colon]\n"
   "\t[-d|--debug]\n"
   "\t[-h|--help]\n"
   "\t[--ignorelockingfailure]\n"
   "\t[--ignoreskippedcluster]\n"
   "\t[-m|--maps]\n"
   "\t[--nosuffix]\n"
   "\t[-P|--partial] " "\n"
   "\t[--units hHbBsSkKmMgGtTpPeE]\n"
   "\t[-v|--verbose]\n"
   "\t[--version]" "\n"
   "\t[LogicalVolume[Path] [LogicalVolume[Path]...]]\n"
   "\n"
   "lvdisplay --columns|-C\n"
   "\t[--aligned]\n"
   "\t[-a|--all]\n"
   "\t[-d|--debug]\n"
   "\t[-h|--help]\n"
   "\t[--ignorelockingfailure]\n"
   "\t[--ignoreskippedcluster]\n"
   "\t[--noheadings]\n"
   "\t[--nosuffix]\n"
   "\t[-o|--options [+]Field[,Field]]\n"
   "\t[-O|--sort [+|-]key1[,[+|-]key2[,...]]]\n"
   "\t[-P|--partial] " "\n"
   "\t[--segments]\n"
   "\t[--separator Separator]\n"
   "\t[--unbuffered]\n"
   "\t[--units hHbBsSkKmMgGtTpPeE]\n"
   "\t[-v|--verbose]\n"
   "\t[--version]" "\n"
   "\t[LogicalVolume[Path] [LogicalVolume[Path]...]]\n",

    aligned_ARG, all_ARG, colon_ARG, columns_ARG, ignorelockingfailure_ARG, 
    ignoreskippedcluster_ARG, maps_ARG, noheadings_ARG, nosuffix_ARG,
    options_ARG, sort_ARG, partial_ARG, segments_ARG, separator_ARG,
    unbuffered_ARG, units_ARG,
    lockgl_ARG, lockvg_ARG, locklv_ARG)

xx(lvextend,
   "Add space to a logical volume",
   0,
   "lvextend\n"
   "\t[-A|--autobackup y|n]\n"
   "\t[--alloc AllocationPolicy]\n"
   "\t[-d|--debug]\n"
   "\t[-f|--force]\n"
   "\t[-h|--help]\n"
   "\t[-i|--stripes Stripes [-I|--stripesize StripeSize]]\n"
   "\t{-l|--extents [+]LogicalExtentsNumber[%{VG|LV|PVS|FREE|ORIGIN}] |\n"
   "\t -L|--size [+]LogicalVolumeSize[bBsSkKmMgGtTpPeE]}\n"
   "\t --poolmetadatasize [+]MetadataVolumeSize[bBsSkKmMgG]}\n"
   "\t[-m|--mirrors Mirrors]\n"
   "\t[--nosync]\n"
   "\t[--use-policies]\n"
   "\t[-n|--nofsck]\n"
   "\t[--noudevsync]\n"
   "\t[-r|--resizefs]\n"
   "\t[-t|--test]\n"
   "\t[--type VolumeType]\n"
   "\t[-v|--verbose]\n"
   "\t[--version]" "\n"
   "\tLogicalVolume[Path] [ PhysicalVolumePath... ]\n",

   alloc_ARG, autobackup_ARG, extents_ARG, force_ARG, mirrors_ARG,
   nofsck_ARG, nosync_ARG, noudevsync_ARG, poolmetadatasize_ARG,
   resizefs_ARG, size_ARG, stripes_ARG,
   stripesize_ARG, test_ARG, type_ARG, use_policies_ARG,
   lockgl_ARG, lockvg_ARG, locklv_ARG)

xx(lvmchange,
   "With the device mapper, this is obsolete and does nothing.",
   0,
   "lvmchange\n"
   "\t[-d|--debug]\n"
   "\t[-h|--help]\n"
   "\t[-R|--reset]\n"
   "\t[-v|--verbose]\n"
   "\t[--version]" "\n",

    reset_ARG)

xx(lvmdiskscan,
   "List devices that may be used as physical volumes",
   PERMITTED_READ_ONLY,
   "lvmdiskscan\n"
   "\t[-d|--debug]\n"
   "\t[-h|--help]\n"
   "\t[-l|--lvmpartition]\n"
   "\t[--version]" "\n",

   lvmpartition_ARG)

xx(lvmsadc,
   "Collect activity data",
   0,
   "lvmsadc\n"
   "\t[-d|--debug]\n"
   "\t[-h|--help]\n"
   "\t[-v|--verbose]\n"
   "\t[--version]" "\n"
   "\t[LogFilePath]\n" )

xx(lvmsar,
   "Create activity report",
   0,
   "lvmsar\n"
   "\t[-d|--debug]\n"
   "\t[-f|--full]\n"
   "\t[-h|--help]\n"
   "\t[-s|--stdin]\n"
   "\t[-v|--verbose]\n"
   "\t[--version]" "\n"
   "\tLogFilePath\n",

   full_ARG, stdin_ARG)

xx(lvreduce,
   "Reduce the size of a logical volume",
   0,
   "lvreduce\n"
   "\t[-A|--autobackup y|n]\n"
   "\t[-d|--debug]\n"
   "\t[-f|--force]\n"
   "\t[-h|--help]\n"
   "\t{-l|--extents [-]LogicalExtentsNumber[%{VG|LV|FREE|ORIGIN}] |\n"
   "\t -L|--size [-]LogicalVolumeSize[bBsSkKmMgGtTpPeE]}\n"
   "\t[-n|--nofsck]\n"
   "\t[--noudevsync]\n"
   "\t[-r|--resizefs]\n"
   "\t[-t|--test]\n"
   "\t[-v|--verbose]\n"
   "\t[--version]" "\n"
   "\t[-y|--yes]\n"
   "\tLogicalVolume[Path]\n",

   autobackup_ARG, force_ARG,  extents_ARG, nofsck_ARG, noudevsync_ARG,
   resizefs_ARG, size_ARG, test_ARG,
   lockgl_ARG, lockvg_ARG, locklv_ARG)

xx(lvremove,
   "Remove logical volume(s) from the system",
   0,
   "lvremove\n"
   "\t[-A|--autobackup y|n]\n"
   "\t[-d|--debug]\n"
   "\t[-f|--force]\n"
   "\t[-h|--help]\n"
   "\t[--noudevsync]\n"
   "\t[-t|--test]\n"
   "\t[-v|--verbose]\n"
   "\t[--version]" "\n"
   "\tLogicalVolume[Path] [LogicalVolume[Path]...]\n",

   autobackup_ARG, force_ARG, noudevsync_ARG, test_ARG,
   lockgl_ARG, lockvg_ARG, locklv_ARG)

xx(lvrename,
   "Rename a logical volume",
   0,
   "lvrename\n"
   "\t[-A|--autobackup {y|n}] " "\n"
   "\t[-d|--debug] " "\n"
   "\t[-h|-?|--help] " "\n"
   "\t[--noudevsync]\n"
   "\t[-t|--test] " "\n"
   "\t[-v|--verbose]" "\n"
   "\t[--version] " "\n"
   "\t{ OldLogicalVolumePath NewLogicalVolumePath |" "\n"
   "\t  VolumeGroupName OldLogicalVolumeName NewLogicalVolumeName }\n",

   autobackup_ARG, noudevsync_ARG, test_ARG,
   lockgl_ARG, lockvg_ARG, locklv_ARG)

xx(lvresize,
   "Resize a logical volume",
   0,
   "lvresize\n"
   "\t[-A|--autobackup y|n]\n"
   "\t[--alloc AllocationPolicy]\n"
   "\t[-d|--debug]\n"
   "\t[-f|--force]\n"
   "\t[-h|--help]\n"
   "\t[-i|--stripes Stripes [-I|--stripesize StripeSize]]\n"
   "\t{-l|--extents [+|-]LogicalExtentsNumber[%{VG|LV|PVS|FREE|ORIGIN}] |\n"
   "\t -L|--size [+|-]LogicalVolumeSize[bBsSkKmMgGtTpPeE]}\n"
   "\t --poolmetadatasize [+]MetadataVolumeSize[bBsSkKmMgG]}\n"
   "\t[-n|--nofsck]\n"
   "\t[--noudevsync]\n"
   "\t[-r|--resizefs]\n"
   "\t[-t|--test]\n"
   "\t[--type VolumeType]\n"
   "\t[-v|--verbose]\n"
   "\t[--version]" "\n"
   "\tLogicalVolume[Path] [ PhysicalVolumePath... ]\n",

   alloc_ARG, autobackup_ARG, extents_ARG, force_ARG, nofsck_ARG,
   noudevsync_ARG, resizefs_ARG, poolmetadatasize_ARG,
   size_ARG, stripes_ARG, stripesize_ARG,
   test_ARG, type_ARG,
   lockgl_ARG, lockvg_ARG, locklv_ARG)

xx(lvs,
   "Display information about logical volumes",
   PERMITTED_READ_ONLY | ENABLE_ALL_VGS | DLOCK_VG_SH,
   "lvs" "\n"
   "\t[-a|--all]\n"
   "\t[--aligned]\n"
   "\t[-d|--debug]\n"
   "\t[-h|--help]\n"
   "\t[--ignorelockingfailure]\n"
   "\t[--ignoreskippedcluster]\n"
   "\t[--nameprefixes]\n"
   "\t[--noheadings]\n"
   "\t[--nosuffix]\n"
   "\t[-o|--options [+]Field[,Field]]\n"
   "\t[-O|--sort [+|-]key1[,[+|-]key2[,...]]]\n"
   "\t[-P|--partial] " "\n"
   "\t[--rows]\n"
   "\t[--segments]\n"
   "\t[--separator Separator]\n"
   "\t[--trustcache]\n"
   "\t[--unbuffered]\n"
   "\t[--units hHbBsSkKmMgGtTpPeE]\n"
   "\t[--unquoted]\n"
   "\t[-v|--verbose]\n"
   "\t[--version]" "\n"
   "\t[LogicalVolume[Path] [LogicalVolume[Path]...]]\n",

   aligned_ARG, all_ARG, ignorelockingfailure_ARG, ignoreskippedcluster_ARG,
   nameprefixes_ARG,
   noheadings_ARG, nolocking_ARG, nosuffix_ARG, options_ARG, partial_ARG,
   rows_ARG, segments_ARG, separator_ARG, sort_ARG, trustcache_ARG,
   unbuffered_ARG, units_ARG, unquoted_ARG,
   lockgl_ARG, lockvg_ARG, locklv_ARG)

xx(lvscan,
   "List all logical volumes in all volume groups",
   PERMITTED_READ_ONLY | ENABLE_ALL_VGS | DLOCK_VG_SH,
   "lvscan " "\n"
   "\t[-a|--all]\n"
   "\t[-b|--blockdevice] " "\n"
   "\t[-d|--debug] " "\n"
   "\t[-h|-?|--help] " "\n"
   "\t[--ignorelockingfailure]\n"
   "\t[-P|--partial] " "\n"
   "\t[-v|--verbose] " "\n"
   "\t[--version]\n",

   all_ARG, blockdevice_ARG, ignorelockingfailure_ARG, partial_ARG,
   lockgl_ARG, lockvg_ARG, locklv_ARG)

xx(pvchange,
   "Change attributes of physical volume(s)",
   0,
   "pvchange\n"
   "\t[-a|--all]\n"
   "\t[-A|--autobackup y|n]\n"
   "\t[-d|--debug]\n"
   "\t[-f|--force]\n"
   "\t[-h|--help]\n"
   "\t[-t|--test]\n"
   "\t[-u|--uuid]\n"
   "\t[-x|--allocatable y|n]\n"
   "\t[--metadataignore y|n]\n"
   "\t[-v|--verbose]\n"
   "\t[--addtag Tag]\n"
   "\t[--deltag Tag]\n"
   "\t[--version]" "\n"
   "\t[PhysicalVolumePath...]\n",

   all_ARG, allocatable_ARG, allocation_ARG, autobackup_ARG, deltag_ARG,
   addtag_ARG, force_ARG, metadataignore_ARG, test_ARG, uuid_ARG,
   lockgl_ARG, lockvg_ARG, locklv_ARG)

xx(pvresize,
   "Resize physical volume(s)",
   0,
   "pvresize " "\n"
   "\t[-d|--debug]" "\n"
   "\t[-h|-?|--help] " "\n"
   "\t[--setphysicalvolumesize PhysicalVolumeSize[bBsSkKmMgGtTpPeE]" "\n"
   "\t[-t|--test] " "\n"
   "\t[-v|--verbose] " "\n"
   "\t[--version] " "\n"
   "\tPhysicalVolume [PhysicalVolume...]\n",

   physicalvolumesize_ARG, test_ARG,
   lockgl_ARG, lockvg_ARG, locklv_ARG)

xx(pvck,
   "Check the consistency of physical volume(s)",
   DLOCK_VG_SH,
   "pvck "
   "\t[-d|--debug]\n"
   "\t[-h|--help]\n"
   "\t[--labelsector sector] " "\n"
   "\t[-v|--verbose]\n"
   "\t[--version]" "\n"
   "\tPhysicalVolume [PhysicalVolume...]\n",

   labelsector_ARG)

xx(pvcreate,
   "Initialize physical volume(s) for use by LVM",
   0,
   "pvcreate " "\n"
   "\t[--norestorefile]\n"
   "\t[--restorefile file]\n"
   "\t[-d|--debug]" "\n"
   "\t[-f[f]|--force [--force]] " "\n"
   "\t[-h|-?|--help] " "\n"
   "\t[--labelsector sector] " "\n"
   "\t[-M|--metadatatype 1|2]" "\n"
   "\t[--pvmetadatacopies #copies]" "\n"
   "\t[--bootloaderareasize BootLoaderAreaSize[bBsSkKmMgGtTpPeE]]" "\n"
   "\t[--metadatasize MetadataSize[bBsSkKmMgGtTpPeE]]" "\n"
   "\t[--dataalignment Alignment[bBsSkKmMgGtTpPeE]]" "\n"
   "\t[--dataalignmentoffset AlignmentOffset[bBsSkKmMgGtTpPeE]]" "\n"
   "\t[--setphysicalvolumesize PhysicalVolumeSize[bBsSkKmMgGtTpPeE]" "\n"
   "\t[-t|--test] " "\n"
   "\t[-u|--uuid uuid] " "\n"
   "\t[-v|--verbose] " "\n"
   "\t[-y|--yes]" "\n"
   "\t[-Z|--zero {y|n}]\n"
   "\t[--version] " "\n"
   "\tPhysicalVolume [PhysicalVolume...]\n",

   dataalignment_ARG, dataalignmentoffset_ARG, bootloaderareasize_ARG,
   force_ARG, test_ARG, labelsector_ARG, metadatatype_ARG,
   metadatacopies_ARG, metadatasize_ARG, metadataignore_ARG,
   norestorefile_ARG, physicalvolumesize_ARG, pvmetadatacopies_ARG,
   restorefile_ARG, uuidstr_ARG, zero_ARG,
   lockgl_ARG, lockvg_ARG, locklv_ARG)

xx(pvdata,
   "Display the on-disk metadata for physical volume(s)",
   0,
   "pvdata " "\n"
   "\t[-a|--all] " "\n"
   "\t[-d|--debug] " "\n"
   "\t[-E|--physicalextent] " "\n"
   "\t[-h|-?|--help]" "\n"
   "\t[-L|--logicalvolume] " "\n"
   "\t[-P[P]|--physicalvolume [--physicalvolume]]" "\n"
   "\t[-U|--uuidlist] " "\n"
   "\t[-v[v]|--verbose [--verbose]] " "\n"
   "\t[-V|--volumegroup]" "\n"
   "\t[--version] " "\n"
   "\tPhysicalVolume [PhysicalVolume...]\n",

   all_ARG,  logicalextent_ARG, physicalextent_ARG,
   physicalvolume_ARG, uuidlist_ARG, volumegroup_ARG)

xx(pvdisplay,
   "Display various attributes of physical volume(s)",
   CACHE_VGMETADATA | PERMITTED_READ_ONLY | ENABLE_ALL_DEVS | DLOCK_VG_SH,
   "pvdisplay\n"
   "\t[-c|--colon]\n"
   "\t[-d|--debug]\n"
   "\t[-h|--help]\n"
   "\t[--ignorelockingfailure]\n"
   "\t[--ignoreskippedcluster]\n"
   "\t[-m|--maps]\n"
   "\t[--nosuffix]\n"
   "\t[-s|--short]\n"
   "\t[--units hHbBsSkKmMgGtTpPeE]\n"
   "\t[-v|--verbose]\n"
   "\t[--version]" "\n"
   "\t[PhysicalVolumePath [PhysicalVolumePath...]]\n"
   "\n"
   "pvdisplay --columns|-C\n"
   "\t[--aligned]\n"
   "\t[-a|--all]\n"
   "\t[-d|--debug]\n"
   "\t[-h|--help]\n"
   "\t[--ignorelockingfailure]\n"
   "\t[--ignoreskippedcluster]\n"
   "\t[--noheadings]\n"
   "\t[--nosuffix]\n"
   "\t[-o|--options [+]Field[,Field]]\n"
   "\t[-O|--sort [+|-]key1[,[+|-]key2[,...]]]\n"
   "\t[--separator Separator]\n"
   "\t[--unbuffered]\n"
   "\t[--units hHbBsSkKmMgGtTpPeE]\n"
   "\t[-v|--verbose]\n"
   "\t[--version]" "\n"
   "\t[PhysicalVolumePath [PhysicalVolumePath...]]\n",

   aligned_ARG, all_ARG, colon_ARG, columns_ARG, ignorelockingfailure_ARG,
   ignoreskippedcluster_ARG, maps_ARG, noheadings_ARG, nosuffix_ARG,
   options_ARG, separator_ARG, short_ARG, sort_ARG, unbuffered_ARG, units_ARG,
   lockgl_ARG, lockvg_ARG, locklv_ARG)

/*
 * pvmove needs ENABLE_ALL_VGS because it calls polldaemon which
 * calls process_each_vg to find work.
 */

xx(pvmove,
   "Move extents from one physical volume to another",
   ENABLE_ALL_VGS,
   "pvmove " "\n"
   "\t[--abort]\n"
   "\t[-A|--autobackup {y|n}]\n"
   "\t[--alloc AllocationPolicy]\n"
   "\t[-b|--background]\n"
   "\t[-d|--debug]\n "
   "\t[-h|-?|--help]\n"
   "\t[-i|--interval seconds]\n"
   "\t[--noudevsync]\n"
   "\t[-t|--test]\n "
   "\t[-v|--verbose]\n "
   "\t[--version]\n"
   "\t[{-n|--name} LogicalVolume]\n"
/* "\t[{-n|--name} LogicalVolume[:LogicalExtent[-LogicalExtent]...]]\n" */
   "\tSourcePhysicalVolume[:PhysicalExtent[-PhysicalExtent]...]}\n"
   "\t[DestinationPhysicalVolume[:PhysicalExtent[-PhysicalExtent]...]...]\n",

   abort_ARG, alloc_ARG, autobackup_ARG, background_ARG,
   interval_ARG, name_ARG, noudevsync_ARG, test_ARG,
   lockgl_ARG, lockvg_ARG, locklv_ARG)

xx(pvremove,
   "Remove LVM label(s) from physical volume(s)",
   0,
   "pvremove " "\n"
   "\t[-d|--debug]" "\n"
   "\t[-f[f]|--force [--force]] " "\n"
   "\t[-h|-?|--help] " "\n"
   "\t[-t|--test] " "\n"
   "\t[-v|--verbose] " "\n"
   "\t[--version] " "\n"
   "\t[-y|--yes]" "\n"
   "\tPhysicalVolume [PhysicalVolume...]\n",

   force_ARG, test_ARG,
   lockgl_ARG, lockvg_ARG, locklv_ARG)

xx(pvs,
   "Display information about physical volumes",
   CACHE_VGMETADATA | PERMITTED_READ_ONLY | ENABLE_ALL_VGS | ENABLE_ALL_DEVS | DLOCK_VG_SH,
   "pvs" "\n"
   "\t[-a|--all]\n"
   "\t[--aligned]\n"
   "\t[-d|--debug]" "\n"
   "\t[-h|-?|--help] " "\n"
   "\t[--ignorelockingfailure]\n"
   "\t[--ignoreskippedcluster]\n"
   "\t[--nameprefixes]\n"
   "\t[--noheadings]\n"
   "\t[--nosuffix]\n"
   "\t[-o|--options [+]Field[,Field]]\n"
   "\t[-O|--sort [+|-]key1[,[+|-]key2[,...]]]\n"
   "\t[-P|--partial] " "\n"
   "\t[--rows]\n"
   "\t[--segments]\n"
   "\t[--separator Separator]\n"
   "\t[--trustcache]\n"
   "\t[--unbuffered]\n"
   "\t[--units hHbBsSkKmMgGtTpPeE]\n"
   "\t[--unquoted]\n"
   "\t[-v|--verbose]\n"
   "\t[--version]\n"
   "\t[PhysicalVolume [PhysicalVolume...]]\n",

   aligned_ARG, all_ARG, ignorelockingfailure_ARG, ignoreskippedcluster_ARG,
   nameprefixes_ARG, noheadings_ARG, nolocking_ARG, nosuffix_ARG, options_ARG,
   partial_ARG, rows_ARG, segments_ARG, separator_ARG, sort_ARG,
   trustcache_ARG, unbuffered_ARG, units_ARG, unquoted_ARG,
   lockgl_ARG, lockvg_ARG, locklv_ARG)

xx(pvscan,
   "List all physical volumes",
   PERMITTED_READ_ONLY | DLOCK_VG_SH,
   "pvscan " "\n"
   "\t[-b|--background]\n"
   "\t[--cache [-a|--activate ay] [ DevicePath | --major major --minor minor]...]\n"
   "\t[-d|--debug] " "\n"
   "\t{-e|--exported | -n|--novolumegroup} " "\n"
   "\t[-h|-?|--help]" "\n"
   "\t[--ignorelockingfailure]\n"
   "\t[-P|--partial] " "\n"
   "\t[-s|--short] " "\n"
   "\t[-u|--uuid] " "\n"
   "\t[-v|--verbose] " "\n"
   "\t[--version]\n",

   activate_ARG, available_ARG, backgroundfork_ARG, cache_ARG,
   exported_ARG, ignorelockingfailure_ARG, major_ARG, minor_ARG,
   novolumegroup_ARG, partial_ARG, short_ARG, uuid_ARG,
   lockgl_ARG, lockvg_ARG, locklv_ARG)

xx(segtypes,
   "List available segment types",
   PERMITTED_READ_ONLY,
   "segtypes\n")

xx(tags,
   "List tags defined on this host",
   PERMITTED_READ_ONLY,
   "tags\n")

xx(vgcfgbackup,
   "Backup volume group configuration(s)",
   PERMITTED_READ_ONLY | ENABLE_ALL_VGS | DLOCK_VG_SH,
   "vgcfgbackup " "\n"
   "\t[-d|--debug] " "\n"
   "\t[-f|--file filename] " "\n"
   "\t[-h|-?|--help] " "\n"
   "\t[--ignorelockingfailure]\n"
   "\t[-P|--partial] " "\n"
   "\t[-v|--verbose]" "\n"
   "\t[--version] " "\n"
   "\t[VolumeGroupName...]\n",

   file_ARG, ignorelockingfailure_ARG, partial_ARG,
   lockgl_ARG, lockvg_ARG, locklv_ARG)

xx(vgcfgrestore,
   "Restore volume group configuration",
   0,
   "vgcfgrestore " "\n"
   "\t[-d|--debug] " "\n"
   "\t[-f|--file filename] " "\n"
   "\t[--force]\n"
   "\t[-l[l]|--list [--list]]" "\n"
   "\t[-M|--metadatatype 1|2]" "\n"
   "\t[-h|--help]" "\n"
   "\t[-t|--test] " "\n"
   "\t[-v|--verbose]" "\n"
   "\t[--version] " "\n"
   "\tVolumeGroupName",

   file_ARG, force_long_ARG, list_ARG, metadatatype_ARG, test_ARG,
   lockgl_ARG, lockvg_ARG, locklv_ARG)

xx(vgchange,
   "Change volume group attributes",
   CACHE_VGMETADATA | PERMITTED_READ_ONLY | ENABLE_ALL_VGS,
   "vgchange" "\n"
   "\t[-A|--autobackup {y|n}] " "\n"
   "\t[--alloc AllocationPolicy] " "\n"
   "\t[-P|--partial] " "\n"
   "\t[-d|--debug] " "\n"
   "\t[--detachprofile] " "\n"
   "\t[-h|--help] " "\n"
   "\t[--ignorelockingfailure]\n"
   "\t[--ignoremonitoring]\n"
   "\t[--ignoreskippedcluster]\n"
   "\t[-K|--ignoreactivationskip] \n"
   "\t[--monitor {y|n}]\n"
   "\t[--[vg]metadatacopies #copies] " "\n"
   "\t[--poll {y|n}]\n"
   "\t[--noudevsync]\n"
   "\t[--refresh]\n"
   "\t[--sysinit]\n"
   "\t[-t|--test]" "\n"
   "\t[-u|--uuid] " "\n"
   "\t[-v|--verbose] " "\n"
   "\t[--version]" "\n"
   "\t{-a|--activate [a|e|l]{y|n}  |" "\n"
   "\t -c|--clustered {y|n} |" "\n"
   "\t -x|--resizeable {y|n} |" "\n"
   "\t -l|--logicalvolume MaxLogicalVolumes |" "\n"
   "\t -p|--maxphysicalvolumes MaxPhysicalVolumes |" "\n"
   "\t -s|--physicalextentsize PhysicalExtentSize[bBsSkKmMgGtTpPeE] |" "\n"
   "\t[--profile ProfileName\n"
   "\t --addtag Tag |\n"
   "\t --deltag Tag}\n"
   "\t[VolumeGroupName...]\n",

   addtag_ARG, alloc_ARG, allocation_ARG, autobackup_ARG, activate_ARG,
   available_ARG, clustered_ARG, deltag_ARG, detachprofile_ARG,
   ignoreactivationskip_ARG, ignorelockingfailure_ARG, ignoremonitoring_ARG,
   ignoreskippedcluster_ARG,
   logicalvolume_ARG, maxphysicalvolumes_ARG, monitor_ARG, noudevsync_ARG,
   metadatacopies_ARG, vgmetadatacopies_ARG, partial_ARG, profile_ARG,
   physicalextentsize_ARG, poll_ARG, refresh_ARG, resizeable_ARG,
   resizable_ARG, sysinit_ARG, test_ARG, uuid_ARG, force_ARG,
   lockgl_ARG, lockvg_ARG, locklv_ARG, lockstop_ARG, locktype_ARG, systemid_ARG,
   lockstart_ARG, lockstartwait_ARG, lockstartauto_ARG, lockstartautowait_ARG)

xx(vgck,
   "Check the consistency of volume group(s)",
   ENABLE_ALL_VGS | DLOCK_VG_SH,
   "vgck "
   "\t[-d|--debug]\n"
   "\t[-h|--help]\n"
   "\t[-v|--verbose]\n"
   "\t[--version]" "\n"
   "\t[VolumeGroupName...]\n" )

xx(vgconvert,
   "Change volume group metadata format",
   0,
   "vgconvert  " "\n"
   "\t[-d|--debug]" "\n"
   "\t[-h|--help] " "\n"
   "\t[--labelsector sector] " "\n"
   "\t[-M|--metadatatype 1|2]" "\n"
   "\t[--pvmetadatacopies #copies]" "\n"
   "\t[--metadatasize MetadataSize[bBsSkKmMgGtTpPeE]]" "\n"
   "\t[--bootloaderareasize BootLoaderAreaSize[bBsSkKmMgGtTpPeE]]" "\n"
   "\t[-t|--test] " "\n"
   "\t[-v|--verbose] " "\n"
   "\t[--version] " "\n"
   "\tVolumeGroupName [VolumeGroupName...]\n",

   force_ARG, test_ARG, labelsector_ARG, bootloaderareasize_ARG,
   metadatatype_ARG, metadatacopies_ARG, pvmetadatacopies_ARG,
   metadatasize_ARG,
   lockgl_ARG, lockvg_ARG, locklv_ARG)

xx(vgcreate,
   "Create a volume group",
   0,
   "vgcreate" "\n"
   "\t[-A|--autobackup {y|n}] " "\n"
   "\t[--addtag Tag] " "\n"
   "\t[--alloc AllocationPolicy] " "\n"
   "\t[-c|--clustered {y|n}] " "\n"
   "\t[-d|--debug]" "\n"
   "\t[-h|--help]" "\n"
   "\t[-l|--maxlogicalvolumes MaxLogicalVolumes]" "\n"
   "\t[-M|--metadatatype 1|2] " "\n"
   "\t[--[vg]metadatacopies #copies] " "\n"
   "\t[-p|--maxphysicalvolumes MaxPhysicalVolumes] " "\n"
   "\t[-s|--physicalextentsize PhysicalExtentSize[bBsSkKmMgGtTpPeE]] " "\n"
   "\t[-t|--test] " "\n"
   "\t[-v|--verbose]" "\n"
   "\t[--version] " "\n"
   "\t[-y|--yes]" "\n"
   "\t[ PHYSICAL DEVICE OPTIONS ] " "\n"
   "\tVolumeGroupName PhysicalDevicePath [PhysicalDevicePath...]\n",

   addtag_ARG, alloc_ARG, autobackup_ARG, clustered_ARG, maxlogicalvolumes_ARG,
   maxphysicalvolumes_ARG, metadatatype_ARG, physicalextentsize_ARG, test_ARG,
   force_ARG, zero_ARG, labelsector_ARG, metadatasize_ARG,
   pvmetadatacopies_ARG, metadatacopies_ARG, vgmetadatacopies_ARG,
   dataalignment_ARG, dataalignmentoffset_ARG,
   lockgl_ARG, lockvg_ARG, locklv_ARG, locktype_ARG)

xx(vgdisplay,
   "Display volume group information",
   PERMITTED_READ_ONLY | ENABLE_ALL_VGS | DLOCK_VG_SH,
   "vgdisplay " "\n"
   "\t[-A|--activevolumegroups]" "\n"
   "\t[-c|--colon | -s|--short | -v|--verbose]" "\n"
   "\t[-d|--debug] " "\n"
   "\t[-h|--help] " "\n"
   "\t[--ignorelockingfailure]" "\n"
   "\t[--ignoreskippedcluster]\n"
   "\t[--nosuffix]\n"
   "\t[-P|--partial] " "\n"
   "\t[--units hHbBsSkKmMgGtTpPeE]\n"
   "\t[--version]" "\n"
   "\t[VolumeGroupName [VolumeGroupName...]]\n"
   "\n"
   "vgdisplay --columns|-C\n"
   "\t[--aligned]\n"
   "\t[-d|--debug] " "\n"
   "\t[-h|--help] " "\n"
   "\t[--ignorelockingfailure]" "\n"
   "\t[--ignoreskippedcluster]\n"
   "\t[--noheadings]\n"
   "\t[--nosuffix]\n"
   "\t[-o|--options [+]Field[,Field]]\n"
   "\t[-O|--sort [+|-]key1[,[+|-]key2[,...]]]\n"
   "\t[-P|--partial] " "\n"
   "\t[--separator Separator]\n"
   "\t[--unbuffered]\n"
   "\t[--units hHbBsSkKmMgGtTpPeE]\n"
   "\t[--verbose]" "\n"
   "\t[--version]" "\n"
   "\t[VolumeGroupName [VolumeGroupName...]]\n",

   activevolumegroups_ARG, aligned_ARG, colon_ARG, columns_ARG,
   ignorelockingfailure_ARG, ignoreskippedcluster_ARG, noheadings_ARG,
   nosuffix_ARG, options_ARG, partial_ARG, short_ARG, separator_ARG,
   sort_ARG, unbuffered_ARG, units_ARG,
   lockgl_ARG, lockvg_ARG, locklv_ARG)

xx(vgexport,
   "Unregister volume group(s) from the system",
   ENABLE_ALL_VGS | DLOCK_VG_SH,
   "vgexport " "\n"
   "\t[-a|--all] " "\n"
   "\t[-d|--debug] " "\n"
   "\t[-h|--help]" "\n"
   "\t[-v|--verbose] " "\n"
   "\t[--version] " "\n"
   "\tVolumeGroupName [VolumeGroupName...]\n",

   all_ARG, test_ARG,
   lockgl_ARG, lockvg_ARG, locklv_ARG)

xx(vgextend,
   "Add physical volumes to a volume group",
   0,
   "vgextend\n"
   "\t[-A|--autobackup y|n]\n"
   "\t[--restoremissing]\n"
   "\t[-d|--debug]\n"
   "\t[-f|--force]\n"
   "\t[-h|--help]\n"
   "\t[-t|--test]\n"
   "\t[-v|--verbose]\n"
   "\t[--version]" "\n"
   "\t[-y|--yes]\n"
   "\t[ PHYSICAL DEVICE OPTIONS ] " "\n"
   "\tVolumeGroupName PhysicalDevicePath [PhysicalDevicePath...]\n",

   autobackup_ARG, test_ARG,
   force_ARG, zero_ARG, labelsector_ARG, metadatatype_ARG,
   metadatasize_ARG, pvmetadatacopies_ARG, metadatacopies_ARG,
   metadataignore_ARG, dataalignment_ARG, dataalignmentoffset_ARG,
   restoremissing_ARG,
   lockgl_ARG, lockvg_ARG, locklv_ARG)

xx(vgimport,
   "Register exported volume group with system",
   0,
   "vgimport " "\n"
   "\t[-a|--all]\n"
   "\t[-d|--debug] " "\n"
   "\t[-f|--force] " "\n"
   "\t[-h|--help] " "\n"
   "\t[-t|--test] " "\n"
   "\t[-v|--verbose]" "\n"
   "\t[--version]" "\n"
   "\tVolumeGroupName..." "\n",

   all_ARG, force_ARG, test_ARG,
   lockgl_ARG, lockvg_ARG, locklv_ARG)

xx(vgmerge,
   "Merge volume groups",
   0,
   "vgmerge\n"
   "\t[-A|--autobackup y|n]\n"
   "\t[-d|--debug]\n"
   "\t[-h|--help]\n"
   "\t[-l|--list]\n"
   "\t[-t|--test]\n"
   "\t[-v|--verbose]\n"
   "\t[--version]" "\n"
   "\tDestinationVolumeGroupName SourceVolumeGroupName\n",

   autobackup_ARG, list_ARG, test_ARG,
   lockgl_ARG, lockvg_ARG, locklv_ARG)

xx(vgmknodes,
   "Create the special files for volume group devices in /dev",
   ENABLE_ALL_VGS,
   "vgmknodes\n"
   "\t[-d|--debug]\n"
   "\t[-h|--help]\n"
   "\t[--ignorelockingfailure]\n"
   "\t[--refresh]\n"
   "\t[-v|--verbose]\n"
   "\t[--version]" "\n"
   "\t[VolumeGroupName...]\n",

   ignorelockingfailure_ARG, refresh_ARG)

xx(vgreduce,
   "Remove physical volume(s) from a volume group",
   0,
   "vgreduce\n"
   "\t[-a|--all]\n"
   "\t[-A|--autobackup y|n]\n"
   "\t[-d|--debug]\n"
   "\t[-h|--help]\n"
   "\t[--mirrorsonly]\n"
   "\t[--removemissing]\n"
   "\t[-f|--force]\n"
   "\t[-t|--test]\n"
   "\t[-v|--verbose]\n"
   "\t[--version]" "\n"
   "\tVolumeGroupName\n"
   "\t[PhysicalVolumePath...]\n",

   all_ARG, autobackup_ARG, force_ARG, mirrorsonly_ARG, removemissing_ARG,
   test_ARG,
   lockgl_ARG, lockvg_ARG, locklv_ARG)

xx(vgremove,
   "Remove volume group(s)",
   0,
   "vgremove\n"
   "\t[-d|--debug]\n"
   "\t[-f|--force]\n"
   "\t[-h|--help]\n"
   "\t[--noudevsync]\n"
   "\t[-t|--test]\n"
   "\t[-v|--verbose]\n"
   "\t[--version]" "\n"
   "\tVolumeGroupName [VolumeGroupName...]\n",

   force_ARG, noudevsync_ARG, test_ARG,
   lockgl_ARG, lockvg_ARG, locklv_ARG)

xx(vgrename,
   "Rename a volume group",
   0,
   "vgrename\n"
   "\t[-A|--autobackup y|n]\n"
   "\t[-d|--debug]\n"
   "\t[-h|--help]\n"
   "\t[-t|--test]\n"
   "\t[-v|--verbose]\n"
   "\t[--version]" "\n"
   "\tOldVolumeGroupPath NewVolumeGroupPath |\n"
   "\tOldVolumeGroupName NewVolumeGroupName\n",

   autobackup_ARG, force_ARG, test_ARG,
   lockgl_ARG, lockvg_ARG, locklv_ARG)

xx(vgs,
   "Display information about volume groups",
   PERMITTED_READ_ONLY | ENABLE_ALL_VGS | DLOCK_VG_SH,
   "vgs" "\n"
   "\t[--aligned]\n"
   "\t[-a|--all]\n"
   "\t[-d|--debug]\n"
   "\t[-h|--help]\n"
   "\t[--ignorelockingfailure]\n"
   "\t[--ignoreskippedcluster]\n"
   "\t[--nameprefixes]\n"
   "\t[--noheadings]\n"
   "\t[--nosuffix]\n"
   "\t[-o|--options [+]Field[,Field]]\n"
   "\t[-O|--sort [+|-]key1[,[+|-]key2[,...]]]\n"
   "\t[-P|--partial] " "\n"
   "\t[--rows]\n"
   "\t[--separator Separator]\n"
   "\t[--trustcache]\n"
   "\t[--unbuffered]\n"
   "\t[--units hHbBsSkKmMgGtTpPeE]\n"
   "\t[--unquoted]\n"
   "\t[-v|--verbose]\n"
   "\t[--version]\n"
   "\t[VolumeGroupName [VolumeGroupName...]]\n",

   aligned_ARG, all_ARG, ignorelockingfailure_ARG, ignoreskippedcluster_ARG,
   nameprefixes_ARG,
   noheadings_ARG, nolocking_ARG, nosuffix_ARG, options_ARG, partial_ARG,
   rows_ARG, separator_ARG, sort_ARG, trustcache_ARG, unbuffered_ARG, units_ARG,
   unquoted_ARG,
   lockgl_ARG, lockvg_ARG, locklv_ARG)

xx(vgscan,
   "Search for all volume groups",
   PERMITTED_READ_ONLY | ENABLE_ALL_VGS | DLOCK_VG_SH,
   "vgscan "
   "\t[--cache]\n"
   "\t[-d|--debug]\n"
   "\t[-h|--help]\n"
   "\t[--ignorelockingfailure]\n"
   "\t[--mknodes]\n"
   "\t[-P|--partial] " "\n"
   "\t[-v|--verbose]\n"
   "\t[--version]" "\n",

   cache_ARG, ignorelockingfailure_ARG, mknodes_ARG, partial_ARG,
   lockgl_ARG, lockvg_ARG, locklv_ARG)

xx(vgsplit,
   "Move physical volumes into a new or existing volume group",
   0,
   "vgsplit " "\n"
   "\t[-A|--autobackup {y|n}] " "\n"
   "\t[--alloc AllocationPolicy] " "\n"
   "\t[-c|--clustered {y|n}] " "\n"
   "\t[-d|--debug] " "\n"
   "\t[-h|--help] " "\n"
   "\t[-l|--maxlogicalvolumes MaxLogicalVolumes]" "\n"
   "\t[-M|--metadatatype 1|2] " "\n"
   "\t[--[vg]metadatacopies #copies] " "\n"
   "\t[-n|--name LogicalVolumeName]\n"
   "\t[-p|--maxphysicalvolumes MaxPhysicalVolumes] " "\n"
   "\t[-t|--test] " "\n"
   "\t[-v|--verbose] " "\n"
   "\t[--version]" "\n"
   "\tSourceVolumeGroupName DestinationVolumeGroupName" "\n"
   "\t[PhysicalVolumePath...]\n",

   alloc_ARG, autobackup_ARG, clustered_ARG,
   maxlogicalvolumes_ARG, maxphysicalvolumes_ARG,
   metadatatype_ARG, vgmetadatacopies_ARG, name_ARG, test_ARG,
   lockgl_ARG, lockvg_ARG, locklv_ARG)

xx(version,
   "Display software and driver version information",
   PERMITTED_READ_ONLY,
   "version\n" )

