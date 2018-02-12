/*
 * Copyright (C) 2001-2004 Sistina Software, Inc. All rights reserved.
 * Copyright (C) 2004-2018 Red Hat, Inc. All rights reserved.
 *
 * This file is part of LVM2.
 *
 * This copyrighted material is made available to anyone wishing to use,
 * modify, copy, or redistribute it subject to the terms and conditions
 * of the GNU Lesser General Public License v.2.1.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include "lib.h"
#include "format-text.h"
#include "import-export.h"
#include "device.h"
#include "lvm-file.h"
#include "config.h"
#include "display.h"
#include "toolcontext.h"
#include "lvm-string.h"
#include "uuid.h"
#include "layout.h"
#include "crc.h"
#include "xlate.h"
#include "label.h"
#include "lvmcache.h"
#include "lvmetad.h"
#include "memlock.h"

#include <unistd.h>
#include <sys/param.h>
#include <limits.h>
#include <dirent.h>
#include <ctype.h>

/*
 * Round up offset within buffer to next location that is an exact multiple of alignment.
 * (We shouldn't assume the start of the metadata area was aligned the same way when it was created.)
 */
#define ALIGN_ABSOLUTE(offset, buffer_start, alignment) ((offset) + (alignment) - UINT64_C(1) - ((buffer_start) + (offset) + (alignment) - UINT64_C(1)) % (alignment))

static struct format_instance *_text_create_text_instance(const struct format_type *fmt,
							  const struct format_instance_ctx *fic);

struct text_fid_context {
	char *raw_metadata_buf;
	uint32_t raw_metadata_buf_size;
};

struct dir_list {
	struct dm_list list;
	char dir[0];
};

struct raw_list {
	struct dm_list list;
	struct device_area dev_area;
};

int rlocn_is_ignored(const struct raw_locn *rlocn)
{
	return (rlocn->flags & RAW_LOCN_IGNORED ? 1 : 0);
}

void rlocn_set_ignored(struct raw_locn *rlocn, unsigned mda_ignored)
{
	if (mda_ignored)
		rlocn->flags |= RAW_LOCN_IGNORED;
	else
		rlocn->flags &= ~RAW_LOCN_IGNORED;
}

/*
 * NOTE: Currently there can be only one vg per text file.
 */

/*
 * Only used by vgcreate.
 */
static int _text_vg_setup(struct format_instance *fid,
			  struct volume_group *vg)
{
	if (!vg_check_new_extent_size(vg->fid->fmt, vg->extent_size))
		return_0;

	return 1;
}

static uint64_t _mda_free_sectors_raw(struct metadata_area *mda)
{
	struct mda_context *mdac = (struct mda_context *) mda->metadata_locn;

	return mdac->free_sectors;
}

static uint64_t _mda_total_sectors_raw(struct metadata_area *mda)
{
	struct mda_context *mdac = (struct mda_context *) mda->metadata_locn;

	return mdac->area.size >> SECTOR_SHIFT;
}

/*
 * Check if metadata area belongs to vg
 */
static int _mda_in_vg_raw(struct format_instance *fid __attribute__((unused)),
			     struct volume_group *vg, struct metadata_area *mda)
{
	struct mda_context *mdac = (struct mda_context *) mda->metadata_locn;
	struct pv_list *pvl;

	dm_list_iterate_items(pvl, &vg->pvs)
		if (pvl->pv->dev == mdac->area.dev)
			return 1;

	return 0;
}

static unsigned _mda_locns_match_raw(struct metadata_area *mda1,
				     struct metadata_area *mda2)
{
	struct mda_context *mda1c = (struct mda_context *) mda1->metadata_locn;
	struct mda_context *mda2c = (struct mda_context *) mda2->metadata_locn;

	if ((mda1c->area.dev == mda2c->area.dev) &&
	    (mda1c->area.start == mda2c->area.start) &&
	    (mda1c->area.size == mda2c->area.size))
		return 1;

	return 0;
}

static struct device *_mda_get_device_raw(struct metadata_area *mda)
{
	struct mda_context *mdac = (struct mda_context *) mda->metadata_locn;
	return mdac->area.dev;
}

/*
 * For circular region between region_start and region_start + region_size,
 * back up one SECTOR_SIZE from 'region_ptr' and return the value.
 * This allows reverse traversal through text metadata area to find old
 * metadata.
 *
 * Parameters:
 *   region_start: start of the region (bytes)
 *   region_size: size of the region (bytes)
 *   region_ptr: pointer within the region (bytes)
 *   NOTE: region_start <= region_ptr <= region_start + region_size
 */
static uint64_t _get_prev_sector_circular(uint64_t region_start,
					  uint64_t region_size,
					  uint64_t region_ptr)
{
	if (region_ptr >= region_start + SECTOR_SIZE)
		return region_ptr - SECTOR_SIZE;

	return (region_start + region_size - SECTOR_SIZE);
}

/*
 * Analyze a metadata area for old metadata records in the circular buffer.
 * This function just looks through and makes a first pass at the data in
 * the sectors for particular things.
 * FIXME: do something with each metadata area (try to extract vg, write
 * raw data to file, etc)
 */
static int _pv_analyze_mda_raw (const struct format_type * fmt,
				struct metadata_area *mda)
{
	struct mda_header *mdah;
	struct raw_locn *rlocn;
	uint64_t area_start;
	uint64_t area_size;
	uint64_t prev_sector, prev_sector2;
	uint64_t latest_mrec_offset;
	uint64_t offset;
	uint64_t offset2;
	size_t size;
	size_t size2;
	const char *buf = NULL;
	struct device_area *area;
	struct mda_context *mdac;
	unsigned circular = 0;
	int r=0;

	mdac = (struct mda_context *) mda->metadata_locn;

	log_print("Found text metadata area: offset=" FMTu64 ", size="
		  FMTu64, mdac->area.start, mdac->area.size);
	area = &mdac->area;

	if (!dev_open_readonly(area->dev))
		return_0;

	if (!(mdah = raw_read_mda_header(fmt->cmd->mem, area, mda_is_primary(mda))))
		goto_out;

	rlocn = mdah->raw_locns;

	/*
	 * The device area includes the metadata header as well as the
	 * records, so remove the metadata header from the start and size
	 */
	area_start = area->start + MDA_HEADER_SIZE;
	area_size = area->size - MDA_HEADER_SIZE;
	latest_mrec_offset = rlocn->offset + area->start;

	/*
	 * Start searching at rlocn (point of live metadata) and go
	 * backwards.
	 */
	prev_sector = _get_prev_sector_circular(area_start, area_size,
					       latest_mrec_offset);
	offset = prev_sector;
	size = SECTOR_SIZE;
	offset2 = size2 = 0;

	while (prev_sector != latest_mrec_offset) {
		prev_sector2 = prev_sector;
		prev_sector = _get_prev_sector_circular(area_start, area_size,
							prev_sector);
		if (prev_sector > prev_sector2)
			goto_out;

		/*
		 * FIXME: for some reason, the whole metadata region from
		 * area->start to area->start+area->size is not used.
		 * Only ~32KB seems to contain valid metadata records
		 * (LVM2 format - format_text).  As a result, I end up with
		 * "dm_config_maybe_section" returning true when there's no valid
		 * metadata in a sector (sectors with all nulls).
		 */

		circular = size2 ? 1 : 0;

		if (circular) {
			if (!(buf = dev_read_circular(area->dev, offset, size, offset2, size2, MDA_CONTENT_REASON(mda_is_primary(mda)))))
				goto_out;
		} else if (!(buf = dev_read(area->dev, offset, size, MDA_CONTENT_REASON(mda_is_primary(mda)))))
			goto_out;

		/*
		 * FIXME: We could add more sophisticated metadata detection
		 */
		if (dm_config_maybe_section(buf, size + size2)) {
			/* FIXME: Validate region, pull out timestamp?, etc */
			/* FIXME: Do something with this region */
			log_verbose ("Found LVM2 metadata record at "
				     "offset=" FMTu64 ", size=" FMTsize_t ", "
				     "offset2=" FMTu64 " size2=" FMTsize_t,
				     offset, size, offset2, size2);
			offset = prev_sector;
			size = SECTOR_SIZE;
			offset2 = size2 = 0;
		} else {
			/*
			 * Not a complete metadata record, assume we have
			 * metadata and just increase the size and offset.
			 * Start the second region if the previous sector is
			 * wrapping around towards the end of the disk.
			 */
			if (prev_sector > offset) {
				offset2 = prev_sector;
				size2 += SECTOR_SIZE;
			} else {
				offset = prev_sector;
				size += SECTOR_SIZE;
			}
		}
		if (circular)
			dm_free((void *)buf);
		buf = NULL;
	}

	r = 1;
 out:
	if (circular)
		dm_free((void *)buf);
	if (!dev_close(area->dev))
		stack;
	return r;
}

static int _text_lv_setup(struct format_instance *fid __attribute__((unused)),
			  struct logical_volume *lv)
{
/******** FIXME Any LV size restriction?
	uint64_t max_size = UINT_MAX;

	if (lv->size > max_size) {
		char *dummy = display_size(max_size);
		log_error("logical volumes cannot be larger than %s", dummy);
		dm_free(dummy);
		return 0;
	}
*/

	if (!*lv->lvid.s && !lvid_create(&lv->lvid, &lv->vg->id)) {
		log_error("Random lvid creation failed for %s/%s.",
			  lv->vg->name, lv->name);
		return 0;
	}

	return 1;
}

static void _xlate_mdah(struct mda_header *mdah)
{
	struct raw_locn *rl;

	mdah->version = xlate32(mdah->version);
	mdah->start = xlate64(mdah->start);
	mdah->size = xlate64(mdah->size);

	rl = &mdah->raw_locns[0];
	while (rl->offset) {
		rl->checksum = xlate32(rl->checksum);
		rl->offset = xlate64(rl->offset);
		rl->size = xlate64(rl->size);
		rl++;
	}
}

struct process_raw_mda_header_params {
	struct mda_header *mdah;
	struct device_area dev_area;
	lvm_callback_fn_t mdah_callback_fn;
	void *mdah_callback_context;
	int ret;
};

static void _process_raw_mda_header(int failed, unsigned ioflags, void *context, const void *data)
{
	struct process_raw_mda_header_params *prmp = context;
	struct mda_header *mdah = prmp->mdah;
	struct device_area *dev_area = &prmp->dev_area;

	if (!dev_close(dev_area->dev))
		goto_bad;

	if (failed)
		goto_bad;

	memcpy(mdah, data, MDA_HEADER_SIZE);

	if (mdah->checksum_xl != xlate32(calc_crc(INITIAL_CRC, (uint8_t *)mdah->magic,
						  MDA_HEADER_SIZE -
						  sizeof(mdah->checksum_xl)))) {
		log_error("Incorrect metadata area header checksum on %s"
			  " at offset " FMTu64, dev_name(dev_area->dev),
			  dev_area->start);
		goto bad;
	}

	_xlate_mdah(mdah);

	if (strncmp((char *)mdah->magic, FMTT_MAGIC, sizeof(mdah->magic))) {
		log_error("Wrong magic number in metadata area header on %s"
			  " at offset " FMTu64, dev_name(dev_area->dev),
			  dev_area->start);
		goto bad;
	}

	if (mdah->version != FMTT_VERSION) {
		log_error("Incompatible metadata area header version: %d on %s"
			  " at offset " FMTu64, mdah->version,
			  dev_name(dev_area->dev), dev_area->start);
		goto bad;
	}

	if (mdah->start != dev_area->start) {
		log_error("Incorrect start sector in metadata area header: "
			  FMTu64 " on %s at offset " FMTu64, mdah->start,
			  dev_name(dev_area->dev), dev_area->start);
		goto bad;
	}

	goto out;

bad:
	prmp->ret = 0;
out:
	if (prmp->mdah_callback_fn)
		prmp->mdah_callback_fn(!prmp->ret, ioflags, prmp->mdah_callback_context, mdah);
}

static struct mda_header *_raw_read_mda_header(struct dm_pool *mem, struct device_area *dev_area, int primary_mda,
					       unsigned ioflags, lvm_callback_fn_t mdah_callback_fn, void *mdah_callback_context)
{
	struct mda_header *mdah;
	struct process_raw_mda_header_params *prmp;

	if (!(mdah = dm_pool_alloc(mem, MDA_HEADER_SIZE))) {
		log_error("struct mda_header allocation failed");
		return NULL;
	}

	if (!(prmp = dm_pool_zalloc(mem, sizeof (*prmp)))) {
		log_error("struct process_raw_mda_header_params allocation failed");
		dm_pool_free(mem, mdah);
		return NULL;
	}

	if (!dev_open_readonly(dev_area->dev)) {
		dm_pool_free(mem, mdah);
		return_NULL;
	}

	prmp->mdah = mdah;
	prmp->dev_area = *dev_area;
	prmp->mdah_callback_fn = mdah_callback_fn;
	prmp->mdah_callback_context = mdah_callback_context;
	prmp->ret = 1;

	dev_read_callback(dev_area->dev, dev_area->start, MDA_HEADER_SIZE, MDA_HEADER_REASON(primary_mda),
			  ioflags, _process_raw_mda_header, prmp);
	if (mdah_callback_fn)
		return mdah;

	if (!prmp->ret)
		return_NULL;
	else
		return mdah;
}

struct mda_header *raw_read_mda_header(struct dm_pool *mem, struct device_area *dev_area, int primary_mda)
{
	return _raw_read_mda_header(mem, dev_area, primary_mda, 0, NULL, NULL);
}

int raw_read_mda_header_callback(struct dm_pool *mem, struct device_area *dev_area, int primary_mda,
				 unsigned ioflags, lvm_callback_fn_t mdah_callback_fn, void *mdah_callback_context)
{
	if (!_raw_read_mda_header(mem, dev_area, primary_mda, ioflags, mdah_callback_fn, mdah_callback_context))
		return_0;

	return 1;
}

static int _raw_write_mda_header(const struct format_type *fmt,
				 struct device *dev, int primary_mda,
				 uint64_t start_byte, struct mda_header *mdah)
{
	strncpy((char *)mdah->magic, FMTT_MAGIC, sizeof(mdah->magic));
	mdah->version = FMTT_VERSION;
	mdah->start = start_byte;

	_xlate_mdah(mdah);
	mdah->checksum_xl = xlate32(calc_crc(INITIAL_CRC, (uint8_t *)mdah->magic,
					     MDA_HEADER_SIZE -
					     sizeof(mdah->checksum_xl)));

	if (!dev_write(dev, start_byte, MDA_HEADER_SIZE, MDA_HEADER_REASON(primary_mda), mdah))
		return_0;

	return 1;
}

static struct raw_locn *_find_vg_rlocn(struct device_area *dev_area,
				       struct mda_header *mdah, int primary_mda,
				       const char *vgname,
				       int *precommitted)
{
	size_t len;
	struct raw_locn *rlocn, *rlocn_precommitted;
	struct lvmcache_info *info;
	struct lvmcache_vgsummary vgsummary_orphan = {
		.vgname = FMT_TEXT_ORPHAN_VG_NAME,
	};
	int rlocn_was_ignored;
	const char *buf;

	memcpy(&vgsummary_orphan.vgid, FMT_TEXT_ORPHAN_VG_NAME, sizeof(FMT_TEXT_ORPHAN_VG_NAME));

	rlocn = mdah->raw_locns;	/* Slot 0 */
	rlocn_precommitted = rlocn + 1;	/* Slot 1 */

	rlocn_was_ignored = rlocn_is_ignored(rlocn);

	/* Should we use precommitted metadata? */
	if (*precommitted && rlocn_precommitted->size &&
	    (rlocn_precommitted->offset != rlocn->offset)) {
		rlocn = rlocn_precommitted;
	} else
		*precommitted = 0;

	/* Do not check non-existent metadata. */
	if (!rlocn->offset && !rlocn->size)
		return NULL;

	/*
	 * Don't try to check existing metadata
	 * if given vgname is an empty string.
	 */
	if (!*vgname)
		return rlocn;

	/*
	 * If live rlocn has ignored flag, data will be out-of-date so skip further checks.
	 */
	if (rlocn_was_ignored)
		return rlocn;

	/* FIXME Loop through rlocns two-at-a-time.  List null-terminated. */
	/* FIXME Ignore if checksum incorrect!!! */
	if (!(buf = dev_read(dev_area->dev, dev_area->start + rlocn->offset,
			     NAME_LEN + 2, MDA_CONTENT_REASON(primary_mda))))
		goto_bad;

	if (!strncmp(buf, vgname, len = strlen(vgname)) &&
	    (isspace(*(buf + len)) || *(buf + len) == '{'))
		return rlocn;

	log_debug_metadata("Volume group name found in %smetadata on %s at " FMTu64 " does "
			   "not match expected name %s.", 
			   *precommitted ? "precommitted " : "",
			   dev_name(dev_area->dev), dev_area->start + rlocn->offset, vgname);

      bad:
	if ((info = lvmcache_info_from_pvid(dev_area->dev->pvid, dev_area->dev, 0)) &&
	    !lvmcache_update_vgname_and_id(info, &vgsummary_orphan))
		stack;

	return NULL;
}

/*
 * Find first aligned offset after end of existing metadata.
 * Based on the alignment provided, this is the exact offset to use for the new metadata.
 * The caller is responsible for validating the result.
 */
static uint64_t _next_rlocn_offset(struct raw_locn *rlocn, struct mda_header *mdah, uint64_t mdac_area_start, uint64_t alignment)
{
	uint64_t old_end, new_start_offset;
	int old_wrapped = 0;	/* Does the old metadata wrap around? */

	if (!rlocn)
		/* Find an empty slot */
		/* FIXME Assumes only one VG per mdah for now */
		return ALIGN_ABSOLUTE(MDA_HEADER_SIZE, mdac_area_start, alignment);

	/* First find the end of the old metadata */
	old_end = rlocn->offset + rlocn->size;

	if (old_end > mdah->size) {
		old_wrapped = 1;
		old_end -= (mdah->size - MDA_HEADER_SIZE);
	}

	/* Calculate new start position relative to start of buffer rounded up to absolute alignment */
	new_start_offset = ALIGN_ABSOLUTE(old_end, mdac_area_start, alignment);

	/* If new location is beyond the end of the buffer, return to start of circular buffer and realign */
	if (new_start_offset >= mdah->size) {
		/* If the start of the buffer is occupied, move past it */
		if (old_wrapped || rlocn->offset == MDA_HEADER_SIZE)
			new_start_offset = old_end;
		else
			new_start_offset = MDA_HEADER_SIZE;
 
		new_start_offset = ALIGN_ABSOLUTE(new_start_offset, mdac_area_start, alignment);
	}

	/*
	 * Note that we don't check here that this location isn't inside the existing metadata.
	 * If it is, then it means this value of alignment cannot be used.
	 */
	return new_start_offset;
}

static int _raw_holds_vgname(struct format_instance *fid,
			     struct device_area *dev_area, const char *vgname)
{
	int r = 0;
	int noprecommit = 0;
	struct mda_header *mdah;

	if (!dev_open_readonly(dev_area->dev))
		return_0;

	if (!(mdah = raw_read_mda_header(fid->fmt->cmd->mem, dev_area, 0)))
		return_0;

	if (_find_vg_rlocn(dev_area, mdah, 0, vgname, &noprecommit))
		r = 1;

	if (!dev_close(dev_area->dev))
		stack;

	return r;
}

static struct volume_group *_vg_read_raw_area(struct format_instance *fid,
					      const char *vgname,
					      struct device_area *area,
					      struct cached_vg_fmtdata **vg_fmtdata,
					      unsigned *use_previous_vg,
					      int precommitted, unsigned ioflags,
					      int single_device, int primary_mda)
{
	struct volume_group *vg = NULL;
	struct raw_locn *rlocn;
	struct mda_header *mdah;
	time_t when;
	char *desc;
	uint32_t wrap = 0;

	if (!(mdah = raw_read_mda_header(fid->fmt->cmd->mem, area, primary_mda)))
		goto_out;

	if (!(rlocn = _find_vg_rlocn(area, mdah, primary_mda, vgname, &precommitted))) {
		log_debug_metadata("VG %s not found on %s", vgname, dev_name(area->dev));
		goto out;
	}

	if (rlocn->offset + rlocn->size > mdah->size)
		wrap = (uint32_t) ((rlocn->offset + rlocn->size) - mdah->size);

	if (wrap > rlocn->offset) {
		log_error("VG %s metadata on %s (" FMTu64 " bytes) too large for circular buffer (" FMTu64 " bytes)",
			  vgname, dev_name(area->dev), rlocn->size, mdah->size - MDA_HEADER_SIZE);
		goto out;
	}

	/* FIXME 64-bit */
	if (!(vg = text_vg_import_fd(fid, NULL, vg_fmtdata, use_previous_vg, single_device, area->dev, 
				     primary_mda,
				     (off_t) (area->start + rlocn->offset),
				     (uint32_t) (rlocn->size - wrap),
				     (off_t) (area->start + MDA_HEADER_SIZE),
				     wrap, calc_crc, rlocn->checksum, ioflags, &when,
				     &desc)) && (!use_previous_vg || !*use_previous_vg))
		goto_out;

	if (vg)
		log_debug_metadata("Read %s %smetadata (%u) from %s at " FMTu64 " size "
				   FMTu64, vg->name, precommitted ? "pre-commit " : "",
				   vg->seqno, dev_name(area->dev),
				   area->start + rlocn->offset, rlocn->size);
	else
		log_debug_metadata("Skipped reading %smetadata from %s at " FMTu64 " size "
				   FMTu64 " with matching checksum.", precommitted ? "pre-commit " : "",
				   dev_name(area->dev),
				   area->start + rlocn->offset, rlocn->size);

	if (vg && precommitted)
		vg->status |= PRECOMMITTED;

      out:
	return vg;
}

static struct volume_group *_vg_read_raw(struct format_instance *fid,
					 const char *vgname,
					 struct metadata_area *mda,
					 struct cached_vg_fmtdata **vg_fmtdata,
					 unsigned *use_previous_vg,
					 int single_device, unsigned ioflags)
{
	struct mda_context *mdac = (struct mda_context *) mda->metadata_locn;
	struct volume_group *vg;

	if (!dev_open_readonly(mdac->area.dev))
		return_NULL;

	vg = _vg_read_raw_area(fid, vgname, &mdac->area, vg_fmtdata, use_previous_vg, 0, ioflags, single_device, mda_is_primary(mda));

	if (!dev_close(mdac->area.dev))
		stack;

	return vg;
}

static struct volume_group *_vg_read_precommit_raw(struct format_instance *fid,
						   const char *vgname,
						   struct metadata_area *mda,
						   struct cached_vg_fmtdata **vg_fmtdata,
						   unsigned *use_previous_vg, unsigned ioflags)
{
	struct mda_context *mdac = (struct mda_context *) mda->metadata_locn;
	struct volume_group *vg;

	if (!dev_open_readonly(mdac->area.dev))
		return_NULL;

	vg = _vg_read_raw_area(fid, vgname, &mdac->area, vg_fmtdata, use_previous_vg, 1, ioflags, 0, mda_is_primary(mda));

	if (!dev_close(mdac->area.dev))
		stack;

	return vg;
}

static int _metadata_fits_into_buffer(struct mda_context *mdac, struct mda_header *mdah,
				      struct raw_locn *rlocn, uint64_t new_wrap)
{
	uint64_t old_wrap = 0;	/* Amount of wrap around in existing metadata */
	uint64_t old_end = 0;	/* The (byte after the) end of the existing metadata */
	uint64_t new_end;	/* The (byte after the) end of the new metadata */
	uint64_t old_start = 0;	/* The start of the existing metadata */
	uint64_t new_start = mdac->rlocn.offset;	/* The proposed start of the new metadata */

	/*
	 * If the (aligned) start of the new metadata is already beyond the end
	 * of the buffer this means it didn't fit with the given alignment.
	 * (The caller has already tried to wrap it back to the start
	 * of the buffer but the alignment pushed it back outside.)
	 */
	if (new_start >= mdah->size)
		return_0;

	/* Does the total amount of metadata, old and new, fit inside the buffer? */
	if (MDA_HEADER_SIZE + (rlocn ? rlocn->size : 0) + mdac->rlocn.size >= mdah->size)
		return_0;

	/* If there's existing metadata, set old_start, old_end and old_wrap. */
	if (rlocn) {
		old_start = rlocn->offset;
		old_end = old_start + rlocn->size;

		/* Does the existing metadata wrap around the end of the buffer? */
		if (old_end > mdah->size)
			old_wrap = old_end - mdah->size;
	}

	new_end = new_wrap ? new_wrap + MDA_HEADER_SIZE : new_start + mdac->rlocn.size;

	/* If both wrap around, there's necessarily overlap */
	if (new_wrap && old_wrap)
		return_0;

	/* If there's no existing metadata, we're OK */
	if (!rlocn)
		return 1;

	/* If either wraps around, there's overlap if the new end falls beyond the old start */
	if ((new_wrap || old_wrap) && (new_end > old_start))
		return_0;

	/* If there's no wrap, check there's no overlap */
	if (!new_wrap && !old_wrap && (old_end > new_start) && (old_start < new_end))
		return_0;

	return 1;
}

static int _vg_write_raw(struct format_instance *fid, struct volume_group *vg,
			 struct metadata_area *mda)
{
	struct mda_context *mdac = (struct mda_context *) mda->metadata_locn;
	struct text_fid_context *fidtc = (struct text_fid_context *) fid->private;
	struct raw_locn *rlocn;
	struct mda_header *mdah;
	struct pv_list *pvl;
	int r = 0;
	uint64_t new_wrap = 0;	/* Number of bytes of new metadata that wrap around to start of buffer */
	uint64_t alignment = MDA_ALIGNMENT;
	int found = 0;
	int noprecommit = 0;
	const char *old_vg_name = NULL;
	uint64_t new_size_rounded = 0;

	/* Ignore any mda on a PV outside the VG. vgsplit relies on this */
	dm_list_iterate_items(pvl, &vg->pvs) {
		if (pvl->pv->dev == mdac->area.dev) {
			found = 1;
			if (pvl->pv->status & PV_MOVED_VG)
				old_vg_name = vg->old_name;
			break;
		}
	}

	if (!found)
		return 1;

	/*
	 * This is paired with the following closes:
	 *  - at the end of this fn if returning 0
	 *  - in _vg_commit_raw_rlocn regardless of return code
	 *    which handles commit (but not pre-commit) and revert.
	 */
	if (!dev_open(mdac->area.dev))
		return_0;

	if (!(mdah = raw_read_mda_header(fid->fmt->cmd->mem, &mdac->area, mda_is_primary(mda))))
		goto_out;

	/* Following space is zero-filled up to the next MDA_ALIGNMENT boundary */
	if (!fidtc->raw_metadata_buf &&
	    !(fidtc->raw_metadata_buf_size =
			text_vg_export_raw(vg, "", &fidtc->raw_metadata_buf))) {
		log_error("VG %s metadata writing failed", vg->name);
		goto out;
	}

	rlocn = _find_vg_rlocn(&mdac->area, mdah, mda_is_primary(mda), old_vg_name ? : vg->name, &noprecommit);

	mdac->rlocn.size = fidtc->raw_metadata_buf_size;

	/* Find where the new metadata would be written with our preferred alignment */
	mdac->rlocn.offset = _next_rlocn_offset(rlocn, mdah, mdac->area.start, alignment);

	/* If metadata extends beyond the buffer, return to the start instead of wrapping it */
	if (mdac->rlocn.offset + mdac->rlocn.size > mdah->size)
		mdac->rlocn.offset = ALIGN_ABSOLUTE(MDA_HEADER_SIZE, mdac->area.start, alignment);

	/*
	 * If the metadata doesn't fit into the buffer correctly with these
	 * settings, fall back to the 512-byte alignment used by the original
	 * LVM2 code and allow the metadata to be split into two parts,
	 * wrapping around from the end of the circular buffer back to the
	 * beginning.
	 */
	if (!_metadata_fits_into_buffer(mdac, mdah, rlocn, 0)) {
		alignment = MDA_ORIGINAL_ALIGNMENT;
		mdac->rlocn.offset = _next_rlocn_offset(rlocn, mdah, mdac->area.start, alignment);

		/* Does the new metadata wrap around? */
		if (mdac->rlocn.offset + mdac->rlocn.size > mdah->size)
			new_wrap = (mdac->rlocn.offset + mdac->rlocn.size) - mdah->size;
		else
			new_wrap = 0;

		if (!_metadata_fits_into_buffer(mdac, mdah, rlocn, new_wrap)) {
			log_error("VG %s metadata on %s (" FMTu64 " bytes) too large for circular buffer (" FMTu64 " bytes with " FMTu64 " used)",
				  vg->name, dev_name(mdac->area.dev), mdac->rlocn.size, mdah->size - MDA_HEADER_SIZE, rlocn ? rlocn->size : 0);
			goto out;
		}

		new_size_rounded = mdac->rlocn.size;
	} else {
		/* Round up to a multiple of the new alignment */
		if (mdac->rlocn.offset + new_size_rounded < mdah->size)
			new_size_rounded = (mdac->rlocn.size | (alignment - 1)) + 1;
		else
			new_size_rounded = mdac->rlocn.size;
	}

	log_debug_metadata("Writing %s metadata to %s at " FMTu64 " len " FMTu64 " (rounded to " FMTu64 ") of " FMTu64 " aligned to " FMTu64,
			    vg->name, dev_name(mdac->area.dev), mdac->area.start +
			    mdac->rlocn.offset, mdac->rlocn.size - new_wrap, new_size_rounded, mdac->rlocn.size, alignment);

	if (!new_wrap) {
		/* Write text out, in alignment-sized blocks */
		if (!dev_write(mdac->area.dev, mdac->area.start + mdac->rlocn.offset,
			       (size_t) new_size_rounded, MDA_CONTENT_REASON(mda_is_primary(mda)),
			       fidtc->raw_metadata_buf))
			goto_out;
	} else {
		/* Write text out, circularly */
		if (!dev_write(mdac->area.dev, mdac->area.start + mdac->rlocn.offset,
			       (size_t) (mdac->rlocn.size - new_wrap), MDA_CONTENT_REASON(mda_is_primary(mda)),
			       fidtc->raw_metadata_buf))
			goto_out;

		log_debug_metadata("Writing wrapped metadata to %s at " FMTu64 " len " FMTu64 " of " FMTu64,
				  dev_name(mdac->area.dev), mdac->area.start +
				  MDA_HEADER_SIZE, new_wrap, mdac->rlocn.size);

		if (!dev_write(mdac->area.dev, mdac->area.start + MDA_HEADER_SIZE,
			       (size_t) new_wrap, MDA_CONTENT_REASON(mda_is_primary(mda)),
			       fidtc->raw_metadata_buf + mdac->rlocn.size - new_wrap))
			goto_out;
	}

	mdac->rlocn.checksum = calc_crc(INITIAL_CRC, (uint8_t *)fidtc->raw_metadata_buf,
					(uint32_t) (mdac->rlocn.size -
						    new_wrap));
	if (new_wrap)
		mdac->rlocn.checksum = calc_crc(mdac->rlocn.checksum,
						(uint8_t *)fidtc->raw_metadata_buf +
						mdac->rlocn.size -
						new_wrap, (uint32_t) new_wrap);

	r = 1;

      out:
	if (!r) {
		if (!dev_close(mdac->area.dev))
			stack;

		dm_free(fidtc->raw_metadata_buf);
		fidtc->raw_metadata_buf = NULL;
	}

	return r;
}

static int _vg_commit_raw_rlocn(struct format_instance *fid,
				struct volume_group *vg,
				struct metadata_area *mda,
				int precommit)
{
	struct mda_context *mdac = (struct mda_context *) mda->metadata_locn;
	struct text_fid_context *fidtc = (struct text_fid_context *) fid->private;
	struct mda_header *mdah;
	struct raw_locn *rlocn;
	struct pv_list *pvl;
	int r = 0;
	int found = 0;
	int noprecommit = 0;
	const char *old_vg_name = NULL;

	/* Ignore any mda on a PV outside the VG. vgsplit relies on this */
	dm_list_iterate_items(pvl, &vg->pvs) {
		if (pvl->pv->dev == mdac->area.dev) {
			found = 1;
			if (pvl->pv->status & PV_MOVED_VG)
				old_vg_name = vg->old_name;
			break;
		}
	}

	if (!found)
		return 1;

	if (!(mdah = raw_read_mda_header(fid->fmt->cmd->mem, &mdac->area, mda_is_primary(mda))))
		goto_out;

	if (!(rlocn = _find_vg_rlocn(&mdac->area, mdah, mda_is_primary(mda), old_vg_name ? : vg->name, &noprecommit))) {
		mdah->raw_locns[0].offset = 0;
		mdah->raw_locns[0].size = 0;
		mdah->raw_locns[0].checksum = 0;
		mdah->raw_locns[1].offset = 0;
		mdah->raw_locns[1].size = 0;
		mdah->raw_locns[1].checksum = 0;
		mdah->raw_locns[2].offset = 0;
		mdah->raw_locns[2].size = 0;
		mdah->raw_locns[2].checksum = 0;
		rlocn = &mdah->raw_locns[0];
	} else if (precommit && rlocn_is_ignored(rlocn) && !mda_is_ignored(mda)) {
		/*
		 * If precommitting into a previously-ignored mda, wipe the live rlocn
		 * as a precaution so that nothing can use it by mistake.
		 */
		mdah->raw_locns[0].offset = 0;
		mdah->raw_locns[0].size = 0;
		mdah->raw_locns[0].checksum = 0;
	}

	if (precommit)
		rlocn++;
	else {
		/* If not precommitting, wipe the precommitted rlocn */
		mdah->raw_locns[1].offset = 0;
		mdah->raw_locns[1].size = 0;
		mdah->raw_locns[1].checksum = 0;
	}

	/* Is there new metadata to commit? */
	if (mdac->rlocn.size) {
		rlocn->offset = mdac->rlocn.offset;
		rlocn->size = mdac->rlocn.size;
		rlocn->checksum = mdac->rlocn.checksum;
		log_debug_metadata("%sCommitting %s %smetadata (%u) to %s header at " FMTu64 " (offset " FMTu64 ", size " FMTu64 ")",
				   precommit ? "Pre-" : "", vg->name, mda_is_ignored(mda) ? "(ignored) " : "", vg->seqno,
				   dev_name(mdac->area.dev), mdac->area.start, mdac->rlocn.offset, mdac->rlocn.size);
	} else
		log_debug_metadata("Wiping pre-committed %s %smetadata from %s "
				   "header at " FMTu64, vg->name,
				   mda_is_ignored(mda) ? "(ignored) " : "",
				   dev_name(mdac->area.dev), mdac->area.start);

	rlocn_set_ignored(mdah->raw_locns, mda_is_ignored(mda));

	if (!_raw_write_mda_header(fid->fmt, mdac->area.dev, mda_is_primary(mda), mdac->area.start,
				   mdah)) {
		dm_pool_free(fid->fmt->cmd->mem, mdah);
		log_error("Failed to write metadata area header");
		goto out;
	}

	r = 1;

      out:
	if (!precommit) {
		/* This is an paired with the open at the start of _vg_write_raw */
		if (!dev_close(mdac->area.dev))
			stack;

		dm_free(fidtc->raw_metadata_buf);
		fidtc->raw_metadata_buf = NULL;
	}

	return r;
}

static int _vg_commit_raw(struct format_instance *fid, struct volume_group *vg,
			  struct metadata_area *mda)
{
	return _vg_commit_raw_rlocn(fid, vg, mda, 0);
}

static int _vg_precommit_raw(struct format_instance *fid,
			     struct volume_group *vg,
			     struct metadata_area *mda)
{
	return _vg_commit_raw_rlocn(fid, vg, mda, 1);
}

/* Close metadata area devices */
static int _vg_revert_raw(struct format_instance *fid, struct volume_group *vg,
			  struct metadata_area *mda)
{
	struct mda_context *mdac = (struct mda_context *) mda->metadata_locn;
	struct pv_list *pvl;
	int found = 0;

	/* Ignore any mda on a PV outside the VG. vgsplit relies on this */
	dm_list_iterate_items(pvl, &vg->pvs) {
		if (pvl->pv->dev == mdac->area.dev) {
			found = 1;
			break;
		}
	}

	if (!found)
		return 1;

	/* Wipe pre-committed metadata */
	mdac->rlocn.size = 0;
	return _vg_commit_raw_rlocn(fid, vg, mda, 0);
}

static int _vg_remove_raw(struct format_instance *fid, struct volume_group *vg,
			  struct metadata_area *mda)
{
	struct mda_context *mdac = (struct mda_context *) mda->metadata_locn;
	struct mda_header *mdah;
	struct raw_locn *rlocn;
	int r = 0;
	int noprecommit = 0;

	if (!dev_open(mdac->area.dev))
		return_0;

	if (!(mdah = raw_read_mda_header(fid->fmt->cmd->mem, &mdac->area, mda_is_primary(mda))))
		goto_out;

	if (!(rlocn = _find_vg_rlocn(&mdac->area, mdah, mda_is_primary(mda), vg->name, &noprecommit))) {
		rlocn = &mdah->raw_locns[0];
		mdah->raw_locns[1].offset = 0;
	}

	rlocn->offset = 0;
	rlocn->size = 0;
	rlocn->checksum = 0;
	rlocn_set_ignored(mdah->raw_locns, mda_is_ignored(mda));

	if (!_raw_write_mda_header(fid->fmt, mdac->area.dev, mda_is_primary(mda), mdac->area.start,
				   mdah)) {
		dm_pool_free(fid->fmt->cmd->mem, mdah);
		log_error("Failed to write metadata area header");
		goto out;
	}

	r = 1;

      out:
	if (!dev_close(mdac->area.dev))
		stack;

	return r;
}

static struct volume_group *_vg_read_file_name(struct format_instance *fid,
					       const char *vgname,
					       const char *read_path)
{
	struct volume_group *vg;
	time_t when;
	char *desc;

	if (!(vg = text_vg_import_file(fid, read_path, &when, &desc)))
		return_NULL;

	/*
	 * Currently you can only have a single volume group per
	 * text file (this restriction may remain).  We need to
	 * check that it contains the correct volume group.
	 */
	if (vgname && strcmp(vgname, vg->name)) {
		fid->ref_count++; /* Preserve FID after vg release */
		release_vg(vg);
		log_error("'%s' does not contain volume group '%s'.",
			  read_path, vgname);
		return NULL;
	}

	log_debug_metadata("Read volume group %s from %s", vg->name, read_path);

	return vg;
}

static struct volume_group *_vg_read_file(struct format_instance *fid,
					  const char *vgname,
					  struct metadata_area *mda,
					  struct cached_vg_fmtdata **vg_fmtdata,
					  unsigned *use_previous_vg __attribute__((unused)),
					  int single_device __attribute__((unused)),
					  unsigned ioflags __attribute__((unused)))
{
	struct text_context *tc = (struct text_context *) mda->metadata_locn;

	return _vg_read_file_name(fid, vgname, tc->path_live);
}

static struct volume_group *_vg_read_precommit_file(struct format_instance *fid,
						    const char *vgname,
						    struct metadata_area *mda,
						    struct cached_vg_fmtdata **vg_fmtdata,
						    unsigned *use_previous_vg __attribute__((unused)),
						    unsigned ioflags __attribute__((unused)))
{
	struct text_context *tc = (struct text_context *) mda->metadata_locn;
	struct volume_group *vg;

	if ((vg = _vg_read_file_name(fid, vgname, tc->path_edit)))
		vg->status |= PRECOMMITTED;
	else
		vg = _vg_read_file_name(fid, vgname, tc->path_live);

	return vg;
}

static int _vg_write_file(struct format_instance *fid __attribute__((unused)),
			  struct volume_group *vg, struct metadata_area *mda)
{
	struct text_context *tc = (struct text_context *) mda->metadata_locn;

	FILE *fp;
	int fd;
	char *slash;
	char temp_file[PATH_MAX], temp_dir[PATH_MAX];

	slash = strrchr(tc->path_edit, '/');

	if (slash == 0)
		strcpy(temp_dir, ".");
	else if (slash - tc->path_edit < PATH_MAX) {
		strncpy(temp_dir, tc->path_edit,
			(size_t) (slash - tc->path_edit));
		temp_dir[slash - tc->path_edit] = '\0';

	} else {
		log_error("Text format failed to determine directory.");
		return 0;
	}

	if (!create_temp_name(temp_dir, temp_file, sizeof(temp_file), &fd,
			      &vg->cmd->rand_seed)) {
		log_error("Couldn't create temporary text file name.");
		return 0;
	}

	if (!(fp = fdopen(fd, "w"))) {
		log_sys_error("fdopen", temp_file);
		if (close(fd))
			log_sys_error("fclose", temp_file);
		return 0;
	}

	log_debug_metadata("Writing %s metadata to %s", vg->name, temp_file);

	if (!text_vg_export_file(vg, tc->desc, fp)) {
		log_error("Failed to write metadata to %s.", temp_file);
		if (fclose(fp))
			log_sys_error("fclose", temp_file);
		return 0;
	}

	if (fsync(fd) && (errno != EROFS) && (errno != EINVAL)) {
		log_sys_error("fsync", tc->path_edit);
		if (fclose(fp))
			log_sys_error("fclose", tc->path_edit);
		return 0;
	}

	if (lvm_fclose(fp, tc->path_edit))
		return_0;

	log_debug_metadata("Renaming %s to %s", temp_file, tc->path_edit);
	if (rename(temp_file, tc->path_edit)) {
		log_error("%s: rename to %s failed: %s", temp_file,
			  tc->path_edit, strerror(errno));
		return 0;
	}

	return 1;
}

static int _vg_commit_file_backup(struct format_instance *fid __attribute__((unused)),
				  struct volume_group *vg,
				  struct metadata_area *mda)
{
	struct text_context *tc = (struct text_context *) mda->metadata_locn;

	if (test_mode()) {
		log_verbose("Test mode: Skipping committing %s metadata (%u)",
			    vg->name, vg->seqno);
		if (unlink(tc->path_edit)) {
			log_debug_metadata("Unlinking %s", tc->path_edit);
			log_sys_error("unlink", tc->path_edit);
			return 0;
		}
	} else {
		log_debug_metadata("Committing %s metadata (%u)", vg->name, vg->seqno);
		log_debug_metadata("Renaming %s to %s", tc->path_edit, tc->path_live);
		if (rename(tc->path_edit, tc->path_live)) {
			log_error("%s: rename to %s failed: %s", tc->path_edit,
				  tc->path_live, strerror(errno));
			return 0;
		}
	}

	sync_dir(tc->path_edit);

	return 1;
}

static int _vg_commit_file(struct format_instance *fid, struct volume_group *vg,
			   struct metadata_area *mda)
{
	struct text_context *tc = (struct text_context *) mda->metadata_locn;
	const char *slash;
	char new_name[PATH_MAX];
	size_t len;

	if (!_vg_commit_file_backup(fid, vg, mda))
		return 0;

	/* vgrename? */
	if ((slash = strrchr(tc->path_live, '/')))
		slash = slash + 1;
	else
		slash = tc->path_live;

	if (strcmp(slash, vg->name)) {
		len = slash - tc->path_live;
		if ((len + strlen(vg->name)) > (sizeof(new_name) - 1)) {
			log_error("Renaming path %s is too long for VG %s.",
				  tc->path_live, vg->name);
			return 0;
		}
		strncpy(new_name, tc->path_live, len);
		strcpy(new_name + len, vg->name);
		log_debug_metadata("Renaming %s to %s", tc->path_live, new_name);
		if (test_mode())
			log_verbose("Test mode: Skipping rename");
		else {
			if (rename(tc->path_live, new_name)) {
				log_error("%s: rename to %s failed: %s",
					  tc->path_live, new_name,
					  strerror(errno));
				sync_dir(new_name);
				return 0;
			}
		}
	}

	return 1;
}

static int _vg_remove_file(struct format_instance *fid __attribute__((unused)),
			   struct volume_group *vg __attribute__((unused)),
			   struct metadata_area *mda)
{
	struct text_context *tc = (struct text_context *) mda->metadata_locn;

	if (path_exists(tc->path_edit) && unlink(tc->path_edit)) {
		log_sys_error("unlink", tc->path_edit);
		return 0;
	}

	if (path_exists(tc->path_live) && unlink(tc->path_live)) {
		log_sys_error("unlink", tc->path_live);
		return 0;
	}

	sync_dir(tc->path_live);

	return 1;
}

static int _scan_file(const struct format_type *fmt, const char *vgname)
{
	struct dirent *dirent;
	struct dir_list *dl;
	struct dm_list *dir_list;
	char *tmp;
	DIR *d;
	struct volume_group *vg;
	struct format_instance *fid;
	struct format_instance_ctx fic;
	char path[PATH_MAX];
	char *scanned_vgname;

	dir_list = &((struct mda_lists *) fmt->private)->dirs;

	dm_list_iterate_items(dl, dir_list) {
		if (!(d = opendir(dl->dir))) {
			log_sys_error("opendir", dl->dir);
			continue;
		}
		while ((dirent = readdir(d)))
			if (strcmp(dirent->d_name, ".") &&
			    strcmp(dirent->d_name, "..") &&
			    (!(tmp = strstr(dirent->d_name, ".tmp")) ||
			     tmp != dirent->d_name + strlen(dirent->d_name)
			     - 4)) {
				scanned_vgname = dirent->d_name;

				/* If vgname supplied, only scan that one VG */
				if (vgname && strcmp(vgname, scanned_vgname))
					continue;

				if (dm_snprintf(path, PATH_MAX, "%s/%s",
						 dl->dir, scanned_vgname) < 0) {
					log_error("Name too long %s/%s",
						  dl->dir, scanned_vgname);
					break;
				}

				/* FIXME stat file to see if it's changed */
				/* FIXME: Check this fid is OK! */
				fic.type = FMT_INSTANCE_PRIVATE_MDAS;
				fic.context.private = NULL;
				if (!(fid = _text_create_text_instance(fmt, &fic))) {
					stack;
					break;
				}
				if ((vg = _vg_read_file_name(fid, scanned_vgname,
							     path))) {
					/* FIXME Store creation host in vg */
					lvmcache_update_vg(vg, 0);
					release_vg(vg);
				}
			}

		if (closedir(d))
			log_sys_error("closedir", dl->dir);
	}

	return 1;
}

struct vgname_from_mda_params{
	const struct format_type *fmt;
	const struct mda_header *mdah;
	struct device_area *dev_area;
	int primary_mda;
	struct lvmcache_vgsummary *vgsummary;
	uint64_t *mda_free_sectors;
	lvm_callback_fn_t update_vgsummary_fn;
	void *update_vgsummary_context;
	uint32_t wrap;
	unsigned used_cached_metadata;
	int ret;
};

static void _vgname_from_mda_process(int failed, unsigned ioflags, void *context, const void *data)
{
	struct vgname_from_mda_params *vfmp = context;
	const struct mda_header *mdah = vfmp->mdah;
	struct device_area *dev_area = vfmp->dev_area;
	struct lvmcache_vgsummary *vgsummary = vfmp->vgsummary;
	uint64_t *mda_free_sectors = vfmp->mda_free_sectors;
	const struct raw_locn *rlocn = mdah->raw_locns;
	uint64_t buffer_size, current_usage;

	if (failed) {
		vfmp->ret = 0;
		goto_out;
	}

	/* Ignore this entry if the characters aren't permissible */
	if (!validate_name(vgsummary->vgname)) {
		vfmp->ret = 0;
		goto_out;
	}

	log_debug_metadata("%s: %s metadata at " FMTu64 " size " FMTu64 " with wrap " FMTu32
			   " (in area at " FMTu64 " size " FMTu64
			   ") for %s (" FMTVGID ")",
			   dev_name(dev_area->dev),
			   vfmp->used_cached_metadata ? "Using cached" : "Found",
			   dev_area->start + rlocn->offset,
			   rlocn->size, vfmp->wrap, dev_area->start, dev_area->size, vgsummary->vgname,
			   (char *)&vgsummary->vgid);

	if (mda_free_sectors) {
		current_usage = ALIGN_ABSOLUTE(rlocn->size, dev_area->start + rlocn->offset, MDA_ALIGNMENT);

		buffer_size = mdah->size - MDA_HEADER_SIZE;

		if (current_usage * 2 >= buffer_size)
			*mda_free_sectors = UINT64_C(0);
		else
			*mda_free_sectors = ((buffer_size - 2 * current_usage) / 2) >> SECTOR_SHIFT;
	}

out:
	vfmp->update_vgsummary_fn(!vfmp->ret, ioflags, vfmp->update_vgsummary_context, vfmp->vgsummary);
}

static void _vgname_from_mda_validate(int failed, unsigned ioflags, void *context, const void *data)
{
	struct vgname_from_mda_params *vfmp = context;
	const char *buffer = data;
	const struct format_type *fmt = vfmp->fmt;
	const struct mda_header *mdah = vfmp->mdah;
	struct device_area *dev_area = vfmp->dev_area;
	struct lvmcache_vgsummary *vgsummary = vfmp->vgsummary;
	const struct raw_locn *rlocn = mdah->raw_locns;
	unsigned len = 0;
	char buf[NAME_LEN + 1] __attribute__((aligned(8)));

	if (failed) {
		vfmp->ret = 0;
		goto_out;
	}

	memcpy(buf, buffer, NAME_LEN);

	while (buf[len] && !isspace(buf[len]) && buf[len] != '{' &&
	       len < (NAME_LEN - 1))
		len++;

	buf[len] = '\0';

	/* Ignore this entry if the characters aren't permissible */
	if (!validate_name(buf)) {
		vfmp->ret = 0;
		goto_out;
	}

	/* We found a VG - now check the metadata */
	if (rlocn->offset + rlocn->size > mdah->size)
		vfmp->wrap = (uint32_t) ((rlocn->offset + rlocn->size) - mdah->size);

	if (vfmp->wrap > rlocn->offset) {
		log_error("%s: metadata (" FMTu64 " bytes) too large for circular buffer (" FMTu64 " bytes)",
			  dev_name(dev_area->dev), rlocn->size, mdah->size - MDA_HEADER_SIZE);
		vfmp->ret = 0;
		goto out;
	}

	/* Did we see this metadata before? */
	vgsummary->mda_checksum = rlocn->checksum;
	vgsummary->mda_size = rlocn->size;

	if (lvmcache_lookup_mda(vgsummary))
		vfmp->used_cached_metadata = 1;

	/* FIXME 64-bit */
	if (!text_vgsummary_import(fmt, dev_area->dev, MDA_CONTENT_REASON(vfmp->primary_mda),
				(off_t) (dev_area->start + rlocn->offset),
				(uint32_t) (rlocn->size - vfmp->wrap),
				(off_t) (dev_area->start + MDA_HEADER_SIZE),
				vfmp->wrap, calc_crc, vgsummary->vgname ? 1 : 0, ioflags,
				vgsummary, _vgname_from_mda_process, vfmp)) {
		vfmp->ret = 0;
		goto_out;
	}

out:
	if (!vfmp->ret && vfmp->update_vgsummary_fn)
		vfmp->update_vgsummary_fn(1, ioflags, vfmp->update_vgsummary_context, vfmp->vgsummary);
}

int vgname_from_mda(const struct format_type *fmt,
		    const struct mda_header *mdah, int primary_mda, struct device_area *dev_area,
		    struct lvmcache_vgsummary *vgsummary, uint64_t *mda_free_sectors, unsigned ioflags,
		    lvm_callback_fn_t update_vgsummary_fn, void *update_vgsummary_context)
{
	const struct raw_locn *rlocn;
	struct vgname_from_mda_params *vfmp;

	if (mda_free_sectors)
		*mda_free_sectors = ((dev_area->size - MDA_HEADER_SIZE) / 2) >> SECTOR_SHIFT;

	if (!mdah) {
		log_error(INTERNAL_ERROR "vgname_from_mda called with NULL pointer for mda_header");
		return 0;
	}

	/* FIXME Cope with returning a list */
	rlocn = mdah->raw_locns;

	/*
	 * If no valid offset, do not try to search for vgname
	 */
	if (!rlocn->offset) {
		log_debug("%s: found metadata with offset 0.",
			  dev_name(dev_area->dev));
		return 0;
	}

	if (!(vfmp = dm_pool_zalloc(fmt->cmd->mem, sizeof(*vfmp)))) {
		log_error("vgname_from_mda_params allocation failed");
		return 0;
	}

	vfmp->fmt = fmt;
	vfmp->mdah = mdah;
	vfmp->dev_area = dev_area;
	vfmp->vgsummary = vgsummary;
	vfmp->primary_mda = primary_mda;
	vfmp->mda_free_sectors = mda_free_sectors;
	vfmp->update_vgsummary_fn = update_vgsummary_fn;
	vfmp->update_vgsummary_context = update_vgsummary_context;
	vfmp->ret = 1;

	/* Do quick check for a vgname */
	/* We cannot read the full metadata here because the name has to be validated before we use the size field */
	dev_read_callback(dev_area->dev, dev_area->start + rlocn->offset, NAME_LEN, MDA_CONTENT_REASON(primary_mda),
			       ioflags, _vgname_from_mda_validate, vfmp);
	if (update_vgsummary_fn)
		return 1;
	else
		return vfmp->ret;
}

static int _scan_raw(const struct format_type *fmt, const char *vgname __attribute__((unused)))
{
	struct raw_list *rl;
	struct dm_list *raw_list;
	struct volume_group *vg;
	struct format_instance fid;
	struct lvmcache_vgsummary vgsummary = { 0 };
	struct mda_header *mdah;

	raw_list = &((struct mda_lists *) fmt->private)->raws;

	fid.fmt = fmt;
	dm_list_init(&fid.metadata_areas_in_use);
	dm_list_init(&fid.metadata_areas_ignored);

	dm_list_iterate_items(rl, raw_list) {
		/* FIXME We're reading mdah twice here... */
		if (!dev_open_readonly(rl->dev_area.dev)) {
			stack;
			continue;
		}

		if (!(mdah = raw_read_mda_header(fmt->cmd->mem, &rl->dev_area, 0))) {
			stack;
			goto close_dev;
		}

		/* TODO: caching as in vgname_from_mda() (trigger this code?) */
		if (vgname_from_mda(fmt, mdah, 0, &rl->dev_area, &vgsummary, NULL, 0, NULL, NULL)) {
			vg = _vg_read_raw_area(&fid, vgsummary.vgname, &rl->dev_area, NULL, NULL, 0, 0, 0, 0);
			if (vg)
				lvmcache_update_vg(vg, 0);
		}
	close_dev:
		if (!dev_close(rl->dev_area.dev))
			stack;
	}

	return 1;
}

static int _text_scan(const struct format_type *fmt, const char *vgname)
{
	return (_scan_file(fmt, vgname) & _scan_raw(fmt, vgname));
}

struct _write_single_mda_baton {
	const struct format_type *fmt;
	struct physical_volume *pv;
};

static int _write_single_mda(struct metadata_area *mda, void *baton)
{
	struct _write_single_mda_baton *p = baton;
	struct mda_context *mdac;

	char buf[MDA_HEADER_SIZE] __attribute__((aligned(8))) = { 0 };
	struct mda_header *mdah = (struct mda_header *) buf;

	mdac = mda->metadata_locn;
	mdah->size = mdac->area.size;
	rlocn_set_ignored(mdah->raw_locns, mda_is_ignored(mda));

	if (!_raw_write_mda_header(p->fmt, mdac->area.dev, mda_is_primary(mda),
				   mdac->area.start, mdah)) {
		if (!dev_close(p->pv->dev))
			stack;
		return_0;
	}
	return 1;
}

static int _set_ext_flags(struct physical_volume *pv, struct lvmcache_info *info)
{
	uint32_t ext_flags = lvmcache_ext_flags(info);

	if (is_orphan(pv))
		ext_flags &= ~PV_EXT_USED;
	else
		ext_flags |= PV_EXT_USED;

	lvmcache_set_ext_version(info, PV_HEADER_EXTENSION_VSN);
	lvmcache_set_ext_flags(info, ext_flags);

	return 1;
}

/* Only for orphans - FIXME That's not true any more */
static int _text_pv_write(const struct format_type *fmt, struct physical_volume *pv)
{
	struct format_instance *fid = pv->fid;
	const char *pvid = (const char *) (*pv->old_id.uuid ? &pv->old_id : &pv->id);
	struct label *label;
	struct lvmcache_info *info;
	struct mda_context *mdac;
	struct metadata_area *mda;
	struct _write_single_mda_baton baton;
	unsigned mda_index;

	/* Add a new cache entry with PV info or update existing one. */
	if (!(info = lvmcache_add(fmt->labeller, (const char *) &pv->id,
				  pv->dev, pv->vg_name,
				  is_orphan_vg(pv->vg_name) ? pv->vg_name : pv->vg ? (const char *) &pv->vg->id : NULL, 0)))
		return_0;

	label = lvmcache_get_label(info);
	label->sector = pv->label_sector;
	label->dev = pv->dev;

	lvmcache_update_pv(info, pv, fmt);

	/* Flush all cached metadata areas, we will reenter new/modified ones. */
	lvmcache_del_mdas(info);

	/*
	 * Add all new or modified metadata areas for this PV stored in
	 * its format instance. If this PV is not part of a VG yet,
	 * pv->fid will be used. Otherwise pv->vg->fid will be used.
	 * The fid_get_mda_indexed fn can handle that transparently,
	 * just pass the right format_instance in.
	 */
	for (mda_index = 0; mda_index < FMT_TEXT_MAX_MDAS_PER_PV; mda_index++) {
		if (!(mda = fid_get_mda_indexed(fid, pvid, ID_LEN, mda_index)))
			continue;

		mdac = (struct mda_context *) mda->metadata_locn;
		log_debug_metadata("Creating metadata area on %s at sector "
				   FMTu64 " size " FMTu64 " sectors",
				   dev_name(mdac->area.dev),
				   mdac->area.start >> SECTOR_SHIFT,
				   mdac->area.size >> SECTOR_SHIFT);

		// if fmt is not the same as info->fmt we are in trouble
		if (!lvmcache_add_mda(info, mdac->area.dev,
				      mdac->area.start, mdac->area.size,
				      mda_is_ignored(mda)))
			return_0;
	}

	if (!lvmcache_update_bas(info, pv))
		return_0;

	/*
	 * FIXME: Allow writing zero offset/size data area to disk.
	 *        This requires defining a special value since we can't
	 *        write offset/size that is 0/0 - this is already reserved
	 *        as a delimiter in data/metadata area area list in PV header
	 *        (needs exploring compatibility with older lvm2).
	 */

	/*
	 * We can't actually write pe_start = 0 (a data area offset)
	 * in PV header now. We need to replace this value here. This can
	 * happen with vgcfgrestore with redefined pe_start or
	 * pvcreate --restorefile. However, we can can have this value in
	 * metadata which will override the value in the PV header.
	 */

	if (!lvmcache_update_das(info, pv))
		return_0;

	if (!dev_open(pv->dev))
		return_0;

	baton.pv = pv;
	baton.fmt = fmt;

	if (!lvmcache_foreach_mda(info, _write_single_mda, &baton))
		return_0;

	if (!_set_ext_flags(pv, info))
		return_0;

	if (!label_write(pv->dev, label)) {
		stack;
		if (!dev_close(pv->dev))
			stack;
		return 0;
	}

	/*
	 *  FIXME: We should probably use the format instance's metadata
	 *        areas for label_write and only if it's successful,
	 *        update the cache afterwards?
	 */

	if (!dev_close(pv->dev))
		return_0;

	return 1;
}

static int _text_pv_needs_rewrite(const struct format_type *fmt, struct physical_volume *pv,
				  int *needs_rewrite)
{
	struct lvmcache_info *info;
	uint32_t ext_vsn;

	*needs_rewrite = 0;

	if (!pv->is_labelled)
		return 1;

	if (!(info = lvmcache_info_from_pvid((const char *)&pv->id, pv->dev, 0))) {
		log_error("Failed to find cached info for PV %s.", pv_dev_name(pv));
		return 0;
	}

	ext_vsn = lvmcache_ext_version(info);

	if (ext_vsn < PV_HEADER_EXTENSION_VSN)
		*needs_rewrite = 1;

	return 1;
}

static int _add_raw(struct dm_list *raw_list, struct device_area *dev_area)
{
	struct raw_list *rl;

	/* Already present? */
	dm_list_iterate_items(rl, raw_list) {
		/* FIXME Check size/overlap consistency too */
		if (rl->dev_area.dev == dev_area->dev &&
		    rl->dev_area.start == dev_area->start)
			return 1;
	}

	if (!(rl = dm_malloc(sizeof(struct raw_list)))) {
		log_error("_add_raw allocation failed");
		return 0;
	}
	memcpy(&rl->dev_area, dev_area, sizeof(*dev_area));
	dm_list_add(raw_list, &rl->list);

	return 1;
}

/*
 * Copy constructor for a metadata_locn.
 */
static void *_metadata_locn_copy_raw(struct dm_pool *mem, void *metadata_locn)
{
	struct mda_context *mdac, *mdac_new;

	mdac = (struct mda_context *) metadata_locn;
	if (!(mdac_new = dm_pool_alloc(mem, sizeof(*mdac_new)))) {
		log_error("mda_context allocation failed");
		return NULL;
	}
	memcpy(mdac_new, mdac, sizeof(*mdac));

	return mdac_new;
}

/*
 * Return a string description of the metadata location.
 */
static const char *_metadata_locn_name_raw(void *metadata_locn)
{
	struct mda_context *mdac = (struct mda_context *) metadata_locn;

	return dev_name(mdac->area.dev);
}

static uint64_t _metadata_locn_offset_raw(void *metadata_locn)
{
	struct mda_context *mdac = (struct mda_context *) metadata_locn;

	return mdac->area.start;
}

static int _text_pv_read(const struct format_type *fmt, const char *pv_name,
		    struct physical_volume *pv, int scan_label_only)
{
	struct lvmcache_info *info;
	struct device *dev;

	if (!(dev = dev_cache_get(pv_name, fmt->cmd->filter)))
		return_0;

	if (lvmetad_used()) {
		info = lvmcache_info_from_pvid(dev->pvid, dev, 0);
		if (!info && !lvmetad_pv_lookup_by_dev(fmt->cmd, dev, NULL))
			return 0;
		info = lvmcache_info_from_pvid(dev->pvid, dev, 0);
	} else {
		struct label *label;
		if (!(label_read(dev, &label, UINT64_C(0))))
			return_0;
		info = label->info;
	}

	if (!info)
		return_0;

	if (!lvmcache_populate_pv_fields(info, pv, scan_label_only))
		return 0;

	return 1;
}

static int _text_pv_initialise(const struct format_type *fmt,
			       struct pv_create_args *pva,
			       struct physical_volume *pv)
{
	unsigned long data_alignment = pva->data_alignment;
	unsigned long data_alignment_offset = pva->data_alignment_offset;
	unsigned long adjustment, final_alignment = 0;

	if (!data_alignment)
		data_alignment = find_config_tree_int(pv->fmt->cmd, devices_data_alignment_CFG, NULL) * 2;

	if (set_pe_align(pv, data_alignment) != data_alignment &&
	    data_alignment) {
		log_error("%s: invalid data alignment of "
			  "%lu sectors (requested %lu sectors)",
			  pv_dev_name(pv), pv->pe_align, data_alignment);
		return 0;
	}

	if (set_pe_align_offset(pv, data_alignment_offset) != data_alignment_offset &&
	    data_alignment_offset) {
		log_error("%s: invalid data alignment offset of "
			  "%lu sectors (requested %lu sectors)",
			  pv_dev_name(pv), pv->pe_align_offset, data_alignment_offset);
		return 0;
	}

	if (pv->pe_align < pv->pe_align_offset) {
		log_error("%s: pe_align (%lu sectors) must not be less "
			  "than pe_align_offset (%lu sectors)",
			  pv_dev_name(pv), pv->pe_align, pv->pe_align_offset);
		return 0;
	}

	final_alignment = pv->pe_align + pv->pe_align_offset;

	if (pv->size < final_alignment) {
		log_error("%s: Data alignment must not exceed device size.",
			  pv_dev_name(pv));
		return 0;
	}

	if (pv->size < final_alignment + pva->ba_size) {
		log_error("%s: Bootloader area with data-aligned start must "
			  "not exceed device size.", pv_dev_name(pv));
		return 0;
	}

	if (pva->pe_start == PV_PE_START_CALC) {
		/*
		 * Calculate new PE start and bootloader area start value.
		 * Make sure both are properly aligned!
		 * If PE start can't be aligned because BA is taking
		 * the whole space, make PE start equal to the PV size
		 * which effectively disables DA - it will have zero size.
		 * This needs to be done as we can't have a PV without any DA.
		 * But we still want to support a PV with BA only!
		 */
		if (pva->ba_size) {
			pv->ba_start = final_alignment;
			pv->ba_size = pva->ba_size;
			if ((adjustment = pva->ba_size % pv->pe_align))
				pv->ba_size += pv->pe_align - adjustment;
			if (pv->size < pv->ba_start + pv->ba_size)
				pv->ba_size = pv->size - pv->ba_start;
			pv->pe_start = pv->ba_start + pv->ba_size;
		} else
			pv->pe_start = final_alignment;
	} else {
		/*
		 * Try to keep the value of PE start set to a firm value if
		 * requested. This is useful when restoring existing PE start
		 * value (e.g. backups). Also, if creating a BA, try to place
		 * it in between the final alignment and existing PE start
		 * if possible.
		 */
		pv->pe_start = pva->pe_start;
		if (pva->ba_size) {
			if ((pva->ba_start && pva->ba_start + pva->ba_size > pva->pe_start) ||
			    (pva->pe_start <= final_alignment) ||
			    (pva->pe_start - final_alignment < pva->ba_size)) {
				log_error("%s: Bootloader area would overlap "
					  "data area.", pv_dev_name(pv));
				return 0;
			}

			pv->ba_start = pva->ba_start ? : final_alignment;
			pv->ba_size = pva->ba_size;
		}
	}

	if (pva->extent_size)
		pv->pe_size = pva->extent_size;

	if (pva->extent_count)
		pv->pe_count = pva->extent_count;

	if ((pv->pe_start + pv->pe_count * (uint64_t)pv->pe_size - 1) > pv->size) {
		log_error("Physical extents end beyond end of device %s.",
			  pv_dev_name(pv));
		return 0;
	}

	if (pva->label_sector != -1)
                pv->label_sector = pva->label_sector;

	return 1;
}

static void _text_destroy_instance(struct format_instance *fid)
{
	if (--fid->ref_count <= 1) {
		if (fid->metadata_areas_index)
			dm_hash_destroy(fid->metadata_areas_index);
		dm_pool_destroy(fid->mem);
	}
}

static void _free_dirs(struct dm_list *dir_list)
{
	struct dm_list *dl, *tmp;

	dm_list_iterate_safe(dl, tmp, dir_list) {
		dm_list_del(dl);
		dm_free(dl);
	}
}

static void _free_raws(struct dm_list *raw_list)
{
	struct dm_list *rl, *tmp;

	dm_list_iterate_safe(rl, tmp, raw_list) {
		dm_list_del(rl);
		dm_free(rl);
	}
}

static void _text_destroy(struct format_type *fmt)
{
	if (fmt->orphan_vg)
		free_orphan_vg(fmt->orphan_vg);

	if (fmt->private) {
		_free_dirs(&((struct mda_lists *) fmt->private)->dirs);
		_free_raws(&((struct mda_lists *) fmt->private)->raws);
		dm_free(fmt->private);
	}

	dm_free(fmt);
}

static struct metadata_area_ops _metadata_text_file_ops = {
	.vg_read = _vg_read_file,
	.vg_read_precommit = _vg_read_precommit_file,
	.vg_write = _vg_write_file,
	.vg_remove = _vg_remove_file,
	.vg_commit = _vg_commit_file
};

static struct metadata_area_ops _metadata_text_file_backup_ops = {
	.vg_read = _vg_read_file,
	.vg_write = _vg_write_file,
	.vg_remove = _vg_remove_file,
	.vg_commit = _vg_commit_file_backup
};

static int _mda_export_text_raw(struct metadata_area *mda,
				struct dm_config_tree *cft,
				struct dm_config_node *parent);
static int _mda_import_text_raw(struct lvmcache_info *info, const struct dm_config_node *cn);

static struct metadata_area_ops _metadata_text_raw_ops = {
	.vg_read = _vg_read_raw,
	.vg_read_precommit = _vg_read_precommit_raw,
	.vg_write = _vg_write_raw,
	.vg_remove = _vg_remove_raw,
	.vg_precommit = _vg_precommit_raw,
	.vg_commit = _vg_commit_raw,
	.vg_revert = _vg_revert_raw,
	.mda_metadata_locn_copy = _metadata_locn_copy_raw,
	.mda_metadata_locn_name = _metadata_locn_name_raw,
	.mda_metadata_locn_offset = _metadata_locn_offset_raw,
	.mda_free_sectors = _mda_free_sectors_raw,
	.mda_total_sectors = _mda_total_sectors_raw,
	.mda_in_vg = _mda_in_vg_raw,
	.pv_analyze_mda = _pv_analyze_mda_raw,
	.mda_locns_match = _mda_locns_match_raw,
	.mda_get_device = _mda_get_device_raw,
	.mda_export_text = _mda_export_text_raw,
	.mda_import_text = _mda_import_text_raw
};

static int _mda_export_text_raw(struct metadata_area *mda,
				struct dm_config_tree *cft,
				struct dm_config_node *parent)
{
	struct mda_context *mdc = (struct mda_context *) mda->metadata_locn;

	if (!mdc || !_raw_read_mda_header(cft->mem, &mdc->area, mda_is_primary(mda), 0, NULL, NULL))
		return 1; /* pretend the MDA does not exist */

	return config_make_nodes(cft, parent, NULL,
				 "ignore = " FMTd64, (int64_t) mda_is_ignored(mda),
				 "start = " FMTd64, (int64_t) mdc->area.start,
				 "size = " FMTd64, (int64_t) mdc->area.size,
				 "free_sectors = " FMTd64, (int64_t) mdc->free_sectors,
				 NULL) ? 1 : 0;
}

static int _mda_import_text_raw(struct lvmcache_info *info, const struct dm_config_node *cn)
{
	struct device *device;
	uint64_t offset;
	uint64_t size;
	int ignore;

	if (!cn->child)
		return 0;

	cn = cn->child;
	device = lvmcache_device(info);
	size = dm_config_find_int64(cn, "size", 0);

	if (!device || !size)
		return 0;

	offset = dm_config_find_int64(cn, "start", 0);
	ignore = dm_config_find_int(cn, "ignore", 0);

	lvmcache_add_mda(info, device, offset, size, ignore);

	return 1;
}

static int _text_pv_setup(const struct format_type *fmt,
			  struct physical_volume *pv,
			  struct volume_group *vg)
{
	struct format_instance *fid = pv->fid;
	const char *pvid = (const char *) (*pv->old_id.uuid ? &pv->old_id : &pv->id);
	struct lvmcache_info *info;
	unsigned mda_index;
	struct metadata_area *pv_mda, *pv_mda_copy;
	struct mda_context *pv_mdac;
	uint64_t pe_count;
	uint64_t size_reduction = 0;

	/* If PV has its own format instance, add mdas from pv->fid to vg->fid. */
	if (pv->fid != vg->fid) {
		for (mda_index = 0; mda_index < FMT_TEXT_MAX_MDAS_PER_PV; mda_index++) {
			if (!(pv_mda = fid_get_mda_indexed(fid, pvid, ID_LEN, mda_index)))
				continue;

			/* Be sure it's not already in VG's format instance! */
			if (!fid_get_mda_indexed(vg->fid, pvid, ID_LEN, mda_index)) {
				if (!(pv_mda_copy = mda_copy(vg->fid->mem, pv_mda)))
					return_0;
				fid_add_mda(vg->fid, pv_mda_copy, pvid, ID_LEN, mda_index);
			}
		}
	}
	/*
	 * Otherwise, if the PV is already a part of the VG (pv->fid == vg->fid),
	 * reread PV mda information from the cache and add it to vg->fid.
	 */
	else {
		if (!pv->dev ||
		    !(info = lvmcache_info_from_pvid(pv->dev->pvid, pv->dev, 0))) {
			log_error("PV %s missing from cache", pv_dev_name(pv));
			return 0;
		}

		if (!lvmcache_check_format(info, fmt))
			return_0;

		if (!lvmcache_fid_add_mdas_pv(info, fid))
			return_0;
	}

	/* If there's the 2nd mda, we need to reduce
	 * usable size for further pe_count calculation! */
	if ((pv_mda = fid_get_mda_indexed(fid, pvid, ID_LEN, 1)) &&
	    (pv_mdac = pv_mda->metadata_locn))
		size_reduction = pv_mdac->area.size >> SECTOR_SHIFT;

	/* From now on, VG format instance will be used. */
	pv_set_fid(pv, vg->fid);

	/* FIXME Cope with genuine pe_count 0 */

	/* If missing, estimate pv->size from file-based metadata */
	if (!pv->size && pv->pe_count)
		pv->size = pv->pe_count * (uint64_t) vg->extent_size +
			   pv->pe_start + size_reduction;

	/* Recalculate number of extents that will fit */
	if (!pv->pe_count && vg->extent_size) {
		pe_count = (pv->size - pv->pe_start - size_reduction) /
			   vg->extent_size;
		if (pe_count > UINT32_MAX) {
			log_error("PV %s too large for extent size %s.",
				  pv_dev_name(pv),
				  display_size(vg->cmd, (uint64_t) vg->extent_size));
			return 0;
		}
		pv->pe_count = (uint32_t) pe_count;
	}

	return 1;
}

static void *_create_text_context(struct dm_pool *mem, struct text_context *tc)
{
	struct text_context *new_tc;
	const char *path;
	char *tmp;

	if (!tc)
		return NULL;

	path = tc->path_live;

	if ((tmp = strstr(path, ".tmp")) && (tmp == path + strlen(path) - 4)) {
		log_error("%s: Volume group filename may not end in .tmp",
			  path);
		return NULL;
	}

	if (!(new_tc = dm_pool_alloc(mem, sizeof(*new_tc))))
		return_NULL;

	if (!(new_tc->path_live = dm_pool_strdup(mem, path)))
		goto_bad;

	/* If path_edit not defined, create one from path_live with .tmp suffix. */
	if (!tc->path_edit) {
		if (!(tmp = dm_pool_alloc(mem, strlen(path) + 5)))
			goto_bad;
		sprintf(tmp, "%s.tmp", path);
		new_tc->path_edit = tmp;
	}
	else if (!(new_tc->path_edit = dm_pool_strdup(mem, tc->path_edit)))
		goto_bad;

	if (!(new_tc->desc = tc->desc ? dm_pool_strdup(mem, tc->desc)
				      : dm_pool_strdup(mem, "")))
		goto_bad;

	return (void *) new_tc;

      bad:
	dm_pool_free(mem, new_tc);

	log_error("Couldn't allocate text format context object.");
	return NULL;
}

static int _create_vg_text_instance(struct format_instance *fid,
                                    const struct format_instance_ctx *fic)
{
	static char path[PATH_MAX];
	uint32_t type = fic->type;
	struct text_fid_context *fidtc;
	struct metadata_area *mda;
	struct mda_context *mdac;
	struct dir_list *dl;
	struct raw_list *rl;
	struct dm_list *dir_list, *raw_list;
	struct text_context tc;
	struct lvmcache_vginfo *vginfo;
	const char *vg_name, *vg_id;

	if (!(fidtc = (struct text_fid_context *)
			dm_pool_zalloc(fid->mem, sizeof(*fidtc)))) {
		log_error("Couldn't allocate text_fid_context.");
		return 0;
	}

	fid->private = (void *) fidtc;

	if (type & FMT_INSTANCE_PRIVATE_MDAS) {
		if (!(mda = dm_pool_zalloc(fid->mem, sizeof(*mda))))
			return_0;
		mda->ops = &_metadata_text_file_backup_ops;
		mda->metadata_locn = _create_text_context(fid->mem, fic->context.private);
		mda->status = 0;
		fid->metadata_areas_index = NULL;
		fid_add_mda(fid, mda, NULL, 0, 0);
	} else {
		vg_name = fic->context.vg_ref.vg_name;
		vg_id = fic->context.vg_ref.vg_id;

		if (!(fid->metadata_areas_index = dm_hash_create(128))) {
			log_error("Couldn't create metadata index for format "
				  "instance of VG %s.", vg_name);
			return 0;
		}

		if (type & FMT_INSTANCE_AUX_MDAS) {
			dir_list = &((struct mda_lists *) fid->fmt->private)->dirs;
			dm_list_iterate_items(dl, dir_list) {
				if (dm_snprintf(path, PATH_MAX, "%s/%s", dl->dir, vg_name) < 0) {
					log_error("Name too long %s/%s", dl->dir, vg_name);
					return 0;
				}

				if (!(mda = dm_pool_zalloc(fid->mem, sizeof(*mda))))
					return_0;
				mda->ops = &_metadata_text_file_ops;
				tc.path_live = path;
				tc.path_edit = tc.desc = NULL;
				mda->metadata_locn = _create_text_context(fid->mem, &tc);
				mda->status = 0;
				fid_add_mda(fid, mda, NULL, 0, 0);
			}

			raw_list = &((struct mda_lists *) fid->fmt->private)->raws;
			dm_list_iterate_items(rl, raw_list) {
				/* FIXME Cache this; rescan below if some missing */
				if (!_raw_holds_vgname(fid, &rl->dev_area, vg_name))
					continue;

				if (!(mda = dm_pool_zalloc(fid->mem, sizeof(*mda))))
					return_0;

				if (!(mdac = dm_pool_zalloc(fid->mem, sizeof(*mdac))))
					return_0;
				mda->metadata_locn = mdac;
				/* FIXME Allow multiple dev_areas inside area */
				memcpy(&mdac->area, &rl->dev_area, sizeof(mdac->area));
				mda->ops = &_metadata_text_raw_ops;
				mda->status = 0;
				/* FIXME MISTAKE? mda->metadata_locn = context; */
				fid_add_mda(fid, mda, NULL, 0, 0);
			}
		}

		if (type & FMT_INSTANCE_MDAS) {
			/*
			 * TODO in theory, this function should be never reached
			 * while in critical_section(), because lvmcache's
			 * cached_vg should be valid. However, this assumption
			 * sometimes fails (possibly due to inconsistent
			 * (precommit) metadata and/or missing devices), and
			 * calling lvmcache_label_scan inside the critical
			 * section may be fatal (i.e. deadlock).
			 */
			if (!critical_section())
				/* Scan PVs in VG for any further MDAs */
				/*
				 * FIXME Only scan PVs believed to be in the VG.
 				 */
				lvmcache_label_scan(fid->fmt->cmd);

			if (!(vginfo = lvmcache_vginfo_from_vgname(vg_name, vg_id)))
				goto_out;
			if (!lvmcache_fid_add_mdas_vg(vginfo, fid))
				goto_out;
		}

		/* FIXME If PV list or raw metadata area count are not as expected rescan */
	}

out:
	return 1;
}

static int _add_metadata_area_to_pv(struct physical_volume *pv,
				    unsigned mda_index,
				    uint64_t mda_start,
				    uint64_t mda_size,
				    unsigned mda_ignored)
{
	struct metadata_area *mda;
	struct mda_context *mdac;
	struct mda_lists *mda_lists = (struct mda_lists *) pv->fmt->private;

	if (mda_index >= FMT_TEXT_MAX_MDAS_PER_PV) {
		log_error(INTERNAL_ERROR "can't add metadata area with "
					 "index %u to PV %s. Metadata "
					 "layout not supported by %s format.",
					  mda_index, dev_name(pv->dev),
					  pv->fmt->name);
	}

	if (!(mda = dm_pool_zalloc(pv->fid->mem, sizeof(struct metadata_area)))) {
		log_error("struct metadata_area allocation failed");
		return 0;
	}

	if (!(mdac = dm_pool_zalloc(pv->fid->mem, sizeof(struct mda_context)))) {
		log_error("struct mda_context allocation failed");
		dm_free(mda);
		return 0;
	}

	mda->ops = mda_lists->raw_ops;
	mda->metadata_locn = mdac;
	mda->status = 0;

	mdac->area.dev = pv->dev;
	mdac->area.start = mda_start;
	mdac->area.size = mda_size;
	mdac->free_sectors = UINT64_C(0);
	memset(&mdac->rlocn, 0, sizeof(mdac->rlocn));
	mda_set_ignored(mda, mda_ignored);

	fid_add_mda(pv->fid, mda, (char *) &pv->id, ID_LEN, mda_index);

	return 1;
}

static int _text_pv_remove_metadata_area(const struct format_type *fmt,
					 struct physical_volume *pv,
					 unsigned mda_index);

static int _text_pv_add_metadata_area(const struct format_type *fmt,
				      struct physical_volume *pv,
				      int pe_start_locked,
				      unsigned mda_index,
				      uint64_t mda_size,
				      unsigned mda_ignored)
{
	struct format_instance *fid = pv->fid;
	const char *pvid = (const char *) (*pv->old_id.uuid ? &pv->old_id : &pv->id);
	uint64_t ba_size, pe_start, first_unallocated;
	uint64_t alignment, alignment_offset;
	uint64_t disk_size;
	uint64_t mda_start;
	uint64_t adjustment, limit, tmp_mda_size;
	uint64_t wipe_size = 8 << SECTOR_SHIFT;
	size_t page_size = lvm_getpagesize();
	struct metadata_area *mda;
	struct mda_context *mdac;
	const char *limit_name;
	int limit_applied = 0;

	if (mda_index >= FMT_TEXT_MAX_MDAS_PER_PV) {
		log_error(INTERNAL_ERROR "invalid index of value %u used "
			      "while trying to add metadata area on PV %s. "
			      "Metadata layout not supported by %s format.",
			       mda_index, pv_dev_name(pv), fmt->name);
		return 0;
	}

	pe_start = pv->pe_start << SECTOR_SHIFT;
	ba_size = pv->ba_size << SECTOR_SHIFT;
	alignment = pv->pe_align << SECTOR_SHIFT;
	alignment_offset = pv->pe_align_offset << SECTOR_SHIFT;
	disk_size = pv->size << SECTOR_SHIFT;
	mda_size = mda_size << SECTOR_SHIFT;

	if (fid_get_mda_indexed(fid, pvid, ID_LEN, mda_index)) {
		if (!_text_pv_remove_metadata_area(fmt, pv, mda_index)) {
			log_error(INTERNAL_ERROR "metadata area with index %u already "
				  "exists on PV %s and removal failed.",
				  mda_index, pv_dev_name(pv));
			return 0;
		}
	}

	/* First metadata area at the start of the device. */
	if (mda_index == 0) {
		/*
		 * Try to fit MDA0 end within given pe_start limit if its value
		 * is locked. If it's not locked, count with any existing MDA1.
		 * If there's no MDA1, just use disk size as the limit.
		 */
		if (pe_start_locked) {
			limit = pe_start;
			limit_name = "pe_start";
		}
		else if ((mda = fid_get_mda_indexed(fid, pvid, ID_LEN, 1)) &&
			 (mdac = mda->metadata_locn)) {
			limit = mdac->area.start;
			limit_name = "MDA1 start";
		}
		else {
			limit = disk_size;
			limit_name = "disk size";
		}

		/* Adjust limits for bootloader area if present. */
		if (ba_size) {
			limit -= ba_size;
			limit_name = "ba_start";
		}

		if (limit > disk_size)
			goto bad;

		mda_start = LABEL_SCAN_SIZE;

		/* Align MDA0 start with page size if possible. */
		if (limit - mda_start >= MDA_SIZE_MIN) {
			if ((adjustment = mda_start % page_size))
				mda_start += (page_size - adjustment);
		}

		/* Align MDA0 end position with given alignment if possible. */
		if (alignment &&
		    (adjustment = (mda_start + mda_size) % alignment)) {
			tmp_mda_size = mda_size + alignment - adjustment;
			if (mda_start + tmp_mda_size <= limit)
				mda_size = tmp_mda_size;
		}

		/* Align MDA0 end position with given alignment offset if possible. */
		if (alignment && alignment_offset &&
		    (((mda_start + mda_size) % alignment) == 0)) {
			tmp_mda_size = mda_size + alignment_offset;
			if (mda_start + tmp_mda_size <= limit)
				mda_size = tmp_mda_size;
		}

		if (mda_start + mda_size > limit) {
			/*
			 * Try to decrease the MDA0 size with twice the
			 * alignment and then align with given alignment.
			 * If pe_start is locked, skip this type of
			 * alignment since it would be useless.
			 * Check first whether we can apply that!
			 */
			if (!pe_start_locked && alignment &&
			    ((limit - mda_start) > alignment * 2)) {
				mda_size = limit - mda_start - alignment * 2;

				if ((adjustment = (mda_start + mda_size) % alignment))
					mda_size += (alignment - adjustment);

				/* Still too much? Then there's nothing else to do. */
				if (mda_start + mda_size > limit)
					goto bad;
			}
			/* Otherwise, give up and take any usable space. */
			else
				mda_size = limit - mda_start;

			limit_applied = 1;
		}

		/*
		 * If PV's pe_start is not locked, update pe_start value with the
		 * start of the area that follows the MDA0 we've just calculated.
		 */
		if (!pe_start_locked) {
			if (ba_size) {
				pv->ba_start = (mda_start + mda_size) >> SECTOR_SHIFT;
				pv->pe_start = pv->ba_start + pv->ba_size;
			} else
				pv->pe_start = (mda_start + mda_size) >> SECTOR_SHIFT;
		}
	}
	/* Second metadata area at the end of the device. */
	else {
		/*
		 * Try to fit MDA1 start within given pe_end or pe_start limit
		 * if defined or locked. If pe_start is not defined yet, count
		 * with any existing MDA0. If MDA0 does not exist, just use
		 * LABEL_SCAN_SIZE.
		 *
		 * The first_unallocated here is the first unallocated byte
		 * beyond existing pe_end if there is any preallocated data area
		 * reserved already so we can take that as lower limit for our MDA1
		 * start calculation. If data area is not reserved yet, we set
		 * first_unallocated to 0, meaning this is not our limiting factor
		 * and we will look at other limiting factors if they exist.
		 * Of course, if we have preallocated data area, we also must
		 * have pe_start assigned too (simply, data area needs its start
		 * and end specification).
		 */
		first_unallocated = pv->pe_count ? (pv->pe_start + pv->pe_count *
						    (uint64_t)pv->pe_size) << SECTOR_SHIFT
						 : 0;

		if (pe_start || pe_start_locked) {
			limit = first_unallocated ? first_unallocated : pe_start;
			limit_name = first_unallocated ? "pe_end" : "pe_start";
		} else {
			if ((mda = fid_get_mda_indexed(fid, pvid, ID_LEN, 0)) &&
				 (mdac = mda->metadata_locn)) {
				limit = mdac->area.start + mdac->area.size;
				limit_name = "MDA0 end";
			}
			else {
				limit = LABEL_SCAN_SIZE;
				limit_name = "label scan size";
			}

			/* Adjust limits for bootloader area if present. */
			if (ba_size) {
				limit += ba_size;
				limit_name = "ba_end";
			}
		}

		if (limit >= disk_size)
			goto bad;

		if (mda_size > disk_size) {
			mda_size = disk_size - limit;
			limit_applied = 1;
		}

		mda_start = disk_size - mda_size;

		/* If MDA1 size is too big, just take any usable space. */
		if (disk_size - mda_size < limit) {
			mda_size = disk_size - limit;
			mda_start = disk_size - mda_size;
			limit_applied = 1;
		}
		/* Otherwise, try to align MDA1 start if possible. */
		else if (alignment &&
		    (adjustment = mda_start % alignment)) {
			tmp_mda_size = mda_size + adjustment;
			if (tmp_mda_size < disk_size &&
			    disk_size - tmp_mda_size >= limit) {
				mda_size = tmp_mda_size;
				mda_start = disk_size - mda_size;
			}
		}
	}

	if (limit_applied)
		log_very_verbose("Using limited metadata area size on %s "
				 "with value " FMTu64 " (limited by %s of "
				 FMTu64 ").", pv_dev_name(pv),
				  mda_size, limit_name, limit);

	if (mda_size) {
		if (mda_size < MDA_SIZE_MIN) {
			log_error("Metadata area size too small: " FMTu64 " bytes. "
				  "It must be at least %u bytes.", mda_size, MDA_SIZE_MIN);
			goto bad;
		}

		/* Wipe metadata area with zeroes. */
		if (!dev_set(pv->dev, mda_start,
			     (size_t) ((mda_size > wipe_size) ?  wipe_size : mda_size),
			     MDA_HEADER_REASON(!mda_index), 0)) {
			log_error("Failed to wipe new metadata area "
				  "at the %s of the %s",
				   mda_index ? "end" : "start",
				   pv_dev_name(pv));
			return 0;
		}

		/* Finally, add new metadata area to PV's format instance. */
		if (!_add_metadata_area_to_pv(pv, mda_index, mda_start,
					      mda_size, mda_ignored))
			return_0;
	}

	return 1;

bad:
	log_error("Not enough space available for metadata area "
		  "with index %u on PV %s.", mda_index, pv_dev_name(pv));
	return 0;
}

static int _remove_metadata_area_from_pv(struct physical_volume *pv,
					 unsigned mda_index)
{
	if (mda_index >= FMT_TEXT_MAX_MDAS_PER_PV) {
		log_error(INTERNAL_ERROR "can't remove metadata area with "
					 "index %u from PV %s. Metadata "
					 "layou not supported by %s format.",
					  mda_index, dev_name(pv->dev),
					  pv->fmt->name);
		return 0;
	}

	return fid_remove_mda(pv->fid, NULL, (const char *) &pv->id,
			      ID_LEN, mda_index);
}

static int _text_pv_remove_metadata_area(const struct format_type *fmt,
					 struct physical_volume *pv,
					 unsigned mda_index)
{
	return _remove_metadata_area_from_pv(pv, mda_index);
}

static int _text_pv_resize(const struct format_type *fmt,
			   struct physical_volume *pv,
			   struct volume_group *vg,
			   uint64_t size)
{
	struct format_instance *fid = pv->fid;
	const char *pvid = (const char *) (*pv->old_id.uuid ? &pv->old_id : &pv->id);
	struct metadata_area *mda;
	struct mda_context *mdac;
	uint64_t size_reduction;
	uint64_t mda_size;
	unsigned mda_ignored;

	/*
	 * First, set the new size and update the cache and reset pe_count.
	 * (pe_count must be reset otherwise it would be considered as
	 * a limiting factor while moving the mda!)
	 */
	pv->size = size;
	pv->pe_count = 0;

	/* If there's an mda at the end, move it to a new position. */
	if ((mda = fid_get_mda_indexed(fid, pvid, ID_LEN, 1)) &&
	    (mdac = mda->metadata_locn)) {
		/* FIXME: Maybe MDA0 size would be better? */
		mda_size = mdac->area.size >> SECTOR_SHIFT;
		mda_ignored = mda_is_ignored(mda);

		if (!_text_pv_remove_metadata_area(fmt, pv, 1) ||
		    !_text_pv_add_metadata_area(fmt, pv, 1, 1, mda_size,
						mda_ignored)) {
			log_error("Failed to move metadata area with index 1 "
				  "while resizing PV %s.", pv_dev_name(pv));
			return 0;
		}
	}

	/* If there's a VG, reduce size by counting in pe_start and metadata areas. */
	if (vg && !is_orphan_vg(vg->name)) {
		size_reduction = pv_pe_start(pv);
		if ((mda = fid_get_mda_indexed(fid, pvid, ID_LEN, 1)) &&
		    (mdac = mda->metadata_locn))
			size_reduction += mdac->area.size >> SECTOR_SHIFT;
		pv->size -= size_reduction;
	}

	return 1;
}

static struct format_instance *_text_create_text_instance(const struct format_type *fmt,
							  const struct format_instance_ctx *fic)
{
	struct format_instance *fid;

	if (!(fid = alloc_fid(fmt, fic)))
		return_NULL;

	if (!_create_vg_text_instance(fid, fic)) {
		dm_pool_destroy(fid->mem);
		return_NULL;
	}

	return fid;
}

static struct format_handler _text_handler = {
	.scan = _text_scan,
	.pv_read = _text_pv_read,
	.pv_initialise = _text_pv_initialise,
	.pv_setup = _text_pv_setup,
	.pv_add_metadata_area = _text_pv_add_metadata_area,
	.pv_remove_metadata_area = _text_pv_remove_metadata_area,
	.pv_resize = _text_pv_resize,
	.pv_write = _text_pv_write,
	.pv_needs_rewrite = _text_pv_needs_rewrite,
	.vg_setup = _text_vg_setup,
	.lv_setup = _text_lv_setup,
	.create_instance = _text_create_text_instance,
	.destroy_instance = _text_destroy_instance,
	.destroy = _text_destroy
};

static int _add_dir(const char *dir, struct dm_list *dir_list)
{
	struct dir_list *dl;

	if (dm_create_dir(dir)) {
		if (!(dl = dm_malloc(sizeof(struct dm_list) + strlen(dir) + 1))) {
			log_error("_add_dir allocation failed");
			return 0;
		}
		log_very_verbose("Adding text format metadata dir: %s", dir);
		strcpy(dl->dir, dir);
		dm_list_add(dir_list, &dl->list);
		return 1;
	}

	return 0;
}

static int _get_config_disk_area(struct cmd_context *cmd,
				 const struct dm_config_node *cn, struct dm_list *raw_list)
{
	struct device_area dev_area;
	const char *id_str;
	struct id id;

	if (!(cn = cn->child)) {
		log_error("Empty metadata disk_area section of config file");
		return 0;
	}

	if (!dm_config_get_uint64(cn, "start_sector", &dev_area.start)) {
		log_error("Missing start_sector in metadata disk_area section "
			  "of config file");
		return 0;
	}
	dev_area.start <<= SECTOR_SHIFT;

	if (!dm_config_get_uint64(cn, "size", &dev_area.size)) {
		log_error("Missing size in metadata disk_area section "
			  "of config file");
		return 0;
	}
	dev_area.size <<= SECTOR_SHIFT;

	if (!dm_config_get_str(cn, "id", &id_str)) {
		log_error("Missing uuid in metadata disk_area section "
			  "of config file");
		return 0;
	}

	if (!id_read_format(&id, id_str)) {
		log_error("Invalid uuid in metadata disk_area section "
			  "of config file: %s", id_str);
		return 0;
	}

	if (!(dev_area.dev = lvmcache_device_from_pvid(cmd, &id, NULL, NULL))) {
		char buffer[64] __attribute__((aligned(8)));

		if (!id_write_format(&id, buffer, sizeof(buffer)))
			log_error("Couldn't find device.");
		else
			log_error("Couldn't find device with uuid '%s'.",
				  buffer);

		return 0;
	}

	return _add_raw(raw_list, &dev_area);
}

struct format_type *create_text_format(struct cmd_context *cmd)
{
	struct format_instance_ctx fic;
	struct format_instance *fid;
	struct format_type *fmt;
	const struct dm_config_node *cn;
	const struct dm_config_value *cv;
	struct mda_lists *mda_lists;

	if (!(fmt = dm_malloc(sizeof(*fmt)))) {
		log_error("Failed to allocate text format type structure.");
		return NULL;
	}

	fmt->cmd = cmd;
	fmt->ops = &_text_handler;
	fmt->name = FMT_TEXT_NAME;
	fmt->alias = FMT_TEXT_ALIAS;
	fmt->orphan_vg_name = ORPHAN_VG_NAME(FMT_TEXT_NAME);
	fmt->features = FMT_SEGMENTS | FMT_MDAS | FMT_TAGS | FMT_PRECOMMIT |
			FMT_UNLIMITED_VOLS | FMT_RESIZE_PV |
			FMT_UNLIMITED_STRIPESIZE | FMT_BAS | FMT_CONFIG_PROFILE |
			FMT_NON_POWER2_EXTENTS | FMT_PV_FLAGS;

	if (!(mda_lists = dm_malloc(sizeof(struct mda_lists)))) {
		log_error("Failed to allocate dir_list");
		dm_free(fmt);
		return NULL;
	}

	dm_list_init(&mda_lists->dirs);
	dm_list_init(&mda_lists->raws);
	mda_lists->file_ops = &_metadata_text_file_ops;
	mda_lists->raw_ops = &_metadata_text_raw_ops;
	fmt->private = (void *) mda_lists;

	dm_list_init(&fmt->mda_ops);
	dm_list_add(&fmt->mda_ops, &_metadata_text_raw_ops.list);

	if (!(fmt->labeller = text_labeller_create(fmt))) {
		log_error("Couldn't create text label handler.");
		goto bad;
	}

	if (!(label_register_handler(fmt->labeller))) {
		log_error("Couldn't register text label handler.");
		fmt->labeller->ops->destroy(fmt->labeller);
		goto bad;
	}

	if ((cn = find_config_tree_array(cmd, metadata_dirs_CFG, NULL))) {
		for (cv = cn->v; cv; cv = cv->next) {
			if (cv->type != DM_CFG_STRING) {
				log_error("Invalid string in config file: "
					  "metadata/dirs");
				goto bad;
			}

			if (!_add_dir(cv->v.str, &mda_lists->dirs)) {
				log_error("Failed to add %s to text format "
					  "metadata directory list ", cv->v.str);
				goto bad;
			}
			cmd->independent_metadata_areas = 1;
		}
	}

	if ((cn = find_config_tree_node(cmd, metadata_disk_areas_CFG_SUBSECTION, NULL))) {
		/* FIXME: disk_areas do not work with lvmetad - the "id" can't be found. */
		for (cn = cn->child; cn; cn = cn->sib) {
			if (!_get_config_disk_area(cmd, cn, &mda_lists->raws))
				goto_bad;
			cmd->independent_metadata_areas = 1;
		}
	}

	if (!(fmt->orphan_vg = alloc_vg("text_orphan", cmd, fmt->orphan_vg_name)))
		goto_bad;

	fic.type = FMT_INSTANCE_AUX_MDAS;
	fic.context.vg_ref.vg_name = fmt->orphan_vg_name;
	fic.context.vg_ref.vg_id = NULL;
	if (!(fid = _text_create_text_instance(fmt, &fic)))
		goto_bad;

	vg_set_fid(fmt->orphan_vg, fid);

	log_very_verbose("Initialised format: %s", fmt->name);

	return fmt;
bad:
	_text_destroy(fmt);

	return NULL;
}
