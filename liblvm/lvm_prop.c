/*
 * Copyright (C) 2013 Red Hat, Inc. All rights reserved.
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

#include "liblvm/lvm_prop.h"
#include "libdm/libdevmapper.h"
#include "lib/metadata/metadata.h"

/* lv create parameters */
GET_LVCREATEPARAMS_NUM_PROPERTY_FN(skip_zero, lvcp->zero)
SET_LVCREATEPARAMS_NUM_PROPERTY_FN(skip_zero, lvcp->zero)

/* PV create parameters */
GET_PVCREATEPARAMS_NUM_PROPERTY_FN(size, pvcp->pva.size)
SET_PVCREATEPARAMS_NUM_PROPERTY_FN(size, pvcp->pva.size)

GET_PVCREATEPARAMS_NUM_PROPERTY_FN(pvmetadatacopies, pvcp->pva.pvmetadatacopies)
SET_PVCREATEPARAMS_NUM_PROPERTY_FN(pvmetadatacopies, pvcp->pva.pvmetadatacopies)

GET_PVCREATEPARAMS_NUM_PROPERTY_FN(pvmetadatasize, pvcp->pva.pvmetadatasize)
SET_PVCREATEPARAMS_NUM_PROPERTY_FN(pvmetadatasize, pvcp->pva.pvmetadatasize)

GET_PVCREATEPARAMS_NUM_PROPERTY_FN(data_alignment, pvcp->pva.data_alignment)
SET_PVCREATEPARAMS_NUM_PROPERTY_FN(data_alignment, pvcp->pva.data_alignment)

GET_PVCREATEPARAMS_NUM_PROPERTY_FN(data_alignment_offset, pvcp->pva.data_alignment_offset)
SET_PVCREATEPARAMS_NUM_PROPERTY_FN(data_alignment_offset, pvcp->pva.data_alignment_offset)

GET_PVCREATEPARAMS_NUM_PROPERTY_FN(zero, pvcp->zero)
SET_PVCREATEPARAMS_NUM_PROPERTY_FN(zero, pvcp->zero)

struct lvm_property_type _lib_properties[] = {
#include "liblvm/lvm_prop_fields.h"
	{ 0, "", 0, 0, 0, 0, { .integer = 0 }, prop_not_implemented_get,
			prop_not_implemented_set },
};

#undef STR
#undef NUM
#undef FIELD

int lv_create_param_get_property(const struct lvcreate_params *lvcp,
		struct lvm_property_type *prop)
{
	return prop_get_property(_lib_properties, lvcp, prop, LV_CREATE_PARAMS);
}

int lv_create_param_set_property(struct lvcreate_params *lvcp,
		    struct lvm_property_type *prop)
{
	return prop_set_property(_lib_properties, lvcp, prop, LV_CREATE_PARAMS);
}

int pv_create_param_get_property(const struct pvcreate_params *pvcp,
		struct lvm_property_type *prop)
{
	return prop_get_property(_lib_properties, pvcp, prop, PV_CREATE_PARAMS);
}

int pv_create_param_set_property(struct pvcreate_params *pvcp,
		    struct lvm_property_type *prop)
{
	return prop_set_property(_lib_properties, pvcp, prop, PV_CREATE_PARAMS);
}
