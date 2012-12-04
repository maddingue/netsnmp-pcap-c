/*
 * This is an extract of snmpmod.h, with just the macros for an easier
 * management of object lists.
 * -- Sebastien Aperghis-Tramoni
 */

/*
 * Copyright (c) 2001-2003
 *	Fraunhofer Institute for Open Communication Systems (FhG Fokus).
 *	All rights reserved.
 *
 * Author: Harti Brandt <harti@freebsd.org>
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $Begemot: bsnmp/snmpd/snmpmod.h,v 1.32 2006/02/14 09:04:20 brandt_h Exp $
 *
 * SNMP daemon data and functions exported to modules.
 */
#ifndef snmpmod_h_
#define snmpmod_h_

#include "bsnmp-asn1.h"

/*
 * These macros help to handle object lists for SNMP tables. They use
 * tail queues to hold the objects in ascending order in the list.
 * ordering can be done either on an integer/unsigned field, an asn_oid
 * or an ordering function.
 */
#define INSERT_OBJECT_OID_LINK_INDEX(PTR, LIST, LINK, INDEX) do {	\
	__typeof (PTR) _lelem;						\
									\
	TAILQ_FOREACH(_lelem, (LIST), LINK)				\
		if (asn_compare_oid(&_lelem->INDEX, &(PTR)->INDEX) > 0)	\
			break;						\
	if (_lelem == NULL)						\
		TAILQ_INSERT_TAIL((LIST), (PTR), LINK);			\
	else								\
		TAILQ_INSERT_BEFORE(_lelem, (PTR), LINK);		\
    } while (0)

#define INSERT_OBJECT_INT_LINK_INDEX(PTR, LIST, LINK, INDEX) do {	\
	__typeof (PTR) _lelem;						\
									\
	TAILQ_FOREACH(_lelem, (LIST), LINK)				\
		if ((asn_subid_t)_lelem->INDEX > (asn_subid_t)(PTR)->INDEX)\
			break;						\
	if (_lelem == NULL)						\
		TAILQ_INSERT_TAIL((LIST), (PTR), LINK);			\
	else								\
		TAILQ_INSERT_BEFORE(_lelem, (PTR), LINK);		\
    } while (0)

#define	INSERT_OBJECT_FUNC_LINK(PTR, LIST, LINK, FUNC) do {		\
	__typeof (PTR) _lelem;						\
									\
	TAILQ_FOREACH(_lelem, (LIST), LINK)				\
		if ((FUNC)(_lelem, (PTR)) > 0)				\
			break;						\
	if (_lelem == NULL)						\
		TAILQ_INSERT_TAIL((LIST), (PTR), LINK);			\
	else								\
		TAILQ_INSERT_BEFORE(_lelem, (PTR), LINK);		\
    } while (0)

#define	INSERT_OBJECT_FUNC_LINK_REV(PTR, LIST, HEAD, LINK, FUNC) do {	\
	__typeof (PTR) _lelem;						\
									\
	TAILQ_FOREACH_REVERSE(_lelem, (LIST), HEAD, LINK)		\
		if ((FUNC)(_lelem, (PTR)) < 0)				\
			break;						\
	if (_lelem == NULL)						\
		TAILQ_INSERT_HEAD((LIST), (PTR), LINK);			\
	else								\
		TAILQ_INSERT_AFTER((LIST), _lelem, (PTR), LINK);	\
    } while (0)

#define FIND_OBJECT_OID_LINK_INDEX(LIST, OID, SUB, LINK, INDEX) ({	\
	__typeof (TAILQ_FIRST(LIST)) _lelem;				\
									\
	TAILQ_FOREACH(_lelem, (LIST), LINK)				\
		if (index_compare(OID, SUB, &_lelem->INDEX) == 0)	\
			break;						\
	(_lelem);							\
    })

#define NEXT_OBJECT_OID_LINK_INDEX(LIST, OID, SUB, LINK, INDEX) ({	\
	__typeof (TAILQ_FIRST(LIST)) _lelem;				\
									\
	TAILQ_FOREACH(_lelem, (LIST), LINK)				\
		if (index_compare(OID, SUB, &_lelem->INDEX) < 0)	\
			break;						\
	(_lelem);							\
    })

#define FIND_OBJECT_INT_LINK_INDEX(LIST, OID, SUB, LINK, INDEX) ({	\
	__typeof (TAILQ_FIRST(LIST)) _lelem;				\
									\
	if ((OID)->len - SUB != 1)					\
		_lelem = NULL;						\
	else								\
		TAILQ_FOREACH(_lelem, (LIST), LINK)			\
			if ((OID)->subs[SUB] == (asn_subid_t)_lelem->INDEX)\
				break;					\
	(_lelem);							\
    })

#define NEXT_OBJECT_INT_LINK_INDEX(LIST, OID, SUB, LINK, INDEX) ({	\
	__typeof (TAILQ_FIRST(LIST)) _lelem;				\
									\
	if ((OID)->len - SUB == 0)					\
		_lelem = TAILQ_FIRST(LIST);				\
	else								\
		TAILQ_FOREACH(_lelem, (LIST), LINK)			\
			if ((OID)->subs[SUB] < (asn_subid_t)_lelem->INDEX)\
				break;					\
	(_lelem);							\
    })

#define FIND_OBJECT_FUNC_LINK(LIST, OID, SUB, LINK, FUNC) ({		\
	__typeof (TAILQ_FIRST(LIST)) _lelem;				\
									\
	TAILQ_FOREACH(_lelem, (LIST), LINK)				\
		if ((FUNC)(OID, SUB, _lelem) == 0)			\
			break;						\
	(_lelem);							\
    })

#define NEXT_OBJECT_FUNC_LINK(LIST, OID, SUB, LINK, FUNC) ({		\
	__typeof (TAILQ_FIRST(LIST)) _lelem;				\
									\
	TAILQ_FOREACH(_lelem, (LIST), LINK)				\
		if ((FUNC)(OID, SUB, _lelem) < 0)			\
			break;						\
	(_lelem);							\
    })

/*
 * Macros for the case where the index field is called 'index'
 */
#define INSERT_OBJECT_OID_LINK(PTR, LIST, LINK)				\
    INSERT_OBJECT_OID_LINK_INDEX(PTR, LIST, LINK, index)

#define INSERT_OBJECT_INT_LINK(PTR, LIST, LINK) do {			\
    INSERT_OBJECT_INT_LINK_INDEX(PTR, LIST, LINK, index)

#define FIND_OBJECT_OID_LINK(LIST, OID, SUB, LINK)			\
    FIND_OBJECT_OID_LINK_INDEX(LIST, OID, SUB, LINK, index)

#define NEXT_OBJECT_OID_LINK(LIST, OID, SUB, LINK)			\
    NEXT_OBJECT_OID_LINK_INDEX(LIST, OID, SUB, LINK, index)

#define FIND_OBJECT_INT_LINK(LIST, OID, SUB, LINK)			\
    FIND_OBJECT_INT_LINK_INDEX(LIST, OID, SUB, LINK, index)

#define NEXT_OBJECT_INT_LINK(LIST, OID, SUB, LINK)			\
    NEXT_OBJECT_INT_LINK_INDEX(LIST, OID, SUB, LINK, index)

/*
 * Macros for the case where the index field is called 'index' and the
 * link field 'link'.
 */
#define INSERT_OBJECT_OID(PTR, LIST)					\
    INSERT_OBJECT_OID_LINK_INDEX(PTR, LIST, link, index)

#define INSERT_OBJECT_INT(PTR, LIST)					\
    INSERT_OBJECT_INT_LINK_INDEX(PTR, LIST, link, index)

#define	INSERT_OBJECT_FUNC_REV(PTR, LIST, HEAD, FUNC)			\
    INSERT_OBJECT_FUNC_LINK_REV(PTR, LIST, HEAD, link, FUNC)

#define FIND_OBJECT_OID(LIST, OID, SUB)					\
    FIND_OBJECT_OID_LINK_INDEX(LIST, OID, SUB, link, index)

#define FIND_OBJECT_INT(LIST, OID, SUB)					\
    FIND_OBJECT_INT_LINK_INDEX(LIST, OID, SUB, link, index)

#define	FIND_OBJECT_FUNC(LIST, OID, SUB, FUNC)				\
    FIND_OBJECT_FUNC_LINK(LIST, OID, SUB, link, FUNC)

#define NEXT_OBJECT_OID(LIST, OID, SUB)					\
    NEXT_OBJECT_OID_LINK_INDEX(LIST, OID, SUB, link, index)

#define NEXT_OBJECT_INT(LIST, OID, SUB)					\
    NEXT_OBJECT_INT_LINK_INDEX(LIST, OID, SUB, link, index)

#define	NEXT_OBJECT_FUNC(LIST, OID, SUB, FUNC)				\
    NEXT_OBJECT_FUNC_LINK(LIST, OID, SUB, link, FUNC)

#endif
