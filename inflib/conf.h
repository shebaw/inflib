/* main configuration file for V
 * read the comments before changing their values
 * 
 */

#ifndef _CONF_H
#define _CONF_H

/* 
 ****INFECTOR CONFIGURATION****
 */

/* the maximum number of sections a PE can have to be deemed
 * as infectable
 * NOTE: the structures will waste stack space if this gets changed to 
 * unneccesarily large value
 */
#define MAX_SECTIONS		40

/* the random number ceiling to be used as a pass count for EPO search routines
 * NOTE: defining this to unneccesarily large value will make the last valid
 * find to be used in most cases and will make the search slow
 * USED IN: epo.c
 */
#define RAND_PASS_CLNG		20

/* factor to be used in relocation table EPO search routines
 * NOTE: defining this to unnecessarily large value will make the first valid
 * find to be used in most cases and will make the search slow
 * USED IN: epo.c
 */
#define RLC_RAND_FCT		15

#endif