/* map implementation in C
 * shebaw
 */
#include "cmap.h"
#include <stdlib.h>
#include <memory.h>

enum RETVAL { EXISTS, NEW_RED, RED_PARENT, BALANCED };

static void FixImbalance(struct cmap * map, struct elem ** cell, int delta);
static struct elem *findCell(const struct cmap * map, struct elem * tree, const void * data);

void map_init(struct cmap * map, int elem_size, int (*cmpFn)(const void *key, const void *data), void (*freeFn)(void *))
{
	map->elem_size = elem_size;
	map->num_elems = 0;
	
	map->cmpFn = cmpFn;
	map->freeFn = freeFn;
	
	map->root = NULL;
}

static void recFree(void (*freeFn)(void *), struct elem * t)
{
	if (t != NULL) {
		recFree(freeFn, t->left);
		recFree(freeFn, t->right);
		if (freeFn)
			freeFn(t->data);
		free(t->data);	
		free(t);
	}
}

void map_free(struct cmap * t)
{
	recFree(t->freeFn, t->root);
}

static void recMapAll(const struct elem * t, void (*fn) (void *, void *), void *passed_data)
{
	if (t != NULL) {
		recMapAll(t->left, fn, passed_data);
		fn((void *)t->data, (void *)passed_data);
		recMapAll(t->right, fn, passed_data);
	}
}	

void map_all(const struct cmap * map, void (*fn)(void *, void *), void *passed_data)
{
	recMapAll(map->root, fn, passed_data);
}

static enum RETVAL recAdd(struct cmap * map, struct elem ** t, const void * data)
{
	int sign, delta = 0;	
	enum RETVAL added;

	if (*t == NULL) {
		*t = (struct elem *)malloc(sizeof(struct elem));
		(*t)->data = malloc(map->elem_size);	
		memcpy((*t)->data, data, map->elem_size);
		(*t)->left = (*t)->right = NULL;
		(*t)->color = (map->num_elems++ == 0 ? 'b' : 'r');
		return NEW_RED;
	}

	sign = map->cmpFn(data, (*t)->data);
	if (sign == 0)
		return EXISTS;
	else if (sign < 0) {
		added = recAdd(map, &(*t)->left, data);
		delta = -1;
	} else {
		added = recAdd(map, &(*t)->right, data);
		delta = +1;
	}

	switch (added) {
		case EXISTS: case BALANCED:
			return added;
		case NEW_RED:
			return (*t)->color == 'r' ? RED_PARENT : BALANCED;
		default:
			FixImbalance(map, t, delta);
			return (*t)->color == 'r' ? NEW_RED : BALANCED;	
	}
}			
	
int map_add(struct cmap * map, const void * data)
{
	return (recAdd(map, &map->root, data) != EXISTS ? 1 : 0);
}
	
void *map_get(const struct cmap * map, const void *data)
{
	struct elem *find = findCell(map, map->root, data);
	if (find != NULL)
		return find->data;
	return NULL;
}

static struct elem *findCell(const struct cmap * map, struct elem * t, const void * data)
{
	int sign;
	if (t == NULL)
		return NULL;

	sign = map->cmpFn(data, t->data);
	if (sign == 0)
		return t;
	else if (sign < 0)
		return findCell(map, t->left, data);
	else 
		return findCell(map, t->right, data);
}
	
static void RotateRight(struct elem ** t)
{
	struct elem * left = (*t)->left;
	(*t)->left = left->right;
	left->right = (*t);
	(*t) = left;
}

static void RotateLeft(struct elem ** t)
{
	struct elem * right = (*t)->right;
	(*t)->right = right->left;
	right->left = (*t);
	(*t) = right;
}

static void FixLeftImbalance(struct cmap * map, struct elem ** t)
{
	struct elem *left = (*t)->left;
	if ((*t)->right && (*t)->right->color == 'r') {
		(*t)->left->color = (*t)->right->color = 'b';
		if ((*t) != map->root)
			(*t)->color = 'r';
	} else {
		if (left->right && left->right->color == 'r') {
			RotateLeft(&(*t)->left);	
			RotateRight(t);
			
		} else
			RotateRight(t);
		(*t)->color = 'b';
		(*t)->right->color = 'r';
	}
}		
			
static void FixRightImbalance(struct cmap * map, struct elem ** t)
{
	struct elem *right = (*t)->right;
	if ((*t)->left && (*t)->left->color == 'r') {
		(*t)->left->color = (*t)->right->color = 'b';
		if ((*t) != map->root)
			(*t)->color = 'r';
	} else {
		if (right->left && right->left->color == 'r') {
			RotateRight(&(*t)->right);	
			RotateLeft(t);
			
		} else
			RotateLeft(t);
		(*t)->color = 'b';
		(*t)->left->color = 'r';
	}
}				
		
static void FixImbalance(struct cmap * map, struct elem ** t, int delta)
{
	if (delta == -1)
		FixLeftImbalance(map, t);
	else 
		FixRightImbalance(map, t);
}