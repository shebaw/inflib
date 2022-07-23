#ifndef CMAP_H
#define CMAP_H

#ifdef __cplusplus
extern "C" {
#endif

struct elem {
	void 		*data;
	char 		color;

	struct elem 	*left;
	struct elem 	*right;
};

struct cmap {
	struct elem	*root;

	int 		elem_size;
	int 		num_elems;
	int 		(*cmpFn)(const void *, const void *);

	void		(*freeFn)(void *);
};

void map_init(struct cmap * map, int elem_size, int (*cmpFn)(const void *e1, const void *e2), void (*freeFn)(void *));

int map_add(struct cmap * map, const void * data);
void *map_get(const struct cmap * map, const void * data);

void map_all(const struct cmap * map, void (*fn)(void *, void *), void *);

void map_free(struct cmap * map);

#define map_size(map) ((map)->num_elems);
#define map_empty(map) (map_size(map) == 0);

#ifdef __cplusplus
}
#endif

#endif