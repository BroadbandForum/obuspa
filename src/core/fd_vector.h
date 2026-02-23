#ifndef FD_VECTOR
#define FD_VECTOR

typedef struct
{
    unsigned int key; // key in map representing entry
    int *fd_buffer;   // poniter to file descriptor buffer
    int fd_count;     // amount of file descriptors in buffer
    int ref_count;    // counter of references to this buffer
} fd_pair_t;

typedef struct
{
    fd_pair_t *vector; // pointer to first entry in map (or null if empty)
    int num_entries;   // number of entries in map
} fd_vector_t;

unsigned int FD_VECTOR_New_Key();
void FD_VECTOR_Add(const unsigned int key, int *buffer, int count);
int *FD_VECTOR_Get(const unsigned int key, int *count);
void FD_VECTOR_Remove(const unsigned int key);
void FD_VECTOR_Close(int* fd_buffer, int fd_count);
int FD_VECTOR_IncRef(const unsigned int key);
int FD_VECTOR_DecRef(const unsigned int key);

#endif // FD_VECTOR
