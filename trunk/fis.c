// fis.c
// see http://svn.chezphil.org/utils
// Based on the C++ version in fis.cc
// To compile, use --std=c99

// (C) 2007 Philip Endecott

// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.


#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>

#include "crc.h"

// Report an error and terminate:

static void fatal(const char* msg)
{
  fputs(msg,stderr);
  fputc('\n',stderr);
  exit(1);
}

// Report a warning and continue:

static void warning(const char* msg)
{
  fputs(msg,stderr);
  fputc('\n',stderr);
}


// Macro to call a library function and check the result, printing an appropriate error 
// message if it fails.  E.g. open() returns -1 if it fails, so you can write:
// CHECK(fd=open(fn),-1);
// (But you can't write CHECK(int fd=open...), even in c99 mode.)

#define CHECK(what,errcode) if ((what)==errcode) { perror(#what); exit(1); }


// Wrapper for malloc() that checks for out-of-memory and other errors:

static void* chk_malloc(size_t size)
{
  void* ptr = malloc(size);
  if (!ptr) {
    perror("malloc");
    exit(1);
  }
  return ptr;
}


// Wrappers for read() and write() that check for error and unexpected conditions.

static void chk_read(int fd, void* buf, size_t count)
{
  size_t rc = read(fd,buf,count);
  if (rc!=count) {
    if ((int)rc==-1) {
      perror("read");
      exit(1);
    } else {
      fatal("short read");
    }
  }
}

static void chk_write(int fd, const void* buf, size_t count)
{
  size_t rc = write(fd,buf,count);
  if (rc!=count) {
    if ((int)rc==-1) {
      perror("write");
      exit(1);
    } else {
      fatal("short write");
    }
  }
}


// Get the size of a file

unsigned int filesize(int fd)
{
  return lseek(fd,0,SEEK_END);
}



static uint32_t swap_end_32(uint32_t data)
{
  uint32_t r = data>>24;
  r |= (data>>8)&0x0000ff00;
  r |= (data<<8)&0x00ff0000;
  r |= data<<24;
  return r;
}



// Parse a string containing a number.  If it starts with 0x, parse the rest as hex.
// !!! NOTE: also parses octal constants that start with '0' !!!

static unsigned int str_to_int_maybe_hex(const char* s)
{
  char* endptr;
  unsigned int i = strtoul(s,&endptr,0);
  if (*s!='\0' && *endptr=='\0') {
    return i;
  }
  fatal("junk after number");
}



// This is taken from drivers/mtd/redboot.c in the Linux source
struct fis_image_desc {
  unsigned char name[16];  // Null terminated name
  uint32_t  flash_base;    // Address within FLASH of image
  uint32_t  mem_base;      // Address in memory where it executes
  uint32_t  size;          // Length of image
  uint32_t  entry_point;   // Execution entry point
  uint32_t  data_length;   // Length of actual data
  uint32_t  skips[53];
  uint32_t  desc_cksum;    // Checksum over image descriptor
  uint32_t  file_cksum;    // Checksum over image data
};

static void dump_desc(FILE* f, const struct fis_image_desc* d)
{
  fprintf(f,"%16s: addr = 0x%08x, size = 0x%08x, entry = 0x%08x, length = 0x%08x, cksum = 0x%08x\n",
	  d->name, d->flash_base, d->size,
	  d->entry_point, d->data_length, d->file_cksum);
  for (unsigned int i=0; i<(sizeof(d->skips)/4); ++i) {
    if (d->skips[i]==0x736b6970 || d->skips[i]==0x70696b73) { // "skip"
      uint32_t offset = d->skips[i+1];
      uint32_t length = d->skips[i+2];
      fprintf(stderr,"                    skip: %08x + %08x\n",
                                                offset,length);
      i+=2;
    }
  }
}


// Use a non-invasive list to represent the entire directory.
// Yes, this probably does look a bit over-the-top, but it's a close match to what the 
// C++ version does, making the other code simpler.

// Each element of the list has one of the following handle structures:

struct dirnode {
  struct fis_image_desc* entry;
  struct dirnode* prev;
  struct dirnode* next;
};

// The list is circularly linked, i.e. the last node's next pointer points to the first 
// node, and the first node's prev pointer points to the last node.  The start of the 
// list is distinguished by the fact that the list as a whole is represented by a 
// pointer to the first node.

// Functions that do read-only operations on a list take a dir_t parameter.  Functions 
// that do read-write operations take a dir_t* since they may have to modify this 
// pointer if the first element changes.  An empty list is represented by a NULL 
// pointer.

// Functions that operate on particular elements of a list use an iter_t parameter.  This 
// is just a pointer to a node handle, but can be treated as opaque.  The for-each macro, 
// below, supplies iter_t iterators which the caller dereferences using get() to get the 
// struct fis_image_desc.

typedef struct dirnode* dir_t;
typedef struct dirnode* iter_t;


static unsigned int dir_size_tail(dir_t d, struct dirnode* n)
{
  if (n==d) {
    return 0;
  } else {
    return 1 + dir_size_tail(d,n->next);
  }
}


// Return the number of entries in a directory.

static unsigned int dir_size(dir_t d)
{
  if (!d) {
    return 0;
  } else {
    return 1 + dir_size_tail(d,d->next);
  }
}


// Create a new empty directory.

static void dir_create(dir_t* dir)
{
  *dir = NULL;
}


// Append an entry to a directory.
// The list takes ownership of the new entry.

static void dir_append(dir_t* dir, struct fis_image_desc* d)
{
  struct dirnode* n = chk_malloc(sizeof(struct dirnode));
  n->entry = d;
  
  if (*dir) {
    n->next = *dir;
    n->prev = (*dir)->prev;
    (*dir)->prev->next = n;
    (*dir)->prev = n;
  } else {
    n->next = n;
    n->prev = n;
    (*dir) = n;
  }
}


// Insert an entry into a directory after the entry referred to by the iterator 'after'.
// If 'after' is NULL, insert at the beginning.
// The list takes ownership of the new entry.

static void dir_insert(dir_t* dir, iter_t after, struct fis_image_desc* d)
{
  // Special case, directory is empty.
  if (!(*dir)) {
    dir_append(dir,d);
    return;
  }

  struct dirnode* n = chk_malloc(sizeof(struct dirnode));
  n->entry = d;

  if (!after) {
    after = (*dir)->prev;
    *dir = n;
  }
  
  n->prev = after;
  n->next = after->next;
  after->next->prev = n;
  after->next = n;
}


// Remove an entry from a directory.
// The entry is free()d.

static void dir_erase(dir_t* dir, iter_t i)
{
  // Erasing the first element:
  if (i==(*dir)) {
    // Erasing the first and only element:
    if (i->next==i) {
      *dir = NULL;
    } else {
      *dir = i->next;
    }
  }

  i->next->prev = i->prev;
  i->prev->next = i->next;

  free(i->entry);
  free(i);
}


// This macro can be used to iterate through a directory.
// It takes the directory and an iterator, which it will declare, as parameters.
// Example:
// FOR_EACH_DIR_ENTRY(dir,i) {
//   dump_desc(stdout,get(i));
// }

#define FOR_EACH_DIR_ENTRY(dir,iterator) \
for (iter_t iterator = dir;  \
     iterator; \
     iterator = (iterator->next==dir) ? NULL : iterator->next)

// Use this to get the struct fis_image_desc from the iterator:
#define get(iterator) (iterator->entry)



static void check_dev(const char* device)
{
  if (!device[0]) {
    fatal("You must specify a device using -d");
  }
}


void check_checksum(const struct fis_image_desc* d)
{
  // This isn't checked by the kernel mtd driver, which has this 
  // comment: "RedBoot doesn't actually write the desc_cksum field yet 
  // AFAICT".  I don't know what checksum is supposed to be used here.
}

void compute_checksum(struct fis_image_desc* d)
{
  // ditto
}


static void swap_entry_endianness(struct fis_image_desc* d)
{
  d->flash_base  = swap_end_32(d->flash_base);
  d->mem_base    = swap_end_32(d->mem_base);
  d->size        = swap_end_32(d->size);
  d->entry_point = swap_end_32(d->entry_point);
  d->data_length = swap_end_32(d->data_length);
  for (unsigned int i=0; i<(sizeof(d->skips)/4); ++i) {
    d->skips[i] = swap_end_32(d->skips[i]);
  }
}


static void load_dir(int fd, int offset, int* size_p, bool swap_endianness,
                     dir_t* dir)
{
  dir_create(dir);
  if ((*size_p)==-1) {
    (*size_p) = filesize(fd)-offset;
  }
  CHECK(lseek(fd,offset,SEEK_SET),-1);
  int num_entries = (*size_p)/sizeof(struct fis_image_desc);
  for (int i=0; i<num_entries; ++i) {
    struct fis_image_desc* d = chk_malloc(sizeof(struct fis_image_desc));
    chk_read(fd,d,sizeof(struct fis_image_desc));
    if (d->name[0]!=0xff) {
      check_checksum(d);
      if (swap_endianness) {
        swap_entry_endianness(d);
      }
      dir_append(dir,d);
    }
    else if (d->name[1]==0xff) break;

  }
}


static void write_blank_entries(int fd, int n)
{
  char dummy[sizeof(struct fis_image_desc)];
  for (unsigned int i=0; i<sizeof(struct fis_image_desc); ++i) {
    dummy[i] = 0xff;
  }
  for (int i=0; i<n; ++i) {
    chk_write(fd,dummy,sizeof(struct fis_image_desc));
  }  
}


static void save_dir(int fd, int offset, int size, bool swap_endianness,
                     const dir_t dir)
{
  CHECK(lseek(fd,offset,SEEK_SET),-1);
  unsigned int num_entries = size/sizeof(struct fis_image_desc);
  if (num_entries<dir_size(dir)) {
    fatal("Too many entries for directory");
  }
  FOR_EACH_DIR_ENTRY(dir,i) {
    compute_checksum(get(i));
    if (swap_endianness) {
      swap_entry_endianness(get(i));
    }
    chk_write(fd,get(i),sizeof(struct fis_image_desc));
  }
  write_blank_entries(fd,num_entries-dir_size(dir));
}


static void fis_list(const char* device, int offset, int size, bool swap_endianness)
{
  int fd;
  CHECK(fd=open(device,O_RDONLY),-1);
  dir_t dir;
  load_dir(fd,offset,&size,swap_endianness,&dir);
  FOR_EACH_DIR_ENTRY(dir,i) {
    dump_desc(stdout,get(i));
  }
}


static void fis_init(const char* device, int offset, int size)
{
  if (size==-1) {
    fatal("size must be specified using -s");
  }
  int fd;
  CHECK(fd=open(device,O_CREAT|O_RDWR,0666),-1);
  CHECK(lseek(fd,offset,SEEK_SET),-1);
  int num_entries = size/sizeof(struct fis_image_desc);
  write_blank_entries(fd,num_entries);
}


static void check_overlap(const dir_t dir, uint32_t addr, uint32_t size)
{
  uint32_t end_addr = addr+size;
  FOR_EACH_DIR_ENTRY(dir,i) {
    if (addr<(get(i)->flash_base+get(i)->size)
        && end_addr>get(i)->flash_base) {
      warning("New partition overlaps existing partitions");
    }
  }
}


static void fis_create(const char* device, int offset, int size, bool swap_endianness,
                       int argc, char* argv[])
{
  struct fis_image_desc* d = chk_malloc(sizeof(struct fis_image_desc));
  d->mem_base = 0;
  d->entry_point = 0;
  d->data_length = 0;
  for (unsigned int i=0; i<(sizeof(d->skips)/4); ++i) {
    d->skips[i] = 0;
  }
  d->desc_cksum = 0;
  d->file_cksum = 0;
  
  for (int i=0; i<argc; ++i) {
    char* arg=argv[i];
    if (strcmp(arg,"-l")==0) {
      if (i==argc-1) {
        fatal("argumnet missing for -l");
      }
      ++i;
      d->size = str_to_int_maybe_hex(argv[i]);
    } else if (strcmp(arg,"-f")==0) {
      if (i==argc-1) {
        fatal("argumnet missing for -f");
      }
      ++i;
      d->flash_base = str_to_int_maybe_hex(argv[i]);
    } else if (strcmp(arg,"-n")==0) {
      if (i==argc-1) {
        fatal("argumnet missing for -n");
      }
      ++i;
      char* name = argv[i];
      if (strlen(name)>=16) {
        fatal("name too long, max 16 chars including terminating null");
      }
      for (int j=0; j<16; j++) {
        char c = name[j];
        d->name[j] = c;
        if (!c) {
          for (; j<16; ++j) {
            d->name[j]=0;
          }
          break;
        }
      }
    } else if (strcmp(arg,"-e")==0) {
      if (i==argc-1) {
        fatal("argumnet missing for -e");
      }
      ++i;
      d->entry_point = str_to_int_maybe_hex(argv[i]);
    } else if (strcmp(arg,"-c")==0) {
      if (i==argc-1) {
        fatal("argumnet missing for -c");
      }
      ++i;
      char* file = argv[i];
      int fd;
      struct stat file_stat;
      CHECK(fd=open(file,O_RDONLY),-1);
      CHECK(fstat(fd,&file_stat),-1);
      d->data_length=file_stat.st_size;
      uint8_t *data;
      CHECK(data=mmap(0,d->data_length,PROT_READ,MAP_PRIVATE,fd,0),MAP_FAILED);
      d->file_cksum=crc32(data,d->data_length);
      munmap(data,d->data_length);
    } else {
      fputs("Unrecognised option '",stderr);
      fputs(arg,stderr);
      fputs("'\n",stderr);
      exit(1);
    }
  }

  int fd;
  CHECK(fd=open(device,O_RDWR),-1);
  dir_t dir;
  load_dir(fd,offset,&size,swap_endianness,&dir);
  check_overlap(dir,d->flash_base,d->size);
  iter_t after = NULL;
  FOR_EACH_DIR_ENTRY(dir,i) {
    if (get(i)->flash_base > d->flash_base) {
      break;
    }
    after = i;
  }
  dir_insert(&dir,after,d);
  save_dir(fd,offset,size,swap_endianness,dir);
}


static void fis_delete(const char* device, int offset, int size, bool swap_endianness,
                       char* name)
{
  int fd;
  CHECK(fd=open(device,O_RDWR),-1);
  dir_t dir;
  load_dir(fd,offset,&size,swap_endianness,&dir);

  FOR_EACH_DIR_ENTRY(dir,i) {
    char* this_name = get(i)->name;
    if (strcmp(this_name,name)==0) {
      dir_erase(&dir,i);
      save_dir(fd,offset,size,swap_endianness,dir);
      return;
    }
  }

  fatal("No partition found with specified name");
}


static void usage()
{
  fputs("Usage:\n"
        "  fis [options] list\n"
        "  fis [options] init\n"
        "  fis [options] create -f address -l size -n name -e entry -c contents\n"
        "  fis [options] delete name\n"
        "Options:\n"
        "  -d device    specify /dev/mtd* device containing directory\n"
        "  -o offset    specify offset into device of start of directory\n"
        "               (in decimal; prefix with 0x for hex)\n"
        "  -s size      specify size of directory in bytes\n"
        "  -e           swap endianness\n", stderr);
}


int main(int argc, char* argv[])
{
    if (argc==1) {
      usage();
      exit(1);
    }

    char* device="";
    int offset=0;
    int size=-1;
    bool swap_endianness=false;

    for (int i=1; i<argc; ++i) {
      char* arg = argv[i];
      if (strcmp(arg,"-d")==0) {
        if (device[0]) {
          fatal("-d option used more than once");
        }
        if (i==argc-1) {
          fatal("-d option is missing its parameter");
        }
        ++i;
        device = argv[i];
      } else if (strcmp(arg,"-o")==0) {
        if (offset!=0) {
          fatal("-o option used more than once");
        }
        if (i==argc-1) {
          fatal("-o option is missing its parameter");
        }
        ++i;
        offset = str_to_int_maybe_hex(argv[i]);
      } else if (strcmp(arg,"-s")==0) {
        if (size!=-1) {
          fatal("-s option used more than once");
        }
        if (i==argc-1) {
          fatal("-s option is missing its parameter");
        }
        ++i;
        size = str_to_int_maybe_hex(argv[i]);
      } else if (strcmp(arg,"-e")==0) {
        swap_endianness = true;
      } else if (strcmp(arg,"list")==0) {
        if (i!=argc-1) {
          fatal("Extra arguments after 'list'");
        }
        check_dev(device);
        fis_list(device,offset,size,swap_endianness);
      } else if (strcmp(arg,"init")==0) {
        if (i!=argc-1) {
          fatal("Extra arguments after 'init'");
        }
        check_dev(device);
        fis_init(device,offset,size);
      } else if (strcmp(arg,"create")==0) {
        check_dev(device);
        fis_create(device,offset,size,swap_endianness,
                   argc-i-1,&argv[i+1]);
        break;
      } else if (strcmp(arg,"delete")==0) {
        if (i!=argc-2) {
          fatal("Exactly one argumnet required after 'delete'");
        }
        ++i;
        char* name = argv[i];
        check_dev(device);
        fis_delete(device,offset,size,swap_endianness,name);
      } else {
        fputs("unrecognised argument '",stderr);
        fputs(arg,stderr);
        fputs("'\n",stderr);
        usage();
        exit(1);
      }
    }
  exit(0);
}

