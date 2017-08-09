#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <assert.h>
#include <ctype.h>

#include "bootsect.h"
#include "bpb.h"
#include "direntry.h"
#include "fat.h"
#include "dos.h"


   
   uint16_t totalClusters;
   //used to keep track of whether or not clusters are referenced
   int array[3000];
   //used to iterate through the array
   uint16_t counter;
   //records value of the biggest unreferenced cluster
   uint16_t unref;
   //records number of lost files
   int fileNum;
   int clustsize;
   //records the starting clusters for lost files
   uint16_t startClust[10];
   //records the length of lost files
   int fileLen[10];
 

 //taken from code provided  
void usage()
{
    fprintf(stderr, "Usage: dos_ls <imagename>\n");
    exit(1);
}

 //taken from code provided  
uint8_t *mmap_file(char *filename, int *fd)
{
    struct stat statbuf;
    int size;
    uint8_t *image_buf;
    char pathname[MAXPATHLEN+1];

    /* If filename isn't an absolute pathname, then we'd better prepend
       the current working directory to it */
    if (filename[0] == '/') {
	strncpy(pathname, filename, MAXPATHLEN);
    } else {
	getcwd(pathname, MAXPATHLEN);
	if (strlen(pathname) + strlen(filename) + 1 > MAXPATHLEN) {
	    fprintf(stderr, "Filename too long\n");
	    exit(1);
	}
	strcat(pathname, "/");
	strcat(pathname, filename);
    }

    /* Step 2: find out how big the disk image file is */
    /* we can use "stat" to do this, by checking the file status */
    if (stat(pathname, &statbuf) < 0) {
	fprintf(stderr, "Cannot read disk image file %s:\n%s\n", 
		pathname, strerror(errno));
	exit(1);
    }

    size = statbuf.st_size;

    /* Step 3: open the file for read/write */
    *fd = open(pathname, O_RDWR);
    if (*fd < 0) {
	fprintf(stderr, "Cannot read disk image file %s:\n%s\n", 
		pathname, strerror(errno));
	exit(1);
    }

    /* Step 3: we memory map the file */

    image_buf = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, *fd, 0);
    if (image_buf == MAP_FAILED) {
	fprintf(stderr, "Failed to memory map: \n%s\n", strerror(errno));
	exit(1);
    }
    return image_buf;
}




 //taken from code provided  
struct bpb33* check_bootsector(uint8_t *image_buf)
{
    struct bootsector33* bootsect;
    struct byte_bpb33* bpb;  /* BIOS parameter block */
    struct bpb33* bpb2;

    bootsect = (struct bootsector33*)image_buf;
    if (bootsect->bsJump[0] == 0xe9 ||
    (bootsect->bsJump[0] == 0xeb && bootsect->bsJump[2] == 0x90)) {
#ifdef DEBUG
    printf("Good jump inst\n");
#endif
    } else {
    fprintf(stderr, "illegal boot sector jump inst: %x%x%x\n", 
        bootsect->bsJump[0], bootsect->bsJump[1], 
        bootsect->bsJump[2]); 
    } 

#ifdef DEBUG
    printf("OemName: %s\n", bootsect->bsOemName);
#endif

    if (bootsect->bsBootSectSig0 == BOOTSIG0
    && bootsect->bsBootSectSig0 == BOOTSIG0) {
    //Good boot sector sig;
#ifdef DEBUG
    printf("Good boot sector signature\n");
#endif
    } else {
    fprintf(stderr, "Boot boot sector signature %x%x\n", 
        bootsect->bsBootSectSig0, 
        bootsect->bsBootSectSig1);
    }

    bpb = (struct byte_bpb33*)&(bootsect->bsBPB[0]);

    /* bpb is a byte-based struct, because this data is unaligned.
       This makes it hard to access the multi-byte fields, so we copy
       it to a slightly larger struct that is word-aligned */
    bpb2 = malloc(sizeof(struct bpb33));

    bpb2->bpbBytesPerSec = getushort(bpb->bpbBytesPerSec);
    bpb2->bpbSecPerClust = bpb->bpbSecPerClust;
    bpb2->bpbResSectors = getushort(bpb->bpbResSectors);
    bpb2->bpbFATs = bpb->bpbFATs;
    bpb2->bpbRootDirEnts = getushort(bpb->bpbRootDirEnts);
    bpb2->bpbSectors = getushort(bpb->bpbSectors);
    bpb2->bpbFATsecs = getushort(bpb->bpbFATsecs);
    bpb2->bpbHiddenSecs = getushort(bpb->bpbHiddenSecs);
   
    totalClusters = bpb2->bpbSectors;

   /* printf("----------------------------------\n");
    printf("Bytes per sector: %d\n", bpb2->bpbBytesPerSec);
    printf("Sectors per cluster: %d\n", bpb2->bpbSecPerClust);
    printf("Reserved sectors: %d\n", bpb2->bpbResSectors);
    printf("Number of FATs: %d\n", bpb->bpbFATs);
    printf("Number of root dir entries: %d\n", bpb2->bpbRootDirEnts);
    printf("Total number of sectors: %d\n", bpb2->bpbSectors);
    printf("Number of sectors per FAT: %d\n", bpb2->bpbFATsecs);
    printf("Number of hidden sectors: %d\n", bpb2->bpbHiddenSecs);*/


    return bpb2;
}


 //taken from code provided  

uint16_t get_fat_entry(uint16_t clusternum, 
               uint8_t *image_buf, struct bpb33* bpb)
{
    uint32_t offset;
    uint16_t value;
    uint8_t b1, b2;
    
    /* this involves some really ugly bit shifting.  This probably
       only works on a little-endian machine. */
    offset = bpb->bpbResSectors * bpb->bpbBytesPerSec * bpb->bpbSecPerClust 
    + (3 * (clusternum/2));
    switch(clusternum % 2) {
    case 0:
    b1 = *(image_buf + offset);
    b2 = *(image_buf + offset + 1);
    /* mjh: little-endian CPUs are ugly! */
    value = ((0x0f & b2) << 8) | b1;
    break;
    case 1:
    b1 = *(image_buf + offset + 1);
    b2 = *(image_buf + offset + 2);
    value = b2 << 4 | ((0xf0 & b1) >> 4);
    break;
    }
    return value;
}

 //taken from code provided  
int is_end_of_file(uint16_t cluster) {
    if (cluster >= (FAT12_MASK & CLUST_EOFS)
    && cluster <= (FAT12_MASK & CLUST_EOFE)) {
    return 1;
    } else 
    return 0;
}

//work out file length in the directry
int get_file_length(uint16_t cluster, uint8_t *image_buf, struct bpb33* bpb)
{
    int length = 1;

    cluster = get_fat_entry(cluster, image_buf, bpb);
    while (is_end_of_file(cluster)==0) {
        cluster = get_fat_entry(cluster, image_buf, bpb);
        length++;
    }

    return length;
}

/* root_dir_addr returns the address in the mmapped disk image for the
   start of the root directory, as indicated in the boot sector */
 //taken from code provided  
uint8_t *root_dir_addr(uint8_t *image_buf, struct bpb33* bpb)
{
    uint32_t offset;
    offset = 
    (bpb->bpbBytesPerSec 
     * (bpb->bpbResSectors + (bpb->bpbFATs * bpb->bpbFATsecs)));
    return image_buf + offset;
}

/* cluster_to_addr returns the memory location where the memory mapped
   cluster actually starts */
 //taken from code provided  
uint8_t *cluster_to_addr(uint16_t cluster, uint8_t *image_buf, 
             struct bpb33* bpb)
{
    uint8_t *p;
    p = root_dir_addr(image_buf, bpb);
    if (cluster != MSDOSFSROOT) {
    /* move to the end of the root directory */
    p += bpb->bpbRootDirEnts * sizeof(struct direntry);
    /* move forward the right number of clusters */
    p += bpb->bpbBytesPerSec * bpb->bpbSecPerClust 
        * (cluster - CLUST_FIRST);
    }
    return p;
}


 //taken from code provided  
void print_indent(int indent)
{
  int i;
  for (i = 0; i < indent; i++)
    printf(" ");
}

//iterates through the files and marks the referenced cluster positions in the array as 1;
//most of the code taken from the follow_dir() function provided
void mark_unreferenced(uint16_t cluster, int indent,
        uint8_t *image_buf, struct bpb33* bpb)
{
    struct direntry *dirent;
    int d, i;
    dirent = (struct direntry*)cluster_to_addr(cluster, image_buf, bpb);
    while (1) {
    for (d = 0; d < bpb->bpbBytesPerSec *
     bpb->bpbSecPerClust; 
         d += sizeof(struct direntry)) {
        char name[9];
        char extension[4];
        uint32_t size;
        uint16_t file_cluster;
        name[8] = ' ';
        extension[3] = ' ';
        memcpy(name, &(dirent->deName[0]), 8);
        memcpy(extension, dirent->deExtension, 3);
        if (name[0] == SLOT_EMPTY)
        return;

        /* skip over deleted entries */
        if (((uint8_t)name[0]) == SLOT_DELETED)
        continue;

        /* names are space padded - remove the spaces */
        for (i = 8; i > 0; i--) {
        if (name[i] == ' ') 
            name[i] = '\0';
        else 
            break;
        }

        /* remove the spaces from extensions */
        for (i = 3; i > 0; i--) {
        if (extension[i] == ' ') 
            extension[i] = '\0';
        else 
            break;
        }

        /* don't print "." or ".." directories */
        if (strcmp(name, ".")==0) {
        dirent++;
        continue;
        }
        if (strcmp(name, "..")==0) {
        dirent++;
        continue;
        }

        if ((dirent->deAttributes & ATTR_VOLUME) != 0) {
        //printf("Volume: %s\n", name);
        } else if ((dirent->deAttributes & ATTR_DIRECTORY) != 0) {
            //print_indent(indent);
        //printf("%s (directory)\n", name);
        file_cluster = getushort(dirent->deStartCluster);


        mark_unreferenced(file_cluster, indent+2, image_buf, bpb);
        } else {

        size = getulong(dirent->deFileSize);
            //print_indent(indent);
          //  printf("\n");

      //  printf("%s.%s (%u bytes)\n",
       //   name, extension, size);

        file_cluster = getushort(dirent->deStartCluster);
        
            while(is_end_of_file(file_cluster)==0)
            {
            //printf("current cluster = %d\n",file_cluster);
            array[file_cluster]=1;
            file_cluster=get_fat_entry(file_cluster, image_buf, bpb);
            
            }
            array[file_cluster]=1;

        }
        dirent++;
    }



    if (cluster == 0) {
        // root dir is special
        dirent++;
    } else {
        cluster = get_fat_entry(cluster, image_buf, bpb);
        dirent = (struct direntry*)cluster_to_addr(cluster, 
                               image_buf, bpb);
    }
    }
}


 //taken from code provided  
void write_dirent(struct direntry *dirent, char *filename, 
           uint16_t start_cluster, uint32_t size)
{
    
    char *p, *p2;
    char *uppername;
    int len, i;

    /* clean out anything old that used to be here */
   memset(dirent, 0, sizeof(struct direntry));

    /* extract just the filename part */
    uppername = strdup(filename);
    p2 = uppername;

    for (i = 0; i < strlen(filename); i++) {
    if (p2[i] == '/' || p2[i] == '\\') {
        uppername = p2+i+1;
    }
    }

    /* convert filename to upper case */
    for (i = 0; i < strlen(uppername); i++) {
    //uppername[i] = toupper(uppername[i]);
    uppername[i] = (char)toupper((unsigned char)uppername[i]);
    }
    /* set the file name and extension */
    memset(dirent->deName, ' ', 8);
    p = strchr(uppername, '.');
    memcpy(dirent->deExtension, "___", 3);
    if (p == NULL) {
    fprintf(stderr, "No filename extension given - defaulting to .___\n");
    } else {
    *p = '\0';
    p++;
    len = strlen(p);
    if (len > 3) len = 3;
    memcpy(dirent->deExtension, p, len);
    }
    if (strlen(uppername)>8) {
    uppername[8]='\0';
    }
    memcpy(dirent->deName, uppername, strlen(uppername));
    free(p2);

    /* set the attributes and file size */
    dirent->deAttributes = ATTR_NORMAL;
    putushort(dirent->deStartCluster, start_cluster);
    putulong(dirent->deFileSize, size);

    /* a real filesystem would set the time and date here, but it's
       not necessary for this coursework */
}

 //taken from code provided  
void create_dirent(struct direntry *dirent, char *filename, 
           uint16_t start_cluster, uint32_t size,
           uint8_t *image_buf, struct bpb33* bpb)
{
    while(1) {

    if (dirent->deName[0] == SLOT_EMPTY) {
        /* we found an empty slot at the end of the directory */
        write_dirent(dirent, filename, start_cluster, size);
        dirent++;

        /* make sure the next dirent is set to be empty, just in
           case it wasn't before */
        memset((uint8_t*)dirent, 0, sizeof(struct direntry));
        dirent->deName[0] = SLOT_EMPTY;
        return;
    }
    if (dirent->deName[0] == SLOT_DELETED) {
        /* we found a deleted entry - we can just overwrite it */
        write_dirent(dirent, filename, start_cluster, size);
        return;
    }
    dirent++;
    }
}

//marks free cluster positions in the array as 1
void mark_free_clusters(uint8_t *image_buf, struct bpb33* bpb)
{
    uint16_t count=0;
    while(count<totalClusters)
    {
        uint16_t entry = get_fat_entry(count, image_buf, bpb);
        if(entry==CLUST_FREE)
        {
            array[count]=1;
        }
        count++;
    }


}

//checks the array to print out cluster positions that arent referenced or free
//array has those positions marked as 0
void print_unreferenced(uint8_t *image_buf, struct bpb33* bpb)
{
    uint16_t count=2;
    int first = 1;
    
    while(count<totalClusters)
    {
        if(array[count]!=1)
        {
            uint16_t cluster = get_fat_entry(count, image_buf, bpb);
            if(is_end_of_file(cluster-1)==0)
            {
                //array[cluster]=1;

                if(first==1)
                {
                    printf("unreferenced: \t");
                    first=0;
                }
                printf("%d ", count);
                if(unref<count)
                {
                    unref=count;
                    //printf("unref count= %d\n", count);
                }
            }
            
        }
        count++;
    }
    printf("\n");
}


//prints a lost file after being called from the find_lost_file function
void print_lost_file(uint8_t *image_buf, struct bpb33* bpb)
{
    int length = get_file_length(counter, image_buf, bpb);
    printf("Lost file: %i %i\n", counter, length);
    

    startClust[fileNum]=counter;
    fileLen[fileNum]=length;

    fileNum++; 
    counter+=length;

}

//looks for lost files through the array and then goes into the print function
void find_lost_file(uint8_t *image_buf, struct bpb33* bpb)
{
    //uint16_t i=2;
    //printf("counter ==== %d\n", counter);
   
    while(array[counter]== 1)
    {
        //printf("counter %d\n", counter);
        counter++;
    }
    if(counter<=unref)
    {
        print_lost_file(image_buf, bpb);
    }
    
    if(counter>unref)
    {
        //printf("xsfg\n");
        return;
    }
    else
    {
        find_lost_file(image_buf, bpb);
    }  


}


 //taken from code provided  
void set_fat_entry(uint16_t clusternum, uint16_t value,
           uint8_t *image_buf, struct bpb33* bpb)
{
    uint32_t offset;
    uint8_t *p1, *p2;
    
    /* this involves some really ugly bit shifting.  This probably
       only works on a little-endian machine. */
    offset = bpb->bpbResSectors * bpb->bpbBytesPerSec * bpb->bpbSecPerClust 
    + (3 * (clusternum/2));
    switch(clusternum % 2) {
    case 0:
    p1 = image_buf + offset;
    p2 = image_buf + offset + 1;
    /* mjh: little-endian CPUs are really ugly! */
    *p1 = (uint8_t)(0xff & value);
    *p2 = (uint8_t)((0xf0 & (*p2)) | (0x0f & (value >> 8)));
    break;
    case 1:
    p1 = image_buf + offset + 1;
    p2 = image_buf + offset + 2;
    *p1 = (uint8_t)((0x0f & (*p1)) | ((0x0f & value) << 4));
    *p2 = (uint8_t)(0xff & (value >> 4));
    break;
    }
}

//sets the clusters past the EOF as free
void free_clusters(uint16_t start, uint16_t end, uint8_t *image_buf, struct bpb33* bpb) 
{
    uint16_t current = start;

    while(1) 
    {
        uint16_t next = get_fat_entry(current, image_buf, bpb);
        set_fat_entry(current, FAT12_MASK&CLUST_FREE, image_buf, bpb);

        if (current == end || is_end_of_file(next)==1) 
        {
            break;
        }

        current = next;
    }
    set_fat_entry(start, FAT12_MASK&CLUST_EOFS, image_buf, bpb);
}

//checks the file lengths in the FAT and dir and if not consistent then 
//calls the free_clusters function to set the extra ones free
//most of the code taken from follow_dir function provided
void fix_file_length(uint16_t cluster, uint8_t *image_buf, struct bpb33* bpb)
{
    struct direntry *dirent;
    int d, i;
    dirent = (struct direntry*) cluster_to_addr(cluster, image_buf, bpb);
    int clust_size = bpb->bpbBytesPerSec * bpb->bpbSecPerClust;

    while (1) {
        for (d = 0; d < clust_size; d += sizeof(struct direntry)) {
            char name[9];
            char extension[4];
            uint32_t size;
            uint16_t file_cluster;
            name[8] = ' ';
            extension[3] = ' ';
            memcpy(name, &(dirent->deName[0]), 8);
            memcpy(extension, dirent->deExtension, 3);

            if (name[0] == SLOT_EMPTY)
                return;

            /* skip over deleted entries */
            if (((uint8_t)name[0]) == SLOT_DELETED)
                continue;

            /* names are space padded - remove the spaces */
            for (i = 8; i > 0; i--) {
                if (name[i] == ' ')
                    name[i] = '\0';
                else
                    break;
            }

            /* remove the spaces from extensions */
            for (i = 3; i > 0; i--) {
                if (extension[i] == ' ')
                    extension[i] = '\0';
                else
                    break;
            }

            /* don't print "." or ".." directories */
            if (strcmp(name, ".") == 0) {
                dirent++;
                continue;
            }
            if (strcmp(name, "..") == 0) {
                dirent++;
                continue;
            }

            if ((dirent->deAttributes & ATTR_VOLUME) != 0) {
                continue;
            } else if ((dirent->deAttributes & ATTR_DIRECTORY) != 0) {
                file_cluster = getushort(dirent->deStartCluster);
                fix_file_length(file_cluster, image_buf, bpb);
            } else {
                size = getulong(dirent->deFileSize);
                file_cluster = getushort(dirent->deStartCluster);

                //real size
                uint16_t clustlen = get_file_length(file_cluster, image_buf, bpb);

                uint32_t dirsize = size + clust_size - 1;
                dirsize/=clust_size;
                uint32_t fatsize = clustlen * dirsize;
                if (dirsize != clustlen) 
                {
                    printf("%s.%s %u %u\n", name, extension, size, fatsize);
                    uint16_t start = dirsize + file_cluster - 1;
                    uint16_t end = clustlen + file_cluster;
                    free_clusters(start, end, image_buf, bpb);
                }
            }

            dirent++;
        }

        /* We've reached the end of the cluster for this directory. Where's the next cluster? */
        if (cluster == 0) {
            // root dir is special
            dirent++;
        } else {
            cluster = get_fat_entry(cluster, image_buf, bpb);
            dirent = (struct direntry*) cluster_to_addr(cluster, image_buf, bpb);
        }
    }
}





int main(int argc, char** argv)
{
   uint8_t *image_buf;
   int fd;
   struct bpb33* bpb;

    if (argc < 2 || argc > 2) {
    usage();
    }
                    
   image_buf = mmap_file(argv[1], &fd);
   bpb = check_bootsector(image_buf);
   clustsize = bpb->bpbSecPerClust * bpb->bpbBytesPerSec;
   unref=2;
   fileNum=0;

   mark_unreferenced(0,0,image_buf, bpb);

   mark_free_clusters(image_buf, bpb);

   print_unreferenced(image_buf, bpb);   

   counter=2;
   find_lost_file(image_buf, bpb);
 
   //printf("%d\n", fileNum);
   int k;
   //for each lost file, loops through and creates a directry entry
   for(k=0; k<fileNum; k++)
   {
    uint32_t size = fileLen[k]*clustsize;
    struct direntry *dirent = (struct direntry*) cluster_to_addr(0, image_buf, bpb);
    //sets the name of file
    char filename[]="foundx.dat";
    filename[5]=(k+1) + '0';
    
    create_dirent(dirent, filename, startClust[k], size, image_buf, bpb);

   }
   //checks and fixes file lengths
   fix_file_length(0, image_buf, bpb);

    close(fd);
	return 0;
}

