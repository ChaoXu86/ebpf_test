#include <stdio.h>
#include <sys/stat.h>

int main(int argc, char** argv)
{
    FILE *p;
    int ret;
    char data[1024*1024];
    int i;
    struct stat st;
    printf("argv %s\n",argv[1]);
    p = fopen(argv[1],"rb");
    if(!p) printf("file open failed\n");
    ret = fread(data, 1, 1024*1024, p);
    printf("read %d\n",ret);
    for(i=0;i<10;i++) printf("%d ",data[i]);
    printf("\n");

    if(stat(argv[1], &st)) {
         printf("open file error\n");
    }
    printf("st size is %ld\n",st.st_size);
    return 0;
}
