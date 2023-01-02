#include <stdio.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <unistd.h>
#include <pthread.h>

#define BPF_OBJFILE ".output/myuprobe.bpf.o"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

/*
 * Taken from https://github.com/torvalds/linux/blob/9b59ec8d50a1f28747ceff9a4f39af5deba9540e/tools/testing/selftests/bpf/trace_helpers.c#L149-L205
 *
 * See discussion in https://github.com/libbpf/libbpf-bootstrap/pull/90
 */
size_t get_uprobe_offset(const void *addr)
{
	size_t start, end, base;
	char buf[256];
	bool found = false;
	FILE *f;

	f = fopen("/proc/self/maps", "r");
	if (!f)
		return -errno;

	while (fscanf(f, "%zx-%zx %s %zx %*[^\n]\n", &start, &end, buf, &base) == 4) {
		if (buf[2] == 'x' && (uintptr_t)addr >= start && (uintptr_t)addr < end) {
			found = true;
			break;
		}
	}

	fclose(f);

	if (!found)
		return -ESRCH;

	return (uintptr_t)addr - start + base;
}

int myuprobe_add(int a, int b)
{
	return a + b;
}

void* thread_loop(void *ptr)
{
	int i;
    for (i=0; ; i++) {
	    printf(".");
		myuprobe_add(i, i+1);
		sleep(1);
	}
}

void* thread_read_count(void *ptr)
{
	int* map_fd = (int*) ptr;
	int key, val;
	int i;

	printf("map_fd in thread is %d\n",*map_fd);

	for (i=0; ; i++) {
		key = 0; //
		if(bpf_map_lookup_elem(*map_fd,&key,&val) != 0) {
			 printf("failed to read entry count\n");
		} else {
			printf("add times %d\n", val);
		}

		key = 1;
		if(bpf_map_lookup_elem(*map_fd,&key,&val) != 0) {
			 printf("failed to read entry exit count\n");
		} else {
			printf("add exit times %d\n", val);
		}
		sleep(1);
	}
}

int main(int argc, char **argv)
{
    int err;
	long uprobe_offset;

    struct bpf_object *obj;
	struct bpf_program *prog, *prog_ret;
	struct bpf_link *link, *link1;
	int map_fd;
    char *filename = BPF_OBJFILE;

	pthread_t thread1, thread2, thread3;
    int  iret1, iret2, iret3;
	
	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);
    
	uprobe_offset = get_uprobe_offset(&myuprobe_add);
	printf("D.chaos uprobe_offset is %lx\n",uprobe_offset);
    
	// TODO: check below links for a more common way for load and unload progs
	// https://elixir.bootlin.com/linux/latest/source/samples/bpf/test_overhead_user.c
    obj = bpf_object__open_file(filename,NULL);
	err = libbpf_get_error(obj);
	if (err) {
		printf("failed to open bpf object file %s\n", filename);
	    return 1;
	}

	prog = bpf_object__find_program_by_name(obj, "myuprobe_add");
	if (!prog) {
		printf("failed to find myuprobe_add\n");
		return 1;
	}

	prog_ret = bpf_object__find_program_by_name(obj, "myuretprobe_add");
	if (!prog_ret) {
		printf("failed to find myuretprobe_add\n");
		return 1;
	}


	err = bpf_object__load(obj);
	if(err) {
		printf("load obj failed\n");
		return 1;
	}
	   
	link = bpf_program__attach_uprobe(prog,
	           false,
	           0,
	           "/proc/self/exe",
	           uprobe_offset);
	if(!link) {
		printf("failed to attach uprobe\n");
		return -1;
	}

	link1 = bpf_program__attach_uprobe(prog_ret,
	           true,
	           0,
	           "/proc/self/exe",
	           uprobe_offset);
	
	if(!link1) {
		printf("failed to attach uprobe\n");
		return -1;
	}

	map_fd = bpf_object__find_map_fd_by_name(obj, "my_cnt");
	if(map_fd < 0) {
		printf("faild to load map_fd\n");
	}

    printf("Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` "
	       "to see output of the BPF programs.\n");
	
    /* Create independent threads each of which will execute function */

    iret1 = pthread_create( &thread1, NULL, thread_loop, NULL);
    iret2 = pthread_create( &thread2, NULL, thread_loop, NULL);
	iret3 = pthread_create( &thread3, NULL, thread_read_count, (void*) &map_fd);

    /* Wait till threads are complete before main continues. Unless we  */
    /* wait we run the risk of executing an exit which will terminate   */
    /* the process and all threads before the threads have completed.   */

    printf("Thread 1 returns: %d\n",iret1);
    printf("Thread 2 returns: %d\n",iret2);
	printf("Thread 3 returns: %d\n",iret3);

    pthread_join( thread1, NULL);
    pthread_join( thread2, NULL); 
   
    return 0;
}
