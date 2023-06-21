#include <inc/lib.h>
#define FALSE 0
#define TRUE !(FALSE)


// malloc()
//	This function use BEST FIT strategy to allocate space in heap
//  with the given size and return void pointer to the start of the allocated space

//	To do this, we need to switch to the kernel, allocate the required space
//	in Page File then switch back to the user again.
//
//	We can use sys_allocateMem(uint32 virtual_address, uint32 size); which
//		switches to the kernel mode, calls allocateMem(struct Env* e, uint32 virtual_address, uint32 size) in
//		"memory_manager.c", then switch back to the user mode here
//	the allocateMem function is empty, make sure to implement it.

//==================================================================================//
//============================ REQUIRED FUNCTIONS ==================================//
//==================================================================================//

// void* malloc(uint32 size)
// {
// 	//TODO: [PROJECT 2023 - MS2 - [2] User Heap] malloc() [User Side]
// 	// Write your code here, remove the panic and write your code
// 	panic("malloc() is not implemented yet...!!");

// 	// Steps:
// 	//	1) Implement BEST FIT strategy to search the heap for suitable space
// 	//		to the required allocation size (space should be on 4 KB BOUNDARY)
// 	//	2) if no suitable space found, return NULL
// 	//	 Else,
// 	//	3) Call sys_allocateMem to invoke the Kernel for allocation
// 	// 	4) Return pointer containing the virtual address of allocated space,
// 	//

// 	//This function should find the space of the required range
// 	// ******** ON 4KB BOUNDARY ******************* //

// 	//Use sys_isUHeapPlacementStrategyBESTFIT() to check the current strategy

// 	//change this "return" according to your answer
// 	return 0;
// }



struct user_heap_info
{
	uint32 address;
	uint32 size;
};

uint32 user_heap[(USER_HEAP_MAX - USER_HEAP_START) / PAGE_SIZE] = {0};
struct user_heap_info alloc_pages[((USER_HEAP_MAX - USER_HEAP_START) / PAGE_SIZE)];
int idx = 0;

void *malloc(uint32 size)
{
	uint32 n = (USER_HEAP_MAX - USER_HEAP_START) / PAGE_SIZE;
	size = ROUNDUP(size, PAGE_SIZE) / PAGE_SIZE;
	uint32 smallest_free_block_size = USER_HEAP_MAX; // Initialize with maximum value
	uint32 start_of_best_fit_block = USER_HEAP_MAX;
	bool found = FALSE;

	if (n >= size && sys_isUHeapPlacementStrategyBESTFIT())
	{
		for (uint32 i = 0; i < n; i++)
		{
			if (user_heap[i] == 0)
			{
				uint32 j = i + 1;
				while (j < n && user_heap[j] == 0)
				{
					j++;
				}
				if (j - i >= size && (j - i) < smallest_free_block_size)
				{
					start_of_best_fit_block = USER_HEAP_START + i * PAGE_SIZE;
					smallest_free_block_size = j - i;
					found = TRUE;
				}
				i = j - 1; // Skip to the last checked block
			}
		}
		if (!found)
		{
			return NULL;
		}

		sys_allocateMem(start_of_best_fit_block, size * PAGE_SIZE);

		for (uint32 i = 0; i < size; i++)
		{
			user_heap[(start_of_best_fit_block - USER_HEAP_START) / PAGE_SIZE + i] = 1;
		}

		alloc_pages[idx].address = start_of_best_fit_block;
		alloc_pages[idx].size = size * PAGE_SIZE;
		idx++;
	}
	else
	{
		return NULL;
	}

	return (void *)start_of_best_fit_block;
}







void *smalloc(char *sharedVarName, uint32 size, uint8 isWritable)
{
	// Write your code here, remove the panic and write your code
	panic("smalloc() is not required...!!");

	// Steps:
	//	1) Implement BEST FIT strategy to search the heap for suitable space
	//		to the required allocation size (space should be on 4 KB BOUNDARY)
	//	2) if no suitable space found, return NULL
	//	 Else,
	//	3) Call sys_createSharedObject(...) to invoke the Kernel for allocation of shared variable
	//		sys_createSharedObject(): if succeed, it returns the ID of the created variable. Else, it returns -ve
	//	4) If the Kernel successfully creates the shared variable, return its virtual address
	//	   Else, return NULL

	// This function should find the space of the required range
	//  ******** ON 4KB BOUNDARY ******************* //

	// Use sys_isUHeapPlacementStrategyBESTFIT() to check the current strategy

	// change this "return" according to your answer
	return 0;
}

void *sget(int32 ownerEnvID, char *sharedVarName)
{
	// Write your code here, remove the panic and write your code
	panic("sget() is not required ...!!");

	// Steps:
	//	1) Get the size of the shared variable (use sys_getSizeOfSharedObject())
	//	2) If not exists, return NULL
	//	3) Implement BEST FIT strategy to search the heap for suitable space
	//		to share the variable (should be on 4 KB BOUNDARY)
	//	4) if no suitable space found, return NULL
	//	 Else,
	//	5) Call sys_getSharedObject(...) to invoke the Kernel for sharing this variable
	//		sys_getSharedObject(): if succeed, it returns the ID of the shared variable. Else, it returns -ve
	//	6) If the Kernel successfully share the variable, return its virtual address
	//	   Else, return NULL
	//

	// This function should find the space for sharing the variable
	//  ******** ON 4KB BOUNDARY ******************* //

	// Use sys_isUHeapPlacementStrategyBESTFIT() to check the current strategy

	// change this "return" according to your answer
	return 0;
}

// free():
//	This function frees the allocation of the given virtual_address
//	To do this, we need to switch to the kernel, free the pages AND "EMPTY" PAGE TABLES
//	from page file and main memory then switch back to the user again.
//
//	We can use sys_freeMem(uint32 virtual_address, uint32 size); which
//		switches to the kernel mode, calls freeMem(struct Env* e, uint32 virtual_address, uint32 size) in
//		"memory_manager.c", then switch back to the user mode here
//	the freeMem function is empty, make sure to implement it.

// void free(void *virtual_address)
// {
// 	// TODO: [PROJECT 2023 - MS2 - [2] User Heap] free() [User Side]
// 	//  Write your code here, remove the panic and write your code
// 	panic("free() is not implemented yet...!!");

// 	// you should get the size of the given allocation using its address
// 	// you need to call sys_freeMem()
// 	// refer to the project presentation and documentation for details
// }

void free(void *virtual_address)
{
	uint32 addr = (uint32)virtual_address;

	for (int i = 0; i < idx; i++)
	{
		if (alloc_pages[i].address == addr)
		{
			uint32 size = alloc_pages[i].size / PAGE_SIZE;
			uint32 page_start = (addr - USER_HEAP_START) / PAGE_SIZE;
			uint32 page_end = page_start + size;

			for (uint32 j = page_start; j < page_end; j++)
			{
				user_heap[j] = 0;
			}

			sys_freeMem(addr, size * PAGE_SIZE);


			alloc_pages[i] = alloc_pages[idx - 1];
			idx--;

			return;
		}
	}


}





//==================================================================================//
//============================== BONUS FUNCTIONS ===================================//
//==================================================================================//

//=============
// [1] sfree():
//=============
//	This function frees the shared variable at the given virtual_address
//	To do this, we need to switch to the kernel, free the pages AND "EMPTY" PAGE TABLES
//	from main memory then switch back to the user again.
//
//	use sys_freeSharedObject(...); which switches to the kernel mode,
//	calls freeSharedObject(...) in "shared_memory_manager.c", then switch back to the user mode here
//	the freeSharedObject() function is empty, make sure to implement it.

void sfree(void *virtual_address)
{
	// Write your code here, remove the panic and write your code
	panic("sfree() is not required ...!!");

	//	1) you should find the ID of the shared variable at the given address
	//	2) you need to call sys_freeSharedObject()
}

//===============
// [2] realloc():
//===============

//	Attempts to resize the allocated space at "virtual_address" to "new_size" bytes,
//	possibly moving it in the heap.
//	If successful, returns the new virtual_address, in which case the old virtual_address must no longer be accessed.
//	On failure, returns a null pointer, and the old virtual_address remains valid.

//	A call with virtual_address = null is equivalent to malloc().
//	A call with new_size = zero is equivalent to free().

//  Hint: you may need to use the sys_moveMem(uint32 src_virtual_address, uint32 dst_virtual_address, uint32 size)
//		which switches to the kernel mode, calls moveMem(struct Env* e, uint32 src_virtual_address, uint32 dst_virtual_address, uint32 size)
//		in "memory_manager.c", then switch back to the user mode here
//	the moveMem function is empty, make sure to implement it.

void *realloc(void *virtual_address, uint32 new_size)
{
	// TODO: [PROJECT 2023 - MS2 - [4] Bonus1] realloc() [User Side]
	//  Write your code here, remove the panic and write your code
	panic("realloc() is not implemented yet...!!");
}
