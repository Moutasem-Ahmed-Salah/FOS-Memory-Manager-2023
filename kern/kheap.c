#include <inc/memlayout.h>
#include <kern/kheap.h>
#include <kern/memory_manager.h>



//NOTE: All kernel heap allocations are multiples of PAGE_SIZE (4KB)
uint32 freeSpaceVA = KERNEL_HEAP_START;
int32 heapContent[((KERNEL_HEAP_MAX - KERNEL_HEAP_START) / PAGE_SIZE)]={0};


void *kmalloc(unsigned int size)
{

	int numPages = ROUNDUP(size, PAGE_SIZE) / PAGE_SIZE;
		uint32 address = 0;
		uint32 addressEnd = 0;
		uint32 finalAddress = 0;
		int kernSize = KERNEL_HEAP_MAX - freeSpaceVA;
		int pageCounter = 0;

		if (kernSize >= numPages * PAGE_SIZE && isKHeapPlacementStrategyFIRSTFIT())
		{
			for (int i = 0; i <= ((KERNEL_HEAP_MAX - KERNEL_HEAP_START) / PAGE_SIZE); i++)
			{
				if (heapContent[i] == 0)
				{
					pageCounter++;
					if (pageCounter == 1)
					{
						address = KERNEL_HEAP_START + (i * PAGE_SIZE);
						finalAddress = address;
					}
				}
				else
				{
					pageCounter = 0;
				}

				if (pageCounter == numPages)
				{
					break;
				}
			}
			if (pageCounter == numPages)
			{
				addressEnd = address + (numPages * PAGE_SIZE);
				for (int i = 0; i < numPages; i++)
				{
					struct Frame_Info *fptr = NULL;
					allocate_frame(&fptr);
					map_frame(ptr_page_directory, fptr, (void *)address, PERM_WRITEABLE);
					heapContent[(address - KERNEL_HEAP_START) / PAGE_SIZE] = numPages;
					address += PAGE_SIZE;
				}
			}
			else
			{
				return NULL;
			}
			freeSpaceVA = addressEnd;
		}
		else
		{
			return NULL;
		}

		return (void *)finalAddress;
}
void kfree(void* virtual_address)
{
	uint32 va = ROUNDDOWN((uint32)virtual_address, PAGE_SIZE);

		int startIndex = (va - KERNEL_HEAP_START) / PAGE_SIZE;

		if (va >= KERNEL_HEAP_START && va <= KERNEL_HEAP_MAX && heapContent[startIndex] != 0)
		{
			int numPages = heapContent[startIndex];
			for (int i = 0; i < numPages; i++)
			{
				int index = startIndex + i;
				if (heapContent[index] != 0)

				{
					va = KERNEL_HEAP_START + (index * PAGE_SIZE);
					unmap_frame(ptr_page_directory, (void *)va);
					heapContent[index] = 0;
				}
			}
			if (startIndex < (KERNEL_HEAP_MAX - KERNEL_HEAP_START) / PAGE_SIZE && heapContent[startIndex + numPages] == 0)
			{
				freeSpaceVA = va;
			}
		}
	}








unsigned int kheap_virtual_address(unsigned int physical_address)
{
	uint32 virtual_address;
		uint32 frame_number = (physical_address / PAGE_SIZE);

		for (virtual_address = KERNEL_HEAP_START; virtual_address < KERNEL_HEAP_MAX; virtual_address += PAGE_SIZE)
		{
			uint32 *ptr_PT = NULL;
			uint32 indd = PTX((void *)virtual_address);
			get_page_table(ptr_page_directory, (void *)virtual_address, &ptr_PT);
			uint32 p_va = ptr_PT[indd] & PERM_PRESENT;
			uint32 f = ptr_PT[PTX(virtual_address)] >> 12;
			if (f == frame_number)
				if (p_va != 0)
					return virtual_address;
		}
		return 0;
}

unsigned int kheap_physical_address(unsigned int virtual_address)
{
	uint32 *ptr_PT = NULL, F_Num;
		get_page_table(ptr_page_directory, (void *)virtual_address, &ptr_PT);
		if (ptr_PT != NULL)
		{
			F_Num = (ptr_PT[PTX(virtual_address)] >> 12) * PAGE_SIZE;
			return F_Num += (virtual_address & 0x00000FFF);
		}
		return 0;
}


//=================================================================================//
//============================== BONUS FUNCTION ===================================//
//=================================================================================//
// krealloc():

//	Attempts to resize the allocated space at "virtual_address" to "new_size" bytes,
//	possibly moving it in the heap.
//	If successful, returns the new virtual_address, in which case the old virtual_address must no longer be accessed.
//	On failure, returns a null pointer, and the old virtual_address remains valid.

//	A call with virtual_address = null is equivalent to kmalloc()>>done.
//	A call with new_size = zero is equivalent to kfree() >>done.

void *krealloc(void *virtual_address, unsigned int new_size)
{
  panic("Not Implemented yet");
}










