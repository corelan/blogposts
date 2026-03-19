// corelanapp1.cpp : This file contains the 'main' function. Program execution begins and ends there.
// Example application used by Corelan for demonstration purposes only
// https://www.corelan.be
// (c) Corelan Consulting bv

#include <iostream>
#include <Windows.h>

int main()
{
	HANDLE hDefault, hAlloc1, hAlloc2;
	int deltaSize;

    std::cout << "Welcome to CorelanApp1!\n";
	std::cout << "www.corelan.be\n";

	hDefault = GetProcessHeap();
	hAlloc1 = HeapAlloc(hDefault, 0, 0x5000);
	hAlloc2 = HeapAlloc(hDefault, 0, 0x5000);
	deltaSize = int(hAlloc2) - int(hAlloc1);
	
	printf("Alloc 1 : 0x%p\n", hAlloc1);
	printf("Alloc 2 : 0x%p\n", hAlloc2);
	printf("The distance from Alloc 1 to Alloc 2 is 0x%x bytes\n", deltaSize);
	system("pause > nul");
}
