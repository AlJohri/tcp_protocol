#include <string>
#include <iostream>
#include "Minet.h"

using namespace std;

int main()
{
	Buffer testbuf;
	testbuf.AddFront(Buffer("abc", 3));
	cout <<testbuf.GetSize()<<endl;
	return 0;
}
