using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace PointerHook {
	unsafe class Program {
		static void Main(string[] args) {
			Console.Title = "Pointer Hook Test";

			HackyPointer Ptr = new HackyPointer(HackyPointer.PageSize);
			Console.WriteLine(Ptr);

			int* IPtr = (int*)Ptr;
			IPtr[2] = 0x42;

			Debugger.Break();
			Ptr.Dispose();
			Console.WriteLine("Done!");
			Console.ReadLine();
		}
	}
}