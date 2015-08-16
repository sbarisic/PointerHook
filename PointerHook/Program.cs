using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PointerHook {
	unsafe class Program {
		static void Main(string[] args) {
			Console.Title = "Pointer Hook Test";

			HackyPointer Ptr = new HackyPointer(HackyPointer.PageSize);
			Console.WriteLine(Ptr);

			int* IPtr = (int*)Ptr;
			IPtr[0] = 314159;
			IPtr[1] = 42;
			Console.WriteLine(IPtr[0]);
			Console.WriteLine(IPtr[1]);

			Ptr.Dispose();
			Console.WriteLine("Done!");
			Console.ReadLine();
		}
	}
}