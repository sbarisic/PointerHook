using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PointerHook {
	unsafe class Program {
		static void Main(string[] args) {
			Console.Title = "Pointer Hook Test";

			HackyPointer Ptr = new HackyPointer(sizeof(int));
			int* IPtr = (int*)Ptr;

			Console.WriteLine("Pointer: {0}", Ptr);


			Console.WriteLine("Done!");
			Console.ReadLine();
		}
	}
}
