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

			HackyPointer Ptr = new HackyPointer(HackyPointer.PageSize, (P, Write, ByteIdx) => {
				if (!Write)
					return;

				byte* BPtr = (byte*)P;
				Console.Write((char)BPtr[ByteIdx]);
				Console.Write((char)BPtr[ByteIdx + 1]);
				Console.Write((char)BPtr[ByteIdx + 2]);
				Console.Write((char)BPtr[ByteIdx + 3]);
			});


			byte[] Bytes = Encoding.ASCII.GetBytes("Hello World!\n");
			Marshal.Copy(Bytes, 0, (IntPtr)Ptr, Bytes.Length);


			Ptr.Dispose();
			HackyPointer.Destroy();
			Console.WriteLine("\nDone!");
			Console.ReadLine();
			Environment.Exit(0);
		}
	}
}